"""Vault-scoped, descriptor-relative filesystem gateway.

Authorization is performed on canonical vault-relative names.  Actual I/O is
then performed relative to directory file descriptors opened with
``O_NOFOLLOW``.  This matters for a network-facing service: checking a
``Path`` and opening that path later leaves a symlink-swap window.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import hashlib
import os
import stat
import sys
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from ..domain.models import FileRevision, RevisionConflictError
from .policy import (
    ProtectedPathError,
    ReadPermissionError,
    VaultAccessPolicy,
    VaultPath,
    VaultPathError,
)

PathTraversalError = VaultPathError


class SecureStorageError(RuntimeError):
    """The platform cannot provide the no-follow descriptor guarantees."""


@dataclass(frozen=True)
class VaultEntry:
    name: str
    relative: str
    is_dir: bool
    size_bytes: int | None
    mtime: float


@dataclass(frozen=True)
class TrashEntry:
    """Metadata exposed by the narrow trash-management capability."""

    name: str
    is_dir: bool
    size_bytes: int | None
    mtime: float


def _configured_policy(vault_root: str | Path) -> VaultAccessPolicy:
    """Use configured authorization for the live vault; fail closed there."""
    root = Path(vault_root).resolve()
    try:
        from ..config import ConfigError, get_config
    except (ImportError, ModuleNotFoundError):
        return VaultAccessPolicy(root)

    try:
        config = get_config()
    except ConfigError:
        # A configured-looking root must not silently become unrestricted.
        raw_vault = os.environ.get("VAULT_PATH")
        if raw_vault and Path(raw_vault).resolve() == root:
            raise
        return VaultAccessPolicy(root)
    if config.vault_path == root:
        return VaultAccessPolicy.from_config(config)
    if root.is_relative_to(config.vault_path):
        raise VaultPathError(
            "An explicit vault root inside the configured vault cannot bypass its access policy"
        )
    return VaultAccessPolicy(root)


def _require_secure_platform() -> None:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "supports_dir_fd"):
        raise SecureStorageError("This platform lacks descriptor-relative no-follow filesystem APIs")
    if os.open not in os.supports_dir_fd:
        raise SecureStorageError("openat-style directory descriptors are unavailable")
    if os.rename not in os.supports_dir_fd:
        raise SecureStorageError("renameat-style directory descriptors are unavailable")
    if os.unlink not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        raise SecureStorageError("unlinkat/mkdirat-style directory descriptors are unavailable")
    if not hasattr(os, "link") or os.link not in os.supports_dir_fd:
        raise SecureStorageError("linkat-style no-replace commits are unavailable")


def _dir_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@contextlib.contextmanager
def _opened_parent(root: Path, relative: str, *, create: bool = False) -> Iterator[tuple[int, str]]:
    """Yield ``(parent_fd, leaf)`` with every parent opened no-follow."""
    _require_secure_platform()
    parts = [part for part in relative.split("/") if part]
    if not parts:
        raise VaultPathError("A child path is required")
    root_fd = os.open(root, _dir_flags())
    fds = [root_fd]
    try:
        current = root_fd
        for component in parts[:-1]:
            try:
                child = os.open(component, _dir_flags(), dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, 0o770, dir_fd=current)
                # Persist each newly-created parent before descending into it.
                _fsync_dir(current)
                child = os.open(component, _dir_flags(), dir_fd=current)
            fds.append(child)
            current = child
        yield current, parts[-1]
    finally:
        for fd in reversed(fds):
            os.close(fd)


@contextlib.contextmanager
def _opened_dir(root: Path, relative: str = "") -> Iterator[int]:
    """Yield a no-follow fd for an existing vault directory."""
    _require_secure_platform()
    if not relative:
        fd = os.open(root, _dir_flags())
        try:
            yield fd
        finally:
            os.close(fd)
        return
    with _opened_parent(root, relative) as (parent_fd, leaf):
        fd = os.open(leaf, _dir_flags(), dir_fd=parent_fd)
        try:
            yield fd
        finally:
            os.close(fd)


def _stat_at(parent_fd: int, leaf: str) -> os.stat_result:
    return os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)


def _ensure_not_symlink(parent_fd: int, leaf: str) -> os.stat_result:
    info = _stat_at(parent_fd, leaf)
    if stat.S_ISLNK(info.st_mode):
        raise VaultPathError(f"Symlink path components are not allowed: {leaf!r}")
    return info


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _fsync_dir(fd: int) -> None:
    """Persist a directory entry update before reporting a mutation done."""
    os.fsync(fd)


def _revision_at(parent_fd: int, leaf: str) -> FileRevision:
    """Hash one regular file through the already-authorized parent fd."""
    fd = os.open(leaf, _file_flags(), dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise IsADirectoryError(leaf)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        content = b"".join(chunks)
        final = os.fstat(fd)
        return FileRevision.from_bytes(content, size=len(content), mtime_ns=final.st_mtime_ns)
    finally:
        os.close(fd)


def _scandir_tree(fd: int, prefix: str = "") -> Iterator[tuple[str, os.stat_result, bool]]:
    """Yield all descendants, rejecting symlinks and using stable dirfds."""
    with os.scandir(fd) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            rel = f"{prefix}/{entry.name}" if prefix else entry.name
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise VaultPathError(f"Symlink path components are not allowed: {rel!r}")
            is_dir = stat.S_ISDIR(info.st_mode)
            yield rel, info, is_dir
            if is_dir:
                child_fd = os.open(entry.name, _dir_flags(), dir_fd=fd)
                try:
                    yield from _scandir_tree(child_fd, rel)
                finally:
                    os.close(child_fd)


def _remove_tree_fd(parent_fd: int, leaf: str) -> None:
    """Remove a directory tree relative to an already-open parent fd."""
    info = _ensure_not_symlink(parent_fd, leaf)
    if not stat.S_ISDIR(info.st_mode):
        os.unlink(leaf, dir_fd=parent_fd)
        return
    child_fd = os.open(leaf, _dir_flags(), dir_fd=parent_fd)
    try:
        with os.scandir(child_fd) as entries:
            for entry in entries:
                child_info = entry.stat(follow_symlinks=False)
                if stat.S_ISLNK(child_info.st_mode):
                    raise VaultPathError(f"Symlink path components are not allowed: {entry.name!r}")
                if stat.S_ISDIR(child_info.st_mode):
                    _remove_tree_fd(child_fd, entry.name)
                else:
                    os.unlink(entry.name, dir_fd=child_fd)
    finally:
        os.close(child_fd)
    os.rmdir(leaf, dir_fd=parent_fd)


def _rename_noreplace(src_parent: int, src_leaf: str, dst_parent: int, dst_leaf: str) -> None:
    """Move one entry without ever replacing a concurrently-created target.

    Linux and macOS expose the required directory-descriptor primitives via
    libc.  For regular files, the hard-link/unlink fallback is also
    no-replace safe.  There is no portable equivalent for directories, so a
    platform without one of the primitives fails closed rather than risking a
    destructive ``rename`` replacement.
    """
    src_name = os.fsencode(src_leaf)
    dst_name = os.fsencode(dst_leaf)
    libc = ctypes.CDLL(None, use_errno=True)
    primitive = None
    flags = 0
    if sys.platform.startswith("linux"):
        primitive = getattr(libc, "renameat2", None)
        flags = 1  # RENAME_NOREPLACE
    elif sys.platform == "darwin":
        primitive = getattr(libc, "renameatx_np", None)
        flags = 4  # RENAME_EXCL
    if primitive is not None:
        primitive.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        primitive.restype = ctypes.c_int
        if primitive(src_parent, src_name, dst_parent, dst_name, flags) == 0:
            _fsync_dir(src_parent)
            if dst_parent != src_parent:
                _fsync_dir(dst_parent)
            return
        error = ctypes.get_errno()
        if error not in (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP):
            raise OSError(error, os.strerror(error), dst_leaf)

    info = _ensure_not_symlink(src_parent, src_leaf)
    if stat.S_ISDIR(info.st_mode):
        raise OSError(errno.ENOTSUP, "directory no-replace move is unavailable", src_leaf)
    # Hard-link creation is atomic and fails with EEXIST if another writer
    # wins the destination race.  It is only a fallback for regular files.
    os.link(src_leaf, dst_leaf, src_dir_fd=src_parent, dst_dir_fd=dst_parent, follow_symlinks=False)
    try:
        os.unlink(src_leaf, dir_fd=src_parent)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(dst_leaf, dir_fd=dst_parent)
        raise
    _fsync_dir(src_parent)
    if dst_parent != src_parent:
        _fsync_dir(dst_parent)


class VaultStorage:
    """Authorize each operation before secure descriptor-relative I/O."""

    def __init__(self, policy: VaultAccessPolicy) -> None:
        self.policy = policy

    @classmethod
    def from_config(cls, config=None) -> VaultStorage:
        if config is None:
            from ..config import get_config

            config = get_config()
        return cls(VaultAccessPolicy.from_config(config))

    def resolve_read(self, path: str, *, allow_empty: bool = False) -> VaultPath:
        return self.policy.resolve_read(path, allow_empty=allow_empty)

    def resolve_write(self, path: str, *, allow_empty: bool = False) -> VaultPath:
        return self.policy.resolve_write(path, allow_empty=allow_empty)

    def resolve_delete(self, path: str, *, permanent: bool = False) -> VaultPath:
        return self.policy.resolve_delete(path, permanent=permanent)

    def stat(self, path: str, *, read: bool = True) -> os.stat_result:
        target = self.resolve_read(path) if read else self.resolve_write(path)
        with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
            return _ensure_not_symlink(parent_fd, leaf)

    def exists(self, path: str, *, read: bool = True) -> bool:
        try:
            self.stat(path, read=read)
            return True
        except (FileNotFoundError, NotADirectoryError):
            return False

    def _tree_paths(self, target: VaultPath) -> list[str]:
        """List a target and descendants using no-follow descriptors."""
        if not target.relative:
            with _opened_dir(self.policy.root, "") as root_fd:
                return [rel for rel, _, _ in _scandir_tree(root_fd)]
        try:
            with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
                info = _ensure_not_symlink(parent_fd, leaf)
                paths = [target.relative]
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(leaf, _dir_flags(), dir_fd=parent_fd)
                    try:
                        paths.extend(f"{target.relative}/{rel}" for rel, _, _ in _scandir_tree(child_fd))
                    finally:
                        os.close(child_fd)
                return paths
        except FileNotFoundError:
            raise FileNotFoundError(f"Path not found: {target.relative!r}") from None

    def tree_paths(self, path: str) -> list[VaultPath]:
        target = self.resolve_read(path, allow_empty=not path)
        # Public discovery must apply read policy to every descendant. Internal
        # mutation preflight intentionally uses _tree_paths() directly and
        # authorizes each returned path with resolve_delete/resolve_write.
        result: list[VaultPath] = []
        for rel in self._tree_paths(target):
            try:
                result.append(self.policy.resolve_read(rel))
            except (VaultPathError, ReadPermissionError):
                continue
        return result

    def authorize_tree(
        self,
        path: str,
        *,
        operation: str = "delete",
        destination: str | None = None,
        permanent: bool = False,
    ) -> list[str]:
        """Preauthorize every source descendant and mapped destination.

        ``operation=delete`` applies write/delete policy to every descendant.
        ``destination`` additionally authorizes each mapped destination before
        any rename or directory creation occurs.
        """
        source = self.resolve_delete(path, permanent=permanent)
        source_paths = self._tree_paths(source)
        source_is_dir = False
        with _opened_parent(self.policy.root, source.relative) as (source_parent, source_leaf):
            source_is_dir = stat.S_ISDIR(_ensure_not_symlink(source_parent, source_leaf).st_mode)
        if source_is_dir:
            source_prefix = source.relative.rstrip("/") + "/"
            if any(
                self.policy.rule_path(rule).startswith(source_prefix)
                for rule in self.policy.deny_write_paths
            ):
                raise ProtectedPathError(
                    f"Directory mutation crosses a protected descendant of {source.relative!r}"
                )
        for rel in source_paths:
            self.policy.resolve_delete(rel, permanent=permanent)
        if destination is not None:
            dest = self.resolve_write(destination)
            if source_is_dir:
                dest_prefix = dest.relative.rstrip("/") + "/"
                if any(
                    self.policy.rule_path(rule).startswith(dest_prefix)
                    for rule in self.policy.deny_write_paths
                ):
                    raise ProtectedPathError(
                        f"Directory mutation crosses a protected destination descendant of {dest.relative!r}"
                    )
            prefix = source.relative + "/"
            for rel in source_paths:
                suffix = rel[len(prefix):] if rel.startswith(prefix) else ""
                mapped = f"{dest.relative}/{suffix}" if suffix else dest.relative
                self.policy.resolve_write(mapped)
        return source_paths

    def _read_fd(self, path: str) -> tuple[bytes, FileRevision]:
        target = self.resolve_read(path)
        with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
            fd = os.open(leaf, _file_flags(), dir_fd=parent_fd)
            try:
                before = os.fstat(fd)
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                content = b"".join(chunks)
                after = os.fstat(fd)
                # If a cooperating or external writer changed the file while
                # it was read, use the final metadata for diagnostics but the
                # hash remains authoritative for the exact bytes returned.
                info = after if after.st_size == len(content) else before
                return content, FileRevision.from_bytes(
                    content, size=len(content), mtime_ns=info.st_mtime_ns
                )
            finally:
                os.close(fd)

    def revision(self, path: str) -> FileRevision:
        """Return the authoritative SHA-256 revision of an authorized file."""
        _, revision = self._read_fd(path)
        return revision

    def tree_revision(self, path: str) -> str:
        """Return a deterministic digest for a directory's current files."""
        target = self.policy.resolve_read(path)
        digest = hashlib.sha256()
        prefix = target.relative.rstrip("/") + "/" if target.relative else ""
        for absolute in sorted(self._tree_paths(target)):
            relative = "." if absolute == target.relative else absolute.removeprefix(prefix)
            info = self.stat(absolute)
            if stat.S_ISDIR(info.st_mode):
                digest.update(relative.encode("utf-8"))
                digest.update(b"\0dir\n")
                continue
            revision = self.revision(absolute)
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(revision.sha256.encode("ascii"))
            digest.update(b"\n")
        return "tree:" + digest.hexdigest()

    def read_text_with_revision(self, path: str) -> tuple[str, FileRevision]:
        content, revision = self._read_fd(path)
        return content.decode("utf-8", "replace"), revision

    def read_bytes_with_revision(self, path: str) -> tuple[bytes, FileRevision]:
        return self._read_fd(path)

    def read_text(self, path: str) -> str:
        target = self.resolve_read(path)
        with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
            fd = os.open(leaf, _file_flags(), dir_fd=parent_fd)
            try:
                with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as stream:
                    fd = -1
                    return stream.read()
            finally:
                if fd >= 0:
                    os.close(fd)

    def read_bytes(self, path: str) -> bytes:
        target = self.resolve_read(path)
        with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
            fd = os.open(leaf, _file_flags(), dir_fd=parent_fd)
            try:
                chunks: list[bytes] = []
                while True:
                    chunk = os.read(fd, 1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)
            finally:
                os.close(fd)

    def _current_revision(self, target: VaultPath) -> FileRevision | None:
        try:
            with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
                return _revision_at(parent_fd, leaf)
        except (FileNotFoundError, NotADirectoryError):
            return None

    @staticmethod
    def _matches_revision(actual: FileRevision | None, expected: FileRevision) -> bool:
        return actual is not None and actual.sha256 == expected.sha256

    def _write_atomic(
        self,
        target: VaultPath,
        data: bytes,
        *,
        expected_revision: FileRevision | str | dict | None = None,
        create_only: bool = False,
    ) -> FileRevision:
        expected = FileRevision.from_value(expected_revision) if expected_revision is not None else None
        before = self._current_revision(target)
        if create_only and before is not None:
            raise RevisionConflictError(target.relative, None, before)
        if expected is not None and not self._matches_revision(before, expected):
            raise RevisionConflictError(target.relative, expected, before)
        tmp_name = f".obsidian-mcp-tmp-{uuid.uuid4().hex}"
        with _opened_parent(self.policy.root, target.relative, create=True) as (parent_fd, leaf):
            # O_EXCL + dirfd ensures the temporary file is created in the
            # already-authorized parent and cannot be redirected by a symlink.
            tmp_fd = os.open(
                tmp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent_fd,
            )
            committed = False
            try:
                _write_all(tmp_fd, data)
                os.fsync(tmp_fd)
                os.close(tmp_fd)
                tmp_fd = -1
                # Re-check immediately before replacement. This catches a
                # sync writer that changed the file while the temporary file
                # was being staged. The final rename remains the unavoidable
                # small race described in the Phase 3 design.
                try:
                    current = _revision_at(parent_fd, leaf)
                except FileNotFoundError:
                    current = None
                if create_only:
                    if current is not None:
                        raise RevisionConflictError(target.relative, None, current)
                elif expected is not None:
                    if not self._matches_revision(current, expected):
                        raise RevisionConflictError(target.relative, expected, current)
                elif before is not None and current is not None and current.sha256 != before.sha256:
                    raise RevisionConflictError(target.relative, before, current)
                elif before is None and current is not None:
                    raise RevisionConflictError(target.relative, None, current)
                if create_only:
                    # link(2) is the portable same-directory no-replace
                    # primitive available here: it fails atomically with
                    # EEXIST if another writer created the destination after
                    # the final check. The temporary name is then removed.
                    try:
                        os.link(
                            tmp_name,
                            leaf,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except FileExistsError:
                        actual = _revision_at(parent_fd, leaf)
                        raise RevisionConflictError(target.relative, None, actual) from None
                    os.unlink(tmp_name, dir_fd=parent_fd)
                    _fsync_dir(parent_fd)
                else:
                    os.rename(tmp_name, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    _fsync_dir(parent_fd)
                committed = True
                final = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                committed_revision = FileRevision.from_bytes(
                    data, size=len(data), mtime_ns=final.st_mtime_ns
                )
            finally:
                if tmp_fd >= 0:
                    os.close(tmp_fd)
                if not committed:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(tmp_name, dir_fd=parent_fd)
        return committed_revision

    def write_text_atomic(
        self,
        path: str,
        content: str,
        *,
        expected_revision: FileRevision | str | dict | None = None,
        create_only: bool = False,
    ) -> FileRevision:
        target = self.resolve_write(path)
        return self._write_atomic(
            target, content.encode("utf-8"), expected_revision=expected_revision, create_only=create_only
        )

    def write_bytes_atomic(
        self,
        path: str,
        content: bytes,
        *,
        expected_revision: FileRevision | str | dict | None = None,
        create_only: bool = False,
    ) -> FileRevision:
        target = self.resolve_write(path)
        return self._write_atomic(
            target, content, expected_revision=expected_revision, create_only=create_only
        )

    def remove_file(self, path: str, *, expected_revision: FileRevision | str | dict | None = None) -> VaultPath:
        """Remove one authorized regular file for transaction rollback.

        This is intentionally not exposed as a user-facing delete operation;
        it exists so a transaction can restore an originally-absent file even
        when ``ALLOW_PERMANENT_DELETE`` is disabled for callers.
        """
        target = self.resolve_write(path)
        with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
            info = _ensure_not_symlink(parent_fd, leaf)
            if not stat.S_ISREG(info.st_mode):
                raise IsADirectoryError(target.relative)
            if expected_revision is not None:
                actual = _revision_at(parent_fd, leaf)
                expected = FileRevision.from_value(expected_revision)
                if actual.sha256 != expected.sha256:
                    raise RevisionConflictError(target.relative, expected, actual)
            os.unlink(leaf, dir_fd=parent_fd)
            _fsync_dir(parent_fd)
        return target

    def make_dir(self, path: str) -> VaultPath:
        target = self.resolve_write(path)
        with _opened_parent(self.policy.root, target.relative, create=True) as (parent_fd, leaf):
            try:
                os.mkdir(leaf, 0o770, dir_fd=parent_fd)
                _fsync_dir(parent_fd)
            except FileExistsError:
                info = _ensure_not_symlink(parent_fd, leaf)
                if not stat.S_ISDIR(info.st_mode):
                    raise
        return target

    def list_dir(self, path: str = "") -> list[VaultEntry]:
        target = self.resolve_read(path, allow_empty=True)
        with _opened_dir(self.policy.root, target.relative) as directory_fd:
            entries: list[VaultEntry] = []
            with os.scandir(directory_fd) as items:
                for item in sorted(items, key=lambda entry: entry.name):
                    rel = f"{target.relative}/{item.name}" if target.relative else item.name
                    try:
                        authorized = self.resolve_read(rel)
                        info = item.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            continue
                    except (VaultPathError, OSError):
                        continue
                    entries.append(
                        VaultEntry(
                            name=item.name,
                            relative=authorized.relative,
                            is_dir=stat.S_ISDIR(info.st_mode),
                            size_bytes=None if stat.S_ISDIR(info.st_mode) else info.st_size,
                            mtime=info.st_mtime,
                        )
                    )
            return entries

    def list_files(self, path: str = "") -> list[VaultPath]:
        target = self.resolve_read(path, allow_empty=True)
        with _opened_dir(self.policy.root, target.relative) as directory_fd:
            result: list[VaultPath] = []

            def walk(fd: int, prefix: str = "") -> Iterator[VaultPath]:
                with os.scandir(fd) as items:
                    for item in items:
                        rel = f"{prefix}/{item.name}" if prefix else item.name
                        full_rel = f"{target.relative}/{rel}" if target.relative else rel
                        try:
                            authorized = self.resolve_read(full_rel)
                            info = item.stat(follow_symlinks=False)
                        except (VaultPathError, OSError):
                            # A denied directory is not descended into.  This
                            # keeps discovery from even enumerating protected
                            # subtrees, while a concurrent/symlink swap fails
                            # closed for this listing.
                            continue
                        if stat.S_ISLNK(info.st_mode):
                            continue
                        if stat.S_ISDIR(info.st_mode):
                            try:
                                child_fd = os.open(item.name, _dir_flags(), dir_fd=fd)
                            except OSError:
                                continue
                            try:
                                yield from walk(child_fd, rel)
                            finally:
                                os.close(child_fd)
                        else:
                            yield authorized

            result.extend(walk(directory_fd))
            return result

    def _rename_relative(self, source: VaultPath, destination: VaultPath) -> None:
        with _opened_parent(self.policy.root, source.relative) as (src_parent, src_leaf):
            _ensure_not_symlink(src_parent, src_leaf)
            with _opened_parent(self.policy.root, destination.relative, create=True) as (dst_parent, dst_leaf):
                try:
                    _stat_at(dst_parent, dst_leaf)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError(f"Target already exists: {destination.relative!r}")
                _rename_noreplace(src_parent, src_leaf, dst_parent, dst_leaf)

    def move(
        self,
        from_path: str,
        to_path: str,
        *,
        expected_revision: FileRevision | str | dict | None = None,
    ) -> tuple[VaultPath, VaultPath]:
        source = self.resolve_delete(from_path)
        destination = self.resolve_write(to_path)
        if source.relative == destination.relative:
            raise VaultPathError("Source and destination must differ")
        if destination.relative.startswith(source.relative + "/"):
            raise VaultPathError("Destination cannot be inside the source tree")
        self.authorize_tree(source.relative, destination=destination.relative)
        if expected_revision is not None:
            if isinstance(expected_revision, str) and expected_revision.startswith("tree:"):
                actual_tree = self.tree_revision(source.relative)
                if actual_tree != expected_revision:
                    raise OSError(errno.EAGAIN, f"Tree revision conflict for {source.relative!r}")
            else:
                with _opened_parent(self.policy.root, source.relative) as (source_parent, source_leaf):
                    actual = _revision_at(source_parent, source_leaf)
                    expected = FileRevision.from_value(expected_revision)
                    if actual.sha256 != expected.sha256:
                        raise RevisionConflictError(source.relative, expected, actual)
        self._rename_relative(source, destination)
        return source, destination

    def delete(
        self,
        path: str,
        *,
        permanent: bool = False,
        expected_revision: FileRevision | str | dict | None = None,
    ) -> VaultPath:
        target = self.resolve_delete(path, permanent=permanent)
        self.authorize_tree(target.relative, permanent=permanent)
        with _opened_parent(self.policy.root, target.relative) as (parent_fd, leaf):
            if expected_revision is not None:
                actual = _revision_at(parent_fd, leaf)
                expected = FileRevision.from_value(expected_revision)
                if actual.sha256 != expected.sha256:
                    raise RevisionConflictError(target.relative, expected, actual)
            if permanent:
                _remove_tree_fd(parent_fd, leaf)
                _fsync_dir(parent_fd)
            else:
                raise IsADirectoryError(f"Use trash() for a folder: {path!r}")
        return target

    def trash(
        self,
        path: str,
        *,
        expected_revision: FileRevision | str | dict | None = None,
        destination_name: str | None = None,
    ) -> tuple[VaultPath, Path]:
        source = self.resolve_delete(path)
        self.authorize_tree(source.relative)
        if destination_name is not None and (
            not destination_name or Path(destination_name).name != destination_name or destination_name in {".", ".."}
        ):
            raise VaultPathError("Trash destination must be a bare filename")
        with _opened_dir(self.policy.root, "") as root_fd:
            try:
                trash_fd = os.open(".trash", _dir_flags(), dir_fd=root_fd)
            except FileNotFoundError:
                os.mkdir(".trash", 0o700, dir_fd=root_fd)
                _fsync_dir(root_fd)
                trash_fd = os.open(".trash", _dir_flags(), dir_fd=root_fd)
            try:
                if stat.S_ISLNK(_stat_at(root_fd, ".trash").st_mode):
                    raise ProtectedPathError("The vault trash directory cannot be a symlink")
                with _opened_parent(self.policy.root, source.relative) as (src_parent, src_leaf):
                    _ensure_not_symlink(src_parent, src_leaf)
                    if expected_revision is not None:
                        if isinstance(expected_revision, str) and expected_revision.startswith("tree:"):
                            actual_tree = self.tree_revision(source.relative)
                            if actual_tree != expected_revision:
                                raise OSError(errno.EAGAIN, f"Tree revision conflict for {source.relative!r}")
                        else:
                            actual = _revision_at(src_parent, src_leaf)
                            expected = FileRevision.from_value(expected_revision)
                            if actual.sha256 != expected.sha256:
                                raise RevisionConflictError(source.relative, expected, actual)
                    fixed_destination = destination_name is not None
                    base_name = destination_name or source.relative.rsplit("/", 1)[-1]
                    for _attempt in range(16):
                        destination_name = base_name
                        if not fixed_destination:
                            try:
                                _stat_at(trash_fd, destination_name)
                            except FileNotFoundError:
                                pass
                            else:
                                stem, dot, suffix = destination_name.rpartition(".")
                                if not dot:
                                    stem, suffix = destination_name, ""
                                destination_name = f"{stem}-{uuid.uuid4().hex[:8]}{('.' + suffix) if suffix else ''}"
                        try:
                            _rename_noreplace(src_parent, src_leaf, trash_fd, destination_name)
                        except FileExistsError:
                            if fixed_destination:
                                raise
                            # A concurrent trash writer won the collision
                            # check; choose a fresh collision name and retry
                            # atomically.
                            continue
                        return source, self.policy.root / ".trash" / destination_name
                    raise FileExistsError(
                        f"Unable to reserve a trash destination for {source.relative!r}"
                    )
            finally:
                os.close(trash_fd)

    def trash_destination_name(self, path: str) -> str:
        """Choose a currently free bare trash name without mutating the vault.

        Transaction callers persist this exact name in their intent before
        invoking :meth:`trash`, so a crash after the rename can still identify
        and verify the attributable destination.  The final operation remains
        no-replace safe if another writer wins the race.
        """
        source = self.resolve_delete(path)
        base_name = source.relative.rsplit("/", 1)[-1]
        with _opened_dir(self.policy.root, "") as root_fd:
            try:
                trash_fd = os.open(".trash", _dir_flags(), dir_fd=root_fd)
            except FileNotFoundError:
                return base_name
            try:
                candidate = base_name
                while True:
                    try:
                        _stat_at(trash_fd, candidate)
                    except FileNotFoundError:
                        return candidate
                    stem, dot, suffix = candidate.rpartition(".")
                    if not dot:
                        stem, suffix = candidate, ""
                    candidate = f"{stem}-{uuid.uuid4().hex[:8]}{('.' + suffix) if suffix else ''}"
            finally:
                os.close(trash_fd)

    def list_trash(self) -> list[TrashEntry]:
        try:
            with _opened_dir(self.policy.root, ".trash") as trash_fd:
                result: list[TrashEntry] = []
                with os.scandir(trash_fd) as items:
                    for item in sorted(items, key=lambda entry: entry.name):
                        info = item.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            continue
                        result.append(
                            TrashEntry(
                                name=item.name,
                                is_dir=stat.S_ISDIR(info.st_mode),
                                size_bytes=None if stat.S_ISDIR(info.st_mode) else info.st_size,
                                mtime=info.st_mtime,
                            )
                        )
                return result
        except FileNotFoundError:
            return []

    def trash_info(self, trashed_name: str) -> TrashEntry:
        if not trashed_name or Path(trashed_name).name != trashed_name:
            raise VaultPathError("Trash item must be a bare filename")
        with _opened_dir(self.policy.root, ".trash") as trash_fd:
            info = _ensure_not_symlink(trash_fd, trashed_name)
            return TrashEntry(
                name=trashed_name,
                is_dir=stat.S_ISDIR(info.st_mode),
                size_bytes=None if stat.S_ISDIR(info.st_mode) else info.st_size,
                mtime=info.st_mtime,
            )

    def trash_tree_revision(self, trashed_name: str) -> str:
        """Digest a trash item without granting ordinary read access to .trash."""
        info = self.trash_info(trashed_name)
        digest = hashlib.sha256()
        with _opened_dir(self.policy.root, ".trash") as trash_fd:
            if not info.is_dir:
                revision = _revision_at(trash_fd, trashed_name)
                return "trash:" + revision.sha256
            item_fd = os.open(trashed_name, _dir_flags(), dir_fd=trash_fd)
            try:
                digest.update(b".\0dir\n")
                entries = sorted(_scandir_tree(item_fd), key=lambda entry: entry[0])
                for relative, _item_info, is_dir in entries:
                    if is_dir:
                        digest.update(relative.encode("utf-8"))
                        digest.update(b"\0dir\n")
                        continue
                    parent = relative.rsplit("/", 1)
                    if len(parent) == 1:
                        revision = _revision_at(item_fd, parent[0])
                    else:
                        with _opened_parent(self.policy.root, ".trash/" + trashed_name + "/" + relative) as (parent_fd, leaf):
                            revision = _revision_at(parent_fd, leaf)
                    digest.update(relative.encode("utf-8"))
                    digest.update(b"\0")
                    digest.update(revision.sha256.encode("ascii"))
                    digest.update(b"\n")
            finally:
                os.close(item_fd)
        return "trash:" + digest.hexdigest()

    def trash_inventory(self, trashed_name: str) -> list[tuple[str, int, str]]:
        """Return regular-file inventory for a trash item without policy reads."""
        info = self.trash_info(trashed_name)
        result: list[tuple[str, int, str]] = []
        with _opened_dir(self.policy.root, ".trash") as trash_fd:
            if not info.is_dir:
                file_info = _stat_at(trash_fd, trashed_name)
                revision = _revision_at(trash_fd, trashed_name)
                return [(f".trash/{trashed_name}", file_info.st_size, revision.token)]
            item_fd = os.open(trashed_name, _dir_flags(), dir_fd=trash_fd)
            try:
                for relative, item_info, is_dir in _scandir_tree(item_fd):
                    if is_dir:
                        continue
                    full = f".trash/{trashed_name}/{relative}"
                    with _opened_parent(self.policy.root, full) as (parent_fd, leaf):
                        revision = _revision_at(parent_fd, leaf)
                    result.append((full, item_info.st_size, revision.token))
            finally:
                os.close(item_fd)
        return result

    def authorize_restore(self, trashed_name: str, to_path: str) -> VaultPath:
        """Preauthorize every destination descendant of a trash directory."""
        info = self.trash_info(trashed_name)
        destination = self.resolve_write(to_path)
        with _opened_dir(self.policy.root, ".trash") as trash_fd:
            if not info.is_dir:
                self.policy.resolve_write(destination.relative)
                return destination
            source_fd = os.open(info.name, _dir_flags(), dir_fd=trash_fd)
            try:
                self.policy.resolve_write(destination.relative)
                for relative, _item_info, _is_dir in _scandir_tree(source_fd):
                    mapped = f"{destination.relative}/{relative}"
                    self.policy.resolve_write(mapped)
            finally:
                os.close(source_fd)
        return destination

    def restore(
        self,
        trashed_name: str,
        to_path: str,
        *,
        expected_revision: FileRevision | str | dict | None = None,
    ) -> VaultPath:
        info = self.trash_info(trashed_name)
        destination = self.authorize_restore(trashed_name, to_path)
        if info.is_dir and expected_revision is not None:
            if not (isinstance(expected_revision, str) and expected_revision.startswith("trash:")):
                raise ValueError("Directory restore requires a trash tree revision")
            actual_tree = self.trash_tree_revision(trashed_name)
            if actual_tree != expected_revision:
                raise OSError(errno.EAGAIN, f"Trash tree revision conflict for {trashed_name!r}")
        if info.is_dir:
            dest_prefix = destination.relative.rstrip("/") + "/"
            if any(
                self.policy.rule_path(rule).startswith(dest_prefix)
                for rule in self.policy.deny_write_paths
            ):
                raise ProtectedPathError(
                    f"Directory restore crosses a protected destination descendant of {destination.relative!r}"
                )
        with (
            _opened_dir(self.policy.root, ".trash") as trash_fd,
            _opened_parent(self.policy.root, destination.relative, create=True) as (dst_parent, dst_leaf),
        ):
            _ensure_not_symlink(trash_fd, info.name)
            if info.is_dir:
                # Folder restore is a multi-file operation and retains the
                # rename path until the Phase 2 transaction layer exists.
                try:
                    _stat_at(dst_parent, dst_leaf)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError(f"Target already exists: {to_path!r}")
                _rename_noreplace(trash_fd, info.name, dst_parent, dst_leaf)
            else:
                source_revision = _revision_at(trash_fd, info.name)
                if expected_revision is not None:
                    if isinstance(expected_revision, str) and expected_revision.startswith("trash:"):
                        if source_revision.sha256 != expected_revision.removeprefix("trash:"):
                            raise OSError(errno.EAGAIN, f"Trash revision conflict for {trashed_name!r}")
                    else:
                        expected = FileRevision.from_value(expected_revision)
                        if source_revision.sha256 != expected.sha256:
                            raise RevisionConflictError(trashed_name, expected, source_revision)
                try:
                    _stat_at(dst_parent, dst_leaf)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError(f"Target already exists: {to_path!r}")
                try:
                    # Same-directory linkat-style commit gives restore true
                    # no-replace semantics. Only after the destination is
                    # verified do we unlink the source in .trash.
                    os.link(
                        info.name,
                        dst_leaf,
                        src_dir_fd=trash_fd,
                        dst_dir_fd=dst_parent,
                        follow_symlinks=False,
                    )
                except FileExistsError:
                    actual = self._current_revision(destination)
                    raise RevisionConflictError(destination.relative, None, actual) from None
                source_removed = False
                try:
                    final_revision = _revision_at(dst_parent, dst_leaf)
                    if final_revision.sha256 != source_revision.sha256:
                        raise RevisionConflictError(destination.relative, source_revision, final_revision)
                    _fsync_dir(dst_parent)
                    os.unlink(info.name, dir_fd=trash_fd)
                    source_removed = True
                    _fsync_dir(trash_fd)
                except Exception:
                    # Before unlinking the trash source, removing the new hard
                    # link rolls back cleanly. Afterwards the destination is
                    # the only copy and must be preserved even if durability
                    # reporting (for example fsync) fails.
                    if not source_removed:
                        with contextlib.suppress(FileNotFoundError):
                            os.unlink(dst_leaf, dir_fd=dst_parent)
                        _fsync_dir(dst_parent)
                    raise
        return destination


def validate_path(vault_root: str | Path, relative_path: str) -> Path:
    return _configured_policy(vault_root).canonicalize(relative_path).absolute


def read_file(vault_root: str | Path, relative_path: str) -> str:
    return VaultStorage(_configured_policy(vault_root)).read_text(relative_path)


def write_file_atomic(vault_root: str | Path, relative_path: str, content: str) -> None:
    VaultStorage(_configured_policy(vault_root)).write_text_atomic(relative_path, content)


def read_file_bytes(vault_root: str | Path, relative_path: str) -> bytes:
    return VaultStorage(_configured_policy(vault_root)).read_bytes(relative_path)


def write_file_atomic_bytes(vault_root: str | Path, relative_path: str, content: bytes) -> None:
    VaultStorage(_configured_policy(vault_root)).write_bytes_atomic(relative_path, content)
