"""Authorization-safe plans and recoverable transactions for multi-file writes."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import tempfile
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..domain.models import FileRevision
from .filesystem import VaultStorage
from .locking import SEMANTIC_GRAPH_LOCK, acquire_lock
from .policy import VaultPath


class MutationError(RuntimeError):
    """Base class for structured multi-file mutation failures."""

    error = "mutation_error"

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.error, "message": str(self)}


class PlanDigestMismatchError(MutationError):
    error = "plan_digest_mismatch"


class PlanApprovalRequiredError(MutationError):
    error = "plan_approval_required"


class MutationPreconditionError(MutationError):
    error = "mutation_precondition_failed"


class MutationLimitError(MutationError):
    error = "mutation_limit_exceeded"


class MutationRecoveryRequiredError(MutationError):
    error = "mutation_recovery_required"


def _validate_operation_id(operation_id: str) -> str:
    if not isinstance(operation_id, str) or not operation_id or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in operation_id):
        raise ValueError("invalid transaction ID")
    return operation_id


@dataclass(frozen=True)
class PlannedWrite:
    path: VaultPath
    original_revision: str | None
    content: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "content", bytes(self.content))

    @property
    def content_digest(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class PlannedMove:
    source: VaultPath
    destination: VaultPath
    original_revision: str | None
    source_is_trash: bool = False
    destination_is_trash: bool = False


@dataclass(frozen=True)
class PlannedDelete:
    path: VaultPath
    original_revision: str | None = None


@dataclass(frozen=True)
class PlannedInventory:
    """Immutable snapshot entry used for limits and directory preconditions."""

    path: str
    size_bytes: int
    revision: str


@dataclass(frozen=True)
class IndexChange:
    action: str
    path: str


@dataclass(frozen=True)
class MutationPlan:
    operation: str
    writes: tuple[PlannedWrite, ...] = ()
    moves: tuple[PlannedMove, ...] = ()
    deletes: tuple[PlannedDelete | VaultPath, ...] = ()
    index_changes: tuple[IndexChange, ...] = ()
    inventory: tuple[PlannedInventory, ...] = ()
    metadata: tuple[tuple[str, str], ...] = ()
    # Revisions of every note inspected by a semantic planner.  Keeping this
    # separate from ``inventory`` avoids charging read-only graph scans
    # against mutation file/byte limits while still making the scan a CAS.
    scan_revisions: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.operation or "/" in self.operation or "\\" in self.operation:
            raise ValueError("Mutation operation must be a simple non-empty name")
        # Callers may hand in lists while constructing a plan.  Normalize all
        # collections at the boundary so a digest cannot change underneath an
        # approval or transaction journal.
        for name in ("writes", "moves", "deletes", "index_changes", "inventory"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "metadata", tuple((str(key), str(value)) for key, value in self.metadata))
        object.__setattr__(self, "scan_revisions", tuple((str(path), str(revision)) for path, revision in self.scan_revisions))

    @staticmethod
    def _path(value: VaultPath | str) -> str:
        return value.relative if isinstance(value, VaultPath) else str(value)

    @property
    def digest(self) -> str:
        payload = {
            "operation": self.operation,
            "writes": [
                {
                    "path": self._path(item.path),
                    "original_revision": item.original_revision,
                    "content": item.content_digest,
                    "content_bytes": len(item.content),
                }
                for item in sorted(self.writes, key=lambda value: self._path(value.path))
            ],
            "moves": [
                {
                    "source": self._path(item.source),
                    "destination": self._path(item.destination),
                    "original_revision": item.original_revision,
                    "source_is_trash": item.source_is_trash,
                    "destination_is_trash": item.destination_is_trash,
                }
                for item in sorted(self.moves, key=lambda value: (self._path(value.source), self._path(value.destination)))
            ],
            "deletes": [
                {"path": self._path(item.path if isinstance(item, PlannedDelete) else item), "original_revision": item.original_revision if isinstance(item, PlannedDelete) else None}
                for item in sorted(self.deletes, key=lambda value: self._path(value.path if isinstance(value, PlannedDelete) else value))
            ],
            "inventory": [asdict(item) for item in sorted(self.inventory, key=lambda value: value.path)],
            "index_changes": [asdict(item) for item in sorted(self.index_changes, key=lambda value: (value.action, value.path))],
            "metadata": list(sorted(self.metadata)),
            "scan_revisions": [
                {"path": path, "revision": revision}
                for path, revision in sorted(self.scan_revisions)
            ],
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def plan_digest(self) -> str:
        return self.digest

    def summary(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "plan_digest": self.digest,
            "writes": [self._path(item.path) for item in self.writes],
            "moves": [{"from": self._path(item.source), "to": self._path(item.destination)} for item in self.moves],
            "deletes": [self._path(item.path if isinstance(item, PlannedDelete) else item) for item in self.deletes],
            "inventory": [asdict(item) for item in self.inventory],
            "index_changes": [asdict(item) for item in self.index_changes],
            "metadata": [list(item) for item in self.metadata],
            "scan_revisions": [
                {"path": path, "revision": revision}
                for path, revision in self.scan_revisions
            ],
        }


def _revision(storage: VaultStorage, path: str) -> FileRevision | None:
    try:
        return storage.revision(path)
    except (FileNotFoundError, IsADirectoryError):
        return None


def inventory_for_paths(storage: VaultStorage, paths: list[str] | tuple[str, ...]) -> tuple[PlannedInventory, ...]:
    """Capture every regular file in a planned tree without mutating it."""
    entries: list[PlannedInventory] = []
    for path in sorted(set(paths)):
        info = storage.stat(path, read=False)
        if stat.S_ISDIR(info.st_mode):
            descendants = storage._tree_paths(storage.policy.canonicalize(path))
            for descendant in descendants:
                child_info = storage.stat(descendant, read=False)
                if stat.S_ISREG(child_info.st_mode):
                    revision = storage.revision(descendant)
                    entries.append(PlannedInventory(descendant, child_info.st_size, revision.token))
        elif stat.S_ISREG(info.st_mode):
            revision = storage.revision(path)
            entries.append(PlannedInventory(path, info.st_size, revision.token))
    return tuple(entries)


def _fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def _fsync_dir_path(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    """Publish a journal JSON document with durable temp-file contents."""
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_dir_path(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class TransactionJournal:
    """Small fsynced JSON journal and external recovery directory."""

    def __init__(self, root: str | Path, operation_id: str | None = None) -> None:
        self.root = Path(root).resolve()
        self.operation_id = _validate_operation_id(operation_id) if operation_id is not None else uuid.uuid4().hex
        self.directory = self.root / self.operation_id
        self.stage_dir = self.directory / "stage"
        self.recovery_dir = self.directory / "recovery"
        self.journal_path = self.directory / "journal.json"
        self.state: dict[str, Any] = {"operation_id": self.operation_id, "status": "new", "steps": []}

    def begin(self, plan: MutationPlan) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        _fsync_dir_path(self.root)
        self.directory.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.stage_dir.mkdir(mode=0o700)
        self.recovery_dir.mkdir(mode=0o700)
        self.directory.chmod(0o700)
        self.stage_dir.chmod(0o700)
        self.recovery_dir.chmod(0o700)
        _fsync_dir_path(self.stage_dir)
        _fsync_dir_path(self.recovery_dir)
        _fsync_dir_path(self.directory)
        _fsync_dir_path(self.root)
        self.state.update({"status": "prepared", "plan": plan.summary()})
        self.flush()

    def flush(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        _write_json_atomic(self.journal_path, self.state)
        _fsync_dir_path(self.root)

    def step(self, description: str, **details: Any) -> None:
        self.state.setdefault("steps", []).append({"step": description, **details})
        self.flush()

    def finish(self, status: str, **details: Any) -> None:
        self.state.update({"status": status, **details})
        self.flush()

    @classmethod
    def scan(cls, root: str | Path) -> list[dict[str, Any]]:
        root = Path(root)
        if not root.exists():
            return []
        result: list[dict[str, Any]] = []
        # A transaction directory without a valid journal is itself evidence
        # of an interrupted/partially-created transaction.  Do not let a
        # crash between mkdir and journal publication disappear from health.
        try:
            directories = sorted(
                (entry for entry in root.iterdir() if entry.is_dir() and not entry.is_symlink()),
                key=lambda entry: entry.name,
            )
        except OSError:
            return [{"operation_id": "<root>", "status": "corrupt", "path": str(root)}]
        for directory in directories:
            journal = directory / "journal.json"
            if not journal.is_file() or journal.is_symlink():
                result.append({"operation_id": directory.name, "status": "orphan", "path": str(directory)})
                continue
            if journal.is_symlink():
                result.append({"operation_id": journal.parent.name, "status": "corrupt", "path": str(journal)})
                continue
            try:
                data = json.loads(journal.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                result.append({"operation_id": journal.parent.name, "status": "corrupt", "path": str(journal)})
                continue
            if data.get("status") not in {"committed", "rolled_back", "discarded"}:
                data["path"] = str(journal)
                result.append(data)
        return result


class MutationExecutor:
    """Validate, stage, commit and recover a complete mutation plan."""

    def __init__(self, storage: VaultStorage, *, index=None, transaction_path: str | Path | None = None):
        self.storage = storage
        self.index = index
        if transaction_path is None:
            from ..config import get_config

            transaction_path = get_config().transaction_path
        self.transaction_path = Path(transaction_path).resolve()

    def _limits(self) -> tuple[int, int, int, float]:
        from ..config import get_config

        cfg = get_config()
        return cfg.mutation_max_files, cfg.mutation_max_bytes, cfg.mutation_max_replacements, cfg.mutation_lock_timeout

    def authorize(self, plan: MutationPlan) -> None:
        """Authorize the entire plan without creating files or locks."""
        max_files, max_bytes, _max_replacements, _timeout = self._limits()
        affected_paths = {item.path for item in plan.inventory}
        affected_paths.update(self._path(item.path) for item in plan.writes)
        affected_paths.update(self._path(item.path if isinstance(item, PlannedDelete) else item) for item in plan.deletes)
        inventory_paths = {item.path for item in plan.inventory}
        for move in plan.moves:
            source = self._path(move.source).rstrip("/") + "/"
            if not any(entry == source[:-1] or entry.startswith(source) for entry in inventory_paths):
                # A complete directory inventory is required for directory
                # plans.  A file-only custom plan may omit inventory, in which
                # case count the source file itself and derive its size below.
                source_path = self._path(move.source)
                if move.source_is_trash:
                    info = self.storage.trash_info(Path(source_path).name)
                    if info.is_dir and self.storage.trash_inventory(Path(source_path).name):
                        raise MutationPreconditionError("directory move requires a complete inventory")
                else:
                    info = self.storage.stat(source_path, read=False)
                    if stat.S_ISDIR(info.st_mode):
                        entries = self.storage._tree_paths(self.storage.policy.canonicalize(source_path))
                        if any(
                            stat.S_ISREG(self.storage.stat(entry, read=False).st_mode)
                            for entry in entries
                        ):
                            raise MutationPreconditionError("directory move requires a complete inventory")
                affected_paths.add(source_path)
        affected = len(affected_paths)
        bytes_by_path = {item.path: item.size_bytes for item in plan.inventory}
        bytes_by_path.update({self._path(item.path): len(item.content) for item in plan.writes})
        for move in plan.moves:
            source_path = self._path(move.source)
            if source_path not in inventory_paths and not any(
                entry.startswith(source_path.rstrip("/") + "/") for entry in inventory_paths
            ):
                if move.source_is_trash:
                    info = self.storage.trash_info(Path(source_path).name)
                    if not info.is_dir:
                        bytes_by_path[source_path] = info.size_bytes or 0
                else:
                    info = self.storage.stat(source_path, read=False)
                    if not stat.S_ISDIR(info.st_mode):
                        bytes_by_path[source_path] = info.st_size
        total_bytes = sum(bytes_by_path.values())
        if affected > max_files:
            raise MutationLimitError(f"mutation affects {affected} files; limit is {max_files}")
        if total_bytes > max_bytes:
            raise MutationLimitError(f"mutation stages {total_bytes} bytes; limit is {max_bytes}")
        for item in plan.inventory:
            if item.path.startswith(".trash/"):
                continue
            actual = _revision(self.storage, item.path)
            if actual is None or actual.token != item.revision:
                raise MutationPreconditionError(f"inventory changed: {item.path!r}")
        for path, expected in plan.scan_revisions:
            actual = _revision(self.storage, path)
            if actual is None or actual.token != expected:
                raise MutationPreconditionError(f"semantic scan changed: {path!r}")
        seen: set[str] = set()
        for item in plan.writes:
            target = self.storage.resolve_write(self._path(item.path))
            if target.relative in seen:
                raise MutationPreconditionError(f"duplicate planned path {target.relative!r}")
            seen.add(target.relative)
        for item in plan.moves:
            if item.source_is_trash:
                source = item.source
                destination = self.storage.resolve_write(self._path(item.destination))
                self.storage.authorize_restore(Path(source.relative).name, destination.relative)
            else:
                source = self.storage.resolve_delete(self._path(item.source))
                destination = (
                    item.destination
                    if item.destination_is_trash
                    else self.storage.resolve_write(self._path(item.destination))
                )
            if source.relative == destination.relative:
                raise MutationPreconditionError("move source and destination must differ")
            if item.source_is_trash:
                try:
                    info = self.storage.trash_info(Path(source.relative).name)
                except FileNotFoundError:
                    raise MutationPreconditionError(f"move source is missing: {source.relative!r}") from None
                is_directory = info.is_dir
            else:
                try:
                    info = self.storage.stat(source.relative, read=False)
                except FileNotFoundError:
                    raise MutationPreconditionError(f"move source is missing: {source.relative!r}") from None
                is_directory = stat.S_ISDIR(info.st_mode)
            if is_directory and not item.source_is_trash:
                self.storage.authorize_tree(source.relative)
                if not item.destination_is_trash:
                    self.storage.authorize_tree(source.relative, destination=destination.relative)
            if destination.relative in seen or source.relative in seen:
                raise MutationPreconditionError("planned paths overlap")
            seen.update((source.relative, destination.relative))
        for item in plan.deletes:
            path = self._path(item.path if isinstance(item, PlannedDelete) else item)
            target = self.storage.resolve_delete(path, permanent=True)
            if stat.S_ISDIR(self.storage.stat(target.relative, read=False).st_mode):
                raise MutationPreconditionError("permanent directory deletion is disabled")
            if target.relative in seen:
                raise MutationPreconditionError("planned paths overlap")
            seen.add(target.relative)

    @staticmethod
    def _path(value: VaultPath | str) -> str:
        return value.relative if isinstance(value, VaultPath) else str(value)

    def validate_preconditions(self, plan: MutationPlan) -> None:
        self.authorize(plan)
        for item in plan.writes:
            path = self._path(item.path)
            actual = _revision(self.storage, path)
            if item.original_revision is None:
                if actual is not None:
                    raise MutationPreconditionError(f"destination appeared: {path!r}")
            elif actual is None or actual.token != item.original_revision:
                raise MutationPreconditionError(f"revision changed: {path!r}")
        for item in plan.moves:
            source = self._path(item.source)
            destination = self._path(item.destination)
            if item.source_is_trash:
                current_tree = self.storage.trash_tree_revision(Path(source).name)
                if item.original_revision and current_tree != item.original_revision:
                    raise MutationPreconditionError(f"trashed directory changed: {source!r}")
                if self.storage.exists(destination, read=False):
                    raise MutationPreconditionError(f"destination appeared: {destination!r}")
                continue
            try:
                self.storage.stat(source, read=False)
            except FileNotFoundError:
                raise MutationPreconditionError(f"move source is missing: {source!r}") from None
            if item.original_revision and item.original_revision.startswith("tree:"):
                try:
                    current_tree = self.storage.tree_revision(source)
                except (FileNotFoundError, OSError, MutationRecoveryRequiredError):
                    raise MutationPreconditionError(f"directory changed: {source!r}") from None
                if current_tree != item.original_revision:
                    raise MutationPreconditionError(f"directory changed: {source!r}")
            actual = _revision(self.storage, source)
            if item.original_revision not in (None, "directory") and not item.original_revision.startswith("tree:") and (actual is None or actual.token != item.original_revision):
                raise MutationPreconditionError(f"revision changed: {source!r}")
            if not item.destination_is_trash and self.storage.exists(destination, read=False):
                raise MutationPreconditionError(f"destination appeared: {destination!r}")
        for item in plan.deletes:
            path = self._path(item.path if isinstance(item, PlannedDelete) else item)
            actual = _revision(self.storage, path)
            expected = item.original_revision if isinstance(item, PlannedDelete) else None
            if expected is not None and (actual is None or actual.token != expected):
                raise MutationPreconditionError(f"revision changed: {path!r}")

    def _snapshot(self, journal: TransactionJournal, plan: MutationPlan) -> list[dict[str, Any]]:
        paths: set[str] = set()
        for item in plan.writes:
            paths.add(self._path(item.path))
        for item in plan.moves:
            source = self._path(item.source)
            if item.source_is_trash:
                continue
            info = self.storage.stat(source, read=False)
            if stat.S_ISDIR(info.st_mode):
                paths.update(self.storage._tree_paths(self.storage.policy.canonicalize(source)))
            else:
                paths.add(source)
        for item in plan.deletes:
            paths.add(self._path(item.path if isinstance(item, PlannedDelete) else item))
        snapshots: list[dict[str, Any]] = []
        for index, path in enumerate(sorted(paths)):
            try:
                info = self.storage.stat(path, read=False)
            except FileNotFoundError:
                snapshots.append({"path": path, "exists": False})
                continue
            if stat.S_ISDIR(info.st_mode):
                snapshots.append({"path": path, "exists": True, "directory": True})
                continue
            content = self.storage.read_bytes(path)
            backup = journal.recovery_dir / f"{index:06d}.bin"
            backup.write_bytes(content)
            backup.chmod(0o600)
            _fsync_file(backup)
            snapshots.append({"path": path, "exists": True, "directory": False, "backup": backup.name, "revision": FileRevision.from_bytes(content, size=len(content), mtime_ns=info.st_mtime_ns).token})
        _fsync_dir_path(journal.recovery_dir)
        return snapshots

    def _stage(self, journal: TransactionJournal, plan: MutationPlan) -> None:
        for index, item in enumerate(sorted(plan.writes, key=lambda value: self._path(value.path))):
            staged = journal.stage_dir / f"{index:06d}.bin"
            staged.write_bytes(item.content)
            staged.chmod(0o600)
            _fsync_file(staged)
            journal.step("staged", path=self._path(item.path), staged=staged.name)
        _fsync_dir_path(journal.stage_dir)

    @staticmethod
    def _step_action(step: dict[str, Any]) -> str | None:
        if step.get("step") == "applied":
            return step.get("action")
        if step.get("step") in {"write", "move", "delete"}:
            return step.get("step")
        return None

    @staticmethod
    def _step_key(step: dict[str, Any]) -> str | None:
        if step.get("intent_id"):
            return str(step["intent_id"])
        action = MutationExecutor._step_action(step)
        if action == "write":
            return f"write:{step.get('path')}"
        if action == "move":
            return f"move:{step.get('source')}:{step.get('destination')}"
        if action == "delete":
            return f"delete:{step.get('path')}"
        return None

    def _applied_steps(self, journal: TransactionJournal) -> list[dict[str, Any]]:
        return [step for step in journal.state.get("steps", []) if self._step_action(step) in {"write", "move", "delete"} and step.get("step") != "intent"]

    def _pending_intents(self, journal: TransactionJournal) -> list[dict[str, Any]]:
        applied = {self._step_key(step) for step in self._applied_steps(journal)}
        return [
            step
            for step in journal.state.get("steps", [])
            if step.get("step") == "intent" and self._step_key(step) not in applied
        ]

    @staticmethod
    def _pending_rollback_step(step: dict[str, Any]) -> dict[str, Any]:
        result = dict(step)
        if step.get("trash"):
            result["post_tree_revision" if step.get("source_is_directory") else "post_revision"] = step.get("_post_revision")
        elif step.get("restore"):
            result["post_tree_revision" if step.get("source_is_directory") else "post_revision"] = _trash_to_live_revision(
                step.get("original_revision"), bool(step.get("source_is_directory"))
            )
        elif step.get("source_is_directory"):
            result["post_tree_revision"] = step.get("original_revision")
        else:
            result["post_revision"] = step.get("original_revision")
        return result

    def _intent_state(self, journal: TransactionJournal, step: dict[str, Any]) -> str:
        """Classify an intent as untouched, exact post-state, or ambiguous."""
        action = step.get("action")
        if action == "write":
            path = step.get("path")
            current = _revision(self.storage, path) if path else None
            original = step.get("original_revision")
            if current is None and original is None:
                return "pre"
            if current is not None and current.token == original:
                return "pre"
            staged = journal.stage_dir / str(step.get("staged", ""))
            if (
                staged.is_file()
                and not staged.is_symlink()
                and current is not None
                and current.sha256 == hashlib.sha256(staged.read_bytes()).hexdigest()
            ):
                return "post"
            return "unknown"
        if action == "delete":
            path = step.get("path")
            current = _revision(self.storage, path) if path else None
            if current is None:
                return "post"
            if current.token == step.get("original_revision"):
                return "pre"
            return "unknown"
        if action != "move":
            return "unknown"
        source = step.get("source")
        destination = step.get("destination")
        original = step.get("original_revision")
        if not source or not destination:
            return "unknown"
        if step.get("trash"):
            try:
                trash_info = self.storage.trash_info(Path(destination).name)
            except FileNotFoundError:
                trash_info = None
            source_exists = self.storage.exists(source, read=False)
            if source_exists:
                current = _revision_or_tree(self.storage, source)
                return "pre" if current == original and trash_info is None else "unknown"
            if trash_info is None:
                return "unknown"
            actual = self.storage.trash_tree_revision(trash_info.name)
            if _trash_to_live_revision(actual, bool(step.get("source_is_directory"))) != original:
                return "unknown"
            step["_post_revision"] = actual
            return "post"
        if step.get("restore"):
            try:
                trash_exists = self.storage.trash_info(Path(source).name)
            except FileNotFoundError:
                trash_exists = None
            destination_exists = self.storage.exists(destination, read=False)
            if trash_exists is not None and not destination_exists:
                return "pre"
            if trash_exists is None and destination_exists:
                expected = _trash_to_live_revision(original, bool(step.get("source_is_directory")))
                return "post" if _recovery_path_revision(self.storage, destination) == expected else "unknown"
            return "unknown"
        source_exists = self.storage.exists(source, read=False)
        destination_exists = self.storage.exists(destination, read=False)
        if source_exists and not destination_exists:
            return "pre" if _revision_or_tree(self.storage, source) == original else "unknown"
        if not source_exists and destination_exists:
            return "post" if _recovery_path_revision(self.storage, destination) == original else "unknown"
        return "unknown"

    def _record_move_step(
        self,
        journal: TransactionJournal,
        item: PlannedMove,
        *,
        actual_destination: str,
        intent_id: str,
    ) -> None:
        source = self._path(item.source)
        details: dict[str, Any] = {"source": source, "destination": actual_destination}
        if item.destination_is_trash:
            details["post_tree_revision"] = self.storage.trash_tree_revision(Path(actual_destination).name)
        else:
            info = self.storage.stat(actual_destination, read=False)
            if stat.S_ISDIR(info.st_mode):
                details["post_tree_revision"] = self.storage.tree_revision(actual_destination)
            else:
                details["post_revision"] = self.storage.revision(actual_destination).token
        if item.destination_is_trash:
            details["trash"] = True
        elif item.source_is_trash:
            details["restore"] = True
        details.update({"action": "move", "intent_id": intent_id})
        journal.step("applied", **details)

    def _restore_file(self, path: str, content: bytes | None) -> None:
        if content is None:
            self.storage.remove_file(path)
        else:
            self.storage.write_bytes_atomic(path, content)

    def _rollback(self, plan: MutationPlan, snapshots: list[dict[str, Any]], moved: list[PlannedMove], journal: TransactionJournal) -> bool:
        ok = True
        snapshot_by_path = {entry["path"]: entry for entry in snapshots}
        move_steps = [step for step in self._applied_steps(journal) if self._step_action(step) == "move"]
        move_steps.extend(
            self._pending_rollback_step(step)
            for step in self._pending_intents(journal)
            if step.get("action") == "move" and step.get("_attributable_post")
        )
        for step in reversed(move_steps):
            source, destination = step.get("source"), step.get("destination")
            try:
                if step.get("trash"):
                    if self.storage.exists(source, read=False) is False:
                        self.storage.restore(
                            Path(destination).name,
                            source,
                            expected_revision=step.get("post_tree_revision") or step.get("post_revision"),
                        )
                elif step.get("restore"):
                    if self.storage.exists(destination, read=False):
                        post = step.get("post_tree_revision") or step.get("post_revision")
                        self.storage.trash(
                            destination,
                            expected_revision=post,
                            destination_name=Path(source).name,
                        )
                elif self.storage.exists(destination, read=False) and not self.storage.exists(source, read=False):
                    post = step.get("post_tree_revision") or step.get("post_revision")
                    self.storage.move(destination, source, expected_revision=post)
            except Exception:
                ok = False
        for path, entry in reversed(list(snapshot_by_path.items())):
            if entry.get("directory"):
                continue
            try:
                backup = journal.recovery_dir / entry["backup"] if entry.get("exists") else None
                current = _revision(self.storage, path)
                if backup:
                    if current is None:
                        raise MutationRecoveryRequiredError(f"post-state is missing for {path!r}")
                    self.storage.write_bytes_atomic(path, backup.read_bytes(), expected_revision=current.token)
                elif current is not None:
                    self.storage.remove_file(path, expected_revision=current.token)
            except Exception:
                ok = False
        return ok

    def _poststate_matches(self, plan: MutationPlan, rewritten: list[str], moved: list[PlannedMove], deleted: list[str], journal: TransactionJournal) -> bool:
        """Only undo bytes that are still exactly this transaction's result."""
        for intent in self._pending_intents(journal):
            state = self._intent_state(journal, intent)
            if state == "unknown":
                return False
            intent["_attributable_post"] = state == "post"

        applied = self._applied_steps(journal)
        move_steps = [step for step in applied if self._step_action(step) == "move"]
        move_steps.extend(
            self._pending_rollback_step(step)
            for step in self._pending_intents(journal)
            if step.get("action") == "move" and step.get("_attributable_post")
        )

        def mapped_path(path: str) -> str:
            for step in move_steps:
                if step.get("restore") or step.get("trash"):
                    continue
                source = str(step.get("source", "")).rstrip("/") + "/"
                if path.startswith(source):
                    return str(step.get("destination", "")).rstrip("/") + "/" + path[len(source):]
            return path

        for item in plan.writes:
            path = self._path(item.path)
            post_path = mapped_path(path)
            actual = _revision(self.storage, post_path)
            expected = FileRevision.from_bytes(item.content, size=len(item.content), mtime_ns=0)
            original = item.original_revision
            if actual is not None and actual.sha256 == expected.sha256:
                continue
            if (actual is None and original is None) or (actual is not None and actual.token == original):
                continue
            return False
        for item in plan.deletes:
            path = self._path(item.path if isinstance(item, PlannedDelete) else item)
            actual = _revision(self.storage, path)
            expected = item.original_revision if isinstance(item, PlannedDelete) else None
            if actual is not None and expected is not None and actual.token == expected:
                continue
            if actual is None:
                continue
            return False
        for step in move_steps:
            source, destination = step.get("source"), step.get("destination")
            try:
                if step.get("trash"):
                    if self.storage.exists(source, read=False):
                        return False
                    if self.storage.trash_tree_revision(Path(destination).name) != step.get("post_tree_revision"):
                        return False
                elif step.get("restore"):
                    if not self.storage.exists(destination, read=False):
                        return False
                    try:
                        self.storage.trash_info(Path(source).name)
                    except FileNotFoundError:
                        pass
                    else:
                        return False
                    if self._path_revision(destination) != (step.get("post_tree_revision") or step.get("post_revision")):
                        return False
                else:
                    if self.storage.exists(source, read=False) or not self.storage.exists(destination, read=False):
                        return False
                    if self._path_revision(destination) != (step.get("post_tree_revision") or step.get("post_revision")):
                        return False
            except (FileNotFoundError, OSError):
                return False
        return True

    def _path_revision(self, path: str) -> str:
        info = self.storage.stat(path, read=False)
        return self.storage.tree_revision(path) if stat.S_ISDIR(info.st_mode) else self.storage.revision(path).token

    def execute(self, plan: MutationPlan, *, operation_id: str | None = None, approved_digest: str | None = None) -> dict[str, Any]:
        if approved_digest is not None and approved_digest != plan.digest:
            raise PlanDigestMismatchError("approved plan digest does not match the current plan")
        self.validate_preconditions(plan)
        lock_timeout = self._limits()[3]
        semantic_lock_needed = dict(plan.metadata).get("semantic_version") is not None
        lock_paths = {
            self._path(item.path) for item in plan.writes
        } | {
            self._path(item.source) for item in plan.moves
        } | {
            self._path(item.destination) for item in plan.moves
        } | {
            self._path(item.path if isinstance(item, PlannedDelete) else item) for item in plan.deletes
        }
        # Directory operations lock every current descendant and its mapped
        # destination, plus parent directories.  This makes a folder rename
        # and a concurrent single-note write contend on the same lock key.
        for item in plan.moves:
            source = self._path(item.source)
            destination = self._path(item.destination)
            if item.destination_is_trash or item.source_is_trash:
                lock_paths.add(".trash")
            try:
                source_paths = self.storage._tree_paths(self.storage.policy.canonicalize(source))
            except FileNotFoundError:
                source_paths = []
            if source_paths:
                prefix = source.rstrip("/") + "/"
                for descendant in source_paths:
                    suffix = descendant[len(prefix):] if descendant.startswith(prefix) else ""
                    lock_paths.add(descendant)
                    lock_paths.add(f"{destination.rstrip('/')}/{suffix}" if suffix else destination)
        lock_paths.update(str(Path(path).parent) for path in tuple(lock_paths) if str(Path(path).parent) not in {"", "."})
        locks = []
        try:
            # Acquire the graph lock first, before path locks.  Ordinary note
            # writers follow the same order, preventing a graph-scan/path
            # lock inversion while a semantic plan is being committed.
            if semantic_lock_needed:
                locks.append(acquire_lock(SEMANTIC_GRAPH_LOCK, timeout=lock_timeout, lock_path=self._lock_path()))
            for path in sorted(lock_paths):
                locks.append(acquire_lock(path, timeout=lock_timeout, lock_path=self._lock_path()))
            # The plan was validated before locks, then is checked again while
            # all cooperating MCP operations are excluded.
            self.validate_preconditions(plan)
            journal = TransactionJournal(self.transaction_path, operation_id)
            journal.begin(plan)
            snapshots = self._snapshot(journal, plan)
            journal.state["snapshots"] = snapshots
            journal.flush()
            self._stage(journal, plan)
            journal.state["status"] = "committing"
            journal.flush()
            moved: list[PlannedMove] = []
            rewritten: list[str] = []
            deleted: list[str] = []
            try:
                ordered_writes = sorted(plan.writes, key=lambda value: self._path(value.path))
                write_indexes = {self._path(item.path): index for index, item in enumerate(ordered_writes)}
                deferred_writes: list[PlannedWrite] = []
                if plan.operation == "rename_folder":
                    for item in ordered_writes:
                        path = self._path(item.path)
                        if any(
                            not move.source_is_trash
                            and not move.destination_is_trash
                            and path.startswith(self._path(move.source).rstrip("/") + "/")
                            for move in plan.moves
                        ):
                            deferred_writes.append(item)

                def mapped_write_path(path: str) -> str:
                    if path in {self._path(item.path) for item in deferred_writes}:
                        for move in plan.moves:
                            source = self._path(move.source).rstrip("/") + "/"
                            if not move.source_is_trash and not move.destination_is_trash and path.startswith(source):
                                return self._path(move.destination).rstrip("/") + "/" + path[len(source):]
                    return path

                def apply_write(item: PlannedWrite) -> None:
                    planned_path = self._path(item.path)
                    path = mapped_write_path(planned_path)
                    write_index = write_indexes[planned_path]
                    intent_id = f"write:{write_index}"
                    journal.step(
                        "intent",
                        action="write",
                        intent_id=intent_id,
                        path=path,
                        planned_path=planned_path,
                        staged=f"{write_index:06d}.bin",
                        original_revision=item.original_revision,
                    )
                    self.storage.write_bytes_atomic(path, item.content, expected_revision=item.original_revision, create_only=item.original_revision is None)
                    post = _revision(self.storage, path)
                    if post is None:
                        raise MutationRecoveryRequiredError(f"write post-state is missing for {path!r}")
                    journal.step(
                        "applied",
                        action="write",
                        intent_id=intent_id,
                        path=path,
                        planned_path=planned_path,
                        staged=f"{write_index:06d}.bin",
                        post_revision=post.token,
                    )
                    rewritten.append(planned_path)

                for item in ordered_writes:
                    if item not in deferred_writes:
                        apply_write(item)
                for item in sorted(plan.deletes, key=lambda value: self._path(value.path if isinstance(value, PlannedDelete) else value)):
                    path = self._path(item.path if isinstance(item, PlannedDelete) else item)
                    intent_id = f"delete:{path}"
                    journal.step(
                        "intent",
                        action="delete",
                        intent_id=intent_id,
                        path=path,
                        original_revision=item.original_revision if isinstance(item, PlannedDelete) else None,
                    )
                    self.storage.delete(path, permanent=True, expected_revision=item.original_revision if isinstance(item, PlannedDelete) else None)
                    journal.step("applied", action="delete", intent_id=intent_id, path=path, post_absent=True)
                    deleted.append(path)
                for move_index, item in enumerate(sorted(plan.moves, key=lambda value: (self._path(value.source), self._path(value.destination)))):
                    intent_id = f"move:{move_index}"
                    source_path = self._path(item.source)
                    trash_name = None
                    intent_destination = self._path(item.destination)
                    if item.destination_is_trash:
                        trash_name = self.storage.trash_destination_name(source_path)
                        intent_destination = f".trash/{trash_name}"
                    journal.step(
                        "intent",
                        action="move",
                        intent_id=intent_id,
                        source=source_path,
                        destination=intent_destination,
                        original_revision=item.original_revision,
                        source_is_trash=item.source_is_trash,
                        destination_is_trash=item.destination_is_trash,
                        trash=item.destination_is_trash,
                        restore=item.source_is_trash,
                        trash_name=trash_name,
                        source_is_directory=self.storage.trash_info(Path(source_path).name).is_dir
                        if item.source_is_trash
                        else stat.S_ISDIR(self.storage.stat(source_path, read=False).st_mode),
                    )
                    if item.destination_is_trash:
                        _source, trash_path = self.storage.trash(
                            source_path,
                            expected_revision=item.original_revision,
                            destination_name=trash_name,
                        )
                        self._record_move_step(journal, item, actual_destination=f".trash/{trash_path.name}", intent_id=intent_id)
                    elif item.source_is_trash:
                        trash_name = Path(self._path(item.source)).name
                        self.storage.restore(
                            trash_name,
                            self._path(item.destination),
                            expected_revision=item.original_revision,
                        )
                        self._record_move_step(journal, item, actual_destination=self._path(item.destination), intent_id=intent_id)
                    else:
                        self.storage.move(
                            self._path(item.source),
                            self._path(item.destination),
                            expected_revision=item.original_revision,
                        )
                        self._record_move_step(journal, item, actual_destination=self._path(item.destination), intent_id=intent_id)
                    moved.append(item)
                # A folder move changes the path, but not the contents or
                # revisions of notes inside it.  Apply those internal link
                # rewrites only after the directory CAS succeeds, at their
                # mapped destination paths.
                for item in deferred_writes:
                    apply_write(item)
            except Exception as exc:
                journal.state["error"] = str(exc)
                journal.state["status"] = "rolling_back"
                journal.flush()
                try:
                    poststate_matches = self._poststate_matches(plan, rewritten, moved, deleted, journal)
                except Exception:
                    poststate_matches = False
                if poststate_matches and self._rollback(plan, snapshots, moved, journal):
                    journal.finish("rolled_back")
                else:
                    journal.finish("recovery_required")
                    raise MutationRecoveryRequiredError(f"transaction {journal.operation_id} requires operator recovery") from exc
                raise
            journal.finish("committed")
            self._update_index(plan)
            revisions: dict[str, str] = {}
            for path in rewritten:
                current = _revision(self.storage, path)
                if current is not None:
                    revisions[path] = current.token
            for item in moved:
                if item.destination_is_trash or item.source_is_trash:
                    continue
                current = _revision(self.storage, self._path(item.destination))
                if current is not None:
                    revisions[self._path(item.destination)] = current.token
            return {
                "operation_id": journal.operation_id,
                "plan_digest": plan.digest,
                "status": "committed",
                "moved": [
                    {"from": step.get("source"), "to": step.get("destination")}
                    for step in journal.state.get("steps", [])
                    if self._step_action(step) == "move" and step.get("step") != "intent"
                ],
                "rewritten": rewritten,
                "deleted": deleted,
                "revisions": revisions,
            }
        finally:
            for lock in reversed(locks):
                lock.release()

    def _lock_path(self) -> Path:
        from ..config import get_config

        return get_config().lock_path

    def _update_index(self, plan: MutationPlan) -> None:
        if self.index is None:
            return
        for change in plan.index_changes:
            if change.action == "remove":
                self.index.remove(change.path)
            elif change.action == "update":
                self.index.update(change.path)


def incomplete_transactions(path: str | Path) -> list[dict[str, Any]]:
    return TransactionJournal.scan(path)


def discard_transaction(path: str | Path, operation_id: str) -> None:
    """Mark a transaction discarded without deleting recovery evidence."""
    _validate_operation_id(operation_id)
    journal = Path(path).resolve() / operation_id / "journal.json"
    if not journal.is_file() or journal.is_symlink():
        raise FileNotFoundError(operation_id)
    data = json.loads(journal.read_text(encoding="utf-8"))
    if data.get("status") in {"committed", "rolled_back", "discarded"}:
        return
    data["status"] = "discarded"
    _write_json_atomic(journal, data)
    _fsync_dir_path(journal.parent.parent)


def recover_transaction(storage: VaultStorage, path: str | Path, operation_id: str) -> dict[str, Any]:
    """Acquire the same stable path locks used by execution before recovery."""
    root = Path(path).resolve()
    _validate_operation_id(operation_id)
    directory = root / operation_id
    journal_path = directory / "journal.json"
    if not journal_path.is_file() or journal_path.is_symlink():
        raise FileNotFoundError(operation_id)
    state = json.loads(journal_path.read_text(encoding="utf-8"))
    if state.get("status") in {"committed", "rolled_back", "discarded"}:
        return state
    lock_paths = set(state.get("plan", {}).get("writes", []))
    inventory_paths = [item.get("path", "") for item in state.get("plan", {}).get("inventory", [])]
    lock_paths.update(item for item in inventory_paths if item)
    scan_paths = [item.get("path", "") for item in state.get("plan", {}).get("scan_revisions", [])]
    lock_paths.update(item for item in scan_paths if item)
    for item in state.get("plan", {}).get("moves", []):
        lock_paths.update((item.get("from", ""), item.get("to", "")))
        source_prefix = item.get("from", "").rstrip("/") + "/"
        destination_prefix = item.get("to", "").rstrip("/") + "/"
        lock_paths.update(
            destination_prefix + path[len(source_prefix):]
            for path in inventory_paths
            if path.startswith(source_prefix) and not item.get("to", "").startswith(".trash/")
        )
    lock_paths.update(item for item in state.get("plan", {}).get("deletes", []) if item)
    for step in state.get("steps", []):
        if step.get("step") == "move":
            lock_paths.update((step.get("source", ""), step.get("destination", "")))
    lock_paths = {item for item in lock_paths if item}
    lock_paths.update(
        str(Path(item).parent)
        for item in tuple(lock_paths)
        if str(Path(item).parent) not in {"", "."}
    )
    from ..config import get_config

    locks = []
    if dict(tuple(item) for item in state.get("plan", {}).get("metadata", [])).get("semantic_version") is not None:
        locks.append(
            acquire_lock(
                SEMANTIC_GRAPH_LOCK,
                timeout=get_config().mutation_lock_timeout,
                lock_path=get_config().lock_path,
            )
        )
    try:
        locks.extend(
            acquire_lock(item, timeout=get_config().mutation_lock_timeout, lock_path=get_config().lock_path)
            for item in sorted(lock_paths)
        )
    except Exception:
        for lock in reversed(locks):
            lock.release()
        raise
    try:
        return _recover_transaction_unlocked(storage, directory, journal_path, state)
    finally:
        for lock in reversed(locks):
            lock.release()


def _recover_transaction_unlocked(
    storage: VaultStorage,
    directory: Path,
    journal_path: Path,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Safely roll back one incomplete transaction.

    Recovery is deliberately conservative: every replacement must still
    contain the exact staged bytes (or an unambiguous moved destination).  If
    an operator or sync process changed a post-state, no further writes are
    attempted and the journal remains ``recovery_required``.
    """
    executor = MutationExecutor(storage, transaction_path=directory.parent)
    journal = TransactionJournal(directory.parent, directory.name)
    journal.state = state
    pending = executor._pending_intents(journal)
    try:
        for intent in pending:
            intent_state = executor._intent_state(journal, intent)
            if intent_state == "unknown":
                raise MutationRecoveryRequiredError("intent post-state is ambiguous")
            intent["_attributable_post"] = intent_state == "post"

        applied = executor._applied_steps(journal)
        write_steps = [step for step in applied if executor._step_action(step) == "write"]
        for intent in pending:
            if intent.get("action") == "write" and intent.get("_attributable_post"):
                staged = directory / "stage" / str(intent.get("staged", ""))
                write_step = dict(intent)
                write_step["post_revision"] = "sha256:" + hashlib.sha256(staged.read_bytes()).hexdigest()
                write_steps.append(write_step)
        moves = [step for step in applied if executor._step_action(step) == "move"]
        moves.extend(
            executor._pending_rollback_step(intent)
            for intent in pending
            if intent.get("action") == "move" and intent.get("_attributable_post")
        )

        def mapped_path(path: str) -> str:
            for step in moves:
                if step.get("trash") or step.get("restore"):
                    continue
                source = str(step.get("source", "")).rstrip("/") + "/"
                if path.startswith(source):
                    return str(step.get("destination", "")).rstrip("/") + "/" + path[len(source):]
            return path

        for step in applied:
            action = executor._step_action(step)
            if action == "write":
                staged = directory / "stage" / step.get("staged", "")
                current = _revision(storage, mapped_path(step.get("path", "")))
                expected = step.get("post_revision")
                if not staged.is_file() or staged.is_symlink() or current is None:
                    raise MutationRecoveryRequiredError("write post-state is missing")
                if expected and current.token != expected:
                    raise MutationRecoveryRequiredError("write post-state changed")
                if not expected and current.sha256 != hashlib.sha256(staged.read_bytes()).hexdigest():
                    raise MutationRecoveryRequiredError("write post-state changed")
            elif action == "move":
                source, destination = step.get("source"), step.get("destination")
                if step.get("trash"):
                    if storage.exists(source, read=False) or not storage.trash_info(Path(destination).name):
                        raise MutationRecoveryRequiredError("trash post-state is missing")
                    if storage.trash_tree_revision(Path(destination).name) != step.get("post_tree_revision"):
                        raise MutationRecoveryRequiredError("trash post-state changed")
                elif step.get("restore"):
                    if storage.exists(source, read=False) or not storage.exists(destination, read=False):
                        raise MutationRecoveryRequiredError("restore post-state is missing")
                    if _recovery_path_revision(storage, destination) != (step.get("post_tree_revision") or step.get("post_revision")):
                        raise MutationRecoveryRequiredError("restore post-state changed")
                elif storage.exists(source, read=False) or not storage.exists(destination, read=False):
                    raise MutationRecoveryRequiredError("move post-state is missing")
                elif _recovery_path_revision(storage, destination) != (step.get("post_tree_revision") or step.get("post_revision")):
                    raise MutationRecoveryRequiredError("move post-state changed")
            elif action == "delete" and storage.exists(step.get("path", ""), read=False):
                raise MutationRecoveryRequiredError("delete post-state is missing")

        # Before restoring backups, ensure every untouched snapshot is still
        # the original state.  A changed value is never overwritten merely
        # because a transaction journal says it was involved.
        for entry in state.get("snapshots", []):
            if entry.get("directory"):
                continue
            path = entry.get("path", "")
            current = _revision(storage, path)
            if entry.get("exists"):
                if current is not None and current.token == entry.get("revision"):
                    continue
                if current is None and mapped_path(path) != path:
                    continue
                if current is not None and any(
                    executor._step_action(step) == "write" and mapped_path(step.get("path", "")) == path
                    and current.token == step.get("post_revision")
                    for step in write_steps
                ):
                    continue
                raise MutationRecoveryRequiredError(f"snapshot changed: {path!r}")
            elif current is None or any(
                executor._step_action(step) == "write" and mapped_path(step.get("path", "")) == path
                and current.token == step.get("post_revision")
                for step in write_steps
            ):
                continue
            raise MutationRecoveryRequiredError(f"unexpected snapshot file: {path!r}")

        for step in reversed(moves):
            if step.get("trash"):
                storage.restore(
                    Path(step["destination"]).name,
                    step["source"],
                    expected_revision=step.get("post_tree_revision") or step.get("post_revision"),
                )
            elif step.get("restore"):
                storage.trash(
                    step["destination"],
                    expected_revision=step.get("post_tree_revision") or step.get("post_revision"),
                    destination_name=Path(step["source"]).name,
                )
            else:
                storage.move(
                    step["destination"],
                    step["source"],
                    expected_revision=step.get("post_tree_revision") or step.get("post_revision"),
                )
        for entry in reversed(state.get("snapshots", [])):
            if entry.get("directory"):
                continue
            original = directory / "recovery" / entry.get("backup", "")
            if entry.get("exists"):
                if not original.is_file() or original.is_symlink():
                    raise MutationRecoveryRequiredError("recovery copy is missing")
                current = storage.revision(entry["path"])
                storage.write_bytes_atomic(entry["path"], original.read_bytes(), expected_revision=current.token)
            elif storage.exists(entry["path"], read=False):
                current = storage.revision(entry["path"])
                storage.remove_file(entry["path"], expected_revision=current.token)
        state["status"] = "rolled_back"
    except Exception as exc:
        state["status"] = "recovery_required"
        state["error"] = str(exc)
    _write_json_atomic(journal_path, state)
    _fsync_dir_path(journal_path.parent.parent)
    return state


def _recovery_path_revision(storage: VaultStorage, path: str) -> str:
    info = storage.stat(path, read=False)
    return storage.tree_revision(path) if stat.S_ISDIR(info.st_mode) else storage.revision(path).token


def _revision_or_tree(storage: VaultStorage, path: str) -> str:
    return _recovery_path_revision(storage, path)


def _trash_to_live_revision(revision: str | None, is_directory: bool = False) -> str | None:
    if not revision:
        return None
    if revision.startswith("trash:"):
        digest = revision.removeprefix("trash:")
        return ("tree:" if is_directory else "sha256:") + digest
    return revision
