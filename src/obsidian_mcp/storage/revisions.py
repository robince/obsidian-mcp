"""Shared policy and response helpers for optimistic file revisions."""

from __future__ import annotations

import contextlib
import json
import os
import uuid
from dataclasses import dataclass
from typing import Any

from ..config import get_config
from ..domain.models import FileRevision, RevisionConflictError
from .filesystem import VaultStorage


class PreconditionRequiredError(PermissionError):
    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"A revision precondition is required for existing file {path!r}")

    def to_dict(self) -> dict[str, Any]:
        return {"error": "precondition_required", "path": self.path}


@dataclass(frozen=True)
class MutationIntent:
    """The effective CAS/create semantics observed before a mutation."""

    expected_revision: FileRevision | str | dict[str, Any] | None
    create_only: bool
    observed_exists: bool
    observed_revision: FileRevision | None


def _write_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short conflict record write")
        view = view[count:]


def enforce_precondition_policy(
    storage: VaultStorage,
    path: str,
    expected_revision: FileRevision | str | dict[str, Any] | None,
    create_only: bool,
) -> MutationIntent:
    """Return effective semantics after observing the current target.

    Blind creation is still an optimistic operation: once the target is seen
    absent, callers must use a no-replace commit so a sync writer cannot be
    overwritten between this observation and replacement.
    """
    exists = storage.exists(path, read=False)
    observed = storage.revision(path) if exists else None
    cfg = get_config()
    if create_only:
        return MutationIntent(expected_revision, True, exists, observed)
    if expected_revision is not None:
        return MutationIntent(expected_revision, False, exists, observed)
    if exists and (cfg.require_write_preconditions or not cfg.allow_blind_overwrite):
        raise PreconditionRequiredError(path)
    if not exists and cfg.require_write_preconditions and not cfg.allow_blind_create:
        raise PreconditionRequiredError(path)
    if exists:
        return MutationIntent(None, False, True, observed)
    return MutationIntent(None, True, False, None)


def revision_result(path: str, revision: FileRevision, **extra: Any) -> dict[str, Any]:
    return {"path": path, "revision": revision.to_dict(), **extra}


def stage_conflict(
    *,
    operation_id: str | None,
    path: str,
    proposed: bytes | None,
    expected: str | None = None,
    actual: str | None = None,
) -> str | None:
    """Optionally save proposed bytes outside the vault for operator review."""
    cfg = get_config()
    if not cfg.conflict_path:
        return None
    # Never use a caller-controlled operation ID as a filesystem component.
    # The operator-facing ID is opaque and restricted to lowercase hex so it
    # cannot escape the conflict root or select an arbitrary existing path.
    # A fresh opaque ID avoids collisions even when different principals use
    # the same caller-scoped operation ID. Keep 64 hex characters for the
    # operator API's deliberately narrow identifier grammar.
    identifier = uuid.uuid4().hex + uuid.uuid4().hex
    root = cfg.conflict_path
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise OSError("conflict root must be a real directory")
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise OSError("conflict root must be a real directory")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    root_fd = os.open(root, flags)
    try:
        with contextlib.suppress(FileExistsError):
            os.mkdir(identifier, 0o700, dir_fd=root_fd)
        record_fd = os.open(identifier, flags, dir_fd=root_fd)
        try:
            os.fchmod(record_fd, 0o700)
            metadata = json.dumps(
                {"path": path, "operation_id": operation_id, "expected": expected, "actual": actual},
                sort_keys=True,
            ).encode("utf-8")
            metadata_fd = os.open(
                "metadata.json",
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
                dir_fd=record_fd,
            )
            try:
                _write_fd(metadata_fd, metadata)
                os.fsync(metadata_fd)
            finally:
                os.close(metadata_fd)
            if cfg.store_conflict_content and proposed is not None:
                payload_fd = os.open(
                    "proposed-content.bin",
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=record_fd,
                )
                try:
                    _write_fd(payload_fd, proposed)
                    os.fsync(payload_fd)
                finally:
                    os.close(payload_fd)
            os.fsync(record_fd)
        finally:
            os.close(record_fd)
    finally:
        os.close(root_fd)
    return identifier


def conflict_response(exc: RevisionConflictError, *, conflict_id: str | None = None) -> dict[str, Any]:
    result = exc.to_dict()
    if conflict_id:
        result["conflict_id"] = conflict_id
    return result
