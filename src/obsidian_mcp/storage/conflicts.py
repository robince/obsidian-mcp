"""Safe operator inspection/removal of staged conflict records."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from ..config import get_config


class ConflictStoreError(RuntimeError):
    pass


_CONFLICT_ID = re.compile(r"^[0-9a-f]{64}$")


def _root() -> Path:
    root = get_config().conflict_path
    if root is None:
        raise ConflictStoreError("CONFLICT_PATH is not configured")
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise ConflictStoreError("conflict root is not a real directory")
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink() or not root.is_dir():
        raise ConflictStoreError("conflict root is not a real directory")
    return root


def list_conflicts() -> list[dict]:
    root = _root()
    result = []
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if entry.is_symlink() or not entry.is_dir():
            continue
        metadata = entry / "metadata.json"
        if metadata.is_symlink() or not metadata.is_file():
            result.append({"id": entry.name, "corrupt": True})
            continue
        try:
            data = json.loads(metadata.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        if not isinstance(data, dict):
            result.append({"id": entry.name, "corrupt": True})
            continue
        result.append(
            {
                **data,
                "id": entry.name,
                "corrupt": False,
                "has_content": any(
                    path.name != "metadata.json" for path in entry.iterdir()
                ),
            }
        )
    return result


def discard_conflict(identifier: str) -> dict:
    if not identifier or identifier in {".", ".."} or "/" in identifier or "\\" in identifier:
        raise ConflictStoreError("conflict id must be a bare directory name")
    if not _CONFLICT_ID.fullmatch(identifier):
        raise ConflictStoreError("conflict id must be an opaque conflict id")
    root = _root()
    target = root / identifier
    if target.parent != root or target.is_symlink() or not target.is_dir():
        raise ConflictStoreError("conflict record not found")
    shutil.rmtree(target)
    return {"id": identifier, "status": "discarded"}
