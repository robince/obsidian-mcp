"""Folder management tools backed by the central vault storage gateway."""

from __future__ import annotations

import stat

from ..config import get_config
from ..domain.index import VaultIndex
from ..domain.semantics import ParserVaultSemantics
from ..storage.filesystem import VaultStorage
from ..storage.locking import SEMANTIC_GRAPH_LOCK, acquire_lock
from ..storage.mutations import (
    IndexChange,
    MutationExecutor,
    MutationPlan,
    PlanApprovalRequiredError,
    PlannedInventory,
    PlannedMove,
    directory_creates_for_destinations,
    inventory_for_paths,
)


def _storage() -> VaultStorage:
    return VaultStorage.from_config()


def create_folder(path: str) -> dict:
    storage = _storage()
    if not path or path in (".", "/", "\\"):
        raise ValueError("A child folder path is required")
    target = storage.resolve_write(path)
    cfg = get_config()
    graph = acquire_lock(
        SEMANTIC_GRAPH_LOCK, timeout=cfg.mutation_lock_timeout, lock_path=cfg.lock_path
    )
    try:
        if storage.exists(target.relative, read=False) and not stat.S_ISDIR(
            storage.stat(target.relative, read=False).st_mode
        ):
            raise ValueError(f"A file already exists at: {path!r}")
        storage.make_dir(target.relative)
    finally:
        graph.release()
    return {"path": target.relative, "status": "created"}


def delete_folder(
    path: str,
    trash: bool = True,
    index: VaultIndex | None = None,
    approved_digest: str | None = None,
    plan_only: bool = False,
    operation_id: str | None = None,
) -> dict:
    storage = _storage()
    target = storage.resolve_delete(path, permanent=not trash)
    if not storage.exists(target.relative, read=False):
        raise FileNotFoundError(f"Folder not found: {path!r}")
    if not stat.S_ISDIR(storage.stat(target.relative, read=False).st_mode):
        raise ValueError(f"Not a folder: {path!r}")
    storage.authorize_tree(target.relative, permanent=not trash)
    cfg = get_config()
    if not trash:
        raise ValueError("Permanent folder deletion is disabled until a fully transactional directory purge exists")
    descendants = storage._tree_paths(target)
    destination = storage.policy.canonicalize(f".trash/{target.relative.rsplit('/', 1)[-1]}")
    plan = MutationPlan(
        operation="delete_folder",
        moves=(PlannedMove(target, destination, storage.tree_revision(target.relative), destination_is_trash=True),),
        inventory=inventory_for_paths(storage, (target.relative,)),
        index_changes=tuple(IndexChange("remove", rel) for rel in descendants if rel.lower().endswith(".md")),
        metadata=(("semantic_version", "filesystem-v1"), ("trash", "true")),
    )
    if plan_only:
        return {**plan.summary(), "status": "planned", "path": target.relative, "trash": True}
    if cfg.enable_delete and not approved_digest:
        raise PlanApprovalRequiredError("run the operation in plan mode and approve its plan_digest")
    result = MutationExecutor(storage, index=None).execute(plan, operation_id=operation_id, approved_digest=approved_digest)
    if index is not None:
        for rel in descendants:
            if rel.lower().endswith(".md"):
                index.remove(rel)
    result.update({"path": target.relative, "status": "deleted", "transaction_status": result.get("status"), "trash": True})
    return result


def list_trash() -> dict:
    items = []
    for item in _storage().list_trash():
        items.append(
            {
                "name": item.name,
                "type": "folder" if item.is_dir else "file",
                "size_bytes": item.size_bytes,
                "mtime": item.mtime,
            }
        )
    return {"items": items}


def restore_folder(
    trashed_name: str,
    to_path: str,
    index: VaultIndex | None = None,
    approved_digest: str | None = None,
    plan_only: bool = False,
    operation_id: str | None = None,
) -> dict:
    if "/" in trashed_name or "\\" in trashed_name or trashed_name in (".", ".."):
        raise ValueError(f"trashed_name must be a bare name, not a path: {trashed_name!r}")
    storage = _storage()
    destination = storage.resolve_write(to_path)
    info = storage.trash_info(trashed_name)
    if not info.is_dir:
        raise FileNotFoundError(f"No trashed folder named {trashed_name!r} in .trash/")
    if storage.exists(destination.relative, read=False):
        raise FileExistsError(f"Target already exists: {destination.relative!r}")
    storage.authorize_restore(trashed_name, destination.relative)
    source = storage.policy.canonicalize(f".trash/{trashed_name}")
    trash_prefix = f".trash/{trashed_name}/"
    restored_notes = tuple(
        IndexChange("update", f"{destination.relative}/{path[len(trash_prefix):]}")
        for path, _size, _revision in storage.trash_inventory(trashed_name)
        if path.startswith(trash_prefix) and path.lower().endswith(".md")
    )
    plan = MutationPlan(
        operation="restore_folder",
        moves=(PlannedMove(source, destination, storage.trash_tree_revision(trashed_name), source_is_trash=True),),
        directory_creates=directory_creates_for_destinations(
            storage, (destination.relative,)
        ),
        inventory=tuple(PlannedInventory(path, size, revision) for path, size, revision in storage.trash_inventory(trashed_name)),
        index_changes=restored_notes,
        metadata=(("semantic_version", "filesystem-v1"), ("trash", "true")),
    )
    if plan_only:
        return {**plan.summary(), "status": "planned", "path": destination.relative}
    if get_config().enable_folder_restore and not approved_digest:
        raise PlanApprovalRequiredError("run the operation in plan mode and approve its plan_digest")
    result = MutationExecutor(storage, index=index).execute(plan, operation_id=operation_id, approved_digest=approved_digest)
    restored = destination

    notes_restored = 0
    if index is not None:
        for p in storage.tree_paths(restored.relative):
            rel = p.relative
            if not rel.lower().endswith(".md"):
                continue
            if storage.policy.can_read(rel):
                index.update(rel)
                notes_restored += 1
    result.update({"path": restored.relative, "status": "restored", "notes_restored": notes_restored})
    return result


def list_folder(path: str = "") -> dict:
    storage = _storage()
    target = storage.resolve_read(path, allow_empty=True)
    folders: list[str] = []
    files: list[str] = []
    try:
        entries = storage.list_dir(target.relative)
    except NotADirectoryError as exc:
        raise ValueError(f"Not a folder: {path!r}") from exc
    for entry in entries:
        if entry.name.startswith("."):
            continue
        (folders if entry.is_dir else files).append(entry.relative)
    return {"path": target.relative or "/", "folders": folders, "files": files}


def rename_folder(
    from_path: str,
    to_path: str,
    index: VaultIndex | None = None,
    approved_digest: str | None = None,
    plan_only: bool = False,
    operation_id: str | None = None,
) -> dict:
    """Plan and transactionally rename a folder and its path-based links."""
    storage = _storage()
    plan = ParserVaultSemantics(storage, index=index).plan_folder_rename(from_path, to_path)
    if plan_only:
        notes_moved = sum(1 for change in plan.index_changes if change.action == "remove")
        return {**plan.summary(), "status": "planned", "notes_moved": notes_moved, "revisions": {item.path.relative: item.original_revision for item in plan.writes}}
    if get_config().enable_folder_rename and not approved_digest:
        raise PlanApprovalRequiredError("run the operation in plan mode and approve its plan_digest")
    result = MutationExecutor(storage, index=index).execute(plan, operation_id=operation_id, approved_digest=approved_digest)
    result["from"] = result["moved"][0]["from"]
    result["to"] = result["moved"][0]["to"]
    result["notes_moved"] = sum(1 for change in plan.index_changes if change.action == "remove")
    result["updated_links_in"] = [path for path in result["rewritten"] if not path.startswith(result["from"] + "/")]
    return result
