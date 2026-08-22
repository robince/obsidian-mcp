from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from obsidian_mcp.domain.index import VaultIndex
from obsidian_mcp.domain.models import FileRevision, RevisionConflictError
from obsidian_mcp.storage.conflicts import ConflictStoreError, discard_conflict, list_conflicts
from obsidian_mcp.storage.filesystem import VaultStorage
from obsidian_mcp.storage.operations import (
    LedgerUnavailableError,
    OperationConflictError,
    OperationLedger,
    OperationOutcomeUnknownError,
)
from obsidian_mcp.storage.policy import VaultAccessPolicy
from obsidian_mcp.storage.watcher import VaultWatcher
from obsidian_mcp.tools.write import (
    append_to_note,
    manage_tags,
    patch_frontmatter,
    patch_note,
    write_note,
)


def test_revision_is_content_authoritative(vault_factory, tmp_path):
    vault_factory({"note.md": "one"})
    storage = VaultStorage.from_config()
    first = storage.revision("note.md")
    (tmp_path / "note.md").touch()
    second = storage.revision("note.md")
    assert first.sha256 == second.sha256
    assert first.size == second.size == 3

    (tmp_path / "note.md").write_text("two")
    assert storage.revision("note.md").sha256 != first.sha256


def test_revision_parser_accepts_quoted_prefixed_uppercase_digest():
    digest = "A" * 64
    assert FileRevision.from_value(f'"sha256:{digest}"').sha256 == digest.lower()
    assert FileRevision.from_value({"sha256": f'"sha256:{digest}"'}).sha256 == digest.lower()


def test_stale_conditional_write_leaves_current_content_untouched(vault_factory):
    vault_factory({"note.md": "one"})
    storage = VaultStorage.from_config()
    old = storage.revision("note.md")
    storage.write_text_atomic("note.md", "remote")
    with pytest.raises(RevisionConflictError) as exc:
        storage.write_text_atomic("note.md", "local", expected_revision=old)
    assert exc.value.actual.sha256 == storage.revision("note.md").sha256
    assert storage.read_text("note.md") == "remote"


def test_atomic_mutations_flush_directory_entries(vault_factory, monkeypatch):
    vault_factory({"note.md": "one"})
    import obsidian_mcp.storage.filesystem as filesystem

    flushed: list[int] = []
    monkeypatch.setattr(filesystem, "_fsync_dir", lambda fd: flushed.append(fd))
    storage = VaultStorage.from_config()
    storage.write_text_atomic("note.md", "two")
    storage.trash("note.md")
    assert len(flushed) >= 3


def test_blind_create_uses_atomic_no_replace(vault_factory, monkeypatch, tmp_path):
    vault_factory({})
    from obsidian_mcp.storage.filesystem import VaultStorage

    original = VaultStorage.write_text_atomic
    injected = {"done": False}

    def external_create(storage, path, content, **kwargs):
        if kwargs.get("create_only") and not injected["done"]:
            injected["done"] = True
            (tmp_path / path).write_text("sync-winner")
        return original(storage, path, content, **kwargs)

    monkeypatch.setattr(VaultStorage, "write_text_atomic", external_create)
    with pytest.raises(RevisionConflictError):
        write_note("new.md", "mcp-proposal")
    assert (tmp_path / "new.md").read_text() == "sync-winner"


def test_required_precondition_rejects_blind_overwrite(vault_factory, monkeypatch):
    vault_factory({"note.md": "one"})
    monkeypatch.setenv("REQUIRE_WRITE_PRECONDITIONS", "true")
    import obsidian_mcp.config as config_module
    config_module._config = None
    with pytest.raises(PermissionError, match="revision precondition"):
        write_note("note.md", "two")


def test_malformed_explicit_revision_is_not_replaced_by_implicit_read_revision(vault_factory):
    vault_factory({"note.md": "# Heading\nold\n"})

    with pytest.raises(ValueError, match="expected_revision"):
        patch_note("note.md", "Heading", "new", expected_revision={})

    assert VaultStorage.from_config().read_text("note.md") == "# Heading\nold\n"


def test_two_mcp_writers_same_revision_only_one_succeeds(vault_factory):
    vault_factory({"note.md": "one"})
    old = VaultStorage.from_config().revision("note.md").token
    results: list[str] = []

    def writer(value: str):
        try:
            write_note("note.md", value, expected_revision=old)
            results.append(value)
        except RevisionConflictError:
            pass

    first = threading.Thread(target=writer, args=("a",))
    second = threading.Thread(target=writer, args=("b",))
    first.start()
    second.start()
    first.join()
    second.join()
    assert len(results) == 1
    assert VaultStorage.from_config().read_text("note.md") == results[0]


@pytest.mark.parametrize("mutation", ["patch", "frontmatter", "tags"])
def test_read_modify_write_uses_exact_read_revision(mutation, vault_factory, monkeypatch, tmp_path):
    vault_factory({"note.md": "---\ntags: [old]\n---\n# Heading\nbody\n"})
    original = VaultStorage.write_text_atomic
    injected = {"done": False}

    def external_write(storage, path, content, **kwargs):
        if kwargs.get("expected_revision") and not injected["done"]:
            injected["done"] = True
            (tmp_path / path).write_text("sync-winner")
        return original(storage, path, content, **kwargs)

    monkeypatch.setattr(VaultStorage, "write_text_atomic", external_write)
    with pytest.raises(RevisionConflictError):
        if mutation == "patch":
            patch_note("note.md", "Heading", "local")
        elif mutation == "frontmatter":
            patch_frontmatter("note.md", {"status": "local"})
        else:
            manage_tags("note.md", add=["local"])
    assert (tmp_path / "note.md").read_text() == "sync-winner"


def test_append_operation_id_is_applied_once(vault_factory):
    vault_factory({"events.md": "start\n"})
    first = append_to_note("events.md", "event", operation_id="evt-1")
    second = append_to_note("events.md", "event", operation_id="evt-1")
    assert first == second
    assert VaultStorage.from_config().read_text("events.md").count("event") == 1
    with pytest.raises(OperationConflictError):
        append_to_note("events.md", "different", operation_id="evt-1")


def test_append_pending_result_is_recovered_without_duplication(vault_factory):
    vault_factory({"events.md": "start\n"})
    storage = VaultStorage.from_config()
    initial = storage.revision("events.md")
    proposed = "start\n\nevent\n"
    result_revision = FileRevision.from_bytes(proposed.encode(), size=len(proposed), mtime_ns=0).token
    from obsidian_mcp.config import get_config
    ledger = OperationLedger(get_config().operation_ledger_path)
    digest = ledger.digest({"tool": "append_to_note", "path": "events.md", "content": "event", "section": None, "create": True, "expected_revision": None})
    ledger.reserve("evt-crash", principal_id="mcp", tool_name="append_to_note", target_path="events.md", request_digest=digest, initial_revision=initial.token, expected_result_revision=result_revision)
    storage.write_text_atomic("events.md", proposed)
    recovered = append_to_note("events.md", "event", operation_id="evt-crash")
    assert recovered["status"] == "recovered"
    assert storage.revision("events.md").token == result_revision


def test_append_unknown_pending_outcome_never_mutates(vault_factory):
    vault_factory({"events.md": "start\n"})
    storage = VaultStorage.from_config()
    initial = storage.revision("events.md")
    from obsidian_mcp.config import get_config
    ledger = OperationLedger(get_config().operation_ledger_path)
    digest = ledger.digest({"tool": "append_to_note", "path": "events.md", "content": "event", "section": None, "create": True, "expected_revision": None})
    proposed = "start\n\nevent\n"
    result_revision = FileRevision.from_bytes(proposed.encode(), size=len(proposed), mtime_ns=0).token
    ledger.reserve("evt-unknown", principal_id="mcp", tool_name="append_to_note", target_path="events.md", request_digest=digest, initial_revision=initial.token, expected_result_revision=result_revision)
    storage.write_text_atomic("events.md", "unrelated")
    with pytest.raises(OperationOutcomeUnknownError):
        append_to_note("events.md", "event", operation_id="evt-unknown")
    assert storage.read_text("events.md") == "unrelated"


def test_append_external_write_after_read_returns_conflict(vault_factory, monkeypatch, tmp_path):
    vault_factory({"events.md": "start\n"})
    from obsidian_mcp.storage.filesystem import VaultStorage

    original = VaultStorage.write_text_atomic
    injected = {"done": False}

    def external_write(storage, path, content, **kwargs):
        if kwargs.get("expected_revision") and not injected["done"]:
            injected["done"] = True
            (tmp_path / path).write_text("sync-winner")
        return original(storage, path, content, **kwargs)

    monkeypatch.setattr(VaultStorage, "write_text_atomic", external_write)
    with pytest.raises(RevisionConflictError):
        append_to_note("events.md", "event", operation_id="evt-race")
    assert (tmp_path / "events.md").read_text() == "sync-winner"

    # A known failed write abandons its reservation, so the same operation ID
    # can be retried against the newly observed sync state.
    result = append_to_note("events.md", "event", operation_id="evt-race")
    assert result["status"] == "appended"


def test_ledger_pending_reservation_can_be_recovered(tmp_path):
    ledger = OperationLedger(tmp_path / "ops.sqlite3")
    digest = "a" * 64
    assert ledger.reserve("op", principal_id="mcp", tool_name="append", target_path="x.md", request_digest=digest, initial_revision="sha256:a") is None
    pending = ledger.reserve("op", principal_id="mcp", tool_name="append", target_path="x.md", request_digest=digest, initial_revision="sha256:a")
    assert pending == {"_pending": True, "initial_revision": "sha256:a", "expected_result_revision": None}
    with pytest.raises(OperationConflictError):
        ledger.reserve("op", principal_id="mcp", tool_name="append", target_path="x.md", request_digest="b" * 64, initial_revision="sha256:a")


def test_ledger_composite_principal_scope_and_corruption(tmp_path):
    ledger = OperationLedger(tmp_path / "ops.sqlite3")
    digest = "a" * 64
    assert ledger.reserve("same", principal_id="one", tool_name="append", target_path="a.md", request_digest=digest, initial_revision=None) is None
    assert ledger.reserve("same", principal_id="two", tool_name="append", target_path="a.md", request_digest=digest, initial_revision=None) is None
    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not sqlite")
    with pytest.raises(LedgerUnavailableError):
        OperationLedger(corrupt)


def test_two_ledger_reservations_share_one_pending_row(tmp_path):
    path = tmp_path / "ops.sqlite3"
    first = OperationLedger(path)
    second = OperationLedger(path)
    barrier = threading.Barrier(2)
    results: list[dict | None] = []
    errors: list[Exception] = []
    digest = "a" * 64

    def reserve(ledger):
        try:
            barrier.wait()
            results.append(
                ledger.reserve(
                    "same", principal_id="mcp", tool_name="append", target_path="x.md",
                    request_digest=digest, initial_revision=None,
                )
            )
        except Exception as exc:  # pragma: no cover - assertion below reports it
            errors.append(exc)

    threads = [threading.Thread(target=reserve, args=(first,)), threading.Thread(target=reserve, args=(second,))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert results.count(None) == 1
    assert results.count({"_pending": True, "initial_revision": None, "expected_result_revision": None}) == 1


def test_operator_conflict_list_and_discard(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("CONFLICT_PATH", str(tmp_path.parent / "conflicts"))
    monkeypatch.setenv("STORE_CONFLICT_CONTENT", "false")
    import obsidian_mcp.config as config_module
    config_module._config = None
    from obsidian_mcp.storage.revisions import stage_conflict

    staged = stage_conflict(operation_id="op-1", path="AI-Memory/a.md", proposed=b"secret")
    assert staged is not None
    assert staged == Path(staged).name
    records = list_conflicts()
    conflict_id = records[0]["id"]
    assert conflict_id != "op-1"
    assert len(conflict_id) == 64
    assert records[0]["has_content"] is False
    assert discard_conflict(conflict_id)["status"] == "discarded"
    assert list_conflicts() == []


def test_conflict_ids_do_not_collide_and_payload_cannot_replace_metadata(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("CONFLICT_PATH", str(tmp_path.parent / "conflicts"))
    monkeypatch.setenv("STORE_CONFLICT_CONTENT", "true")
    import obsidian_mcp.config as config_module
    config_module._config = None
    from obsidian_mcp.storage.revisions import stage_conflict

    first = stage_conflict(operation_id="same", path="metadata.json", proposed=b"proposal")
    second = stage_conflict(operation_id="same", path="metadata.json", proposed=b"proposal")
    assert first != second
    root = tmp_path.parent / "conflicts" / first
    assert (root / "metadata.json").read_text().startswith("{")
    assert (root / "proposed-content.bin").read_bytes() == b"proposal"


def test_conflict_ids_are_opaque_and_symlink_safe(tmp_path, vault_factory, monkeypatch):
    vault_factory({})
    monkeypatch.setenv("CONFLICT_PATH", str(tmp_path.parent / "conflicts"))
    import obsidian_mcp.config as config_module
    config_module._config = None
    from obsidian_mcp.storage.revisions import stage_conflict

    stage_conflict(operation_id="../outside", path="AI-Memory/a.md", proposed=b"secret")
    conflict_id = list_conflicts()[0]["id"]
    with pytest.raises(ConflictStoreError):
        discard_conflict("../outside")
    root = tmp_path.parent / "conflicts"
    (root / "external").mkdir()
    (root / ("a" * 64)).symlink_to(root / "external", target_is_directory=True)
    with pytest.raises(ConflictStoreError):
        discard_conflict("a" * 64)
    assert discard_conflict(conflict_id)["status"] == "discarded"


def test_watcher_captures_before_ready_and_replays_after_mark_ready(tmp_path, monkeypatch):
    (tmp_path / "note.md").write_text("one")
    policy = VaultAccessPolicy(tmp_path)
    seen: list[str] = []
    monkeypatch.setenv("WATCH_MODE", "poll")
    watcher = VaultWatcher(tmp_path, policy=policy, poll_interval=60, reconcile_interval=0, debounce_ms=0)
    watcher.start(seen.append)
    watcher._emit(str(tmp_path / "note.md"))
    time.sleep(0.05)
    assert seen == []
    watcher.mark_ready()
    for _ in range(20):
        if seen:
            break
        time.sleep(0.02)
    watcher.stop()
    assert seen == ["note.md"]


def test_startup_release_publishes_index_only_after_replay_and_overflow_reconcile(tmp_path, monkeypatch):
    (tmp_path / "note.md").write_text("one")
    policy = VaultAccessPolicy(tmp_path)
    index = VaultIndex(tmp_path, policy=policy)
    seen: list[str] = []
    reconciled: list[bool] = []
    monkeypatch.setenv("WATCH_MODE", "poll")
    monkeypatch.setenv("WATCHER_MAX_PENDING_EVENTS", "1")
    watcher = VaultWatcher(tmp_path, policy=policy, poll_interval=60, reconcile_interval=0, debounce_ms=0)

    def on_change(path: str) -> None:
        seen.append(path)
        index.update(path)
        if path == "note.md":
            (tmp_path / "during-replay.md").write_text("during")
            watcher._emit(str(tmp_path / "during-replay.md"))

    def reconcile() -> None:
        reconciled.append(True)
        index.reconcile()

    watcher.start(on_change, on_reconcile=reconcile)
    index.build(publish_ready=False)
    assert not index.is_ready()
    watcher._emit(str(tmp_path / "note.md"))
    watcher._emit(str(tmp_path / "overflow.md"))
    watcher.release(on_ready=index.mark_ready)
    watcher.stop()

    assert index.is_ready()
    assert "during-replay.md" in index.get_all_notes()
    assert reconciled
    assert watcher.health()["capture_overflow"] is False


def test_startup_release_reconciles_an_overflow_during_reconciliation(tmp_path, monkeypatch):
    policy = VaultAccessPolicy(tmp_path)
    reconciled = 0
    monkeypatch.setenv("WATCH_MODE", "poll")
    monkeypatch.setenv("WATCHER_MAX_PENDING_EVENTS", "1")
    watcher = VaultWatcher(tmp_path, policy=policy, poll_interval=60, reconcile_interval=0, debounce_ms=0)

    def reconcile() -> None:
        nonlocal reconciled
        reconciled += 1
        if reconciled == 1:
            watcher._emit(str(tmp_path / "queued.md"))
            watcher._emit(str(tmp_path / "overflow-again.md"))

    watcher.start(lambda _path: None, on_reconcile=reconcile)
    watcher._emit(str(tmp_path / "first.md"))
    watcher._emit(str(tmp_path / "overflow.md"))
    watcher.release()
    watcher.stop()

    assert reconciled == 2
    assert watcher.health()["capture_overflow"] is False


def test_reconcile_repairs_a_dropped_event(vault_factory, tmp_path):
    index = vault_factory({"note.md": "one"})
    (tmp_path / "note.md").write_text("two")
    assert index.reconcile() == {"changed": 1, "removed": 0}


def test_restore_keeps_destination_after_source_unlink_if_final_fsync_fails(vault_factory, monkeypatch, tmp_path):
    vault_factory({"note.md": "important"})
    storage = VaultStorage.from_config()
    _, trashed = storage.trash("note.md")
    import obsidian_mcp.storage.filesystem as filesystem

    calls = 0

    def fail_second_fsync(_fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated durability failure")

    monkeypatch.setattr(filesystem, "_fsync_dir", fail_second_fsync)
    with pytest.raises(OSError, match="durability"):
        storage.restore(trashed.name, "restored.md")
    assert (tmp_path / "restored.md").read_text() == "important"
    assert not trashed.exists()
