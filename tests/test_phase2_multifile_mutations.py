from __future__ import annotations

import json

import pytest

import obsidian_mcp.config as cfg_mod
import obsidian_mcp.server as server_module
import obsidian_mcp.storage.filesystem as filesystem_module
import obsidian_mcp.storage.mutations as mutations_module
from obsidian_mcp.domain.semantics import ParserVaultSemantics, SemanticAmbiguityError
from obsidian_mcp.storage.filesystem import VaultStorage
from obsidian_mcp.storage.mutations import (
    MutationExecutor,
    MutationLimitError,
    MutationPlan,
    MutationPreconditionError,
    MutationRecoveryRequiredError,
    PlanApprovalRequiredError,
    PlannedDelete,
    PlannedDirectoryCreate,
    PlannedMove,
    PlannedWrite,
    TransactionJournal,
    directory_creates_for_destinations,
    incomplete_transactions,
    inventory_for_paths,
    recover_transaction,
)
from obsidian_mcp.storage.policy import ReadPermissionError, WritePermissionError
from obsidian_mcp.tools.folders import delete_folder, rename_folder, restore_folder
from obsidian_mcp.tools.write import find_replace_in_vault, move_note


def _enable(monkeypatch, **values):
    for name, value in values.items():
        monkeypatch.setenv(name, "true" if value is True else str(value))
    cfg_mod._config = None


def test_move_plan_is_read_only_and_digest_is_content_sensitive(tmp_path, vault_factory):
    vault_factory({"old.md": "body", "link.md": "[[old#Heading|Alias]]"})
    storage = VaultStorage.from_config()
    semantics = ParserVaultSemantics(storage)
    first = semantics.plan_move("old.md", "new.md")
    second = semantics.plan_move("old.md", "new.md")
    assert first.digest == second.digest
    assert not (tmp_path / "new.md").exists()
    changed = MutationPlan(
        operation="move_note",
        writes=(PlannedWrite(first.writes[0].path, first.writes[0].original_revision, b"changed"),),
        moves=first.moves,
        index_changes=first.index_changes,
        metadata=(("semantic_version", "parser-v1"),),
    )
    assert changed.digest != first.digest


def test_move_plan_explicitly_creates_missing_destination_parents(tmp_path, vault_factory):
    vault_factory({"old.md": "body"})
    preview = move_note("old.md", "Archive/Deep/new.md", plan_only=True)
    assert preview["directory_creates"] == ["Archive", "Archive/Deep"]
    move_note("old.md", "Archive/Deep/new.md")
    assert (tmp_path / "Archive/Deep/new.md").read_text() == "body"


def test_plan_digest_binds_directory_creation(vault_factory):
    vault_factory({})
    storage = VaultStorage.from_config()
    target = storage.resolve_write("Nested/note.md")
    without_directory = MutationPlan(
        operation="directory-digest",
        writes=(PlannedWrite(target, None, b"content"),),
    )
    with_directory = MutationPlan(
        operation="directory-digest",
        writes=without_directory.writes,
        directory_creates=(
            PlannedDirectoryCreate(storage.resolve_write("Nested")),
        ),
    )
    assert without_directory.digest != with_directory.digest


def test_executor_rejects_unplanned_missing_parent(vault_factory):
    vault_factory({})
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="unplanned-parent",
        writes=(PlannedWrite(storage.resolve_write("Missing/note.md"), None, b"content"),),
    )
    with pytest.raises(MutationPreconditionError, match="unplanned destination directory"):
        MutationExecutor(storage).execute(plan)


def test_executor_rejects_tampered_staged_artifact(tmp_path, vault_factory, monkeypatch):
    vault_factory({"note.md": "before"})
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="staging-integrity",
        writes=(
            PlannedWrite(
                storage.resolve_write("note.md"),
                storage.revision("note.md").token,
                b"approved",
            ),
        ),
    )
    executor = MutationExecutor(storage)
    original_stage = executor._stage

    def tamper_after_staging(journal, staged_plan):
        original_stage(journal, staged_plan)
        (journal.stage_dir / "000000.bin").write_bytes(b"tampered")

    monkeypatch.setattr(executor, "_stage", tamper_after_staging)
    with pytest.raises(MutationPreconditionError, match="does not match approved plan"):
        executor.execute(plan)
    assert (tmp_path / "note.md").read_text() == "before"


def test_move_rejects_protected_backlink_before_mutating(tmp_path, vault_factory, monkeypatch):
    vault_factory({"Allowed/old.md": "body", "outside.md": "[[Allowed/old]]"})
    _enable(monkeypatch, ENABLE_MOVE=True, WRITE_PATHS="Allowed/")
    plan = move_note("Allowed/old.md", "Allowed/new.md", plan_only=True)
    with pytest.raises(WritePermissionError):
        move_note("Allowed/old.md", "Allowed/new.md", approved_digest=plan["plan_digest"])
    assert (tmp_path / "Allowed/old.md").read_text() == "body"
    assert (tmp_path / "outside.md").read_text() == "[[Allowed/old]]"


def test_move_link_corpus_preserves_heading_block_embed_and_code(tmp_path, vault_factory):
    idx = vault_factory(
        {
            "old.md": "body",
            "links.md": "---\naliases: Legacy\n---\n[[old#H|A]] ![[old^block]]\n```\n[[old]]\n```",
        }
    )
    move_note("old.md", "new.md", idx)
    content = (tmp_path / "links.md").read_text()
    assert "[[new#H|A]]" in content
    assert "![[new^block]]" in content
    assert "```\n[[old]]\n```" in content
    assert "aliases: Legacy" in content


def test_move_link_corpus_handles_tilde_and_multibacktick_code(tmp_path, vault_factory):
    vault_factory({"old.md": "body", "links.md": "~~~md\n[[old]]\n~~~~\n``[[old]]``\n[[old]]"})
    move_note("old.md", "new.md")
    content = (tmp_path / "links.md").read_text()
    assert "~~~md\n[[old]]\n~~~~" in content
    assert "``[[old]]``" in content
    assert content.endswith("[[new]]")


def test_move_does_not_rewrite_wikilink_inside_code_span_with_shorter_runs(tmp_path, vault_factory):
    vault_factory({"old.md": "body", "links.md": "`` ` [[old]] ` ``\n[[old]]"})
    move_note("old.md", "new.md")
    assert (tmp_path / "links.md").read_text() == "`` ` [[old]] ` ``\n[[new]]"


def test_move_rewrites_self_reference_at_destination(tmp_path, vault_factory):
    vault_factory({"old.md": "# Heading\n[[old#Heading]]"})
    move_note("old.md", "new.md")
    assert (tmp_path / "new.md").read_text() == "# Heading\n[[new#Heading]]"


def test_move_rejects_duplicate_stem_ambiguity(vault_factory):
    vault_factory({"old.md": "one", "Other/old.md": "two", "links.md": "[[old]]"})
    with pytest.raises(SemanticAmbiguityError):
        ParserVaultSemantics(VaultStorage.from_config()).plan_move("old.md", "new.md")


def test_move_rejects_duplicate_alias_ambiguity(vault_factory):
    vault_factory({"old.md": "---\naliases: [Legacy]\n---\none", "other.md": "---\naliases: [Legacy]\n---\ntwo", "links.md": "[[Legacy]]"})
    with pytest.raises(SemanticAmbiguityError):
        ParserVaultSemantics(VaultStorage.from_config()).plan_move("old.md", "new.md")


def test_move_preserves_alias_link_and_rewrites_relative_path(tmp_path, vault_factory):
    vault_factory({
        "Folder/old.md": "---\naliases: [Legacy]\n---\none",
        "Folder/Sub/links.md": "[[../old]] [[Legacy]]",
    })
    move_note("Folder/old.md", "Folder/new.md")
    content = (tmp_path / "Folder/Sub/links.md").read_text()
    assert "[[../new]]" in content
    assert "[[Legacy]]" in content


def test_enabled_bulk_requires_approved_plan(vault_factory, monkeypatch):
    vault_factory({"a.md": "foo"})
    _enable(monkeypatch, ENABLE_BULK_REPLACE=True)
    dry = find_replace_in_vault("foo", "bar", dry_run=True)
    with pytest.raises(PlanApprovalRequiredError):
        find_replace_in_vault("foo", "bar", dry_run=False)
    # The fixture's vault is available through the configured storage; change
    # it after planning to force the revision precondition to fail.
    VaultStorage.from_config().write_text_atomic("a.md", "changed")
    with pytest.raises(PlanApprovalRequiredError):
        find_replace_in_vault("foo", "bar", dry_run=False, approved_digest=dry["plan_digest"])


def test_scan_root_precondition_detects_new_markdown_file(vault_factory):
    vault_factory({"a.md": "one"})
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="scan-only",
        scan_revisions=(("a.md", storage.revision("a.md").token),),
        scan_roots=("",),
    )
    storage.write_text_atomic("new.md", "new", create_only=True)
    with pytest.raises(MutationPreconditionError, match="path inventory"):
        MutationExecutor(storage).execute(plan)


def test_exact_bulk_replacement_keeps_backslashes_literal(tmp_path, vault_factory):
    vault_factory({"a.md": "needle"})
    find_replace_in_vault("needle", r"\1\n", dry_run=False)
    assert (tmp_path / "a.md").read_text() == r"\1\n"


def test_remote_bulk_regex_is_always_rejected(vault_factory, monkeypatch):
    vault_factory({"a.md": "task-123"})
    _enable(monkeypatch, ENABLE_BULK_REPLACE=True, ALLOW_REGEX_MUTATIONS=True)
    with pytest.raises(ValueError, match="regex"):
        find_replace_in_vault(r"task-\d+", "TASK", mode="regex", dry_run=True)


def test_folder_rename_uses_transaction_and_updates_path_links(tmp_path, vault_factory):
    idx = vault_factory({"Old/note.md": "body", "index.md": "[[Old/note]]"})
    result = rename_folder("Old", "New", index=idx)
    assert result["status"] == "committed"
    assert result["transaction_status"] == "committed"
    assert (tmp_path / "New/note.md").exists()
    assert (tmp_path / "index.md").read_text() == "[[New/note]]"


def test_folder_rename_does_not_retarget_bare_note_link(tmp_path, vault_factory):
    vault_factory(
        {
            "Old.md": "the note",
            "Old/child.md": "the child",
            "index.md": "[[Old]] [[Old/child]]",
        }
    )
    rename_folder("Old", "New")
    assert (tmp_path / "index.md").read_text() == "[[Old]] [[New/child]]"


def test_folder_rename_rewrites_internal_link_after_tree_move(tmp_path, vault_factory):
    idx = vault_factory(
        {
            "Old/a.md": "[[Old/b]]",
            "Old/b.md": "body",
            "outside.md": "[[Old/a]]",
        }
    )
    result = rename_folder("Old", "New", index=idx)
    assert result["status"] == "committed"
    assert (tmp_path / "New/a.md").read_text() == "[[New/b]]"
    assert (tmp_path / "New/b.md").read_text() == "body"
    assert "New/a.md" in idx.get_backlinks("New/b.md")
    assert incomplete_transactions(cfg_mod.get_config().transaction_path) == []


def test_folder_rename_rebases_relative_links_from_mapped_note_path(tmp_path, vault_factory):
    vault_factory({"Old/Sub/a.md": "[[../b]]", "Old/b.md": "body"})
    rename_folder("Old", "Archive/New")
    assert (tmp_path / "Archive/New/Sub/a.md").read_text() == "[[../b]]"


def test_folder_rename_preview_and_commit_report_same_notes_moved(vault_factory):
    vault_factory({"Old/a.md": "body", "outside.md": "[[Old/a]]"})
    preview = rename_folder("Old", "New", plan_only=True)
    result = rename_folder("Old", "New")
    assert preview["notes_moved"] == result["notes_moved"] == 1


def test_folder_rename_rolls_back_if_move_crashes_before_internal_rewrite(vault_factory, monkeypatch):
    vault_factory({"Old/a.md": "[[Old/b]]", "Old/b.md": "body"})
    storage = VaultStorage.from_config()
    plan = ParserVaultSemantics(storage).plan_folder_rename("Old", "New")
    original_move = storage.move
    calls = 0

    def crash_after_move(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original_move(*args, **kwargs)
        if calls == 1:
            raise OSError("crash after folder move")
        return result

    monkeypatch.setattr(storage, "move", crash_after_move)
    with pytest.raises(OSError, match="crash after folder move"):
        MutationExecutor(storage).execute(plan)
    assert storage.read_text("Old/a.md") == "[[Old/b]]"
    assert not storage.exists("New", read=False)


def test_semantic_plan_rejects_any_scanned_note_revision_change(vault_factory):
    vault_factory({"old.md": "body", "links.md": "[[old]]", "unrelated.md": "text"})
    storage = VaultStorage.from_config()
    plan = ParserVaultSemantics(storage).plan_move("old.md", "new.md")
    storage.write_text_atomic("unrelated.md", "changed")
    with pytest.raises(MutationPreconditionError, match="semantic scan changed"):
        MutationExecutor(storage).execute(plan, approved_digest=plan.digest)


def test_intent_state_treats_policy_failure_as_unknown(
    tmp_path, vault_factory, monkeypatch
):
    vault_factory({"note.md": "before"})
    storage = VaultStorage.from_config()
    executor = MutationExecutor(storage)
    journal = TransactionJournal(tmp_path.parent / "transactions", "policy-failure")
    journal.state = {"steps": []}

    def deny_revision(_path):
        raise ReadPermissionError("denied during recovery")

    monkeypatch.setattr(storage, "revision", deny_revision)
    plan = MutationPlan(
        operation="policy-failure",
        writes=(
            PlannedWrite(
                storage.resolve_write("note.md"),
                "sha256:" + "0" * 64,
                b"after",
            ),
        ),
    )
    with pytest.raises(MutationPreconditionError, match="became inaccessible"):
        executor.validate_preconditions(plan)
    assert (
        executor._intent_state(
            journal,
            {
                "action": "write",
                "path": "note.md",
                "original_revision": "sha256:" + "0" * 64,
                "staged": "000000.bin",
            },
        )
        == "unknown"
    )


def test_delete_folder_tool_passes_live_index(monkeypatch):
    marker = object()
    received = {}

    def fake_delete(path, **kwargs):
        received.update({"path": path, **kwargs})
        return {"status": "deleted"}

    monkeypatch.setattr(server_module, "_index", marker)
    monkeypatch.setattr(server_module, "delete_folder", fake_delete)
    assert server_module.delete_folder_tool("Folder") == {"status": "deleted"}
    assert received["index"] is marker


def test_folder_trash_restore_uses_approved_transactions(tmp_path, vault_factory, monkeypatch):
    idx = vault_factory({"Temp/note.md": "content"})
    _enable(monkeypatch, ENABLE_DELETE=True, ENABLE_FOLDER_RESTORE=True)
    delete_plan = delete_folder("Temp", plan_only=True)
    with pytest.raises(PlanApprovalRequiredError):
        delete_folder("Temp")
    deleted = delete_folder("Temp", index=idx, approved_digest=delete_plan["plan_digest"])
    assert deleted["status"] == "deleted"
    restore_plan = restore_folder("Temp", "Temp", plan_only=True)
    with pytest.raises(PlanApprovalRequiredError):
        restore_folder("Temp", "Temp")
    restored = restore_folder("Temp", "Temp", index=idx, approved_digest=restore_plan["plan_digest"])
    assert restored["status"] == "restored"
    assert restored["transaction_status"] == "committed"
    assert (tmp_path / "Temp/note.md").read_text() == "content"


def test_rollback_refuses_external_edit_of_poststate(tmp_path, vault_factory, monkeypatch):
    vault_factory({"a.md": "foo", "b.md": "foo"})
    storage = VaultStorage.from_config()
    first = storage.resolve_write("a.md")
    second = storage.resolve_write("b.md")
    plan = MutationPlan(
        operation="fault-injected",
        writes=(
            PlannedWrite(first, storage.revision("a.md").token, b"bar"),
            PlannedWrite(second, storage.revision("b.md").token, b"bar"),
        ),
    )
    original = storage.write_bytes_atomic
    calls = 0

    def inject(path, content, **kwargs):
        nonlocal calls
        calls += 1
        result = original(path, content, **kwargs)
        if calls == 1:
            (tmp_path / "a.md").write_text("external")
        else:
            raise OSError("injected commit failure")
        return result

    monkeypatch.setattr(storage, "write_bytes_atomic", inject)
    with pytest.raises(MutationRecoveryRequiredError):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "a.md").read_text() == "external"
    assert (tmp_path / "b.md").read_text() == "bar"


def test_rollback_removes_transaction_created_directories(tmp_path, vault_factory, monkeypatch):
    vault_factory({"z.md": "before"})
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="directory-rollback",
        writes=(
            PlannedWrite(storage.resolve_write("Nested/a.md"), None, b"created"),
            PlannedWrite(storage.resolve_write("z.md"), storage.revision("z.md").token, b"after"),
        ),
        directory_creates=directory_creates_for_destinations(
            storage, ("Nested/a.md",)
        ),
    )
    original_write = storage.write_bytes_atomic
    calls = 0

    def fail_second(path, content, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected write failure")
        return original_write(path, content, **kwargs)

    monkeypatch.setattr(storage, "write_bytes_atomic", fail_second)
    with pytest.raises(OSError, match="write failure"):
        MutationExecutor(storage).execute(plan)
    assert not (tmp_path / "Nested").exists()
    assert (tmp_path / "z.md").read_text() == "before"


def test_rollback_never_removes_unexpected_directory_child(tmp_path, vault_factory, monkeypatch):
    vault_factory({"z.md": "before"})
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="directory-rollback-external-child",
        writes=(
            PlannedWrite(storage.resolve_write("Nested/a.md"), None, b"created"),
            PlannedWrite(storage.resolve_write("z.md"), storage.revision("z.md").token, b"after"),
        ),
        directory_creates=directory_creates_for_destinations(
            storage, ("Nested/a.md",)
        ),
    )
    original_write = storage.write_bytes_atomic
    calls = 0

    def inject_child_then_fail(path, content, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            result = original_write(path, content, **kwargs)
            (tmp_path / "Nested/external.txt").write_text("external")
            return result
        if calls == 2:
            raise OSError("injected write failure")
        return original_write(path, content, **kwargs)

    monkeypatch.setattr(storage, "write_bytes_atomic", inject_child_then_fail)
    with pytest.raises(MutationRecoveryRequiredError):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "Nested/external.txt").read_text() == "external"


def test_folder_trash_collision_is_recorded_as_actual_destination(tmp_path, vault_factory):
    vault_factory({"Temp/note.md": "content"})
    (tmp_path / ".trash").mkdir()
    (tmp_path / ".trash/Temp").mkdir()
    result = delete_folder("Temp")
    assert result["moved"][0]["to"].startswith(".trash/Temp-")


def test_trash_collision_retry_is_bounded(vault_factory, monkeypatch):
    vault_factory({"note.md": "content"})
    calls = 0

    def always_collide(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise FileExistsError

    monkeypatch.setattr(filesystem_module, "_rename_noreplace", always_collide)
    with pytest.raises(FileExistsError, match="Unable to reserve"):
        VaultStorage.from_config().trash("note.md")
    assert calls == 16


def test_live_and_trash_tree_revisions_use_same_order(vault_factory):
    vault_factory({"Old/b/z.md": "nested", "Old/b.md": "sibling"})
    storage = VaultStorage.from_config()
    live = storage.tree_revision("Old").removeprefix("tree:")
    storage.trash("Old")
    trashed = storage.trash_tree_revision("Old").removeprefix("trash:")
    assert trashed == live


def test_crash_after_trash_move_before_applied_journal_rolls_back(tmp_path, vault_factory, monkeypatch):
    vault_factory({"Temp/note.md": "content"})
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="trash-window",
        moves=(
            PlannedMove(
                storage.resolve_delete("Temp"),
                storage.policy.canonicalize(".trash/Temp"),
                storage.tree_revision("Temp"),
                destination_is_trash=True,
            ),
        ),
        inventory=inventory_for_paths(storage, ("Temp",)),
    )
    original = storage.trash
    calls = 0

    def crash_after(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original(*args, **kwargs)
        if calls == 1:
            raise OSError("crash after trash")
        return result

    monkeypatch.setattr(storage, "trash", crash_after)
    with pytest.raises(OSError, match="crash after trash"):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "Temp/note.md").read_text() == "content"
    assert not (tmp_path / ".trash/Temp").exists()


def test_directory_move_rollback_uses_tree_poststate_cas(tmp_path, vault_factory, monkeypatch):
    vault_factory({"A/a.md": "a", "B/b.md": "b"})
    storage = VaultStorage.from_config()
    from obsidian_mcp.storage.mutations import PlannedMove, inventory_for_paths

    plan = MutationPlan(
        operation="two-directory-moves",
        moves=(
            PlannedMove(
                storage.resolve_delete("A"),
                storage.resolve_write("A2"),
                storage.tree_revision("A"),
            ),
            PlannedMove(
                storage.resolve_delete("B"),
                storage.resolve_write("B2"),
                storage.tree_revision("B"),
            ),
        ),
        inventory=inventory_for_paths(storage, ("A", "B")),
    )
    original_move = storage.move
    calls = 0

    def fail_second(source, destination, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected directory move failure")
        return original_move(source, destination, **kwargs)

    monkeypatch.setattr(storage, "move", fail_second)
    with pytest.raises(OSError, match="injected"):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "A/a.md").read_text() == "a"
    assert (tmp_path / "B/b.md").read_text() == "b"
    assert not (tmp_path / "A2").exists()
    assert not (tmp_path / "B2").exists()


def test_file_move_never_replaces_existing_destination(tmp_path, vault_factory):
    vault_factory({"source.md": "source", "destination.md": "existing"})
    storage = VaultStorage.from_config()
    with pytest.raises(FileExistsError):
        storage.move("source.md", "destination.md")
    assert (tmp_path / "source.md").read_text() == "source"
    assert (tmp_path / "destination.md").read_text() == "existing"


def test_restore_rollback_target_name_is_no_replace(tmp_path, vault_factory):
    vault_factory({"note.md": "original"})
    storage = VaultStorage.from_config()
    storage.trash("note.md")
    storage.restore("note.md", "restored.md")
    (tmp_path / ".trash/note.md").write_text("external")
    with pytest.raises(FileExistsError):
        storage.trash("restored.md", destination_name="note.md")
    assert (tmp_path / "restored.md").read_text() == "original"
    assert (tmp_path / ".trash/note.md").read_text() == "external"


def test_crash_after_write_intent_before_mutation_rolls_back(tmp_path, vault_factory, monkeypatch):
    vault_factory({"note.md": "before"})
    storage = VaultStorage.from_config()
    revision = storage.revision("note.md").token
    plan = MutationPlan(
        operation="intent-window",
        writes=(PlannedWrite(storage.resolve_write("note.md"), revision, b"after"),),
    )
    original = storage.write_bytes_atomic
    calls = 0
    def crash_before(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("crash before write")
        return original(*args, **kwargs)

    monkeypatch.setattr(storage, "write_bytes_atomic", crash_before)
    with pytest.raises(OSError, match="crash before write"):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "note.md").read_text() == "before"


def test_crash_after_write_before_applied_journal_rolls_back(tmp_path, vault_factory, monkeypatch):
    vault_factory({"note.md": "before"})
    storage = VaultStorage.from_config()
    revision = storage.revision("note.md").token
    plan = MutationPlan(
        operation="applied-window",
        writes=(PlannedWrite(storage.resolve_write("note.md"), revision, b"after"),),
    )
    original = storage.write_bytes_atomic
    calls = 0
    def crash_after(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original(*args, **kwargs)
        if calls == 1:
            raise OSError("crash after write")
        return result

    monkeypatch.setattr(storage, "write_bytes_atomic", crash_after)
    with pytest.raises(OSError, match="crash after write"):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "note.md").read_text() == "before"


def test_crash_after_directory_move_before_applied_journal_rolls_back(tmp_path, vault_factory, monkeypatch):
    vault_factory({"Source/note.md": "before"})
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="move-window",
        moves=(
            PlannedMove(
                storage.resolve_delete("Source"),
                storage.resolve_write("Destination"),
                storage.tree_revision("Source"),
            ),
        ),
        inventory=inventory_for_paths(storage, ("Source",)),
    )
    original = storage.move
    calls = 0

    def crash_after(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original(*args, **kwargs)
        if calls == 1:
            raise OSError("crash after move")
        return result

    monkeypatch.setattr(storage, "move", crash_after)
    with pytest.raises(OSError, match="crash after move"):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "Source/note.md").read_text() == "before"
    assert not (tmp_path / "Destination").exists()


def test_orphan_transaction_directory_is_reported(tmp_path):
    orphan = tmp_path / "transactions" / "orphan-id"
    orphan.mkdir(parents=True)
    findings = TransactionJournal.scan(orphan.parent)
    assert findings == [{"operation_id": "orphan-id", "status": "orphan", "path": str(orphan)}]


def test_symlinked_transaction_journal_is_reported_corrupt(tmp_path):
    directory = tmp_path / "transactions" / "symlinked"
    directory.mkdir(parents=True)
    external = tmp_path / "external.json"
    external.write_text('{"status":"committed"}')
    journal = directory / "journal.json"
    journal.symlink_to(external)

    assert TransactionJournal.scan(directory.parent) == [
        {
            "operation_id": "symlinked",
            "status": "corrupt",
            "path": str(journal),
        }
    ]


def test_non_object_transaction_journal_is_reported_corrupt(tmp_path):
    directory = tmp_path / "transactions" / "bad"
    directory.mkdir(parents=True)
    (directory / "journal.json").write_text("[]")
    assert TransactionJournal.scan(directory.parent)[0]["status"] == "corrupt"


@pytest.mark.parametrize("operation_id", [".", ".."])
def test_transaction_ids_reject_traversal_names(tmp_path, operation_id):
    with pytest.raises(ValueError, match="invalid transaction ID"):
        TransactionJournal(tmp_path / "transactions", operation_id)


def test_recovery_locks_applied_collision_destination_and_reports_missing_trash(
    tmp_path, vault_factory, monkeypatch
):
    vault_factory({})
    root = tmp_path.parent / "transactions"
    directory = root / "op"
    directory.mkdir(parents=True)
    state = {
        "operation_id": "op",
        "status": "committing",
        "plan": {
            "writes": [], "inventory": [], "scan_revisions": [], "deletes": [],
            "moves": [{"from": "Folder", "to": ".trash/Folder"}], "metadata": [],
        },
        "steps": [{
            "step": "applied", "action": "move", "source": "Folder",
            "destination": ".trash/Folder-collision", "trash": True,
            "post_tree_revision": "trash:missing",
        }],
        "snapshots": [],
    }
    (directory / "journal.json").write_text(json.dumps(state))
    locked: list[str] = []

    class FakeLock:
        def release(self):
            pass

    def record_lock(path, **_kwargs):
        locked.append(path)
        return FakeLock()

    monkeypatch.setattr(mutations_module, "acquire_lock", record_lock)
    result = recover_transaction(VaultStorage.from_config(), root, "op")
    assert ".trash/Folder-collision" in locked
    assert result["status"] == "recovery_required"
    assert "trash post-state is missing" in result["error"]


def test_delete_rollback_recreates_absent_file(tmp_path, vault_factory, monkeypatch):
    vault_factory({"a.md": "one", "b.md": "two"})
    _enable(monkeypatch, ALLOW_PERMANENT_DELETE=True)
    storage = VaultStorage.from_config()
    plan = MutationPlan(
        operation="two-deletes",
        deletes=(
            PlannedDelete(storage.resolve_delete("a.md", permanent=True), storage.revision("a.md").token),
            PlannedDelete(storage.resolve_delete("b.md", permanent=True), storage.revision("b.md").token),
        ),
    )
    original_delete = storage.delete
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected delete failure")
        return original_delete(*args, **kwargs)

    monkeypatch.setattr(storage, "delete", fail_second)
    with pytest.raises(OSError, match="delete failure"):
        MutationExecutor(storage).execute(plan)
    assert (tmp_path / "a.md").read_text() == "one"
    assert (tmp_path / "b.md").read_text() == "two"


def test_directory_inventory_counts_against_file_limit_before_mutation(tmp_path, vault_factory, monkeypatch):
    vault_factory({"Folder/a.md": "one", "Folder/b.md": "two"})
    _enable(monkeypatch, MUTATION_MAX_FILES=1)
    with pytest.raises(MutationLimitError):
        rename_folder("Folder", "Moved")
    assert (tmp_path / "Folder/a.md").exists()
    assert not (tmp_path / "Moved").exists()
