from __future__ import annotations

import pytest

import obsidian_mcp.config as cfg_mod
from obsidian_mcp.domain.semantics import ParserVaultSemantics, SemanticAmbiguityError
from obsidian_mcp.storage.filesystem import VaultStorage
from obsidian_mcp.storage.mutations import (
    MutationExecutor,
    MutationLimitError,
    MutationPlan,
    MutationPreconditionError,
    MutationRecoveryRequiredError,
    PlanApprovalRequiredError,
    PlannedMove,
    PlannedWrite,
    TransactionJournal,
    incomplete_transactions,
    inventory_for_paths,
)
from obsidian_mcp.storage.policy import WritePermissionError
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


def test_move_rejects_protected_backlink_before_mutating(tmp_path, vault_factory, monkeypatch):
    vault_factory({"Allowed/old.md": "body", "outside.md": "[[Allowed/old]]"})
    _enable(monkeypatch, ENABLE_MOVE=True, WRITE_PATHS="Allowed")
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


def test_enabled_bulk_requires_approved_plan_and_detects_stale_revision(vault_factory, monkeypatch):
    vault_factory({"a.md": "foo"})
    _enable(monkeypatch, ENABLE_BULK_REPLACE=True)
    dry = find_replace_in_vault("foo", "bar", dry_run=True)
    with pytest.raises(Exception, match="plan"):
        find_replace_in_vault("foo", "bar", dry_run=False)
    # The fixture's vault is available through the configured storage; change
    # it after planning to force the revision precondition to fail.
    VaultStorage.from_config().write_text_atomic("a.md", "changed")
    with pytest.raises(PlanApprovalRequiredError):
        find_replace_in_vault("foo", "bar", dry_run=False, approved_digest=dry["plan_digest"])


def test_remote_bulk_regex_is_always_rejected(vault_factory, monkeypatch):
    vault_factory({"a.md": "task-123"})
    _enable(monkeypatch, ENABLE_BULK_REPLACE=True, ALLOW_REGEX_MUTATIONS=True)
    with pytest.raises(ValueError, match="regex"):
        find_replace_in_vault(r"task-\d+", "TASK", mode="regex", dry_run=True)


def test_folder_rename_uses_transaction_and_updates_path_links(tmp_path, vault_factory):
    idx = vault_factory({"Old/note.md": "body", "index.md": "[[Old/note]]"})
    result = rename_folder("Old", "New", index=idx)
    assert result["status"] == "committed"
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
        MutationExecutor(storage).execute(plan)


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


def test_folder_trash_collision_is_recorded_as_actual_destination(tmp_path, vault_factory):
    vault_factory({"Temp/note.md": "content"})
    (tmp_path / ".trash").mkdir()
    (tmp_path / ".trash/Temp").mkdir()
    result = delete_folder("Temp")
    assert result["moved"][0]["to"].startswith(".trash/Temp-")


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


def test_directory_inventory_counts_against_file_limit_before_mutation(tmp_path, vault_factory, monkeypatch):
    vault_factory({"Folder/a.md": "one", "Folder/b.md": "two"})
    _enable(monkeypatch, MUTATION_MAX_FILES=1)
    with pytest.raises(MutationLimitError):
        rename_folder("Folder", "Moved")
    assert (tmp_path / "Folder/a.md").exists()
    assert not (tmp_path / "Moved").exists()
