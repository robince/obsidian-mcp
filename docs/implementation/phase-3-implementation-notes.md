# Phase 3 implementation notes

Status: implemented on `codex/phase-3-sync-concurrency`, stacked on the Phase 1
authorization commit.

## Delivered

- Added `FileRevision` (`sha256`, byte size, nanosecond mtime) and a canonical
  `sha256:<digest>` token/strong HTTP ETag representation.
- Added descriptor-relative revision calculation and staged conditional atomic
  writes. Existing-file writes can require `expected_revision`; `create_only`
  rejects an existing destination. The destination is re-hashed immediately
  before replacement, directory entries are fsynced, and stale writes raise a
  structured `revision_conflict` without changing the current file.
- Propagated revisions through note, attachment, Canvas, Bases, Excalidraw and
  Kanban reads and writes, plus templates. High-impact multi-file operations
  remain independently feature-gated and are not made transactional here.
- Added `REQUIRE_WRITE_PRECONDITIONS`, `ALLOW_BLIND_CREATE`,
  `ALLOW_BLIND_OVERWRITE`, operation retention, metadata-only conflict records
  (proposed bytes require explicit `STORE_CONFLICT_CONTENT=true`), watcher
  debounce and reconciliation settings.
- Added HTTP attachment `ETag`, `If-Match`, `If-None-Match: *`, 412 conflict and
  428 precondition-required behavior.
- Added an SQLite ledger outside the vault. Append operation IDs reserve a
  pending row before mutation, validate tool/path/digest reuse, return
  completed retries, and recover a crash-after-replacement only when the
  proposed result revision is present. If the initial revision is still
  present a retry is safe; any other state returns
  `operation_outcome_unknown` without mutation. Ledger rows contain metadata
  and result revisions, never note content. The composite
  `(principal_id, operation_id)` key prevents one authenticated principal from
  replaying another principal's operation, and unavailable/corrupt/locked
  ledgers fail closed. Reservations use a single immediate transaction plus
  conflict-safe insert, so concurrent processes converge on one pending row.
- Added a safe operator command for listing and discarding conflict records:
  `python scripts/manage_conflicts.py list|discard <id>`. Conflict IDs are
  opaque SHA-256 directory keys, created with no-follow descriptors and
  restrictive permissions; traversal and symlinked records are rejected.
- Made single-file note restore a no-replace hard-link commit from `.trash`,
  with an optional source revision precondition, exact final verification and
  directory fsyncs. Folder restore remains behind the default-off
  `ENABLE_FOLDER_RESTORE` gate pending Phase 2 multi-file transactions.
- Made every listed read-modify-write path parse the exact bytes returned with
  its revision and use that revision as an implicit CAS when the caller did
  not provide one. Full replacement writes retain the configured blind-write
  behavior.
- Added strict HTTP entity-tag parsing for quoted strong/weak lists and
  wildcards. Conditional PUTs read one exact revision and carry its token as
  the final CAS/create-only intent; ambiguous or malformed conditions are
  rejected.
- Reworked watcher startup to capture/debounce events while the initial index
  snapshot runs, keep the index unpublished through synchronous replay, force
  reconciliation on capture overflow, and publish the index before watcher
  readiness. Index entries retain revisions and skip duplicate events. Health
  exposes readiness, queue, event/reconcile timestamps and capture overflow
  state.
- Added `/data` ledger/conflict/reconciliation configuration to both Compose
  examples. The home-server example still uses the full-vault read-only bind
  plus nested AI-Memory/AI-Output read-write overlays.

## Verification

The Phase 3 test module covers stable content revisions, metadata-only changes,
stale conditional writes, adversarial create/write races, two-writer optimistic
concurrency, read-modify-write race matrices, idempotent append and digest
reuse, crash-state recovery and unknown outcomes, composite-principal ledger
isolation/corruption, metadata-only conflict records and operator discard,
atomic restore/fsync behavior, HTTP entity-tag conditions, startup event replay
and dropped-event reconciliation. The existing suite and new tests pass:

```text
476 passed
ruff check src: clean
git diff --check: clean
```

## Explicit residuals

1. The final `rename(2)` has an unavoidable tiny race with a non-cooperating
   external writer; the implementation narrows the window and never claims a
   portable compare-and-swap guarantee. Filesystem/Obsidian history backups
   remain required.
2. Server-invoked append calls scope ledger operation IDs to FastMCP's verified
   client identity (with a session fallback); direct helper calls use the fixed
   internal principal `mcp`. The principal is never a caller-supplied tool
   argument. A future FastMCP upgrade should retain this context-injection
   contract and add a regression test for the authenticated identity mapping.
3. Pending-ledger recovery cannot prove which process performed a replacement.
   It returns `recovered` only when the current revision equals the recorded
   proposed result, retries only when the recorded initial revision is still
   present, and otherwise returns `operation_outcome_unknown` without writing.
   This is safe but less informative than a transaction journal.
4. Watcher capture is bounded by `WATCHER_MAX_PENDING_EVENTS`; overflow is
   surfaced in health and periodic reconciliation remains the correctness
   backstop. A deployment should alert on `capture_overflow=true`.
5. Folder restore, folder moves, backlink rewrites and bulk replacement retain
   Phase 2's feature gates and are not conditional multi-file transactions.
   Keep them disabled during continuous external sync.
6. End-to-end Linux Docker nested-bind and real Headless Sync acceptance was
   not run in this macOS worktree. Local fault-injection tests cover a sync
   writer racing create, append and stale conditional writes, but do not prove
   container mount or Obsidian behavior. Run the documented bind-mount and
   [backup/restore drill](../deployment/backup-restore.md), including a real
   restore, before enabling production writes.
