# Phase 2 implementation notes

Status: implemented on `codex/phase-2-multifile-mutations`, stacked on the
Phase 1 authorization and Phase 3 concurrency commits.

## Delivered

- Added immutable `MutationPlan`, `PlannedWrite`, `PlannedMove`,
  `PlannedDelete`, and `IndexChange` types.  A plan digest covers the
  operation, canonical paths, original revisions, proposed-content hashes,
  semantic backend version, bulk-operation arguments, and the complete
  regular-file inventory of moved/deleted/restored directory trees.
- Added the parser/index-backed `VaultSemantics` backend.  Move and folder
  rename planning handles path-qualified links, stem links, aliases, heading
  and block suffixes, embeds, duplicate-stem ambiguity, and ignores YAML
  frontmatter and fenced code blocks.  A folder rename never retargets a bare
  `[[Folder]]` link (it is retained when it resolves to `Folder.md`, and
  ambiguous candidates fail closed); only descendant path links are remapped.
- Replaced move, folder rename, and bulk replacement commit paths with a
  complete read-only plan, authorization preflight, SHA-256 precondition
  validation, stable lock acquisition, external staging, fsynced recovery
  copies, journaled commit steps, conservative rollback, and post-commit
  index publication. Folder-renamed notes are written at their mapped
  destination only after the directory tree CAS succeeds, avoiding internal
  writes that would invalidate the source tree revision.
- Enabled mutation plans to reject a stale source, changed backlink, newly
  occupied destination, protected rewrite, or inaccessible/excluded Markdown
  candidate before the first vault mutation.  Semantic plans include an
  immutable revision for every scanned Markdown note, and execute under a
  stable external semantic-graph lock.  Ordinary note writers acquire that
  lock before their path lock, so cooperating scans and read/modify/write
  operations cannot cross each other.  File moves perform a final
  source/tree-revision check and no-replace destination check under the lock.
- Dry-run bulk replacement now returns a bounded preview, per-file revision,
  and plan digest.  Enabled remote bulk/move/folder-rename registrations
  require the approved digest.  Regex bulk replacement is rejected for
  enabled remote operations because the stdlib engine has no timeout.
- Added bounded mutation limits (`MUTATION_MAX_FILES`,
  `MUTATION_MAX_BYTES`, `MUTATION_MAX_REPLACEMENTS`, and
  `MUTATION_LOCK_TIMEOUT`) and an external `TRANSACTION_PATH`.
- Added startup and runtime incomplete-journal detection, degraded `/health` readiness,
  and the operator-only `scripts/manage_transactions.py list|recover` command.
  Journals durably record an `intent` before each mutation and an `applied`
  step with the exact post-state after it, including collision-selected trash
  names. Recovery acquires the same stable locks, classifies crash windows
  conservatively, uses exact tree/file CAS and no-replace restoration, and
  refuses to overwrite a changed post-state. Transaction directories with a
  missing/corrupt journal are degraded as orphaned evidence. Every newly
  created parent and `.trash` directory is fsynced before use. Live file moves
  use atomic no-replace primitives (or a hard-link fallback); directory moves
  fail closed when the host has no no-replace primitive.

## Verification

The existing suite plus Phase 2 coverage remains green (`503 passed`), with Ruff and
`git diff --check` required before hand-off.  Manual checks cover approved
move and bulk plans, stale-plan rejection, heading/block/embed preservation,
and folder path-link rewrites.

## Explicit residuals

1. Permanent folder deletion remains deliberately rejected: a fully
   transactional recursive purge and recovery format is not yet provided.
2. No ordinary filesystem transaction can make a rename atomic with a
   non-cooperating Headless Sync writer.  Phase 3 revisions narrow the race;
   backups and the sync provider's conflict history remain required.
3. Recovery copies are retained under `TRANSACTION_PATH`; an operator should
   apply a retention/backup policy rather than deleting them immediately.
4. A failed move/restore may leave an empty auto-created parent directory;
   this is harmless but is not currently garbage-collected.
5. `MUTATION_MAX_BYTES` bounds logical proposed content. Stage and recovery
   copies are external overhead, so transient transaction disk use can be
   roughly twice the logical payload (plus filesystem metadata).
6. The parser backend rewrites Obsidian wikilinks only. Markdown links,
   Dataview-generated links, and plugin-specific reference syntaxes are not
   inferred or rewritten; a future semantic backend must either support them
   explicitly or reject the plan when they are in scope.
7. A non-cooperating sync process can still win the unavoidable final
   filesystem race after validation; revision checks, no-replace operations,
   and recovery-required evidence prevent silent overwrite but cannot provide
   cross-process atomicity.
