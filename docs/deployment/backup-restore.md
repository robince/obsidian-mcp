# Vault backup and restore drill

Do this before enabling automated writes, and repeat after changing the sync
topology. Obsidian Sync history is a recovery layer, not the only backup.

1. Stop MCP writes (`READ_ONLY=true` or stop the Compose stack) and record the
   current sync status.
2. Create a host filesystem snapshot or versioned backup of the complete vault,
   including `.obsidian` and attachments. Keep the backup outside the sync
   directory and retain enough history to cover delayed discovery of an AI
   mistake.
3. Verify the backup contains one known note, one AI-Memory event, one
   AI-Output draft and an attachment. Record their SHA-256 values.
4. In a disposable restore directory, restore the snapshot and start a test
   MCP instance with `VAULT_PATH` pointing only at that directory. Confirm
   reads return the recorded revisions and that the nested writable paths are
   the only writable paths.
5. Delete or modify a disposable restored note, then restore the individual
   file from the backup. Finally restore the complete disposable vault and
   verify the known hashes again.
6. Restart the test MCP and Headless Sync containers. Confirm the operation
   ledger under `/data` survives restart and that a retry with the same append
   operation ID does not duplicate an event.
7. Record the date, snapshot identifier, restore result and operator. Do not
   declare production writes enabled until the individual-file and full-vault
   restore both succeed.

Monitor free space, pending watcher events and conflict records. Keep
`/data/conflicts` and `/data/operations.sqlite3` in the host backup set; they
are outside the vault and are needed to investigate failed or retried writes.
