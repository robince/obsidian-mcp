#!/usr/bin/env python3
"""Inspect and conservatively recover Phase 2 mutation journals.

Usage: ``python scripts/manage_transactions.py list``
and ``... recover <transaction-id>``.  IDs are opaque journal directory names;
the command never accepts a path supplied by a remote MCP caller.
"""

from __future__ import annotations

import argparse
import json

from obsidian_mcp.config import get_config
from obsidian_mcp.storage.filesystem import VaultStorage
from obsidian_mcp.storage.mutations import incomplete_transactions, recover_transaction


def main() -> int:
    parser = argparse.ArgumentParser(description="inspect/recover mutation transactions")
    parser.add_argument("command", choices=("list", "recover"))
    parser.add_argument("transaction_id", nargs="?")
    args = parser.parse_args()
    cfg = get_config()
    if args.command == "list":
        print(json.dumps(incomplete_transactions(cfg.transaction_path), indent=2, sort_keys=True))
        return 0
    if not args.transaction_id:
        parser.error("recover requires transaction_id")
    if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in args.transaction_id):
        parser.error("invalid transaction_id")
    result = recover_transaction(VaultStorage.from_config(cfg), cfg.transaction_path, args.transaction_id)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "rolled_back" else 2


if __name__ == "__main__":
    raise SystemExit(main())
