#!/usr/bin/env python3
"""List or discard MCP conflict records outside the vault.

Examples:
  VAULT_PATH=/srv/vault CONFLICT_PATH=/data/conflicts python scripts/manage_conflicts.py list
  ... discard <id>
"""

from __future__ import annotations

import argparse
import json

from obsidian_mcp.storage.conflicts import discard_conflict, list_conflicts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list conflict metadata")
    discard = sub.add_parser("discard", help="discard one conflict record")
    discard.add_argument("id")
    args = parser.parse_args()
    result = list_conflicts() if args.command == "list" else discard_conflict(args.id)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
