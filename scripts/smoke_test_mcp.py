#!/usr/bin/env python3
"""End-to-end smoke test for a running obsidian-mcp HTTP server."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastmcp import Client


def _structured(result: Any) -> Any:
    if result.is_error:
        text = "\n".join(getattr(item, "text", repr(item)) for item in result.content)
        raise RuntimeError(text)
    if result.data is not None:
        return result.data
    if result.structured_content is not None:
        value = result.structured_content.get("result", result.structured_content)
        return value
    if len(result.content) == 1 and hasattr(result.content[0], "text"):
        return json.loads(result.content[0].text)
    raise RuntimeError(f"Unexpected MCP response: {result!r}")


async def run(args: argparse.Namespace) -> None:
    async with Client(args.url, auth=args.api_key) as client:
        tools = {tool.name for tool in await client.list_tools()}
        required = {"list_notes_tool", "read_note_tool", "write_note_tool"}
        missing = required - tools
        if missing:
            raise RuntimeError(f"Missing required tools: {sorted(missing)}")

        created = _structured(
            await client.call_tool(
                "write_note_tool",
                {
                    "path": args.note,
                    "content": "# MCP smoke test\n\ncreated over real HTTP\n",
                    "create_only": True,
                },
            )
        )
        first_read = _structured(
            await client.call_tool("read_note_tool", {"path": args.note})
        )
        revision = first_read.get("revision")
        if not revision:
            raise RuntimeError(f"Read response has no revision: {first_read!r}")

        updated = _structured(
            await client.call_tool(
                "write_note_tool",
                {
                    "path": args.note,
                    "content": "# MCP smoke test\n\nupdated with revision precondition\n",
                    "expected_revision": revision,
                },
            )
        )
        final_read = _structured(
            await client.call_tool("read_note_tool", {"path": args.note})
        )
        if "updated with revision precondition" not in final_read.get("content", ""):
            raise RuntimeError("Updated content was not returned by read_note_tool")

        denied_result = await client.call_tool(
            "write_note_tool",
            {
                "path": args.denied_note,
                "content": "this must not be written\n",
                "create_only": True,
            },
            raise_on_error=False,
        )
        denied_text = "\n".join(
            getattr(item, "text", repr(item)) for item in denied_result.content
        )
        if not denied_result.is_error or "denied" not in denied_text.lower():
            raise RuntimeError(f"Expected a denied write, got: {denied_result!r}")

        if args.vault_path:
            disk_path = args.vault_path / args.note
            disk_content = disk_path.read_text(encoding="utf-8").rstrip("\n")
            returned_content = final_read["content"].rstrip("\n")
            if disk_content != returned_content:
                raise RuntimeError(f"On-disk content differs at {disk_path}")
            if (args.vault_path / args.denied_note).exists():
                raise RuntimeError("Denied note was unexpectedly created on disk")

        print(
            json.dumps(
                {
                    "status": "ok",
                    "tools_advertised": len(tools),
                    "created_revision": created.get("revision"),
                    "updated_revision": updated.get("revision"),
                    "denied_write": "access_denied",
                    "note": args.note,
                },
                indent=2,
                sort_keys=True,
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000/mcp")
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--note")
    parser.add_argument("--denied-note", default="outside-write-scope.md")
    parser.add_argument("--vault-path", type=Path)
    args = parser.parse_args()
    args.note = args.note or f"AI-Memory/mcp-smoke-test-{uuid4().hex}.md"
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
