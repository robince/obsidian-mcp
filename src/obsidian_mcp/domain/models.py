from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FileRevision:
    """Content revision returned by reads and accepted by conditional writes.

    ``sha256`` is the authoritative value.  Size and mtime are diagnostics and
    fast change hints only; callers must never use them as an authorization
    decision.  The compact string form is deliberately an HTTP-ETag-friendly
    value while the mapping form is convenient for MCP JSON responses.
    """

    sha256: str
    size: int
    mtime_ns: int

    @property
    def etag(self) -> str:
        return f'"sha256:{self.sha256}"'

    @property
    def token(self) -> str:
        return f"sha256:{self.sha256}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sha256": self.sha256,
            "size": self.size,
            "mtime_ns": self.mtime_ns,
        }

    @classmethod
    def from_value(cls, value: FileRevision | str | dict[str, Any]) -> FileRevision:
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            digest = value.strip().strip('"').removeprefix("sha256:").lower()
            if len(digest) != 64:
                raise ValueError("expected_revision must be a sha256 revision")
            int(digest, 16)
            return cls(sha256=digest, size=-1, mtime_ns=-1)
        if isinstance(value, dict) and isinstance(value.get("sha256"), str):
            digest = value["sha256"].strip().strip('"').removeprefix("sha256:").lower()
            if len(digest) != 64:
                raise ValueError("expected_revision must be a sha256 revision")
            int(digest, 16)
            return cls(
                sha256=digest,
                size=int(value.get("size", -1)),
                mtime_ns=int(value.get("mtime_ns", -1)),
            )
        raise ValueError("expected_revision must be a sha256 string or revision object")

    @classmethod
    def from_bytes(cls, content: bytes, *, size: int, mtime_ns: int) -> FileRevision:
        return cls(hashlib.sha256(content).hexdigest(), size, mtime_ns)


class RevisionConflictError(RuntimeError):
    """A conditional mutation observed a different current file revision."""

    def __init__(
        self,
        path: str,
        expected: FileRevision | str | dict[str, Any] | None,
        actual: FileRevision | None,
    ) -> None:
        self.path = path
        self.expected = FileRevision.from_value(expected).token if expected is not None else None
        self.actual = actual
        super().__init__(f"Revision conflict for {path!r}")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "error": "revision_conflict",
            "path": self.path,
            "expected": self.expected,
            "actual": self.actual.token if self.actual else None,
            "current_mtime_ns": self.actual.mtime_ns if self.actual else None,
        }
        conflict_id = getattr(self, "conflict_id", None)
        if conflict_id:
            result["conflict_id"] = conflict_id
        return result


@dataclass
class WikiLink:
    target: str
    alias: str | None = None
    heading: str | None = None


@dataclass
class BlockRef:
    block_id: str
    line: int
    text: str


@dataclass
class Callout:
    type: str   # NOTE | WARNING | TIP | IMPORTANT | QUESTION | ...
    title: str
    body: str


@dataclass
class Task:
    text: str
    done: bool
    line: int
    due: str | None = None          # 📅 YYYY-MM-DD
    recurrence: str | None = None   # 🔁 freeform, e.g. "every week"
    priority: str | None = None     # ⏫ high | 🔼 medium | 🔽 low
    done_date: str | None = None    # ✅ YYYY-MM-DD


@dataclass
class Note:
    path: str
    frontmatter: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    wikilinks: list[WikiLink] = field(default_factory=list)
    block_refs: list[BlockRef] = field(default_factory=list)
    block_links: list[str] = field(default_factory=list)
    callouts: list[Callout] = field(default_factory=list)
    tasks: list[Task] = field(default_factory=list)
    inline_fields: dict[str, str] = field(default_factory=dict)
    content: str = ""
    mtime: float = 0.0
