"""Semantic vault operations used by the multi-file mutation layer.

The semantic backend deliberately knows about Markdown links, but it does not
perform I/O or make authorization decisions.  That separation lets a future
Obsidian-CLI backend produce the same :class:`MutationPlan` without widening
the filesystem capability of the MCP process.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..storage.filesystem import VaultStorage
from ..storage.policy import ReadPermissionError, VaultPath, VaultPathError
from .index import VaultIndex
from .models import FileRevision
from .parser import parse_note


class SemanticAmbiguityError(ValueError):
    """A link target cannot be rewritten deterministically."""


@dataclass(frozen=True)
class SemanticFile:
    path: VaultPath
    content: bytes
    revision: FileRevision

    @property
    def note(self):
        return parse_note(self.content.decode("utf-8", "replace"), path=self.path.relative)


class VaultSemantics(Protocol):
    def backlinks(self, path: str) -> list[str]: ...

    def plan_move(self, source: str, destination: str): ...


# Obsidian links are intentionally handled with a small scanner rather than a
# broad substitution: frontmatter and fenced code are not prose links, and the
# optional embed marker must survive unchanged.
_LINK_RE = re.compile(r"(?P<embed>!?)\[\[(?P<target>[^\]|#^]+)(?P<suffix>(?:[#^][^\]|]*(?:\|[^\]]*)?|\|[^\]]*)?)\]\]")
_FRONTMATTER_RE = re.compile(r"\A---\r?\n.*?\r?\n---\r?\n?", re.DOTALL)


def _fence_ranges(raw: str) -> list[tuple[int, int]]:
    """Return Markdown backtick/tilde fence ranges, including unclosed ones."""
    ranges: list[tuple[int, int]] = []
    opening: tuple[int, str, int] | None = None
    offset = 0
    for line in raw.splitlines(keepends=True):
        if opening is None:
            match = re.match(r"^[ \t]*(?P<fence>`{3,}|~{3,})[^\n]*(?:\n|$)", line)
            if match:
                marker = match.group("fence")
                opening = (offset, marker[0], len(marker))
        else:
            close = re.match(r"^[ \t]*(?P<fence>`+|~+)[ \t]*(?:\r?\n)?$", line)
            if close and close.group("fence")[0] == opening[1] and len(close.group("fence")) >= opening[2]:
                ranges.append((opening[0], offset + len(line)))
                opening = None
        offset += len(line)
    if opening is not None:
        ranges.append((opening[0], len(raw)))
    return ranges


def _code_span_ranges(raw: str) -> list[tuple[int, int]]:
    """Return inline code spans paired by equal-length backtick runs."""
    ranges: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(raw):
        start = raw.find("`", cursor)
        if start < 0:
            break
        opener_end = start
        while opener_end < len(raw) and raw[opener_end] == "`":
            opener_end += 1
        width = opener_end - start
        search = opener_end
        closing_end = None
        while search < len(raw):
            closing = raw.find("`", search)
            if closing < 0:
                break
            run_end = closing
            while run_end < len(raw) and raw[run_end] == "`":
                run_end += 1
            if run_end - closing == width:
                closing_end = run_end
                break
            search = run_end
        if closing_end is None:
            cursor = opener_end
            continue
        ranges.append((start, closing_end))
        cursor = closing_end
    return ranges


def _replace_prose(raw: str, transform, *, pattern: re.Pattern[str] = _LINK_RE) -> str:
    """Apply ``transform`` to wikilinks outside frontmatter and code fences."""
    protected: list[tuple[int, int, str]] = []
    for match in _FRONTMATTER_RE.finditer(raw):
        protected.append((match.start(), match.end(), match.group(0)))
    for start, end in _fence_ranges(raw):
        protected.append((start, end, raw[start:end]))
    for start, end in _code_span_ranges(raw):
        protected.append((start, end, raw[start:end]))
    protected.sort()
    chunks: list[str] = []
    cursor = 0
    for start, end, value in protected:
        if start < cursor:
            continue
        chunks.append(pattern.sub(transform, raw[cursor:start]))
        chunks.append(value)
        cursor = end
    chunks.append(pattern.sub(transform, raw[cursor:]))
    return "".join(chunks)


def _no_extension(path: str) -> str:
    return path[:-3] if path.lower().endswith(".md") else path


class ParserVaultSemantics:
    """Parser/index-backed semantic planner.

    It only scans paths readable through the configured policy.  Every file it
    proposes to rewrite is subsequently authorized again by the transaction
    executor before any mutation occurs.
    """

    def __init__(self, storage: VaultStorage, index: VaultIndex | None = None) -> None:
        self.storage = storage
        self.index = index

    def backlinks(self, path: str) -> list[str]:
        if self.index is not None:
            return self.index.get_backlinks(path)
        target = _no_extension(path).lower()
        result: list[str] = []
        for candidate in self.storage.list_files():
            if not candidate.relative.lower().endswith(".md"):
                continue
            raw = self.storage.read_text(candidate.relative)
            if any(match.group("target").strip().lower() in {target, Path(target).stem} for match in _LINK_RE.finditer(raw)):
                result.append(candidate.relative)
        return sorted(result)

    def _readable_notes(self) -> list[SemanticFile]:
        notes: list[SemanticFile] = []
        for candidate in self.storage.list_files():
            if candidate.relative.lower().endswith(".md"):
                content, revision = self.storage.read_bytes_with_revision(candidate.relative)
                notes.append(SemanticFile(candidate, content, revision))
        return notes

    def _link_candidates(self, target: str, records: list[SemanticFile] | None = None) -> list[SemanticFile]:
        """Resolve a stem/path/alias using parsed note metadata.

        The index intentionally keeps a single alias winner for query speed;
        mutation planning must be stricter and reject every duplicate alias or
        stem rather than inheriting that lossy behavior.
        """
        target_norm = _no_extension(target.strip().replace("\\", "/")).casefold()
        records = records if records is not None else self._readable_notes()
        candidates: list[SemanticFile] = []
        for note in records:
            canonical = _no_extension(note.path.relative).casefold()
            stem = Path(canonical).name
            aliases = {str(alias).strip().casefold() for alias in note.note.aliases}
            if target_norm in {canonical, stem, *aliases}:
                candidates.append(note)
        return candidates

    def _assert_complete_scan(self) -> None:
        """Fail closed when a move could hide a backlink we cannot inspect."""
        from ..config import get_config

        excluded = get_config().exclude_paths
        for relative in self.storage._tree_paths(self.storage.policy.canonicalize("")):
            # Trash is intentionally outside the live semantic graph.  It is
            # denied by the read policy and must not make every live rename
            # fail merely because an old trashed note exists.
            if relative == ".trash" or relative.startswith(".trash/"):
                continue
            if relative.lower().endswith(".md"):
                try:
                    self.storage.policy.resolve_read(relative)
                    if any(relative == rule or relative.startswith(rule.rstrip("/") + "/") for rule in excluded):
                        raise ReadPermissionError("multi-file mutation cannot inspect an excluded Markdown file")
                except (ReadPermissionError, VaultPathError) as exc:
                    raise ReadPermissionError(
                        "multi-file mutation cannot inspect a protected or excluded Markdown file"
                    ) from exc

    def _resolve_link_target(
        self,
        target: str,
        source: str,
        source_path: str,
        destination_path: str,
        *,
        records: list[SemanticFile] | None = None,
    ) -> str | None:
        source_noext = _no_extension(source).replace("\\", "/")
        destination_noext = _no_extension(destination_path).replace("\\", "/")
        target_norm = target.strip().replace("\\", "/")
        target_noext = _no_extension(target_norm)
        source_stem = Path(source_noext).name
        destination_stem = Path(destination_noext).name

        # Resolve relative path links from the linking note's directory.
        resolved_target = target_noext
        if target_noext.startswith("./") or target_noext.startswith("../"):
            source_dir = posixpath.dirname(source_path.replace("\\", "/"))
            resolved_target = posixpath.normpath(posixpath.join(source_dir, target_noext))
        candidates = self._link_candidates(resolved_target, records)
        source_matches = [note for note in candidates if note.path.relative.casefold() == source.casefold()]
        if len(candidates) > 1 and source_matches:
            raise SemanticAmbiguityError(
                f"Link target [[{target}]] is ambiguous ({len(candidates)} matching notes)"
            )
        if target_noext.casefold() == source_stem.casefold() and not source_matches:
            raise SemanticAmbiguityError(f"Link target [[{target}]] cannot be resolved to the moved note")

        # A path-qualified link is unambiguous and should retain the extension
        # convention used by the caller (Obsidian normally omits .md).
        if source_matches and ("/" in target_noext or target_norm.lower().endswith(".md") or target_noext.startswith(("./", "../"))):
            replacement = destination_noext
            if target_noext.startswith(("./", "../")):
                linking_path = (
                    destination_path
                    if source_path.casefold() == source.casefold()
                    else source_path
                )
                replacement = posixpath.relpath(
                    destination_noext, posixpath.dirname(linking_path) or "."
                )
                if not replacement.startswith("."):
                    replacement = "./" + replacement
            return replacement if not target_norm.lower().endswith(".md") else replacement + ".md"
        if "/" in target_noext or target_noext.startswith(("./", "../")):
            return None

        # Stem-only links are only rewritten if the source stem itself is
        # changing.  A folder move that keeps the stem leaves [[Note]] valid.
        if target_noext.casefold() != source_stem.casefold() or source_stem.casefold() == destination_stem.casefold():
            return None
        matches = [note for note in candidates if Path(_no_extension(note.path.relative)).stem.casefold() == source_stem.casefold()]
        # An alias referring to the moved note remains valid.  However, any
        # duplicate alias/stem candidate is unsafe and must abort the plan.
        if len(candidates) > 1:
            raise SemanticAmbiguityError(
                f"Stem/alias link [[{source_stem}]] is ambiguous ({len(candidates)} matching notes)"
            )
        if not source_matches:
            return None
        if not matches:
            # This was an alias to the source, so it remains valid after move.
            return None
        return destination_stem

    def rewrite_links(
        self,
        raw: str,
        source: str,
        destination: str,
        *,
        note_path: str = "",
        records: list[SemanticFile] | None = None,
    ) -> tuple[str, bool]:
        changed = False

        def transform(match: re.Match[str]) -> str:
            nonlocal changed
            target = match.group("target").strip()
            replacement = self._resolve_link_target(target, source, note_path, destination, records=records)
            if replacement is None:
                return match.group(0)
            changed = True
            return f"{match.group('embed')}[[{replacement}{match.group('suffix')}]]"

        return _replace_prose(raw, transform), changed

    def plan_move(self, source: str, destination: str):
        # Imported lazily to avoid a domain -> storage -> domain import cycle.
        from ..storage.mutations import (
            IndexChange,
            MutationPlan,
            PlannedMove,
            PlannedWrite,
            inventory_for_paths,
        )

        source_target = self.storage.resolve_delete(source)
        destination_target = self.storage.resolve_write(destination)
        source = source_target.relative
        destination = destination_target.relative
        if source == destination:
            raise ValueError("Source and destination must differ")
        if not self.storage.exists(source, read=False):
            raise FileNotFoundError(f"Source note not found: {source!r}")
        if self.storage.exists(destination, read=False):
            raise FileExistsError(f"Target already exists: {destination!r}")
        if not source.lower().endswith(".md") or not destination.lower().endswith(".md"):
            raise ValueError("Note paths must end in .md")

        from ..config import get_config

        if get_config().enable_move:
            self._assert_complete_scan()

        notes = self._readable_notes()
        source_note = next((note for note in notes if note.path.relative == source), None)
        if source_note is None:
            raise ReadPermissionError("multi-file mutation cannot inspect the source note")
        source_revision = source_note.revision
        writes: list[PlannedWrite] = []
        for note in notes:
            rewritten, changed = self.rewrite_links(
                note.content.decode("utf-8", "replace"),
                source,
                destination,
                note_path=note.path.relative,
                records=notes,
            )
            if changed:
                writes.append(
                    PlannedWrite(
                        path=note.path,
                        original_revision=note.revision.token,
                        content=rewritten.encode("utf-8"),
                    )
                )
        return MutationPlan(
            operation="move_note",
            writes=tuple(writes),
            moves=(PlannedMove(source=source_target, destination=destination_target, original_revision=source_revision.token),),
            deletes=(),
            index_changes=(
                IndexChange("remove", source),
                IndexChange("update", destination),
                *(IndexChange("update", item.path.relative) for item in writes if item.path.relative != source),
            ),
            inventory=inventory_for_paths(self.storage, (source,)),
            metadata=(("semantic_version", "parser-v1"),),
            scan_revisions=tuple((note.path.relative, note.revision.token) for note in notes),
            scan_roots=("",),
        )

    def plan_folder_rename(self, source: str, destination: str):
        from ..storage.mutations import (
            IndexChange,
            MutationPlan,
            PlannedMove,
            PlannedWrite,
            inventory_for_paths,
        )

        source_target = self.storage.resolve_delete(source)
        destination_target = self.storage.resolve_write(destination)
        source = source_target.relative.rstrip("/")
        destination = destination_target.relative.rstrip("/")
        if source == destination or destination.startswith(source + "/"):
            raise ValueError("Destination cannot be inside the source folder")
        if not self.storage.exists(source, read=False):
            raise FileNotFoundError(f"Folder not found: {source!r}")
        import stat

        if not stat.S_ISDIR(self.storage.stat(source, read=False).st_mode):
            raise ValueError(f"Not a folder: {source!r}")
        if self.storage.exists(destination, read=False):
            raise FileExistsError(f"Target already exists: {destination!r}")
        from ..config import get_config

        if get_config().enable_folder_rename:
            self._assert_complete_scan()
        descendants = self.storage._tree_paths(source_target)
        notes = self._readable_notes()
        writes: list[PlannedWrite] = []
        prefix = source + "/"
        for note in notes:
            raw = note.content.decode("utf-8", "replace")
            note_path = note.path.relative
            changed = False

            def replace_folder(match: re.Match[str], note_path: str = note_path) -> str:
                nonlocal changed
                target = match.group("target").strip().replace("\\", "/")
                resolved = target
                if target.startswith(("./", "../")):
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(note_path), target))
                # A bare [[Old]] resolves to Old.md when that note exists.  A
                # folder rename must never silently retarget it to Old/foo;
                # unresolved bare folder names are left untouched as well.
                if "/" not in resolved and resolved.casefold() == Path(source).name.casefold():
                    candidates = self._link_candidates(resolved, notes)
                    if len(candidates) > 1:
                        raise SemanticAmbiguityError(
                            f"Bare folder link [[{target}]] is ambiguous ({len(candidates)} matching notes)"
                        )
                    return match.group(0)
                if not (resolved.casefold() == source.casefold() or resolved.casefold().startswith(prefix.casefold())):
                    return match.group(0)
                suffix = resolved[len(prefix):] if resolved.casefold().startswith(prefix.casefold()) else ""
                mapped = f"{destination}/{suffix}" if suffix else destination
                if target.startswith(("./", "../")):
                    mapped_note_path = note_path
                    if note_path == source or note_path.startswith(prefix):
                        note_suffix = note_path[len(prefix):] if note_path.startswith(prefix) else ""
                        mapped_note_path = f"{destination}/{note_suffix}" if note_suffix else destination
                    mapped = posixpath.relpath(mapped, posixpath.dirname(mapped_note_path) or ".")
                    if not mapped.startswith("."):
                        mapped = "./" + mapped
                changed = True
                if target.lower().endswith(".md"):
                    mapped += ".md" if not mapped.lower().endswith(".md") else ""
                return f"{match.group('embed')}[[{mapped}{match.group('suffix')}]]"

            rewritten = _replace_prose(raw, replace_folder)
            if changed:
                writes.append(PlannedWrite(note.path, note.revision.token, rewritten.encode("utf-8")))
        # The directory move itself is authorized recursively by the executor.
        moved_notes = [path for path in descendants if path.lower().endswith(".md")]
        return MutationPlan(
            operation="rename_folder",
            writes=tuple(writes),
            moves=(PlannedMove(source_target, destination_target, self.storage.tree_revision(source)),),
            deletes=(),
            index_changes=tuple(
                [*(IndexChange("remove", p) for p in moved_notes),
                 *(IndexChange("update", f"{destination}/{p[len(prefix):]}") for p in moved_notes),
                 *(IndexChange("update", w.path.relative) for w in writes if not w.path.relative.startswith(prefix))]
            ),
            inventory=inventory_for_paths(self.storage, (source,)),
            metadata=(("semantic_version", "parser-v1"),),
            scan_revisions=tuple((note.path.relative, note.revision.token) for note in notes),
            scan_roots=("",),
        )
