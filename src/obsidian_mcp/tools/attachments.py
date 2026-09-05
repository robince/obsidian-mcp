from __future__ import annotations

import base64
import mimetypes
import stat
from pathlib import Path

from ..config import get_config
from ..storage.filesystem import VaultStorage
from ..storage.policy import InvalidFileTypeError, matches_path_rule

_TEXT_SUFFIXES = {".md", ".txt", ".csv", ".json", ".yaml", ".yml", ".toml", ".xml", ".html", ".css", ".js", ".ts"}
_ALLOWED_ATTACHMENT_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".tif", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".epub", ".docx", ".xlsx", ".pptx",
    ".odt", ".ods", ".odp", ".mp3", ".wav", ".m4a", ".ogg", ".flac", ".mp4", ".webm",
    ".mov", ".avi", ".woff", ".woff2", ".ttf", ".otf", ".csv", ".txt",
}


class AttachmentTooLargeError(ValueError):
    """An attachment exceeds the configured write-size limit."""


def validate_attachment_path(path: str, *, write: bool = False) -> str:
    """Apply attachment-specific policy after the vault policy."""
    canonical = VaultStorage.from_config().resolve_write(path) if write else VaultStorage.from_config().resolve_read(path)
    parts = Path(canonical.relative).parts
    if any(part.startswith(".") for part in parts):
        raise InvalidFileTypeError("Hidden files and directories are not attachments")
    if write and Path(canonical.relative).suffix.lower() not in _ALLOWED_ATTACHMENT_SUFFIXES:
        raise InvalidFileTypeError("Attachment writes require an approved binary attachment extension")
    return canonical.relative


def list_attachments(folder: str = "") -> list[dict]:
    """List all non-Markdown files in the vault (images, PDFs, audio, etc.)."""
    cfg = get_config()
    storage = VaultStorage.from_config(cfg)

    results = []
    for resolved in storage.list_files(folder):
        p = resolved.absolute
        if p.suffix.lower() == ".md":
            continue
        rel = resolved.relative
        # Listing is intentionally narrower than direct reads: only the
        # positive attachment formats are advertised to MCP callers.
        if p.suffix.lower() not in _ALLOWED_ATTACHMENT_SUFFIXES:
            continue
        try:
            rel = validate_attachment_path(rel)
            info = resolved.stat_result
        except InvalidFileTypeError:
            continue
        if any(matches_path_rule(rel, rule) for rule in cfg.exclude_paths):
            continue
        mime, _ = mimetypes.guess_type(rel)
        results.append({
            "path": rel,
            "size_bytes": info.st_size,
            "mime_type": mime or "application/octet-stream",
            "mtime": info.st_mtime,
        })

    return sorted(results, key=lambda x: x["path"])


def read_attachment(path: str) -> dict:
    """Read an attachment file. Text files returned as UTF-8 string; binary files as base64."""
    cfg = get_config()
    storage = VaultStorage.from_config(cfg)
    target = storage.resolve_read(path)
    path = validate_attachment_path(target.relative)
    target = storage.resolve_read(path)
    try:
        info = storage.stat(path)
    except FileNotFoundError:
        raise FileNotFoundError(f"Attachment not found: {path!r}") from None
    if stat.S_ISDIR(info.st_mode):
        raise IsADirectoryError(f"Path is a directory: {path!r}")

    mime, _ = mimetypes.guess_type(path)
    mime = mime or "application/octet-stream"
    is_text = mime.startswith("text/") or Path(path).suffix.lower() in _TEXT_SUFFIXES

    if is_text:
        return {
            "path": path,
            "mime_type": mime,
            "encoding": "utf-8",
            "content": storage.read_text(path),
        }

    data = storage.read_bytes(path)
    return {
        "path": path,
        "mime_type": mime,
        "encoding": "base64",
        "content": base64.b64encode(data).decode("ascii"),
        "size_bytes": len(data),
    }


def write_attachment_bytes(path: str, data: bytes) -> dict:
    """Write raw bytes as a binary attachment.

    Shared by add_attachment (decodes base64 from an MCP tool call) and the
    server's direct HTTP upload route (raw bytes, no MCP tool-call/base64
    round trip needed).
    """
    cfg = get_config()
    storage = VaultStorage.from_config(cfg)
    path = validate_attachment_path(path, write=True)
    if len(data) > cfg.max_attachment_bytes:
        raise AttachmentTooLargeError(
            f"Attachment exceeds MAX_ATTACHMENT_BYTES ({cfg.max_attachment_bytes} bytes)"
        )

    storage.write_bytes_atomic(path, data)

    mime, _ = mimetypes.guess_type(path)
    return {
        "path": path,
        "status": "written",
        "size_bytes": len(data),
        "mime_type": mime or "application/octet-stream",
    }


def add_attachment(path: str, content_base64: str) -> dict:
    """Write a binary attachment from a base64-encoded string.
    Use this to add images, PDFs, or other binary files to the vault."""
    cfg = get_config()
    # Reject obviously oversized encodings before allocating their decoded
    # byte string.  write_attachment_bytes repeats the exact post-decode check.
    encoded_limit = ((cfg.max_attachment_bytes + 2) // 3) * 4 + 4
    if len(content_base64) > encoded_limit:
        raise AttachmentTooLargeError(
            f"Attachment exceeds MAX_ATTACHMENT_BYTES ({cfg.max_attachment_bytes} bytes)"
        )
    try:
        data = base64.b64decode(content_base64, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64 content: {exc}") from exc

    return write_attachment_bytes(path, data)
