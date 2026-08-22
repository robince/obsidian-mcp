"""Durable, fail-closed idempotency records outside the vault."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any


class LedgerUnavailableError(RuntimeError):
    """The idempotency ledger cannot safely answer a mutation request."""

    def __init__(self, detail: str = "operation ledger unavailable") -> None:
        self.detail = detail
        super().__init__(detail)

    def to_dict(self) -> dict[str, str]:
        return {"error": "ledger_unavailable", "message": "operation ledger unavailable"}


class OperationConflictError(RuntimeError):
    def __init__(self, operation_id: str) -> None:
        self.operation_id = operation_id
        super().__init__(f"Operation ID {operation_id!r} was already used with different content")

    def to_dict(self) -> dict[str, str]:
        return {"error": "operation_conflict", "operation_id": self.operation_id}


class OperationOutcomeUnknownError(RuntimeError):
    def __init__(self, operation_id: str, path: str) -> None:
        self.operation_id = operation_id
        self.path = path
        super().__init__(f"The outcome of operation {operation_id!r} is unknown for {path!r}")

    def to_dict(self) -> dict[str, str]:
        return {"error": "operation_outcome_unknown", "operation_id": self.operation_id, "path": self.path}


class OperationLedger:
    _DIGEST = re.compile(r"^[0-9a-f]{64}$")
    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS operations (
            principal_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            target_path TEXT NOT NULL,
            request_digest TEXT NOT NULL,
            result_json TEXT,
            result_revision TEXT,
            expected_result_revision TEXT,
            status TEXT NOT NULL DEFAULT 'complete',
            initial_revision TEXT,
            created_at REAL NOT NULL,
            PRIMARY KEY (principal_id, operation_id)
        )
    """

    def __init__(self, path: str | Path, *, retention_seconds: int = 604800) -> None:
        self.path = Path(path)
        self.retention_seconds = retention_seconds
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._initialize()
        except LedgerUnavailableError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise LedgerUnavailableError(str(exc)) from exc

    def _raw_connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10, isolation_level="IMMEDIATE")
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout = 10000")
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA synchronous = FULL")
        return db

    def _connect(self) -> sqlite3.Connection:
        try:
            return self._raw_connect()
        except (OSError, sqlite3.Error) as exc:
            raise LedgerUnavailableError(str(exc)) from exc

    def _initialize(self) -> None:
        with closing(self._raw_connect()) as db, db:
            info = db.execute("PRAGMA table_info(operations)").fetchall()
            if not info:
                db.execute(self._SCHEMA)
            else:
                names = {row["name"] for row in info}
                required = {
                    "principal_id", "operation_id", "tool_name", "target_path",
                    "request_digest", "result_json", "result_revision", "status",
                    "initial_revision", "created_at",
                }
                if not required.issubset(names):
                    raise LedgerUnavailableError("operation ledger schema is corrupt")
                primary = [row["name"] for row in sorted(info, key=lambda row: row["pk"]) if row["pk"]]
                if primary != ["principal_id", "operation_id"] or "expected_result_revision" not in names:
                    # Migrate the Phase 3 preview schema (operation_id-only
                    # primary key) into the composite-key schema. Existing
                    # rows belong to the trusted internal principal.
                    db.execute("ALTER TABLE operations RENAME TO operations_legacy")
                    db.execute(self._SCHEMA)
                    columns = [
                        "principal_id", "operation_id", "tool_name", "target_path",
                        "request_digest", "result_json", "result_revision", "status",
                        "initial_revision", "created_at",
                    ]
                    db.execute(
                        "INSERT INTO operations (" + ",".join(columns) + ") "
                        "SELECT principal_id, operation_id, tool_name, target_path, request_digest, "
                        "result_json, result_revision, status, initial_revision, created_at "
                        "FROM operations_legacy"
                    )
                    db.execute("DROP TABLE operations_legacy")
            db.commit()

    @staticmethod
    def digest(payload: Any) -> str:
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        except (TypeError, ValueError) as exc:
            raise LedgerUnavailableError("operation request cannot be serialized") from exc
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _validate(cls, operation_id: str, principal_id: str, tool_name: str, target_path: str, request_digest: str) -> None:
        for name, value in (("operation_id", operation_id), ("principal_id", principal_id), ("tool_name", tool_name), ("target_path", target_path)):
            if not isinstance(value, str) or not value or "\x00" in value or len(value) > 1024:
                raise LedgerUnavailableError(f"invalid {name}")
        if not isinstance(request_digest, str) or not cls._DIGEST.fullmatch(request_digest):
            raise LedgerUnavailableError("invalid operation request digest")

    @staticmethod
    def _json_result(row: sqlite3.Row) -> dict[str, Any]:
        try:
            value = json.loads(row["result_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise LedgerUnavailableError("operation ledger result is corrupt") from exc
        if not isinstance(value, dict):
            raise LedgerUnavailableError("operation ledger result is corrupt")
        return value

    def get(self, operation_id: str, *, principal_id: str, request_digest: str) -> dict[str, Any] | None:
        self._validate(operation_id, principal_id, "unknown", "unknown", request_digest)
        self.cleanup()
        try:
            with closing(self._connect()) as db:
                row = db.execute(
                    "SELECT * FROM operations WHERE principal_id = ? AND operation_id = ?",
                    (principal_id, operation_id),
                ).fetchone()
        except LedgerUnavailableError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise LedgerUnavailableError(str(exc)) from exc
        if row is None:
            return None
        if row["request_digest"] != request_digest:
            raise OperationConflictError(operation_id)
        if row["status"] != "complete" or row["result_json"] is None:
            return None
        return self._json_result(row)

    def reserve(
        self,
        operation_id: str,
        *,
        principal_id: str,
        tool_name: str,
        target_path: str,
        request_digest: str,
        initial_revision: str | None,
        expected_result_revision: str | None = None,
    ) -> dict[str, Any] | None:
        self._validate(operation_id, principal_id, tool_name, target_path, request_digest)
        self.cleanup()
        try:
            with closing(self._connect()) as db, db:
                # Serialize the scoped insert/read decision. The conflict
                # clause also makes the result robust if another SQLite
                # connection wins the reservation while this one waits.
                db.execute("BEGIN IMMEDIATE")
                inserted = db.execute(
                    """INSERT INTO operations
                    (principal_id, operation_id, tool_name, target_path, request_digest,
                     result_json, result_revision, expected_result_revision, status,
                     initial_revision, created_at)
                    VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, 'pending', ?, ?)
                    ON CONFLICT(principal_id, operation_id) DO NOTHING""",
                    (principal_id, operation_id, tool_name, target_path, request_digest,
                     expected_result_revision, initial_revision, time.time()),
                ).rowcount == 1
                row = db.execute(
                    "SELECT * FROM operations WHERE principal_id = ? AND operation_id = ?",
                    (principal_id, operation_id),
                ).fetchone()
                if not inserted and row is not None:
                    if row["request_digest"] != request_digest or row["target_path"] != target_path or row["tool_name"] != tool_name:
                        raise OperationConflictError(operation_id)
                    if row["status"] == "complete" and row["result_json"] is not None:
                        return self._json_result(row)
                    return {
                        "_pending": True,
                        "initial_revision": row["initial_revision"],
                        "expected_result_revision": row["expected_result_revision"],
                    }
        except OperationConflictError:
            raise
        except LedgerUnavailableError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise LedgerUnavailableError(str(exc)) from exc
        return None

    def record(
        self,
        operation_id: str,
        *,
        principal_id: str,
        tool_name: str,
        target_path: str,
        request_digest: str,
        result: dict[str, Any],
        result_revision: str | None = None,
    ) -> None:
        self._validate(operation_id, principal_id, tool_name, target_path, request_digest)
        if not isinstance(result, dict):
            raise LedgerUnavailableError("operation result must be an object")
        try:
            encoded = json.dumps(result, sort_keys=True, ensure_ascii=False)
            with closing(self._connect()) as db, db:
                updated = db.execute(
                    """UPDATE operations SET result_json = ?, result_revision = ?, status = 'complete'
                    WHERE principal_id = ? AND operation_id = ? AND tool_name = ?
                      AND target_path = ? AND request_digest = ?""",
                    (encoded, result_revision, principal_id, operation_id, tool_name, target_path, request_digest),
                ).rowcount
                if not updated:
                    raise LedgerUnavailableError("operation reservation is missing")
        except LedgerUnavailableError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
            raise LedgerUnavailableError(str(exc)) from exc

    def abandon(
        self,
        operation_id: str,
        *,
        principal_id: str,
        tool_name: str,
        target_path: str,
        request_digest: str,
    ) -> None:
        """Release an uncommitted reservation after a known failed mutation."""
        self._validate(operation_id, principal_id, tool_name, target_path, request_digest)
        try:
            with closing(self._connect()) as db, db:
                db.execute(
                    """DELETE FROM operations
                    WHERE principal_id = ? AND operation_id = ? AND tool_name = ?
                      AND target_path = ? AND request_digest = ? AND status = 'pending'""",
                    (principal_id, operation_id, tool_name, target_path, request_digest),
                )
        except LedgerUnavailableError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise LedgerUnavailableError(str(exc)) from exc

    def cleanup(self) -> None:
        cutoff = time.time() - self.retention_seconds
        try:
            with closing(self._connect()) as db, db:
                db.execute("DELETE FROM operations WHERE created_at < ?", (cutoff,))
        except LedgerUnavailableError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise LedgerUnavailableError(str(exc)) from exc
