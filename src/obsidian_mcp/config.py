"""Load and validate environment configuration."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .storage.policy import VaultPathError, path_rules_from_env


class ConfigError(Exception):
    pass


class _ImmutableList(list):
    """List-shaped configuration value that cannot be changed in place."""

    def _immutable(self, *args, **kwargs):
        raise TypeError("Configuration collections are immutable")

    __delitem__ = __setitem__ = append = clear = extend = insert = pop = remove = reverse = sort = _immutable
    __iadd__ = __imul__ = _immutable


class Config:
    vault_path: Path
    read_only: bool
    write_paths: list[str]
    exclude_paths: list[str]
    deny_read_paths: list[str]
    deny_write_paths: list[str]
    lock_path: Path
    operation_ledger_path: Path
    transaction_path: Path
    conflict_path: Path | None
    store_conflict_content: bool
    require_write_preconditions: bool
    allow_blind_create: bool
    allow_blind_overwrite: bool
    operation_retention_seconds: int
    index_reconcile_interval: float
    watcher_debounce_ms: int
    watcher_max_pending_events: int
    allow_permanent_delete: bool
    max_attachment_bytes: int
    transport: str
    host: str
    port: int
    api_key: str
    public_base_url: str
    oauth_github_client_id: str
    oauth_github_client_secret: str
    oauth_github_allowed_logins: list[str]
    enable_canvas: bool
    enable_excalidraw: bool
    enable_kanban: bool
    enable_bases: bool
    enable_move: bool
    enable_folder_rename: bool
    enable_folder_restore: bool
    enable_bulk_replace: bool
    enable_delete: bool
    mutation_max_files: int
    mutation_max_bytes: int
    mutation_max_replacements: int
    mutation_lock_timeout: float

    _initialized: bool = False

    def __setattr__(self, name, value):
        if getattr(self, "_initialized", False):
            raise AttributeError("Config is immutable after startup")
        object.__setattr__(self, name, value)

    def __init__(self) -> None:
        raw_vault = os.environ.get("VAULT_PATH", "")
        if not raw_vault:
            raise ConfigError("VAULT_PATH is required")
        self.vault_path = Path(raw_vault).resolve()
        if not self.vault_path.is_dir():
            raise ConfigError(f"VAULT_PATH does not exist or is not a directory: {self.vault_path}")

        self.read_only = os.environ.get("READ_ONLY", "false").lower() in ("1", "true", "yes")

        raw_write = os.environ.get("WRITE_PATHS", "")
        try:
            self.write_paths = _ImmutableList(path_rules_from_env(raw_write, name="WRITE_PATHS"))
            self.deny_read_paths = _ImmutableList(path_rules_from_env(
                os.environ.get("DENY_READ_PATHS", ".obsidian/,.trash/"),
                name="DENY_READ_PATHS",
            ))
            self.deny_write_paths = _ImmutableList(path_rules_from_env(
                os.environ.get("DENY_WRITE_PATHS", ".obsidian/,.trash/,_AI_INSTRUCTIONS.md"),
                name="DENY_WRITE_PATHS",
            ))
            # EXCLUDE_PATHS remains a discovery/index filter, but normalize it
            # as well so component-aware matching is consistent everywhere.
            self.exclude_paths = _ImmutableList(path_rules_from_env(
                os.environ.get("EXCLUDE_PATHS", "private,.obsidian"),
                name="EXCLUDE_PATHS",
            ))
        except VaultPathError as exc:
            raise ConfigError(str(exc)) from exc

        raw_lock_path = os.environ.get("LOCK_PATH", "")
        if raw_lock_path:
            self.lock_path = Path(raw_lock_path).expanduser().resolve()
        elif os.environ.get("FASTMCP_HOME"):
            self.lock_path = (Path(os.environ["FASTMCP_HOME"]).expanduser() / "locks").resolve()
        else:
            # Native installs need a usable lock domain without requiring a
            # root-owned /data directory. Docker supplies /data/locks
            # explicitly in its Compose configuration.
            self.lock_path = (Path(tempfile.gettempdir()) / "obsidian-mcp-locks").resolve()
        if self.lock_path == self.vault_path or self.vault_path in self.lock_path.parents:
            raise ConfigError("LOCK_PATH must be outside VAULT_PATH")

        raw_ledger = os.environ.get("OPERATION_LEDGER_PATH", "")
        self.operation_ledger_path = (
            Path(raw_ledger).expanduser().resolve()
            if raw_ledger
            else self.lock_path / "operations.sqlite3"
        )
        if self.operation_ledger_path == self.vault_path or self.vault_path in self.operation_ledger_path.parents:
            raise ConfigError("OPERATION_LEDGER_PATH must be outside VAULT_PATH")
        raw_transactions = os.environ.get("TRANSACTION_PATH", "")
        self.transaction_path = (
            Path(raw_transactions).expanduser().resolve()
            if raw_transactions
            else self.lock_path.parent / "transactions"
        )
        if self.transaction_path == self.vault_path or self.vault_path in self.transaction_path.parents:
            raise ConfigError("TRANSACTION_PATH must be outside VAULT_PATH")
        raw_conflicts = os.environ.get("CONFLICT_PATH", "")
        self.conflict_path = Path(raw_conflicts).expanduser().resolve() if raw_conflicts else None
        if self.conflict_path and (
            self.conflict_path == self.vault_path or self.vault_path in self.conflict_path.parents
        ):
            raise ConfigError("CONFLICT_PATH must be outside VAULT_PATH")
        self.store_conflict_content = os.environ.get("STORE_CONFLICT_CONTENT", "false").lower() in (
            "1", "true", "yes"
        )

        self.require_write_preconditions = os.environ.get(
            "REQUIRE_WRITE_PRECONDITIONS", "false"
        ).lower() in ("1", "true", "yes")
        self.allow_blind_create = os.environ.get("ALLOW_BLIND_CREATE", "true").lower() in (
            "1", "true", "yes"
        )
        # Keep existing installations compatible until REQUIRE_* is enabled;
        # operators can explicitly set this false for a create-only rollout.
        self.allow_blind_overwrite = os.environ.get("ALLOW_BLIND_OVERWRITE", "true").lower() in (
            "1", "true", "yes"
        )
        try:
            self.operation_retention_seconds = int(os.environ.get("OPERATION_RETENTION_SECONDS", "604800"))
            self.index_reconcile_interval = float(os.environ.get("INDEX_RECONCILE_INTERVAL", "300"))
            self.watcher_debounce_ms = int(os.environ.get("WATCHER_DEBOUNCE_MS", "100"))
            self.watcher_max_pending_events = int(os.environ.get("WATCHER_MAX_PENDING_EVENTS", "10000"))
        except ValueError as exc:
            raise ConfigError("Operation retention, reconciliation and debounce settings must be numeric") from exc
        if self.operation_retention_seconds <= 0 or self.index_reconcile_interval <= 0 or self.watcher_debounce_ms < 0 or self.watcher_max_pending_events <= 0:
            raise ConfigError("Operation retention, reconciliation and watcher queue size must be positive; debounce cannot be negative")

        try:
            self.mutation_max_files = int(os.environ.get("MUTATION_MAX_FILES", "1000"))
            self.mutation_max_bytes = int(os.environ.get("MUTATION_MAX_BYTES", str(50 * 1024 * 1024)))
            self.mutation_max_replacements = int(os.environ.get("MUTATION_MAX_REPLACEMENTS", "10000"))
            self.mutation_lock_timeout = float(os.environ.get("MUTATION_LOCK_TIMEOUT", "10"))
        except ValueError as exc:
            raise ConfigError("Mutation limits and lock timeout must be numeric") from exc
        if (
            self.mutation_max_files <= 0
            or self.mutation_max_bytes <= 0
            or self.mutation_max_replacements <= 0
            or self.mutation_lock_timeout <= 0
        ):
            raise ConfigError("Mutation limits and lock timeout must be positive")

        self.allow_permanent_delete = os.environ.get(
            "ALLOW_PERMANENT_DELETE", "false"
        ).lower() in ("1", "true", "yes")
        raw_max_attachment_bytes = os.environ.get("MAX_ATTACHMENT_BYTES", str(25 * 1024 * 1024))
        try:
            self.max_attachment_bytes = int(raw_max_attachment_bytes)
        except ValueError as exc:
            raise ConfigError("MAX_ATTACHMENT_BYTES must be a positive integer") from exc
        if self.max_attachment_bytes <= 0:
            raise ConfigError("MAX_ATTACHMENT_BYTES must be a positive integer")

        # Optional plugin-format tool groups — opt-in, disabled by default.
        self.enable_canvas = os.environ.get("ENABLE_CANVAS", "false").lower() in ("1", "true", "yes")
        self.enable_excalidraw = os.environ.get("ENABLE_EXCALIDRAW", "false").lower() in ("1", "true", "yes")
        self.enable_kanban = os.environ.get("ENABLE_KANBAN", "false").lower() in ("1", "true", "yes")
        self.enable_bases = os.environ.get("ENABLE_BASES", "false").lower() in ("1", "true", "yes")
        self.enable_move = os.environ.get("ENABLE_MOVE", "false").lower() in ("1", "true", "yes")
        self.enable_folder_rename = os.environ.get("ENABLE_FOLDER_RENAME", "false").lower() in ("1", "true", "yes")
        self.enable_folder_restore = os.environ.get("ENABLE_FOLDER_RESTORE", "false").lower() in ("1", "true", "yes")
        self.enable_bulk_replace = os.environ.get("ENABLE_BULK_REPLACE", "false").lower() in ("1", "true", "yes")
        self.enable_delete = os.environ.get("ENABLE_DELETE", "false").lower() in ("1", "true", "yes")

        self.transport = os.environ.get("TRANSPORT", "stdio")
        self.host = os.environ.get("HOST", "0.0.0.0")
        self.port = int(os.environ.get("PORT", "8000"))
        self.api_key = os.environ.get("API_KEY") or os.environ.get("OBSIDIAN_MCP_API_KEY") or ""
        self.public_base_url = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")

        self.oauth_github_client_id = os.environ.get("OAUTH_GITHUB_CLIENT_ID", "")
        self.oauth_github_client_secret = os.environ.get("OAUTH_GITHUB_CLIENT_SECRET", "")
        raw_logins = os.environ.get("OAUTH_GITHUB_ALLOWED_LOGINS", "")
        self.oauth_github_allowed_logins = _ImmutableList([
            login.strip().lower() for login in raw_logins.split(",") if login.strip()
        ])
        oauth_configured = bool(self.oauth_github_client_id or self.oauth_github_client_secret)
        if oauth_configured:
            if not (self.oauth_github_client_id and self.oauth_github_client_secret):
                raise ConfigError(
                    "OAUTH_GITHUB_CLIENT_ID and OAUTH_GITHUB_CLIENT_SECRET must both be set "
                    "to enable GitHub OAuth"
                )
            if not self.oauth_github_allowed_logins:
                raise ConfigError(
                    "OAUTH_GITHUB_ALLOWED_LOGINS is required when GitHub OAuth is configured "
                    "(comma-separated GitHub usernames) — without it, any GitHub account could "
                    "authenticate and get full access to the vault"
                )
            if not self.public_base_url:
                raise ConfigError(
                    "PUBLIC_BASE_URL is required when GitHub OAuth is configured "
                    "(used as the OAuth callback base URL, e.g. https://your-server.com)"
                )

        if self.transport != "stdio" and not self.api_key and not oauth_configured:
            raise ConfigError(
                f"API_KEY or GitHub OAuth (OAUTH_GITHUB_CLIENT_ID/SECRET) is required when "
                f"TRANSPORT={self.transport} "
                "(the server would otherwise be reachable without authentication)"
            )
        object.__setattr__(self, "_initialized", True)


_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config
