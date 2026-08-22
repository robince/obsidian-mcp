"""Loss-tolerant vault event capture and reconciliation.

Watchdog/inotify is an optimization, not a source of truth. Events are
captured while the initial index scan runs, debounced, and replayed only after
the index marks itself ready. Periodic reconciliation repairs dropped events.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import UTC
from pathlib import Path

from .filesystem import VaultStorage
from .policy import VaultAccessPolicy

logger = logging.getLogger(__name__)


class VaultWatcher:
    def __init__(self, vault_root: Path, poll_interval: float = 2.0,
                 policy: VaultAccessPolicy | None = None,
                 reconcile_interval: float | None = None,
                 debounce_ms: int | None = None) -> None:
        self._vault_root = vault_root
        self._policy = policy or VaultAccessPolicy(vault_root)
        self._storage = VaultStorage(self._policy)
        self._poll_interval = poll_interval
        self._reconcile_interval = reconcile_interval if reconcile_interval is not None else float(os.environ.get("INDEX_RECONCILE_INTERVAL", "300"))
        debounce = debounce_ms if debounce_ms is not None else int(os.environ.get("WATCHER_DEBOUNCE_MS", "100"))
        self._debounce = debounce / 1000
        self._max_pending = int(os.environ.get("WATCHER_MAX_PENDING_EVENTS", "10000"))
        self._observer = None
        self._poll_thread: threading.Thread | None = None
        self._worker: threading.Thread | None = None
        self._reconcile_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._condition = threading.Condition()
        self._pending: dict[str, float] = {}
        self._ready = False
        self._releasing = False
        self._on_change = None
        self._on_reconcile = None
        self._last_event_at: float | None = None
        self._last_reconcile_at: float | None = None
        self._conflicts_total = 0
        self._overflow = False

    def start(self, on_change, on_reconcile=None) -> None:
        self._on_change = on_change
        self._on_reconcile = on_reconcile
        watch_mode = os.environ.get("WATCH_MODE", "auto").lower()
        self._worker = threading.Thread(target=self._process, daemon=True)
        self._worker.start()
        if watch_mode == "poll" or not self._try_watchdog():
            self._start_polling()
        if self._on_reconcile is not None and self._reconcile_interval > 0:
            self._reconcile_thread = threading.Thread(target=self._reconcile_loop, daemon=True)
            self._reconcile_thread.start()

    def mark_ready(self, on_ready=None) -> None:
        """Drain the startup capture queue, then publish readiness atomically.

        ``on_ready`` is normally ``VaultIndex.mark_ready``. It is invoked
        while capture is paused on the condition so an event cannot fall
        between the final replay and publication of the two readiness flags.
        Events emitted while callbacks run remain queued and are drained
        before publication.
        """
        self.release(on_ready=on_ready)

    def release(self, on_ready=None) -> None:
        with self._condition:
            if self._ready:
                return
            self._releasing = True
            self._condition.notify_all()
        overflow_reconciled = False
        try:
            while True:
                with self._condition:
                    due = list(self._pending)
                    for path in due:
                        self._pending.pop(path, None)
                    overflowed = self._overflow and not overflow_reconciled
                for path in due:
                    try:
                        self._on_change(path)
                    except Exception:
                        logger.exception("Watcher startup callback failed for %s", path)
                        raise
                if overflowed:
                    if self._on_reconcile is None:
                        raise RuntimeError("watcher capture overflowed without reconciliation")
                    self._on_reconcile()
                    self._last_reconcile_at = time.time()
                    overflow_reconciled = True
                    continue
                with self._condition:
                    if self._pending:
                        continue
                    # Keep the condition held across the index publication and
                    # watcher state change. An emitter either queues before
                    # this point or after both readiness flags are visible.
                    if on_ready is not None:
                        on_ready()
                    self._ready = True
                    self._releasing = False
                    self._condition.notify_all()
                    return
        except Exception:
            with self._condition:
                self._releasing = False
                self._condition.notify_all()
            raise

    def stop(self) -> None:
        self._stop_event.set()
        with self._condition:
            self._condition.notify_all()
        if self._observer is not None:
            self._observer.stop()
            self._observer.join()
        for thread in (self._poll_thread, self._worker, self._reconcile_thread):
            if thread is not None:
                thread.join(timeout=max(self._poll_interval + 1, 2))

    def health(self) -> dict:
        with self._condition:
            pending = len(self._pending)
        return {
            "index_ready": self._ready,
            "last_event_at": self._iso(self._last_event_at),
            "last_reconcile_at": self._iso(self._last_reconcile_at),
            "pending_events": pending,
            "conflicts_total": self._conflicts_total,
            "capture_overflow": self._overflow,
        }

    def note_conflict(self) -> None:
        with self._condition:
            self._conflicts_total += 1

    @staticmethod
    def _iso(value: float | None) -> str | None:
        if value is None:
            return None
        from datetime import datetime
        return datetime.fromtimestamp(value, UTC).isoformat()

    def _relative(self, path: str) -> str | None:
        try:
            rel = Path(path).relative_to(self._vault_root).as_posix()
        except (ValueError, OSError):
            return None
        if not rel or any(part.startswith(".") for part in Path(rel).parts):
            return None
        if self._is_ignored(rel):
            return None
        return rel if self._policy.can_read(rel) else None

    @staticmethod
    def _is_ignored(rel: str) -> bool:
        name = Path(rel).name
        return name.startswith(".obsidian-mcp-") or name.endswith(".lock") or "/.trash/" in f"/{rel}/"

    def _emit(self, path: str) -> None:
        rel = self._relative(path)
        if rel is None:
            return
        now = time.monotonic()
        with self._condition:
            if rel not in self._pending and len(self._pending) >= self._max_pending:
                self._overflow = True
                return
            self._pending[rel] = now
            self._last_event_at = time.time()
            self._condition.notify_all()

    def _process(self) -> None:
        while not self._stop_event.is_set():
            with self._condition:
                while not self._stop_event.is_set() and (not self._ready or not self._pending):
                    self._condition.wait(timeout=0.5)
                if self._stop_event.is_set():
                    return
                now = time.monotonic()
                due = [path for path, seen in self._pending.items() if now - seen >= self._debounce]
                if not due:
                    self._condition.wait(timeout=max(self._debounce, 0.01))
                    continue
                for path in due:
                    self._pending.pop(path, None)
            for path in due:
                try:
                    self._on_change(path)
                except Exception:
                    logger.exception("Watcher callback failed for %s", path)

    def _try_watchdog(self) -> bool:
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
            watcher = self

            class _Handler(FileSystemEventHandler):
                def on_modified(self, event):
                    if not event.is_directory:
                        watcher._emit(event.src_path)
                def on_created(self, event):
                    watcher._emit(event.src_path)
                def on_deleted(self, event):
                    watcher._emit(event.src_path)
                def on_moved(self, event):
                    watcher._emit(event.src_path)
                    watcher._emit(event.dest_path)

            self._observer = Observer()
            self._observer.schedule(_Handler(), str(self._vault_root), recursive=True)
            self._observer.start()
            logger.info("VaultWatcher: using watchdog observer")
            return True
        except Exception as exc:
            logger.warning("watchdog unavailable (%s), falling back to polling", exc)
            return False

    def _start_polling(self) -> None:
        logger.info("VaultWatcher: using polling fallback (interval=%ss)", self._poll_interval)
        mtimes: dict[str, tuple[int, int]] = {}

        def _poll() -> None:
            while not self._stop_event.is_set():
                try:
                    current: dict[str, tuple[int, int]] = {}
                    for path in self._storage.list_files():
                        if path.relative.lower().endswith(".md"):
                            try:
                                info = self._storage.stat(path.relative)
                            except (FileNotFoundError, NotADirectoryError):
                                # A concurrent deletion/replacement is itself
                                # a change; do not abort the rest of the scan.
                                continue
                            current[path.relative] = (info.st_size, info.st_mtime_ns)
                    for rel, marker in current.items():
                        if mtimes.get(rel) != marker:
                            self._emit(str(self._vault_root / rel))
                    for rel in set(mtimes) - set(current):
                        self._emit(str(self._vault_root / rel))
                    mtimes.clear()
                    mtimes.update(current)
                except Exception:
                    logger.exception("Polling error")
                self._stop_event.wait(self._poll_interval)

        self._poll_thread = threading.Thread(target=_poll, daemon=True)
        self._poll_thread.start()

    def _reconcile_loop(self) -> None:
        while not self._stop_event.wait(self._reconcile_interval):
            try:
                self._on_reconcile()
                self._last_reconcile_at = time.time()
            except Exception:
                logger.exception("Vault reconciliation failed")
