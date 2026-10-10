"""Optional periodic scanning with ONE background worker thread.

Intended for a single local process only. The worker is created once by the
application factory (never from a request handler), polls the settings table,
and uses the scanner's lock so scans never overlap. Under a multi-process
server (e.g. several gunicorn workers) every process would start its own
worker, which this lightweight design does not coordinate.
"""
from __future__ import annotations

import logging
import threading
import time

from . import database as db
from .scanner import ScanBusy, ScanError, run_scan

log = logging.getLogger("fim.monitor")

POLL_SECONDS = 1.0


class MonitorWorker:
    _instance_lock = threading.Lock()

    def __init__(self, db_path: str, scan_config: dict):
        self._db_path = db_path
        self._scan_config = scan_config
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._state_lock = threading.Lock()
        self.last_run_epoch: float | None = None
        self.last_run_iso: str | None = None
        self.last_error: str | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> bool:
        """Start the worker if it is not already running. Returns True if started."""
        with self._instance_lock:
            if self._thread is not None and self._thread.is_alive():
                return False  # already running: never create a duplicate
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="fim-monitor", daemon=True)
            self._thread.start()
            return True

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)

    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # -- status ------------------------------------------------------------
    def status(self, conn) -> dict:
        enabled = db.get_setting(conn, "periodic_enabled") == "1"
        interval = int(db.get_setting(conn, "scan_interval_seconds") or 300)
        with self._state_lock:
            return {
                "worker_alive": self.is_alive(),
                "enabled": enabled,
                "interval": interval,
                "last_run": self.last_run_iso,
                "last_error": self.last_error,
                "label": ("ACTIVE" if enabled and self.is_alive()
                          else "ENABLED (worker not running)" if enabled
                          else "DISABLED"),
            }

    # -- internals ---------------------------------------------------------
    def _loop(self) -> None:
        log.info("Monitoring worker started")
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:  # never let the thread die silently
                self._record_error(f"Worker error: {exc.__class__.__name__}")
                log.exception("Unexpected worker error")
            self._stop.wait(POLL_SECONDS)
        log.info("Monitoring worker stopped")

    def _tick(self) -> None:
        conn = db.connect(self._db_path)
        try:
            if db.get_setting(conn, "periodic_enabled") != "1":
                with self._state_lock:
                    self.last_run_epoch = None  # restart the countdown when re-enabled
                return
            interval = int(db.get_setting(conn, "scan_interval_seconds") or 300)
            now = time.monotonic()
            with self._state_lock:
                if self.last_run_epoch is None:
                    self.last_run_epoch = now  # first period starts when enabled
                    return
                if now - self.last_run_epoch < interval:
                    return
                self.last_run_epoch = now
            self._scan_all(conn)
        finally:
            conn.close()

    def _scan_all(self, conn) -> None:
        rows = conn.execute(
            "SELECT d.* FROM monitored_directories d "
            "WHERE EXISTS (SELECT 1 FROM file_baselines b WHERE b.directory_id = d.id)").fetchall()
        for directory in rows:
            if self._stop.is_set():
                return
            try:
                run_scan(conn, directory, self._scan_config, trigger="PERIODIC")
            except ScanBusy:
                log.info("Periodic scan skipped: another scan is running")
            except ScanError as exc:
                self._record_error(str(exc), conn, directory)
        with self._state_lock:
            self.last_run_iso = db.utcnow()
            self.last_error = None if self.last_error is None else self.last_error

    def _record_error(self, message: str, conn=None, directory=None) -> None:
        with self._state_lock:
            self.last_error = message
        own = conn is None
        try:
            if own:
                conn = db.connect(self._db_path)
            db.add_event(conn, category="SERVICE_ERROR",
                         directory_id=directory["id"] if directory else None,
                         directory_path=directory["path"] if directory else None,
                         description=f"Periodic monitoring error: {message}")
        except Exception:
            log.exception("Could not record monitoring error")
        finally:
            if own and conn is not None:
                conn.close()
