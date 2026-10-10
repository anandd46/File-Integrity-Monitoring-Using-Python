"""Baseline creation and change detection.

Design rules (see README for the reasoning):

* A normal scan NEVER modifies the baseline. Only an explicit baseline /
  rebaseline action replaces it, and only if every file could be read.
* An unreadable file is reported as ERROR. It is never reported as DELETED.
* Symbolic links are skipped, not followed.
* Scans are serialised with a single lock so two scans never overlap.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import database as db
from .hashing import HashError, hash_file

SCAN_LOCK = threading.Lock()

STATUSES = ("UNCHANGED", "MODIFIED", "NEW", "DELETED", "ERROR")


class ScanError(Exception):
    """An operation could not run. The message is safe to show to users."""


class ScanBusy(ScanError):
    pass


@dataclass
class WalkResult:
    files: dict = field(default_factory=dict)          # rel_path -> absolute Path
    skipped_links: int = 0
    unreadable_dirs: list = field(default_factory=list)  # rel prefixes that could not be listed
    truncated: bool = False


def walk_directory(root: Path, max_files: int) -> WalkResult:
    """Enumerate regular files below ``root`` without following symlinks."""
    result = WalkResult()
    root = Path(root)

    def on_error(err: OSError):
        try:
            rel = Path(err.filename).relative_to(root).as_posix() if err.filename else ""
        except ValueError:
            rel = ""
        result.unreadable_dirs.append(rel)

    for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=on_error):
        cur_path = Path(current)
        # Symlinked directories show up in dirnames; count and prune them.
        kept = []
        for name in dirnames:
            if (cur_path / name).is_symlink():
                result.skipped_links += 1
            else:
                kept.append(name)
        dirnames[:] = sorted(kept)
        for name in sorted(filenames):
            full = cur_path / name
            if full.is_symlink():
                result.skipped_links += 1
                continue
            if len(result.files) >= max_files:
                result.truncated = True
                return result
            rel = full.relative_to(root).as_posix()
            result.files[rel] = full
    return result


def _root_problem(root: Path) -> str | None:
    try:
        if root.is_symlink():
            return "The monitored directory is now a symbolic link."
        if not root.is_dir():
            return "The monitored directory no longer exists."
        if not os.access(root, os.R_OK | os.X_OK):
            return "The monitored directory is not readable."
    except OSError:
        return "The monitored directory could not be accessed."
    return None


def _under(prefixes, rel: str) -> bool:
    for prefix in prefixes:
        if prefix == "" or rel == prefix or rel.startswith(prefix + "/"):
            return True
    return False


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------
def create_baseline(conn: sqlite3.Connection, directory: sqlite3.Row, config, *, replace: bool) -> dict:
    """Create (or, with ``replace=True``, deliberately replace) the baseline.

    Aborts without touching the existing baseline if any file cannot be read,
    because a partial baseline would silently trust an incomplete picture.
    """
    if not SCAN_LOCK.acquire(blocking=False):
        raise ScanBusy("Another scan or baseline operation is already running.")
    try:
        root = Path(directory["path"])
        problem = _root_problem(root)
        if problem:
            raise ScanError(problem)

        existing = conn.execute(
            "SELECT COUNT(*) AS n FROM file_baselines WHERE directory_id = ?", (directory["id"],)
        ).fetchone()["n"]
        if existing and not replace:
            raise ScanError("A baseline already exists. Use the explicit rebaseline action to replace it.")

        walked = walk_directory(root, config["MAX_FILES_PER_DIRECTORY"])
        problems = []
        if walked.truncated:
            problems.append(f"directory exceeds the {config['MAX_FILES_PER_DIRECTORY']} file limit")
        if walked.unreadable_dirs:
            problems.append(f"{len(walked.unreadable_dirs)} subdirectories could not be listed")

        hashed: dict = {}
        unreadable = 0
        for rel, full in walked.files.items():
            try:
                size = full.stat().st_size
                if size > config["MAX_FILE_SIZE_BYTES"]:
                    raise HashError("TOO_LARGE", "File exceeds the configured size limit")
                hashed[rel] = hash_file(full)
            except HashError:
                unreadable += 1
            except OSError:
                unreadable += 1
        if unreadable:
            problems.append(f"{unreadable} files could not be read")

        if problems:
            db.add_event(
                conn, category="SCAN_FAILURE", directory_id=directory["id"], directory_path=directory["path"],
                description="Baseline NOT changed: " + "; ".join(problems) + ". Fix the problems and try again.",
            )
            raise ScanError("Baseline not changed: " + "; ".join(problems) + ".")

        old = {r["rel_path"]: r["sha256"] for r in conn.execute(
            "SELECT rel_path, sha256 FROM file_baselines WHERE directory_id = ?", (directory["id"],))}
        now = db.utcnow()
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM file_baselines WHERE directory_id = ?", (directory["id"],))
            conn.executemany(
                "INSERT INTO file_baselines (directory_id, rel_path, sha256, size, mtime_ns, baseline_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [(directory["id"], rel, h.sha256, h.size, h.mtime_ns, now) for rel, h in hashed.items()],
            )
            conn.execute("UPDATE monitored_directories SET last_baseline_at = ? WHERE id = ?",
                         (now, directory["id"]))
            if existing:
                changed = sum(1 for r, h in hashed.items() if r in old and old[r] != h.sha256)
                added = sum(1 for r in hashed if r not in old)
                removed = sum(1 for r in old if r not in hashed)
                desc = (f"Baseline deliberately REPLACED (rebaseline): {len(hashed)} files now trusted. "
                        f"Compared with the previous baseline: {changed} modified, {added} new, {removed} removed.")
            else:
                desc = f"Baseline created: {len(hashed)} files recorded."
            db.add_event(conn, category="BASELINE_CHANGE", directory_id=directory["id"],
                         directory_path=directory["path"], description=desc)
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return {"files": len(hashed), "replaced": bool(existing), "skipped_links": walked.skipped_links}
    finally:
        SCAN_LOCK.release()


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------
def run_scan(conn: sqlite3.Connection, directory: sqlite3.Row, config, *, trigger: str = "MANUAL") -> dict:
    """Compare the current filesystem with the saved baseline and persist the outcome."""
    if trigger not in ("MANUAL", "PERIODIC"):
        raise ScanError("Invalid scan trigger.")
    if not SCAN_LOCK.acquire(blocking=False):
        raise ScanBusy("Another scan or baseline operation is already running.")
    scan_id = None
    try:
        dir_id = directory["id"]
        dir_path = directory["path"]
        root = Path(dir_path)

        baseline_rows = conn.execute(
            "SELECT rel_path, sha256, size FROM file_baselines WHERE directory_id = ?", (dir_id,)
        ).fetchall()
        if not baseline_rows:
            raise ScanError("No baseline exists for this directory. Create a baseline first.")
        baseline = {r["rel_path"]: r for r in baseline_rows}

        started = db.utcnow()
        scan_id = conn.execute(
            "INSERT INTO scan_history (directory_id, started_at, status, trigger_type) VALUES (?, ?, 'RUNNING', ?)",
            (dir_id, started, trigger),
        ).lastrowid

        problem = _root_problem(root)
        if problem:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE scan_history SET status='FAILED', finished_at=?, message=? WHERE id=?",
                         (db.utcnow(), problem, scan_id))
            db.add_event(conn, category="SCAN_FAILURE", directory_id=dir_id, directory_path=dir_path,
                         scan_id=scan_id, description=f"Scan failed: {problem} No files were marked deleted.")
            conn.execute("COMMIT")
            return {"scan_id": scan_id, "status": "FAILED", "message": problem, "counts": {}}

        # Previous results (for event de-duplication)
        prev_scan = conn.execute(
            "SELECT id FROM scan_history WHERE directory_id=? AND id<>? AND status IN ('COMPLETED','PARTIAL') "
            "ORDER BY id DESC LIMIT 1", (dir_id, scan_id)).fetchone()
        prev = {}
        if prev_scan:
            for r in conn.execute("SELECT rel_path, status, current_hash, error FROM scan_results WHERE scan_id=?",
                                  (prev_scan["id"],)):
                prev[r["rel_path"]] = (r["status"], r["current_hash"], r["error"])

        walked = walk_directory(root, config["MAX_FILES_PER_DIRECTORY"])
        results = []  # dicts
        for rel, full in walked.files.items():
            base = baseline.get(rel)
            try:
                size = full.stat().st_size
                if size > config["MAX_FILE_SIZE_BYTES"]:
                    raise HashError("TOO_LARGE", "File exceeds the configured size limit")
                h = hash_file(full)
            except HashError as exc:
                results.append(dict(rel=rel, status="ERROR", prev=base["sha256"] if base else None,
                                    cur=None, size=None, error=exc.message))
                continue
            except OSError:
                results.append(dict(rel=rel, status="ERROR", prev=base["sha256"] if base else None,
                                    cur=None, size=None, error="Could not read file"))
                continue
            if base is None:
                status = "NEW"
            elif base["sha256"] == h.sha256:
                status = "UNCHANGED"
            else:
                status = "MODIFIED"
            results.append(dict(rel=rel, status=status, prev=base["sha256"] if base else None,
                                cur=h.sha256, size=h.size, error=None))

        seen = set(walked.files)
        if not walked.truncated:
            for rel, base in baseline.items():
                if rel in seen:
                    continue
                if _under(walked.unreadable_dirs, rel):
                    results.append(dict(rel=rel, status="ERROR", prev=base["sha256"], cur=None,
                                        size=None, error="Parent directory could not be listed"))
                else:
                    results.append(dict(rel=rel, status="DELETED", prev=base["sha256"], cur=None,
                                        size=None, error=None))

        counts = {s: 0 for s in STATUSES}
        for r in results:
            counts[r["status"]] += 1
        incomplete = bool(counts["ERROR"] or walked.truncated or walked.unreadable_dirs)
        status = "PARTIAL" if incomplete else "COMPLETED"
        notes = []
        if walked.truncated:
            notes.append(f"file limit of {config['MAX_FILES_PER_DIRECTORY']} reached; deletion checks skipped")
        if walked.unreadable_dirs:
            notes.append(f"{len(walked.unreadable_dirs)} subdirectories could not be listed")
        if counts["ERROR"]:
            notes.append(f"{counts['ERROR']} files could not be checked")
        if walked.skipped_links:
            notes.append(f"{walked.skipped_links} symbolic links skipped")
        message = "; ".join(notes) or None

        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.executemany(
                "INSERT INTO scan_results (scan_id, directory_id, rel_path, status, previous_hash, current_hash, "
                "size, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [(scan_id, dir_id, r["rel"], r["status"], r["prev"], r["cur"], r["size"], r["error"])
                 for r in results])
            for r in results:
                if r["status"] == "UNCHANGED":
                    continue
                before = prev.get(r["rel"])
                if before and before[0] == r["status"] and before[1] == r["cur"] and before[2] == r["error"]:
                    continue  # same finding as last scan: do not repeat the alert
                if r["status"] == "ERROR":
                    db.add_event(conn, category="INSPECTION_ERROR", directory_id=dir_id, directory_path=dir_path,
                                 rel_path=r["rel"], previous_hash=r["prev"], scan_id=scan_id,
                                 description=f"File could not be checked: {r['error']}. Not treated as deleted.")
                else:
                    text = {
                        "MODIFIED": "File contents differ from the trusted baseline. This may be a legitimate "
                                    "edit or an unauthorized change; investigate.",
                        "NEW": "File is not in the trusted baseline.",
                        "DELETED": "File present in the baseline was not found.",
                    }[r["status"]]
                    db.add_event(conn, category="FILE_CHANGE", change_type=r["status"], directory_id=dir_id,
                                 directory_path=dir_path, rel_path=r["rel"], previous_hash=r["prev"],
                                 current_hash=r["cur"], scan_id=scan_id, description=text)
            if walked.truncated or walked.unreadable_dirs:
                db.add_event(conn, category="INSPECTION_ERROR", directory_id=dir_id, directory_path=dir_path,
                             scan_id=scan_id,
                             description="Scan incomplete: " + (message or "some areas were not inspected") + ".")
            conn.execute(
                "UPDATE scan_history SET status=?, finished_at=?, total_files=?, unchanged=?, modified=?, "
                "new_files=?, deleted=?, errors=?, message=? WHERE id=?",
                (status, db.utcnow(), len(walked.files), counts["UNCHANGED"], counts["MODIFIED"], counts["NEW"],
                 counts["DELETED"], counts["ERROR"], message, scan_id))
            conn.execute("UPDATE monitored_directories SET last_scan_at=? WHERE id=?", (db.utcnow(), dir_id))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return {"scan_id": scan_id, "status": status, "message": message, "counts": counts}
    except ScanError:
        raise
    except Exception as exc:  # unexpected: record safely, never leak details
        if scan_id is not None:
            try:
                conn.execute("UPDATE scan_history SET status='FAILED', finished_at=?, message=? WHERE id=?",
                             (db.utcnow(), "Internal error during scan", scan_id))
                db.add_event(conn, category="SCAN_FAILURE", directory_id=directory["id"],
                             directory_path=directory["path"], scan_id=scan_id,
                             description=f"Scan failed with an internal error ({exc.__class__.__name__}). "
                                         "The baseline was not modified.")
            except sqlite3.Error:
                pass
        raise ScanError("The scan failed because of an internal error. The baseline was not modified.")
    finally:
        SCAN_LOCK.release()
