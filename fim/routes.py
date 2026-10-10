"""HTTP routes. Every user-controlled value is validated server-side."""
from __future__ import annotations

import math
from pathlib import Path

from flask import (Blueprint, Response, abort, current_app, flash, redirect, render_template,
                   request, url_for)

from . import database as db
from . import reports
from .scanner import STATUSES, ScanBusy, ScanError, create_baseline, run_scan
from .security import (PathSecurityError, ValidationError, escape_like, parse_choice, parse_int,
                       parse_label, parse_optional_int, parse_page, parse_search, safe_join,
                       validate_directory_input)
from config import (DEFAULT_SCAN_INTERVAL, HASH_ALGORITHM, MAX_SCAN_INTERVAL, MIN_SCAN_INTERVAL)

bp = Blueprint("fim", __name__)

CATEGORIES = {
    "source": ("Application source code",
               "Modified source files are the classic sign of a backdoor, web shell or injected code."),
    "config": ("Configuration files",
               "Attackers alter configs to weaken security settings, add users or redirect traffic."),
    "templates": ("HTML templates",
                  "Injected markup or script in templates can skim form data or serve malicious content."),
    "assets": ("JavaScript and CSS assets",
               "Tampered static assets (for example a skimmer appended to a script) hit every visitor."),
    "scripts": ("Application scripts",
                "Deployment, cron and helper scripts often run with elevated privileges."),
    "other": ("Other explicitly selected directories",
              "Any directory you own and are authorised to monitor."),
}
EVENT_CATEGORIES = {
    "FILE_CHANGE": "Detected file change",
    "INSPECTION_ERROR": "File inspection error",
    "SCAN_FAILURE": "Scan failure",
    "BASELINE_CHANGE": "Baseline change",
    "SERVICE_ERROR": "Monitoring-service error",
}
INVENTORY_STATUSES = STATUSES + ("BASELINED",)
INVENTORY_SORTS = {"path": "inv.rel_path", "status": "inv.status", "size": "inv.size", "directory": "d.path"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _worker():
    return current_app.extensions["fim_worker"]


def _bad_request(exc: Exception):
    abort(400, description=str(exc))


def _page_size() -> int:
    return current_app.config["PAGE_SIZE"]


def paginate(conn, count_sql: str, params: list, page: int):
    total = conn.execute(count_sql, params).fetchone()[0]
    size = _page_size()
    pages = max(1, math.ceil(total / size))
    page = min(page, pages)
    return total, pages, page, size, (page - 1) * size


def authorize_directory(conn, raw_id, *, check_root: bool = True):
    """Server-side authorisation: the ID alone proves nothing.

    The ID must be well formed, must exist in OUR table of registered
    directories, and the stored path must still pass the safety checks
    (it may have become a symlink or moved since registration).
    """
    try:
        dir_id = parse_int(raw_id, "Directory ID")
    except ValidationError as exc:
        _bad_request(exc)
    row = conn.execute("SELECT * FROM monitored_directories WHERE id = ?", (dir_id,)).fetchone()
    if row is None:
        abort(404, description="Monitored directory not found.")
    if check_root:
        try:
            real = validate_directory_input(row["path"])
            if str(real) != row["path"]:
                raise PathSecurityError("The registered path no longer resolves to the same location.")
        except PathSecurityError as exc:
            abort(409, description=f"This directory can no longer be accessed safely: {exc}")
    return row


def _require_confirmation():
    if request.form.get("confirm") != "yes":
        flash("This action requires confirmation. Please use the confirmation dialog.", "danger")
        return False
    return True


def _counts_summary(counts: dict) -> str:
    return (f"{counts.get('MODIFIED', 0)} modified, {counts.get('NEW', 0)} new, "
            f"{counts.get('DELETED', 0)} deleted, {counts.get('UNCHANGED', 0)} unchanged, "
            f"{counts.get('ERROR', 0)} errors")


def _flash_scan(result: dict, label: str = "") -> None:
    prefix = f"Scan #{result['scan_id']}{(' of ' + label) if label else ''}"
    if result["status"] == "FAILED":
        flash(f"{prefix} failed: {result['message']}", "danger")
        return
    counts = result["counts"]
    changes = counts["MODIFIED"] + counts["NEW"] + counts["DELETED"]
    text = f"{prefix} {result['status'].lower()}: {_counts_summary(counts)}."
    if changes:
        text += " Changes were detected; review them, they are not proof of malicious activity."
    flash(text, "warning" if changes or result["status"] == "PARTIAL" else "success")


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------
@bp.get("/")
def dashboard():
    conn = db.get_db()
    latest = ("SELECT s.* FROM scan_history s WHERE s.id = (SELECT MAX(x.id) FROM scan_history x "
              "WHERE x.directory_id = s.directory_id AND x.status IN ('COMPLETED','PARTIAL'))")
    agg = conn.execute(
        f"SELECT COALESCE(SUM(unchanged),0) u, COALESCE(SUM(modified),0) m, COALESCE(SUM(new_files),0) n, "
        f"COALESCE(SUM(deleted),0) d, COALESCE(SUM(errors),0) e FROM ({latest})").fetchone()
    stats = {
        "directories": conn.execute("SELECT COUNT(*) FROM monitored_directories").fetchone()[0],
        "baseline_files": conn.execute("SELECT COUNT(*) FROM file_baselines").fetchone()[0],
        "unchanged": agg["u"], "modified": agg["m"], "new": agg["n"], "deleted": agg["d"], "errors": agg["e"],
        "last_success": conn.execute(
            "SELECT MAX(finished_at) FROM scan_history WHERE status = 'COMPLETED'").fetchone()[0],
    }
    stats["changes"] = stats["modified"] + stats["new"] + stats["deleted"]
    events = conn.execute(
        "SELECT * FROM security_events ORDER BY timestamp DESC, id DESC LIMIT 8").fetchall()
    scans = conn.execute(
        "SELECT s.*, d.path AS dir_path, d.label AS dir_label FROM scan_history s "
        "JOIN monitored_directories d ON d.id = s.directory_id ORDER BY s.id DESC LIMIT 6").fetchall()
    chart_rows = conn.execute(
        "SELECT id, modified, new_files, deleted, errors FROM scan_history "
        "WHERE status IN ('COMPLETED','PARTIAL') ORDER BY id DESC LIMIT 12").fetchall()[::-1]
    chart = {
        "labels": [f"#{r['id']}" for r in chart_rows],
        "modified": [r["modified"] for r in chart_rows],
        "new": [r["new_files"] for r in chart_rows],
        "deleted": [r["deleted"] for r in chart_rows],
        "errors": [r["errors"] for r in chart_rows],
    }
    return render_template("dashboard.html", stats=stats, events=events, scans=scans, chart=chart,
                           monitor=_worker().status(conn), first_dir=conn.execute(
                               "SELECT id FROM monitored_directories ORDER BY id LIMIT 1").fetchone())


# ---------------------------------------------------------------------------
# monitored directories
# ---------------------------------------------------------------------------
@bp.get("/directories")
def directories():
    conn = db.get_db()
    rows = conn.execute(
        "SELECT d.*, (SELECT COUNT(*) FROM file_baselines b WHERE b.directory_id = d.id) AS baseline_count "
        "FROM monitored_directories d ORDER BY d.id").fetchall()
    return render_template("monitored_paths.html", directories=rows, categories=CATEGORIES)


@bp.post("/directories/add")
def add_directory():
    conn = db.get_db()
    try:
        real = validate_directory_input(request.form.get("path"))
        label = parse_label(request.form.get("label"))
        category = parse_choice(request.form.get("category"), "Category", CATEGORIES, "other")
    except ValidationError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("fim.directories"))
    real_text = str(real)
    for row in conn.execute("SELECT path FROM monitored_directories"):
        existing = Path(row["path"])
        if existing == real:
            flash("This directory is already registered.", "danger")
            return redirect(url_for("fim.directories"))
        if existing in real.parents or real in existing.parents:
            flash("This directory overlaps with an already registered directory.", "danger")
            return redirect(url_for("fim.directories"))
    conn.execute("INSERT INTO monitored_directories (label, path, category, created_at) VALUES (?, ?, ?, ?)",
                 (label or real.name, real_text, category, db.utcnow()))
    flash("Directory registered. Next step: create a trusted baseline.", "success")
    return redirect(url_for("fim.directories"))


@bp.post("/directories/<dir_id>/remove")
def remove_directory(dir_id):
    conn = db.get_db()
    row = authorize_directory(conn, dir_id, check_root=False)
    if not _require_confirmation():
        return redirect(url_for("fim.directories"))
    conn.execute("BEGIN IMMEDIATE")
    try:
        db.add_event(conn, category="BASELINE_CHANGE", directory_path=row["path"],
                     description="Monitored directory removed; its baseline and scan data were deleted.")
        conn.execute("DELETE FROM monitored_directories WHERE id = ?", (row["id"],))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    flash("Directory removed from monitoring. Files on disk were not touched.", "success")
    return redirect(url_for("fim.directories"))


@bp.post("/directories/<dir_id>/baseline")
def baseline_directory(dir_id):
    conn = db.get_db()
    row = authorize_directory(conn, dir_id)
    try:
        result = create_baseline(conn, row, current_app.config, replace=False)
        flash(f"Baseline created with {result['files']} files.", "success")
    except ScanError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("fim.directories"))


@bp.post("/directories/<dir_id>/rebaseline")
def rebaseline_directory(dir_id):
    conn = db.get_db()
    row = authorize_directory(conn, dir_id)
    if not _require_confirmation():
        return redirect(url_for("fim.directories"))
    try:
        result = create_baseline(conn, row, current_app.config, replace=True)
        flash(f"Baseline replaced: the current state of {result['files']} files is now the trusted reference.",
              "warning")
    except ScanError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("fim.directories"))


@bp.post("/directories/<dir_id>/scan")
def scan_directory(dir_id):
    conn = db.get_db()
    row = authorize_directory(conn, dir_id)
    try:
        _flash_scan(run_scan(conn, row, current_app.config), row["label"] or "")
    except ScanBusy as exc:
        flash(str(exc), "warning")
    except ScanError as exc:
        flash(str(exc), "danger")
    nxt = request.form.get("next")
    return redirect(url_for("fim.dashboard") if nxt == "dashboard" else url_for("fim.scan_history"))


@bp.post("/scan-all")
def scan_all():
    conn = db.get_db()
    rows = conn.execute("SELECT * FROM monitored_directories WHERE EXISTS "
                        "(SELECT 1 FROM file_baselines b WHERE b.directory_id = monitored_directories.id) "
                        "ORDER BY id").fetchall()
    if not rows:
        flash("No directory has a baseline yet. Register a directory and create a baseline first.", "warning")
        return redirect(url_for("fim.dashboard"))
    for row in rows:
        try:
            authorize_directory(conn, row["id"])
            _flash_scan(run_scan(conn, row, current_app.config), row["label"] or "")
        except ScanBusy as exc:
            flash(str(exc), "warning")
        except ScanError as exc:
            flash(str(exc), "danger")
    return redirect(url_for("fim.dashboard"))


# ---------------------------------------------------------------------------
# file inventory
# ---------------------------------------------------------------------------
@bp.get("/inventory")
def inventory():
    conn = db.get_db()
    try:
        dir_id = parse_optional_int(request.args.get("directory_id"), "Directory ID")
        status = parse_choice(request.args.get("status"), "Status", INVENTORY_STATUSES)
        q = parse_search(request.args.get("q"))
        sort = parse_choice(request.args.get("sort"), "Sort", INVENTORY_SORTS, "path")
        order = parse_choice(request.args.get("order"), "Order", ("asc", "desc"), "asc")
        page = parse_page(request.args.get("page"))
    except ValidationError as exc:
        _bad_request(exc)
    if dir_id is not None:
        authorize_directory(conn, dir_id, check_root=False)

    base = (
        "WITH inv AS ("
        " SELECT r.directory_id, r.rel_path, r.status, r.previous_hash, r.current_hash, r.size, r.error, r.scan_id"
        " FROM scan_results r WHERE r.scan_id = (SELECT MAX(s.id) FROM scan_history s"
        "   WHERE s.directory_id = r.directory_id AND s.status IN ('COMPLETED','PARTIAL'))"
        " UNION ALL"
        " SELECT b.directory_id, b.rel_path, 'BASELINED', b.sha256, b.sha256, b.size, NULL, NULL"
        " FROM file_baselines b WHERE NOT EXISTS (SELECT 1 FROM scan_history s WHERE s.directory_id = b.directory_id"
        "   AND s.status IN ('COMPLETED','PARTIAL'))) "
        "SELECT inv.*, d.label AS dir_label, d.path AS dir_path FROM inv "
        "JOIN monitored_directories d ON d.id = inv.directory_id")
    where, params = [], []
    if dir_id is not None:
        where.append("inv.directory_id = ?"); params.append(dir_id)
    if status:
        where.append("inv.status = ?"); params.append(status)
    if q:
        where.append("inv.rel_path LIKE ? ESCAPE '\\'"); params.append(f"%{escape_like(q)}%")
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total, pages, page, size, offset = paginate(conn, f"SELECT COUNT(*) FROM ({base}{clause})", params, page)
    order_sql = INVENTORY_SORTS[sort] + (" ASC" if order == "asc" else " DESC")  # both from allowlists
    rows = conn.execute(f"{base}{clause} ORDER BY {order_sql}, inv.rel_path LIMIT ? OFFSET ?",
                        params + [size, offset]).fetchall()
    dirs = conn.execute("SELECT id, label, path FROM monitored_directories ORDER BY id").fetchall()
    return render_template("file_inventory.html", rows=rows, dirs=dirs, total=total, page=page, pages=pages,
                           statuses=INVENTORY_STATUSES, f=dict(directory_id=dir_id, status=status or "", q=q,
                                                              sort=sort, order=order))


@bp.get("/inventory/detail")
def file_detail():
    conn = db.get_db()
    try:
        dir_id = parse_int(request.args.get("directory_id"), "Directory ID")
    except ValidationError as exc:
        _bad_request(exc)
    row = authorize_directory(conn, dir_id)
    rel = request.args.get("path", "")
    try:
        safe_join(row["path"], rel)  # proves containment; nothing is read from disk
    except (PathSecurityError, FileNotFoundError, OSError) as exc:
        abort(400, description=str(exc) if isinstance(exc, PathSecurityError) else "Invalid path.")
    base = conn.execute("SELECT * FROM file_baselines WHERE directory_id = ? AND rel_path = ?",
                        (row["id"], rel)).fetchone()
    results = conn.execute(
        "SELECT r.*, s.started_at FROM scan_results r JOIN scan_history s ON s.id = r.scan_id "
        "WHERE r.directory_id = ? AND r.rel_path = ? ORDER BY r.scan_id DESC LIMIT 20",
        (row["id"], rel)).fetchall()
    if base is None and not results:
        abort(404, description="File is not known to the monitor.")
    return render_template("file_detail.html", d=row, rel=rel, base=base, results=results)


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------
@bp.get("/events")
def events():
    conn = db.get_db()
    try:
        category = parse_choice(request.args.get("category"), "Category", EVENT_CATEGORIES)
        dir_id = parse_optional_int(request.args.get("directory_id"), "Directory ID")
        scan_id = parse_optional_int(request.args.get("scan_id"), "Scan ID")
        change = parse_choice(request.args.get("change"), "Change type", ("MODIFIED", "NEW", "DELETED"))
        q = parse_search(request.args.get("q"))
        page = parse_page(request.args.get("page"))
    except ValidationError as exc:
        _bad_request(exc)
    where, params = [], []
    if category:
        where.append("e.category = ?"); params.append(category)
    if dir_id is not None:
        where.append("e.directory_id = ?"); params.append(dir_id)
    if scan_id is not None:
        where.append("e.scan_id = ?"); params.append(scan_id)
    if change:
        where.append("e.change_type = ?"); params.append(change)
    if q:
        like = f"%{escape_like(q)}%"
        where.append("(e.rel_path LIKE ? ESCAPE '\\' OR e.description LIKE ? ESCAPE '\\' "
                     "OR e.directory_path LIKE ? ESCAPE '\\')")
        params += [like, like, like]
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    total, pages, page, size, offset = paginate(conn, f"SELECT COUNT(*) FROM security_events e{clause}", params, page)
    rows = conn.execute(f"SELECT e.* FROM security_events e{clause} ORDER BY e.timestamp DESC, e.id DESC "
                        f"LIMIT ? OFFSET ?", params + [size, offset]).fetchall()
    dirs = conn.execute("SELECT id, label, path FROM monitored_directories ORDER BY id").fetchall()
    return render_template("events.html", rows=rows, dirs=dirs, total=total, page=page, pages=pages,
                           categories=EVENT_CATEGORIES,
                           f=dict(category=category or "", directory_id=dir_id, scan_id=scan_id,
                                  change=change or "", q=q))


# ---------------------------------------------------------------------------
# scan history
# ---------------------------------------------------------------------------
@bp.get("/scans")
def scan_history():
    conn = db.get_db()
    try:
        page = parse_page(request.args.get("page"))
        dir_id = parse_optional_int(request.args.get("directory_id"), "Directory ID")
    except ValidationError as exc:
        _bad_request(exc)
    where, params = "", []
    if dir_id is not None:
        where, params = " WHERE s.directory_id = ?", [dir_id]
    total, pages, page, size, offset = paginate(conn, f"SELECT COUNT(*) FROM scan_history s{where}", params, page)
    rows = conn.execute(
        f"SELECT s.*, d.path AS dir_path, d.label AS dir_label FROM scan_history s "
        f"JOIN monitored_directories d ON d.id = s.directory_id{where} ORDER BY s.id DESC LIMIT ? OFFSET ?",
        params + [size, offset]).fetchall()
    dirs = conn.execute("SELECT id, label, path FROM monitored_directories ORDER BY id").fetchall()
    return render_template("scan_history.html", rows=rows, dirs=dirs, total=total, page=page, pages=pages,
                           f=dict(directory_id=dir_id), scan=None, results=None)


@bp.get("/scans/<scan_id>")
def scan_detail(scan_id):
    conn = db.get_db()
    try:
        sid = parse_int(scan_id, "Scan ID")
    except ValidationError as exc:
        _bad_request(exc)
    scan = conn.execute(
        "SELECT s.*, d.path AS dir_path, d.label AS dir_label FROM scan_history s "
        "JOIN monitored_directories d ON d.id = s.directory_id WHERE s.id = ?", (sid,)).fetchone()
    if scan is None:
        abort(404, description="Scan not found.")
    results = conn.execute(
        "SELECT * FROM scan_results WHERE scan_id = ? AND status <> 'UNCHANGED' ORDER BY status, rel_path "
        "LIMIT 500", (sid,)).fetchall()
    return render_template("scan_history.html", rows=[], dirs=[], total=0, page=1, pages=1, f={},
                           scan=scan, results=results)


# ---------------------------------------------------------------------------
# reports
# ---------------------------------------------------------------------------
@bp.get("/reports")
def reports_page():
    conn = db.get_db()
    dirs = conn.execute("SELECT id, label, path FROM monitored_directories ORDER BY id").fetchall()
    scans = conn.execute("SELECT s.id, s.started_at, s.status, d.label FROM scan_history s "
                         "JOIN monitored_directories d ON d.id = s.directory_id "
                         "WHERE s.status IN ('COMPLETED','PARTIAL') ORDER BY s.id DESC LIMIT 30").fetchall()
    return render_template("reports.html", dirs=dirs, scans=scans, statuses=STATUSES)


@bp.get("/reports/download")
def download_report():
    conn = db.get_db()
    try:
        scan_id = parse_optional_int(request.args.get("scan_id"), "Scan ID")
        dir_id = parse_optional_int(request.args.get("directory_id"), "Directory ID")
        status = parse_choice(request.args.get("status"), "Status", STATUSES)
    except ValidationError as exc:
        _bad_request(exc)
    if dir_id is not None:
        authorize_directory(conn, dir_id, check_root=False)
    if scan_id is not None:
        found = conn.execute("SELECT directory_id FROM scan_history WHERE id = ?", (scan_id,)).fetchone()
        if found is None:
            abort(404, description="Scan not found.")
        if dir_id is not None and found["directory_id"] != dir_id:
            abort(400, description="The scan does not belong to the selected directory.")
    csv_text = reports.build_report(conn, scan_id=scan_id, directory_id=dir_id, status=status)
    filename = reports.report_filename(scan_id)
    try:  # keep a local copy in the configured export folder (best effort)
        export_dir = Path(current_app.config["EXPORT_DIR"])
        (export_dir / filename).write_text(csv_text, encoding="utf-8", newline="")
    except OSError:
        current_app.logger.warning("Could not save report copy to export directory")
    return Response(csv_text, mimetype="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    })


# ---------------------------------------------------------------------------
# settings & monitoring
# ---------------------------------------------------------------------------
@bp.get("/settings")
def settings():
    conn = db.get_db()
    cfg = current_app.config
    info = {
        "version": cfg["APP_VERSION"],
        "algorithm": HASH_ALGORITHM,
        "database_status": db.check_database(conn),
        "log_location": str(Path(cfg["LOG_DIR"]).resolve()),
        "export_location": str(Path(cfg["EXPORT_DIR"]).resolve()),
        "min_interval": MIN_SCAN_INTERVAL,
        "max_interval": MAX_SCAN_INTERVAL,
    }
    return render_template("settings.html", info=info, monitor=_worker().status(conn))


@bp.post("/settings")
def update_settings():
    conn = db.get_db()
    try:
        interval = parse_int(request.form.get("scan_interval_seconds"), "Scan interval",
                             MIN_SCAN_INTERVAL, MAX_SCAN_INTERVAL)
    except ValidationError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("fim.settings"))
    enabled = "1" if request.form.get("periodic_enabled") == "on" else "0"
    conn.execute("BEGIN IMMEDIATE")
    try:
        db.set_setting(conn, "scan_interval_seconds", str(interval))
        db.set_setting(conn, "periodic_enabled", enabled)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    flash("Settings saved.", "success")
    return redirect(url_for("fim.settings"))


@bp.post("/monitoring/toggle")
def toggle_monitoring():
    conn = db.get_db()
    action = request.form.get("action")
    if action not in ("start", "stop"):
        abort(400, description="Unsupported monitoring action.")
    db.set_setting(conn, "periodic_enabled", "1" if action == "start" else "0")
    if action == "start":
        # The single worker thread is created once by the app factory; it simply
        # notices the setting. No thread is ever started from a request handler.
        flash("Periodic scanning enabled.", "success")
    else:
        flash("Periodic scanning disabled.", "success")
    return redirect(url_for("fim.dashboard"))


@bp.get("/about")
def about():
    return render_template("about.html", cfg_version=current_app.config["APP_VERSION"])
