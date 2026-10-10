"""CSV report generation with formula-injection protection."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

from . import database as db

CSV_COLUMNS = [
    "report_generated_at", "scan_id", "monitored_directory", "relative_path",
    "integrity_status", "previous_hash", "current_hash", "file_size_bytes", "inspection_error",
]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def sanitize_cell(value) -> str:
    """Neutralise spreadsheet formula injection.

    Cells beginning with =, +, - or @ (or a tab/CR/LF) can be executed as
    formulas by Excel/LibreOffice. A leading apostrophe forces text.
    """
    if value is None:
        return ""
    text = str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def report_filename(scan_id: int | None = None) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = f"_scan{int(scan_id)}" if scan_id is not None else "_latest"
    return f"fim_report{suffix}_{stamp}.csv"  # built only from integers/time: always safe


def build_report(conn, *, scan_id: int | None, directory_id: int | None, status: str | None) -> str:
    """Return CSV text. All filters are bound parameters."""
    where, params = [], []
    if scan_id is not None:
        where.append("r.scan_id = ?")
        params.append(scan_id)
    else:
        where.append("r.scan_id = (SELECT MAX(s.id) FROM scan_history s WHERE s.directory_id = r.directory_id "
                     "AND s.status IN ('COMPLETED','PARTIAL'))")
    if directory_id is not None:
        where.append("r.directory_id = ?")
        params.append(directory_id)
    if status:
        where.append("r.status = ?")
        params.append(status)
    sql = ("SELECT r.scan_id, d.path AS dir_path, r.rel_path, r.status, r.previous_hash, r.current_hash, "
           "r.size, r.error FROM scan_results r JOIN monitored_directories d ON d.id = r.directory_id "
           "WHERE " + " AND ".join(where) + " ORDER BY r.directory_id, r.rel_path")
    generated = db.utcnow()
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for row in conn.execute(sql, params):
        writer.writerow([
            generated, row["scan_id"], sanitize_cell(row["dir_path"]), sanitize_cell(row["rel_path"]),
            row["status"], row["previous_hash"] or "", row["current_hash"] or "",
            "" if row["size"] is None else row["size"], sanitize_cell(row["error"]),
        ])
    return buf.getvalue()
