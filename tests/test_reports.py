import csv
import io
import re
from pathlib import Path

from fim.reports import CSV_COLUMNS, report_filename, sanitize_cell
from helpers import baseline, db_rows, post, register, scan


def _rows(resp):
    return list(csv.reader(io.StringIO(resp.get_data(as_text=True))))


def test_sanitize_cell_neutralises_formulas():
    assert sanitize_cell("=SUM(A1:A9)") == "'=SUM(A1:A9)"
    assert sanitize_cell("+1+1") == "'+1+1"
    assert sanitize_cell("-2+3") == "'-2+3"
    assert sanitize_cell("@cmd") == "'@cmd"
    assert sanitize_cell("\t=1") == "'\t=1"
    assert sanitize_cell("normal/path.txt") == "normal/path.txt"
    assert sanitize_cell(None) == ""
    assert sanitize_cell(42) == "42"


def test_report_filename_is_safe():
    for sid in (None, 7):
        name = report_filename(sid)
        assert re.fullmatch(r"fim_report_(latest|scan[0-9]+)_[0-9]{8}_[0-9]{6}\.csv", name), name


def test_csv_report_content_and_headers(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    (site / "app.py").write_text("changed")
    (site / "new.txt").write_text("n")
    (site / "config.ini").unlink()
    scan(client, dir_id)
    resp = client.get("/reports/download")
    assert resp.status_code == 200
    assert resp.mimetype == "text/csv"
    disposition = resp.headers["Content-Disposition"]
    assert disposition.startswith("attachment; filename=\"fim_report_latest_") and disposition.endswith(".csv\"")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    rows = _rows(resp)
    assert rows[0] == CSV_COLUMNS
    by_path = {r[3]: r for r in rows[1:]}
    assert by_path["app.py"][4] == "MODIFIED" and len(by_path["app.py"][5]) == 64 and len(by_path["app.py"][6]) == 64
    assert by_path["new.txt"][4] == "NEW" and by_path["new.txt"][5] == ""
    assert by_path["config.ini"][4] == "DELETED" and by_path["config.ini"][6] == ""
    assert by_path["app.py"][7] == str(len("changed"))
    assert all(r[0] and r[1] == "1" for r in rows[1:])  # generation time and scan id present


def test_report_filters_and_specific_scan(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    scan(client, dir_id)                      # scan 1: clean
    (site / "app.py").write_text("changed")
    scan(client, dir_id)                      # scan 2: one modification
    only_mod = _rows(client.get("/reports/download?status=MODIFIED"))
    assert [r[3] for r in only_mod[1:]] == ["app.py"]
    scan1 = _rows(client.get("/reports/download?scan_id=1"))
    assert all(r[4] == "UNCHANGED" for r in scan1[1:]) and len(scan1) == 5
    assert client.get("/reports/download?scan_id=1&directory_id=%d" % dir_id).status_code == 200


def test_report_scan_must_belong_to_directory(client, app, site, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "f.txt").write_text("x")
    _, d1 = register(client, app, site)
    _, d2 = register(client, app, other)
    baseline(client, d1)
    scan(client, d1)
    assert client.get(f"/reports/download?scan_id=1&directory_id={d2}").status_code == 400


def test_report_neutralises_formula_filenames(client, app, site):
    name = "=HYPERLINK(\"http://evil.example\",\"x\").txt"
    try:
        (site / name).write_text("x")
    except OSError:
        name = "=1+1.txt"
        (site / name).write_text("x")
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    scan(client, dir_id)
    rows = _rows(client.get("/reports/download"))
    cells = [r[3] for r in rows[1:] if "=" in r[3]]
    assert cells and all(c.startswith("'=") for c in cells)
    # no cell in the whole file starts with a formula character
    for row in rows[1:]:
        for cell in (row[2], row[3], row[8]):
            assert not cell.startswith(("=", "+", "-", "@"))


def test_report_copy_saved_to_export_dir_and_no_secrets(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    scan(client, dir_id)
    resp = client.get("/reports/download")
    saved = list(Path(app.config["EXPORT_DIR"]).glob("fim_report_*.csv"))
    assert len(saved) == 1
    body = resp.get_data(as_text=True)
    assert app.config["SECRET_KEY"] not in body
    assert "SECRET" not in body.upper().replace("SECRETS", "")


def test_empty_report_has_only_header(client):
    rows = _rows(client.get("/reports/download"))
    assert rows == [CSV_COLUMNS]


def test_report_includes_inspection_errors(client, app, site):
    from unittest import mock
    from fim.hashing import HashError
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    real = __import__("fim.scanner", fromlist=["hash_file"]).hash_file

    def fake(path, *a, **k):
        if str(path).endswith("app.py"):
            raise HashError("PERMISSION", "Permission denied")
        return real(path, *a, **k)

    with mock.patch("fim.scanner.hash_file", side_effect=fake):
        scan(client, dir_id)
    rows = _rows(client.get("/reports/download?status=ERROR"))
    assert rows[1][3] == "app.py" and rows[1][8] == "Permission denied"
