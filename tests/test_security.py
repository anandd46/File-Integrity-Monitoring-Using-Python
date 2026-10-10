"""Defensive web-application-security tests against this application only."""
import os
import re
from pathlib import Path
from unittest import mock

from helpers import baseline, csrf_token, db_rows, db_scalar, post, register, scan
from fim.security import PathSecurityError, safe_join, validate_directory_input


def _raises(exc_type, fn, *args):
    try:
        fn(*args)
    except exc_type:
        return
    raise AssertionError(f"{exc_type.__name__} not raised for {args!r}")


# ---------------------------------------------------------------- path traversal
def test_traversal_paths_rejected_on_registration(client, app, site):
    attempts = [
        str(site / ".." / ".." / "etc"),
        f"{site}/../..",
        "../../etc/passwd",
        "..\\..\\Windows\\System32",
        f"{site}/%2e%2e/%2e%2e",
        f"{site}%2f..%2f..",
        f"{site}/%252e%252e/",       # double encoded
        "/etc/../etc",
        "relative/path",
        "",
        "   ",
        "x" * 5000,
        f"{site}\x00/etc",
    ]
    for attempt in attempts:
        resp = post(client, "/directories/add", {"path": attempt})
        assert resp.status_code == 200
        assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 0, attempt
    assert "traversal" in post(client, "/directories/add", {"path": "../../etc"}).get_data(as_text=True).lower()


def test_nonexistent_and_file_paths_rejected(client, app, site):
    for bad in (str(site / "missing"), str(site / "app.py")):
        post(client, "/directories/add", {"path": bad})
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 0


def test_symlinked_directory_rejected(client, app, site, tmp_path):
    link = tmp_path / "linked"
    try:
        link.symlink_to(site, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    resp = post(client, "/directories/add", {"path": str(link)})
    assert "symbolic" in resp.get_data(as_text=True).lower()
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 0


def test_restricted_locations_rejected(client, app):
    candidates = ["/", "/etc", "/proc", "/sys", "/dev", "/usr/bin", "C:\\Windows", "C:\\"]
    for path in candidates:
        post(client, "/directories/add", {"path": path})
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 0


def test_application_runtime_directories_rejected(client, app, tmp_path):
    for target in (Path(app.config["DATABASE"]).parent, Path(app.config["LOG_DIR"]), Path(app.config["EXPORT_DIR"])):
        resp = post(client, "/directories/add", {"path": str(target)})
        assert "own data, logs or exports" in resp.get_data(as_text=True)
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 0
    # an ancestor of the runtime data would also contain the database
    resp = post(client, "/directories/add", {"path": str(tmp_path)})
    assert "own data, logs or exports" in resp.get_data(as_text=True)


def test_safe_join_blocks_escape_attempts(site, tmp_path):
    for rel in ("../outside.txt", "a/../../outside.txt", "/etc/passwd", "C:\\Windows\\win.ini", "%2e%2e/x", ""):
        _raises(PathSecurityError, safe_join, site, rel)
    assert safe_join(site, "templates/index.html") == (site / "templates" / "index.html").resolve()


def test_safe_join_blocks_symlink_escape(site, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("s")
    try:
        (site / "escape").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    _raises(PathSecurityError, safe_join, site, "escape/secret.txt")


def test_file_detail_route_cannot_reach_outside_root(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    for evil in ("../../etc/passwd", "/etc/passwd", "..%2f..%2fetc%2fpasswd", "templates/../../x"):
        resp = client.get("/inventory/detail", query_string={"directory_id": dir_id, "path": evil})
        assert resp.status_code == 400, evil
        assert "root:" not in resp.get_data(as_text=True)
    assert client.get(f"/inventory/detail?directory_id={dir_id}&path=not_monitored.txt").status_code == 404


def test_directory_id_alone_is_not_authorisation(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    import shutil
    moved = site.parent / "site_moved"
    site.rename(moved)
    site.mkdir()  # an unrelated empty directory now sits at the registered path
    # the stored path still passes safety checks, but a symlink swap must be refused:
    shutil.rmtree(site)
    try:
        site.symlink_to(moved, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    resp = client.post("/directories/%d/scan" % dir_id, data={"csrf_token": csrf_token(client)})
    assert resp.status_code == 409
    assert db_scalar(app, "SELECT COUNT(*) FROM scan_history") == 0


# ---------------------------------------------------------------- invalid IDs
def test_invalid_directory_and_scan_ids(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    scan(client, dir_id)
    for bad in ("abc", "1 OR 1=1", "1;DROP TABLE scan_history", "-1", "0", "99999999999", "%00", "1.5", "１２"):
        assert client.get(f"/scans/{bad}").status_code in (400, 404), bad
        assert client.get("/inventory", query_string={"directory_id": bad}).status_code == 400, bad
        assert client.get("/reports/download", query_string={"scan_id": bad}).status_code == 400, bad
        assert post(client, f"/directories/{bad}/scan").status_code in (400, 404), bad
    assert client.get("/scans/99999").status_code == 404
    assert client.get("/inventory?directory_id=99999").status_code == 404
    assert post(client, "/directories/99999/scan").status_code == 404
    assert client.get("/reports/download?scan_id=99999").status_code == 404
    assert db_scalar(app, "SELECT COUNT(*) FROM scan_history") == 1  # nothing bogus created


def test_pagination_and_filter_validation(client):
    for q in ("page=0", "page=-1", "page=abc", "page=1;DROP", "category=EVIL", "change=EVIL", "scan_id=x"):
        assert client.get("/events?" + q).status_code == 400, q
    for q in ("status=EVIL", "sort=rel_path;DROP TABLE x", "order=sideways", "page=abc"):
        assert client.get("/inventory?" + q).status_code == 400, q
    assert client.get("/events?q=" + "a" * 101).status_code == 400
    assert client.get("/events?q=%00").status_code == 400
    assert client.get("/reports/download?status=EVIL").status_code == 400


# ---------------------------------------------------------------- SQL injection
def test_sql_injection_style_inputs_do_not_bypass_logic(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    (site / "app.py").write_text("changed")
    scan(client, dir_id)
    total_events = db_scalar(app, "SELECT COUNT(*) FROM security_events")
    payloads = ["' OR '1'='1", "' OR 1=1 --", "'; DROP TABLE security_events; --", "%' OR '%'='",
                "\" OR \"\"=\"", "1' UNION SELECT sha256,1,1,1,1,1,1,1,1,1 FROM file_baselines--", "_", "%", "\\"]
    for p in payloads:
        resp = client.get("/events", query_string={"q": p})
        assert resp.status_code == 200, p
        resp2 = client.get("/inventory", query_string={"q": p})
        assert resp2.status_code == 200
    # the injection payload must match literally, never everything
    html = client.get("/events", query_string={"q": "' OR '1'='1"}).get_data(as_text=True)
    assert "No matching events" in html
    # wildcards are escaped: '%' alone must not match unrelated rows
    assert "No matching events" in client.get("/events", query_string={"q": "%zzz%"}).get_data(as_text=True)
    assert db_scalar(app, "SELECT COUNT(*) FROM security_events") == total_events
    assert db_scalar(app, "SELECT COUNT(*) FROM sqlite_master WHERE name='security_events'") == 1
    # SQL text as an ID is rejected, not executed
    assert client.get("/events", query_string={"directory_id": "1 OR 1=1"}).status_code == 400
    assert client.get("/inventory", query_string={"sort": "path; DROP TABLE file_baselines"}).status_code == 400
    assert db_scalar(app, "SELECT COUNT(*) FROM file_baselines") == 4


def test_sql_injection_in_registration_fields(client, app, site):
    label = "x'); DROP TABLE monitored_directories;--"
    resp, dir_id = register(client, app, site, label=label)
    assert dir_id is not None
    assert db_scalar(app, "SELECT label FROM monitored_directories") == label  # stored verbatim, inert
    assert db_scalar(app, "SELECT COUNT(*) FROM sqlite_master WHERE name='monitored_directories'") == 1


# ---------------------------------------------------------------- XSS
XSS_NAME = "<script>alert(1)</script>.txt"


def _make_xss_file(site):
    try:
        (site / XSS_NAME).write_text("x")
        return True
    except OSError:
        return False  # e.g. Windows forbids < and > in file names


def test_malicious_filename_and_label_rendered_as_text(client, app, site):
    label = "<img src=x onerror=alert(1)>"
    created = _make_xss_file(site)
    _, dir_id = register(client, app, site, label=label)
    baseline(client, dir_id)
    (site / "app.py").write_text("changed")
    scan(client, dir_id)
    pages = ["/directories", "/inventory", "/events", "/scans", "/", "/reports", "/scans/1"]
    for url in pages:
        html = client.get(url).get_data(as_text=True)
        assert "<img src=x onerror" not in html, url
        assert "<script>alert(1)" not in html, url
        if created and url in ("/inventory", "/events"):
            assert "&lt;script&gt;alert(1)&lt;/script&gt;.txt" in html or XSS_NAME not in html
    if created:
        assert "&lt;script&gt;alert(1)&lt;/script&gt;.txt" in client.get("/inventory").get_data(as_text=True)
    assert "&lt;img src=x onerror=alert(1)&gt;" in client.get("/directories").get_data(as_text=True)


def test_search_text_is_escaped_when_echoed(client):
    html = client.get("/events", query_string={"q": '"><script>alert(1)</script>'}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&gt;&lt;script&gt;" in html or "&#34;&gt;&lt;script&gt;" in html


def test_chart_data_attribute_is_safe(client, app, site):
    _make_xss_file(site)
    _, dir_id = register(client, app, site, label="x")
    baseline(client, dir_id)
    scan(client, dir_id)
    html = client.get("/").get_data(as_text=True)
    assert "data-chart='" in html
    assert "</script>" not in re.search(r"data-chart='([^']*)'", html).group(1)


def test_no_innerhtml_in_javascript():
    js = (Path(__file__).resolve().parent.parent / "static" / "js" / "app.js").read_text()
    assert "innerHTML" not in js and "outerHTML" not in js and "document.write" not in js and "eval(" not in js


def test_templates_have_no_inline_scripts_or_handlers():
    tdir = Path(__file__).resolve().parent.parent / "templates"
    for tpl in tdir.glob("*.html"):
        text = tpl.read_text()
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), tpl.name
        assert not re.search(r"\son[a-z]+\s*=", text), tpl.name
        assert "|safe" not in text, tpl.name
        assert 'style="' not in text, tpl.name


# ---------------------------------------------------------------- CSRF
STATE_CHANGING = [
    ("/directories/add", {"path": "/tmp"}),
    ("/directories/1/remove", {"confirm": "yes"}),
    ("/directories/1/baseline", {}),
    ("/directories/1/rebaseline", {"confirm": "yes"}),
    ("/directories/1/scan", {}),
    ("/scan-all", {}),
    ("/settings", {"scan_interval_seconds": "60"}),
    ("/monitoring/toggle", {"action": "start"}),
]


def test_csrf_missing_token_rejected(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    for url, data in STATE_CHANGING:
        resp = client.post(url, data=data)
        assert resp.status_code == 400, url
        assert "CSRF" in resp.get_data(as_text=True), url
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 1
    assert db_scalar(app, "SELECT value FROM application_settings WHERE key='periodic_enabled'") == "0"


def test_csrf_invalid_and_foreign_session_tokens_rejected(client, app):
    csrf_token(client)  # establish a session token
    for url, data in STATE_CHANGING:
        assert client.post(url, data={**data, "csrf_token": "forged"}).status_code == 400, url
    other = app.test_client()
    foreign = csrf_token(other)
    assert client.post("/scan-all", data={"csrf_token": foreign}).status_code == 400


def test_csrf_token_via_header_accepted_and_valid_form_token_works(client):
    token = csrf_token(client)
    assert client.post("/scan-all", headers={"X-CSRF-Token": token}).status_code == 302
    assert client.post("/scan-all", data={"csrf_token": token}).status_code == 302


def test_state_changing_urls_reject_get(client):
    for url, _ in STATE_CHANGING:
        if url == "/settings":
            continue  # /settings has a read-only GET page; its POST is covered by the CSRF tests
        assert client.get(url).status_code == 405, url


# ---------------------------------------------------------------- headers, errors, config
def test_security_headers_present(client):
    resp = client.get("/")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp and "object-src 'none'" in csp
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["Cache-Control"] == "no-store"


def test_session_cookie_flags(client):
    resp = client.get("/")
    cookie = resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_secure_defaults():
    from config import Config
    assert Config.DEBUG is False
    assert Config.HOST == "127.0.0.1"
    assert Config.FOLLOW_SYMLINKS is False
    src = (Path(__file__).resolve().parent.parent / "app.py").read_text()
    assert "debug=False" in src


def test_error_pages_do_not_leak_details(client, app):
    resp = client.get("/no-such-page")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 404 and "Traceback" not in html
    with mock.patch("fim.routes.paginate", side_effect=RuntimeError("super-secret-internal-detail")):
        resp = client.get("/events")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 500
    assert "super-secret-internal-detail" not in html and "Traceback" not in html
    assert app.config["SECRET_KEY"] not in html
    assert client.put("/").status_code in (400, 405)  # CSRF check or method check; never 200


def test_oversized_request_rejected(client):
    big = "A" * (70 * 1024)
    assert client.post("/directories/add", data={"path": big, "csrf_token": "x"}).status_code == 413


def test_baseline_database_not_exposed_via_static(client, app):
    assert client.get("/static/../data/fim.sqlite3").status_code == 404
    assert client.get("/static/%2e%2e/config.py").status_code == 404
