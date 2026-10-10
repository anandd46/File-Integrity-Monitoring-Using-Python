"""Application-functionality tests through Flask's test client."""
import sqlite3
from unittest import mock

from helpers import baseline, db_rows, db_scalar, post, rebaseline, register, scan


def test_database_initialises_automatically(app):
    tables = {r["name"] for r in db_rows(app, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"monitored_directories", "file_baselines", "scan_history", "security_events",
            "application_settings", "scan_results"} <= tables
    assert db_scalar(app, "SELECT value FROM application_settings WHERE key='periodic_enabled'") == "0"
    conn = sqlite3.connect(app.config["DATABASE"])
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0  # per-connection; app enables it
    conn.close()


def test_every_page_renders(client):
    for url in ["/", "/directories", "/inventory", "/events", "/scans", "/reports", "/settings", "/about"]:
        resp = client.get(url)
        assert resp.status_code == 200, url


def test_dashboard_empty_state_and_actions(client):
    html = client.get("/").get_data(as_text=True)
    assert "Security Dashboard" in html
    assert "Getting started" in html
    for label in ("Register directory", "Create baseline", "Run scan", "View changes", "Export report"):
        assert label in html


def test_register_directory_and_duplicate_rejected(client, app, site):
    resp, dir_id = register(client, app, site, label="My site", category="source")
    assert dir_id is not None
    assert "Directory registered" in resp.get_data(as_text=True)
    resp2, _ = register(client, app, site)
    assert "already registered" in resp2.get_data(as_text=True)
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 1


def test_overlapping_directories_rejected(client, app, site):
    register(client, app, site)
    resp, _ = register(client, app, site / "templates")
    assert "overlaps" in resp.get_data(as_text=True)


def test_full_workflow_baseline_scan_modify_new_delete_rebaseline(client, app, site):
    _, dir_id = register(client, app, site)
    assert "Baseline created with 4 files" in baseline(client, dir_id).get_data(as_text=True)

    html = scan(client, dir_id).get_data(as_text=True)
    assert "0 modified, 0 new, 0 deleted, 4 unchanged" in html

    (site / "app.py").write_text("print('changed')\n")
    (site / "extra.txt").write_text("extra")
    (site / "config.ini").unlink()
    html = scan(client, dir_id).get_data(as_text=True)
    assert "1 modified, 1 new, 1 deleted, 2 unchanged" in html
    assert "not proof of malicious activity" in html

    statuses = {r["rel_path"]: r["status"] for r in db_rows(
        app, "SELECT rel_path, status FROM scan_results WHERE scan_id = (SELECT MAX(id) FROM scan_history)")}
    assert statuses["app.py"] == "MODIFIED" and statuses["extra.txt"] == "NEW" and statuses["config.ini"] == "DELETED"

    events = client.get("/events?category=FILE_CHANGE").get_data(as_text=True)
    assert "app.py" in events and "extra.txt" in events and "config.ini" in events

    assert "Baseline replaced" in rebaseline(client, dir_id).get_data(as_text=True)
    html = scan(client, dir_id).get_data(as_text=True)
    assert "0 modified, 0 new, 0 deleted, 4 unchanged" in html
    assert db_scalar(app, "SELECT COUNT(*) FROM scan_history WHERE status='COMPLETED'") == 3


def test_baseline_twice_is_refused(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    assert "already exists" in baseline(client, dir_id).get_data(as_text=True)


def test_rebaseline_and_remove_require_confirmation(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    (site / "app.py").write_text("changed")
    html = rebaseline(client, dir_id, confirm=False).get_data(as_text=True)
    assert "requires confirmation" in html
    # baseline untouched
    scan(client, dir_id)
    assert db_scalar(app, "SELECT COUNT(*) FROM scan_results WHERE status='MODIFIED'") == 1
    html = post(client, f"/directories/{dir_id}/remove").get_data(as_text=True)
    assert "requires confirmation" in html
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 1
    post(client, f"/directories/{dir_id}/remove", {"confirm": "yes"})
    assert db_scalar(app, "SELECT COUNT(*) FROM monitored_directories") == 0
    assert db_scalar(app, "SELECT COUNT(*) FROM file_baselines") == 0  # cascade
    assert (site / "app.py").exists()  # files on disk untouched


def test_events_scan_history_and_inventory_pages_show_data(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    (site / "app.py").write_text("changed")
    scan(client, dir_id)
    assert "MODIFIED" in client.get("/inventory?status=MODIFIED").get_data(as_text=True)
    assert "app.py" in client.get("/inventory?q=app").get_data(as_text=True)
    assert "Baselined" not in client.get("/inventory").get_data(as_text=True)
    assert "#1" in client.get("/scans").get_data(as_text=True)
    assert "app.py" in client.get("/scans/1").get_data(as_text=True)
    detail = client.get(f"/inventory/detail?directory_id={dir_id}&path=app.py")
    assert detail.status_code == 200 and "Baseline SHA-256" in detail.get_data(as_text=True)


def test_inventory_shows_baseline_before_first_scan(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    html = client.get("/inventory").get_data(as_text=True)
    assert "app.py" in html and "Baselined" in html


def test_events_are_newest_first_and_paginated(client, app, site):
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    for i in range(30):  # every iteration creates a distinct modification
        (site / "app.py").write_text(f"version {i}")
        scan(client, dir_id)
    ids = [r["id"] for r in db_rows(app, "SELECT id FROM security_events ORDER BY timestamp DESC, id DESC")]
    page1 = client.get("/events").get_data(as_text=True)
    assert "Page 1 of 2" in page1
    first_row_id = f"<tr><td>{ids[0]}</td>"
    assert first_row_id in page1
    assert "Page 2 of 2" in client.get("/events?page=2").get_data(as_text=True)
    assert client.get("/events?page=999").status_code == 200  # clamped, not an error


def test_settings_validation(client, app):
    ok = post(client, "/settings", {"scan_interval_seconds": "120", "periodic_enabled": "on"})
    assert "Settings saved" in ok.get_data(as_text=True)
    assert db_scalar(app, "SELECT value FROM application_settings WHERE key='scan_interval_seconds'") == "120"
    assert db_scalar(app, "SELECT value FROM application_settings WHERE key='periodic_enabled'") == "1"
    for bad in ("5", "999999", "abc", "-30", "30.5", "", "1e3"):
        resp = post(client, "/settings", {"scan_interval_seconds": bad})
        assert "Scan interval" in resp.get_data(as_text=True), bad
    assert db_scalar(app, "SELECT value FROM application_settings WHERE key='scan_interval_seconds'") == "120"


def test_settings_page_exposes_no_secrets(client, app):
    html = client.get("/settings").get_data(as_text=True)
    assert app.config["SECRET_KEY"] not in html
    for needle in ("Hashing algorithm", "SHA-256", "Log location", "Export location", "Database status", "OK"):
        assert needle in html


def test_monitoring_toggle_does_not_start_threads(client, app):
    import threading
    before = threading.active_count()
    post(client, "/monitoring/toggle", {"action": "start"})
    assert db_scalar(app, "SELECT value FROM application_settings WHERE key='periodic_enabled'") == "1"
    post(client, "/monitoring/toggle", {"action": "stop"})
    assert db_scalar(app, "SELECT value FROM application_settings WHERE key='periodic_enabled'") == "0"
    assert threading.active_count() == before
    assert post(client, "/monitoring/toggle", {"action": "explode"}).status_code == 400


def test_worker_start_is_idempotent_and_stops(app):
    worker = app.extensions["fim_worker"]
    assert worker.start() is True
    assert worker.start() is False  # no duplicate
    assert worker.is_alive()
    worker.stop()
    assert not worker.is_alive()


def test_periodic_worker_scans_and_records_history(app, site, client):
    from fim.monitoring import MonitorWorker
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    (site / "app.py").write_text("changed")
    worker = MonitorWorker(app.config["DATABASE"], {"MAX_FILES_PER_DIRECTORY": 1000,
                                                    "MAX_FILE_SIZE_BYTES": 10**9})
    from fim import database as db
    conn = db.connect(app.config["DATABASE"])
    db.set_setting(conn, "periodic_enabled", "1")
    worker._scan_all(conn)
    conn.close()
    assert db_scalar(app, "SELECT trigger_type FROM scan_history ORDER BY id DESC") == "PERIODIC"
    assert db_scalar(app, "SELECT COUNT(*) FROM security_events WHERE category='FILE_CHANGE'") == 1


def test_worker_exception_is_recorded_as_service_error(app, site, client):
    from fim.monitoring import MonitorWorker
    from fim import database as db
    _, dir_id = register(client, app, site)
    baseline(client, dir_id)
    worker = MonitorWorker(app.config["DATABASE"], {"MAX_FILES_PER_DIRECTORY": 1000,
                                                    "MAX_FILE_SIZE_BYTES": 10**9})
    from fim.scanner import ScanError
    conn = db.connect(app.config["DATABASE"])
    with mock.patch("fim.monitoring.run_scan", side_effect=ScanError("simulated failure")):
        worker._scan_all(conn)
    conn.close()
    assert db_scalar(app, "SELECT COUNT(*) FROM security_events WHERE category='SERVICE_ERROR'") == 1


def test_scan_all_without_baselines_is_friendly(client):
    html = post(client, "/scan-all").get_data(as_text=True)
    assert "No directory has a baseline" in html
