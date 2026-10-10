"""Integrity engine tests: baseline, classification, rebaseline, errors, partial scans."""
import hashlib
import os
from unittest import mock

from fim import database as db
from fim.hashing import HashError
from fim.scanner import SCAN_LOCK, ScanBusy, ScanError, create_baseline, run_scan, walk_directory


def _setup(app, site):
    """Register `site` directly in the DB and return (conn, directory_row)."""
    conn = db.connect(app.config["DATABASE"])
    conn.execute("INSERT INTO monitored_directories (label, path, category, created_at) VALUES (?,?,?,?)",
                 ("site", str(site.resolve()), "source", db.utcnow()))
    row = conn.execute("SELECT * FROM monitored_directories").fetchone()
    return conn, row


def _statuses(conn, scan_id):
    return {r["rel_path"]: r["status"] for r in
            conn.execute("SELECT rel_path, status FROM scan_results WHERE scan_id=?", (scan_id,))}


def _expect(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type as exc:
        return exc
    raise AssertionError(f"{exc_type.__name__} not raised")


def test_baseline_records_real_sha256_and_metadata(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    rows = {r["rel_path"]: r for r in conn.execute("SELECT * FROM file_baselines")}
    assert set(rows) == {"app.py", "config.ini", "templates/index.html", "static/site.js"}
    expected = hashlib.sha256((site / "app.py").read_bytes()).hexdigest()
    assert rows["app.py"]["sha256"] == expected
    assert rows["app.py"]["size"] == (site / "app.py").stat().st_size
    assert rows["app.py"]["baseline_at"]
    conn.close()


def test_unchanged_scan(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    result = run_scan(conn, d, app.config)
    assert result["status"] == "COMPLETED"
    assert result["counts"]["UNCHANGED"] == 4
    assert result["counts"]["MODIFIED"] == result["counts"]["NEW"] == result["counts"]["DELETED"] == 0
    # unchanged files must not produce file-change events
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE category='FILE_CHANGE'").fetchone()[0] == 0
    conn.close()


def test_modified_new_and_deleted_detected(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    old_hash = conn.execute("SELECT sha256 FROM file_baselines WHERE rel_path='app.py'").fetchone()[0]
    (site / "app.py").write_text("print('tampered')\n")
    (site / "added.php").write_text("<?php // new file ?>")
    (site / "config.ini").unlink()
    result = run_scan(conn, d, app.config)
    st = _statuses(conn, result["scan_id"])
    assert st["app.py"] == "MODIFIED"
    assert st["added.php"] == "NEW"
    assert st["config.ini"] == "DELETED"
    assert st["static/site.js"] == "UNCHANGED"
    ev = conn.execute("SELECT * FROM security_events WHERE rel_path='app.py' AND category='FILE_CHANGE'").fetchone()
    assert ev["change_type"] == "MODIFIED" and ev["previous_hash"] == old_hash
    assert ev["current_hash"] == hashlib.sha256(b"print('tampered')\n").hexdigest()
    assert ev["scan_id"] == result["scan_id"]
    conn.close()


def test_scan_never_updates_baseline(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    before = {r["rel_path"]: r["sha256"] for r in conn.execute("SELECT rel_path, sha256 FROM file_baselines")}
    (site / "app.py").write_text("changed")
    run_scan(conn, d, app.config)
    run_scan(conn, d, app.config)
    after = {r["rel_path"]: r["sha256"] for r in conn.execute("SELECT rel_path, sha256 FROM file_baselines")}
    assert before == after
    # still MODIFIED on the next scan: modified files are not silently trusted
    third = run_scan(conn, d, app.config)
    assert third["counts"]["MODIFIED"] == 1
    conn.close()


def test_repeated_scans_do_not_repeat_alerts(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    (site / "app.py").write_text("changed")
    run_scan(conn, d, app.config)
    first = conn.execute("SELECT COUNT(*) FROM security_events WHERE category='FILE_CHANGE'").fetchone()[0]
    run_scan(conn, d, app.config)
    run_scan(conn, d, app.config)
    again = conn.execute("SELECT COUNT(*) FROM security_events WHERE category='FILE_CHANGE'").fetchone()[0]
    assert first == 1 and again == 1
    conn.close()


def test_further_change_after_modification_creates_new_event(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    (site / "app.py").write_text("v2")
    run_scan(conn, d, app.config)
    (site / "app.py").write_text("v3")
    run_scan(conn, d, app.config)
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE category='FILE_CHANGE'").fetchone()[0] == 2
    conn.close()


def test_baseline_cannot_be_replaced_without_explicit_flag(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    exc = _expect(ScanError, create_baseline, conn, d, app.config, replace=False)
    assert "rebaseline" in str(exc).lower()
    conn.close()


def test_rebaseline_makes_current_state_the_reference(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    (site / "app.py").write_text("legitimate change")
    (site / "new.txt").write_text("n")
    (site / "config.ini").unlink()
    assert run_scan(conn, d, app.config)["counts"]["MODIFIED"] == 1
    res = create_baseline(conn, d, app.config, replace=True)
    assert res["replaced"] is True
    clean = run_scan(conn, d, app.config)
    assert clean["status"] == "COMPLETED"
    assert clean["counts"]["UNCHANGED"] == 4
    assert clean["counts"]["MODIFIED"] == clean["counts"]["NEW"] == clean["counts"]["DELETED"] == 0
    ev = conn.execute("SELECT description FROM security_events WHERE category='BASELINE_CHANGE' "
                      "ORDER BY id DESC").fetchone()[0]
    assert "REPLACED" in ev and "1 modified" in ev and "1 new" in ev and "1 removed" in ev
    conn.close()


def test_unreadable_file_is_error_not_deleted(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    real = __import__("fim.scanner", fromlist=["hash_file"]).hash_file

    def fake(path, *a, **k):
        if str(path).endswith("app.py"):
            raise HashError("PERMISSION", "Permission denied")
        return real(path, *a, **k)

    with mock.patch("fim.scanner.hash_file", side_effect=fake):
        result = run_scan(conn, d, app.config)
    st = _statuses(conn, result["scan_id"])
    assert st["app.py"] == "ERROR"
    assert "DELETED" not in st.values()
    assert result["status"] == "PARTIAL"
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE category='INSPECTION_ERROR'").fetchone()[0] == 1
    assert conn.execute("SELECT status FROM scan_history WHERE id=?", (result["scan_id"],)).fetchone()[0] == "PARTIAL"
    conn.close()


def test_real_permission_error_when_not_root(app, site):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return  # permissions are not enforced for root; the mocked test above covers the logic
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    target = site / "config.ini"
    target.chmod(0)
    try:
        result = run_scan(conn, d, app.config)
        assert _statuses(conn, result["scan_id"])["config.ini"] == "ERROR"
    finally:
        target.chmod(0o600)
    conn.close()


def test_unlistable_subdirectory_is_error_not_deleted(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    real_walk = os.walk

    def fake_walk(top, topdown=True, onerror=None, followlinks=False):
        for entry in real_walk(top, topdown=topdown, onerror=onerror, followlinks=followlinks):
            current, dirnames, filenames = entry
            if os.path.basename(current) == "templates":
                continue
            if current == str(top) and "templates" in dirnames and onerror:
                onerror(PermissionError(13, "denied", os.path.join(str(top), "templates")))
            yield entry

    with mock.patch("fim.scanner.os.walk", side_effect=fake_walk):
        result = run_scan(conn, d, app.config)
    st = _statuses(conn, result["scan_id"])
    assert st["templates/index.html"] == "ERROR"
    assert result["status"] == "PARTIAL"
    conn.close()


def test_missing_root_is_failed_scan_without_false_deletions(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    import shutil
    shutil.rmtree(site)
    result = run_scan(conn, d, app.config)
    assert result["status"] == "FAILED"
    assert conn.execute("SELECT COUNT(*) FROM scan_results WHERE status='DELETED'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM file_baselines").fetchone()[0] == 4  # baseline intact
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE category='SCAN_FAILURE'").fetchone()[0] == 1
    conn.close()


def test_failed_baseline_keeps_existing_baseline(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    old = [tuple(r) for r in conn.execute("SELECT rel_path, sha256 FROM file_baselines ORDER BY rel_path")]
    (site / "app.py").write_text("changed")
    with mock.patch("fim.scanner.hash_file", side_effect=HashError("PERMISSION", "Permission denied")):
        _expect(ScanError, create_baseline, conn, d, app.config, replace=True)
    new = [tuple(r) for r in conn.execute("SELECT rel_path, sha256 FROM file_baselines ORDER BY rel_path")]
    assert old == new
    assert conn.execute("SELECT COUNT(*) FROM security_events WHERE category='SCAN_FAILURE'").fetchone()[0] == 1
    conn.close()


def test_unexpected_exception_rolls_back_and_marks_scan_failed(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    before = [tuple(r) for r in conn.execute("SELECT rel_path, sha256 FROM file_baselines")]
    with mock.patch("fim.scanner.walk_directory", side_effect=RuntimeError("boom-secret")):
        exc = _expect(ScanError, run_scan, conn, d, app.config)
    assert "boom-secret" not in str(exc)
    assert conn.execute("SELECT status FROM scan_history ORDER BY id DESC").fetchone()[0] == "FAILED"
    assert before == [tuple(r) for r in conn.execute("SELECT rel_path, sha256 FROM file_baselines")]
    conn.close()


def test_scan_requires_a_baseline(app, site):
    conn, d = _setup(app, site)
    exc = _expect(ScanError, run_scan, conn, d, app.config)
    assert "baseline" in str(exc).lower()
    conn.close()


def test_overlapping_scans_are_refused(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    assert SCAN_LOCK.acquire(blocking=False)
    try:
        _expect(ScanBusy, run_scan, conn, d, app.config)
    finally:
        SCAN_LOCK.release()
    conn.close()


def test_symlinks_are_skipped_not_followed(app, site, tmp_path):
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("outside")
    try:
        (site / "link.txt").symlink_to(outside)
        (site / "linkdir").symlink_to(tmp_path, target_is_directory=True)
    except (OSError, NotImplementedError):
        return
    walked = walk_directory(site, 1000)
    assert "link.txt" not in walked.files
    assert not any(k.startswith("linkdir") for k in walked.files)
    assert walked.skipped_links == 2


def test_file_limit_makes_scan_partial_and_skips_deletion_checks(app, site):
    conn, d = _setup(app, site)
    create_baseline(conn, d, app.config, replace=False)
    (site / "app.py").unlink()
    result = run_scan(conn, d, {**app.config, "MAX_FILES_PER_DIRECTORY": 2})
    assert result["status"] == "PARTIAL"
    assert result["counts"]["DELETED"] == 0
    conn.close()
