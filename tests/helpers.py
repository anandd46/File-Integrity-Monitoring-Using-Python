"""Shared helpers for the test-suite (plain functions, no pytest dependency)."""
from __future__ import annotations

import re

from fim import database as db


def csrf_token(client) -> str:
    """Load a page and read the CSRF token that the server embedded in it."""
    html = client.get("/about").get_data(as_text=True)
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    assert match, "CSRF token meta tag missing"
    return match.group(1)


def post(client, url, data=None, token=True, follow=True):
    payload = dict(data or {})
    if token is True:
        payload["csrf_token"] = csrf_token(client)
    elif token:
        payload["csrf_token"] = token
    return client.post(url, data=payload, follow_redirects=follow)


def db_rows(app, sql, params=()):
    conn = db.connect(app.config["DATABASE"])
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def db_scalar(app, sql, params=()):
    rows = db_rows(app, sql, params)
    return rows[0][0] if rows else None


def register(client, app, path, label="", category="other"):
    resp = post(client, "/directories/add", {"path": str(path), "label": label, "category": category})
    row = db_rows(app, "SELECT id FROM monitored_directories WHERE path = ?", (str(path.resolve()),))
    return resp, (row[0]["id"] if row else None)


def baseline(client, dir_id):
    return post(client, f"/directories/{dir_id}/baseline")


def scan(client, dir_id):
    return post(client, f"/directories/{dir_id}/scan")


def rebaseline(client, dir_id, confirm=True):
    return post(client, f"/directories/{dir_id}/rebaseline", {"confirm": "yes"} if confirm else {})
