import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for entry in (str(ROOT), str(ROOT / "tests")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from config import TestConfig  # noqa: E402
from fim import create_app  # noqa: E402


@pytest.fixture
def app(tmp_path):
    """Application bound to an isolated temporary database, log and export folder."""
    return create_app(TestConfig, {
        "DATABASE": str(tmp_path / "appdata" / "fim.sqlite3"),
        "LOG_DIR": str(tmp_path / "applogs"),
        "EXPORT_DIR": str(tmp_path / "appexports"),
    })


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def site(tmp_path):
    """A small fake web-app directory used as the monitored target."""
    root = tmp_path / "site"
    (root / "templates").mkdir(parents=True)
    (root / "static").mkdir()
    (root / "app.py").write_text("print('hello')\n")
    (root / "config.ini").write_text("debug = false\n")
    (root / "templates" / "index.html").write_text("<h1>Home</h1>\n")
    (root / "static" / "site.js").write_text("console.log('ok');\n")
    return root
