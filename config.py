"""Application configuration.

All secrets are read from environment variables. Nothing sensitive is
hardcoded. See ``.env.example`` for the supported variable names.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
APP_VERSION = "1.0.0"
HASH_ALGORITHM = "SHA-256"

MIN_SCAN_INTERVAL = 30          # seconds
MAX_SCAN_INTERVAL = 86400       # 24 hours
DEFAULT_SCAN_INTERVAL = 300     # 5 minutes


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no extra dependency). Existing env vars win."""
    if not path.is_file():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            os.environ.setdefault(key, value)
    except OSError:
        pass


_load_dotenv(BASE_DIR / ".env")


class Config:
    # If FIM_SECRET_KEY is not provided, a random key is generated for this
    # process only. Sessions (and CSRF tokens) then reset on every restart,
    # which is safe for a local single-user tool.
    SECRET_KEY = os.environ.get("FIM_SECRET_KEY") or secrets.token_hex(32)

    DEBUG = False  # never enabled by default; see app.py
    TESTING = False

    DATABASE = os.environ.get("FIM_DATABASE", str(BASE_DIR / "data" / "fim.sqlite3"))
    LOG_DIR = os.environ.get("FIM_LOG_DIR", str(BASE_DIR / "logs"))
    EXPORT_DIR = os.environ.get("FIM_EXPORT_DIR", str(BASE_DIR / "exports"))

    HOST = os.environ.get("FIM_HOST", "127.0.0.1")
    PORT = int(os.environ.get("FIM_PORT", "5000"))

    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("FIM_COOKIE_SECURE", "0") == "1"
    SESSION_COOKIE_NAME = "fim_session"

    MAX_CONTENT_LENGTH = 64 * 1024  # forms are tiny; reject large bodies

    # Scanner limits
    MAX_FILES_PER_DIRECTORY = int(os.environ.get("FIM_MAX_FILES", "20000"))
    MAX_FILE_SIZE_BYTES = int(os.environ.get("FIM_MAX_FILE_SIZE", str(512 * 1024 * 1024)))
    FOLLOW_SYMLINKS = False  # fixed by design

    START_WORKER = True      # background worker is started once from create_app
    PAGE_SIZE = 25


class TestConfig(Config):
    TESTING = True
    START_WORKER = False
    SECRET_KEY = "test-only-secret-not-for-production"
    WTF_CSRF_ENABLED = True
