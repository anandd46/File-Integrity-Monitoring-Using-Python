"""Application factory for the File Integrity Monitor."""
from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, render_template
from werkzeug.exceptions import HTTPException

from config import APP_VERSION, Config
from . import database as db
from .monitoring import MonitorWorker
from .security import apply_security_headers, get_csrf_token, validate_csrf


def _configure_logging(app: Flask) -> None:
    log_dir = Path(app.config["LOG_DIR"])
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(log_dir / "fim.log", maxBytes=512 * 1024, backupCount=3,
                                      encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handler.setLevel(logging.INFO)
        root = logging.getLogger("fim")
        root.setLevel(logging.INFO)
        if not any(isinstance(h, RotatingFileHandler) and h.baseFilename == handler.baseFilename
                   for h in root.handlers):
            root.addHandler(handler)
        app.logger.addHandler(handler)
    except OSError:
        pass  # logging to file is best effort


def create_app(config_object=Config, overrides: dict | None = None) -> Flask:
    base = Path(__file__).resolve().parent.parent
    app = Flask(__name__, template_folder=str(base / "templates"), static_folder=str(base / "static"))
    app.config.from_object(config_object)
    if overrides:
        app.config.update(overrides)
    app.config["APP_VERSION"] = APP_VERSION

    for key in ("LOG_DIR", "EXPORT_DIR"):
        Path(app.config[key]).mkdir(parents=True, exist_ok=True)
    _configure_logging(app)
    db.init_db(app.config["DATABASE"])

    app.teardown_appcontext(db.close_db)
    app.before_request(validate_csrf)
    app.after_request(apply_security_headers)
    app.jinja_env.autoescape = True
    app.jinja_env.globals["csrf_token"] = get_csrf_token

    from .routes import bp
    app.register_blueprint(bp)

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        code = err.code or 500
        message = err.description if 400 <= code < 500 else "The server could not complete the request."
        return render_template("error.html", code=code, name=err.name, message=message), code

    @app.errorhandler(Exception)
    def _unhandled(err: Exception):
        app.logger.exception("Unhandled error")  # details go to the log only
        return render_template("error.html", code=500, name="Internal Server Error",
                               message="Something went wrong. The error was logged."), 500

    # The worker is created ONCE here, never inside a request handler.
    worker = MonitorWorker(app.config["DATABASE"], {
        "MAX_FILES_PER_DIRECTORY": app.config["MAX_FILES_PER_DIRECTORY"],
        "MAX_FILE_SIZE_BYTES": app.config["MAX_FILE_SIZE_BYTES"],
    })
    app.extensions["fim_worker"] = worker
    if app.config.get("START_WORKER") and not app.debug:
        worker.start()
    return app
