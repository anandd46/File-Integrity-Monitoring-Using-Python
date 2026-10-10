"""Web-application security helpers.

Everything that decides whether user-supplied input is acceptable lives here:
path validation and containment, input parsing, CSRF protection and HTTP
security headers.
"""
from __future__ import annotations

import hmac
import os
import re
import secrets
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import unquote

from flask import abort, current_app, request, session

MAX_PATH_LENGTH = 4096
MAX_LABEL_LENGTH = 80
MAX_SEARCH_LENGTH = 100
MAX_ID = 2**31 - 1
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class ValidationError(ValueError):
    """User input was rejected. The message is safe to show to the user."""


class PathSecurityError(ValidationError):
    """A path failed a safety check."""


# --------------------------------------------------------------------------
# Generic input parsing
# --------------------------------------------------------------------------
def parse_int(value, name: str, minimum: int = 1, maximum: int = MAX_ID) -> int:
    if value is None or isinstance(value, bool):
        raise ValidationError(f"{name} is required.")
    text = str(value).strip()
    if not re.fullmatch(r"[0-9]{1,10}", text):
        raise ValidationError(f"{name} must be a whole number.")
    number = int(text)
    if number < minimum or number > maximum:
        raise ValidationError(f"{name} must be between {minimum} and {maximum}.")
    return number


def parse_optional_int(value, name: str, minimum: int = 1, maximum: int = MAX_ID):
    if value is None or str(value).strip() == "":
        return None
    return parse_int(value, name, minimum, maximum)


def parse_choice(value, name: str, allowed, default=None):
    if value is None or str(value).strip() == "":
        return default
    text = str(value).strip()
    if text not in allowed:
        raise ValidationError(f"{name} has an unsupported value.")
    return text


def parse_search(value) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > MAX_SEARCH_LENGTH:
        raise ValidationError(f"Search text is limited to {MAX_SEARCH_LENGTH} characters.")
    if CONTROL_CHARS.search(text):
        raise ValidationError("Search text contains invalid characters.")
    return text


def parse_label(value) -> str:
    text = (value or "").strip()
    if len(text) > MAX_LABEL_LENGTH:
        raise ValidationError(f"Label is limited to {MAX_LABEL_LENGTH} characters.")
    if CONTROL_CHARS.search(text):
        raise ValidationError("Label contains invalid characters.")
    return text


def parse_page(value) -> int:
    if value is None or str(value).strip() == "":
        return 1
    return parse_int(value, "Page", 1, 1_000_000)


def escape_like(text: str) -> str:
    """Escape LIKE wildcards so user text is matched literally (used with ESCAPE '\\')."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# --------------------------------------------------------------------------
# Path safety
# --------------------------------------------------------------------------
def _restricted_roots() -> list[Path]:
    roots: list[Path] = []
    if os.name == "nt":
        for var in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData"):
            value = os.environ.get(var)
            if value:
                roots.append(Path(value))
        roots.append(Path("C:/Windows"))
    else:
        for name in ("/etc", "/proc", "/sys", "/dev", "/boot", "/run", "/bin", "/sbin",
                     "/usr", "/lib", "/lib32", "/lib64", "/var/lib", "/root/.ssh",
                     "/System", "/Library", "/private/etc"):
            roots.append(Path(name))
    return roots


def _app_runtime_paths() -> list[Path]:
    paths: list[Path] = []
    cfg = current_app.config
    for key in ("DATABASE",):
        paths.append(Path(cfg[key]).resolve().parent)
    for key in ("LOG_DIR", "EXPORT_DIR"):
        paths.append(Path(cfg[key]).resolve())
    return paths


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _has_traversal(raw: str) -> bool:
    """Detect '..' components, including percent-encoded and double-encoded forms."""
    candidates = {raw}
    current = raw
    for _ in range(3):  # decode up to three layers of percent-encoding
        decoded = unquote(current)
        if decoded == current:
            break
        candidates.add(decoded)
        current = decoded
    for candidate in candidates:
        parts = re.split(r"[\\/]+", candidate)
        if any(part == ".." for part in parts):
            return True
    return False


def validate_directory_input(raw) -> Path:
    """Validate a directory path supplied for registration and return its real path.

    Raises ``PathSecurityError`` with a user-safe message on any problem.
    """
    if raw is None:
        raise PathSecurityError("Directory path is required.")
    text = str(raw).strip()
    if not text:
        raise PathSecurityError("Directory path is required.")
    if len(text) > MAX_PATH_LENGTH:
        raise PathSecurityError("Directory path is too long.")
    if CONTROL_CHARS.search(text):
        raise PathSecurityError("Directory path contains invalid characters.")
    if _has_traversal(text):
        raise PathSecurityError("Path traversal sequences ('..') are not allowed.")

    candidate = Path(text)
    if not candidate.is_absolute():
        raise PathSecurityError("Please enter an absolute directory path.")

    try:
        if candidate.is_symlink():
            raise PathSecurityError("Symbolic links are not followed; register the real directory instead.")
        real = candidate.resolve(strict=True)
    except PathSecurityError:
        raise
    except (FileNotFoundError, NotADirectoryError):
        raise PathSecurityError("The directory does not exist.")
    except (OSError, RuntimeError):
        raise PathSecurityError("The directory could not be accessed.")

    if not real.is_dir():
        raise PathSecurityError("The path is not a directory.")
    if real.parent == real:
        raise PathSecurityError("A filesystem root cannot be monitored.")
    if not os.access(real, os.R_OK | os.X_OK):
        raise PathSecurityError("The directory is not readable by this application.")

    for restricted in _restricted_roots():
        try:
            restricted_real = restricted.resolve()
        except OSError:
            continue
        if _is_within(real, restricted_real):
            raise PathSecurityError("This location is a protected system directory and cannot be monitored.")

    for runtime in _app_runtime_paths():
        if _is_within(real, runtime) or _is_within(runtime, real):
            raise PathSecurityError(
                "This directory contains or is part of the application's own data, logs or exports "
                "and cannot be monitored."
            )
    return real


def validate_relative_path(rel) -> str:
    """Validate a stored/user-supplied relative path (POSIX-style separators)."""
    if rel is None:
        raise PathSecurityError("Relative path is required.")
    text = str(rel)
    if not text or len(text) > MAX_PATH_LENGTH:
        raise PathSecurityError("Relative path has an invalid length.")
    if "\x00" in text:
        raise PathSecurityError("Relative path contains invalid characters.")
    if _has_traversal(text):
        raise PathSecurityError("Path traversal sequences ('..') are not allowed.")
    if text.startswith(("/", "\\")) or PureWindowsPath(text).is_absolute() \
            or PurePosixPath(text).is_absolute() or re.match(r"^[A-Za-z]:", text):
        raise PathSecurityError("Absolute paths are not allowed here.")
    return text


def safe_join(root: str | os.PathLike, rel) -> Path:
    """Join ``rel`` to ``root`` and prove the result stays inside ``root``.

    Rejects traversal, absolute paths, and any symlink along the way (a symlink
    could point outside the monitored root).
    """
    rel_text = validate_relative_path(rel)
    root_real = Path(root).resolve(strict=True)
    target = root_real.joinpath(*[p for p in re.split(r"[\\/]+", rel_text) if p])
    # Walk components: no symlinks allowed
    probe = root_real
    for part in target.relative_to(root_real).parts:
        probe = probe / part
        if probe.is_symlink():
            raise PathSecurityError("Symbolic links are not followed.")
    resolved = target.resolve(strict=False)
    if not _is_within(resolved, root_real):
        raise PathSecurityError("Path escapes the monitored directory.")
    return resolved


def to_relative(root: Path, absolute: Path) -> str:
    """Return a POSIX-style relative path for storage."""
    return absolute.relative_to(root).as_posix()


# --------------------------------------------------------------------------
# CSRF protection (session-bound synchroniser token)
# --------------------------------------------------------------------------
CSRF_SESSION_KEY = "_csrf_token"
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def get_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[CSRF_SESSION_KEY] = token
    return token


def validate_csrf() -> None:
    """Abort with 400 if the request lacks a valid CSRF token."""
    if request.method not in UNSAFE_METHODS:
        return
    expected = session.get(CSRF_SESSION_KEY, "")
    supplied = request.form.get(CSRF_FIELD) or request.headers.get(CSRF_HEADER, "")
    if not expected or not supplied or not hmac.compare_digest(str(expected), str(supplied)):
        abort(400, description="CSRF validation failed. Reload the page and try again.")


# --------------------------------------------------------------------------
# HTTP security headers
# --------------------------------------------------------------------------
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers.pop("Server", None)
    return response
