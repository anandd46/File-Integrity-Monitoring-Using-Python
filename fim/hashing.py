"""SHA-256 hashing service.

Files are opened read-only in binary mode and processed in fixed-size chunks,
so large files never need to fit in memory. The file is never written to.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

CHUNK_SIZE = 1024 * 1024  # 1 MiB


class HashError(Exception):
    """Raised when a file cannot be hashed reliably."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class HashResult:
    sha256: str
    size: int
    mtime_ns: int


def hash_file(path: str | os.PathLike, chunk_size: int = CHUNK_SIZE) -> HashResult:
    """Return the SHA-256 digest of ``path``.

    Raises ``HashError`` (never a raw OS exception) for missing files,
    permission problems, non-regular files, and files that change while being
    read. A file is considered unstable if its size or modification time
    differs before and after hashing.
    """
    p = Path(path)
    try:
        before = os.stat(p, follow_symlinks=False)
    except FileNotFoundError:
        raise HashError("MISSING", "File not found")
    except PermissionError:
        raise HashError("PERMISSION", "Permission denied")
    except OSError as exc:
        raise HashError("OS_ERROR", f"Could not stat file ({exc.__class__.__name__})")

    import stat as _stat
    if not _stat.S_ISREG(before.st_mode):
        raise HashError("NOT_REGULAR", "Not a regular file")

    digest = hashlib.sha256()
    total = 0
    try:
        with open(p, "rb") as handle:  # read-only, binary
            while True:
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
    except FileNotFoundError:
        raise HashError("MISSING", "File disappeared while hashing")
    except PermissionError:
        raise HashError("PERMISSION", "Permission denied")
    except OSError as exc:
        raise HashError("OS_ERROR", f"Read error ({exc.__class__.__name__})")

    try:
        after = os.stat(p, follow_symlinks=False)
    except OSError:
        raise HashError("UNSTABLE", "File changed or disappeared while hashing")

    if (after.st_size != before.st_size or after.st_mtime_ns != before.st_mtime_ns
            or total != before.st_size):
        raise HashError("UNSTABLE", "File changed while it was being hashed")

    return HashResult(sha256=digest.hexdigest(), size=total, mtime_ns=after.st_mtime_ns)
