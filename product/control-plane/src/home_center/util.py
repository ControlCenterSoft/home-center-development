"""Small security-oriented helpers shared by the runtime."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if tmp.exists():
            tmp.unlink()


def utc_now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def secure_file(path: Path, *, allow_group_read: bool = False) -> None:
    """Fail closed if a secret/private file has unsafe ownership or mode."""

    stat = path.stat()
    forbidden = 0o007 | (0 if allow_group_read else 0o070)
    if stat.st_mode & forbidden:
        raise PermissionError(f"unsafe permissions on {path}")
    if stat.st_uid not in {0, os.geteuid()}:
        raise PermissionError(f"unexpected owner on {path}")
