"""Fail-closed interlock between manual HA transitions and release updates.

The cluster updater already serializes mutation with an exclusive ``flock`` on
``/var/lib/home-center-auto-update/update.lock``. A manual HA executor must hold
the same lock for the whole role transition so an update cannot start between
preflight and writer promotion.
"""
from __future__ import annotations

import errno
import fcntl
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

DEFAULT_UPDATE_LOCK = Path("/var/lib/home-center-auto-update/update.lock")


class HAUpdateInterlockRejected(RuntimeError):
    """The update/rollout exclusion gate could not be proven."""


@dataclass(frozen=True, slots=True)
class UpdateInterlockEvidence:
    """Bounded evidence that the shared updater lock is held by this process."""

    lock_path: str
    acquired: bool


def _require_secure_directory(path: Path, *, expected_uid: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise HAUpdateInterlockRejected("update_state_directory_missing") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != expected_uid
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise HAUpdateInterlockRejected("update_state_directory_unsafe")


def _open_lock(path: Path, *, expected_uid: int) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise HAUpdateInterlockRejected("update_lock_unavailable") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise HAUpdateInterlockRejected("update_lock_unsafe")
        return fd
    except Exception:
        os.close(fd)
        raise


@contextmanager
def hold_update_interlock(
    lock_path: Path = DEFAULT_UPDATE_LOCK,
    *,
    expected_uid: int = 0,
) -> Iterator[UpdateInterlockEvidence]:
    """Hold the updater's exclusive lock for a complete manual HA transition.

    Failure to inspect or acquire the canonical updater lock is a hard reject.
    The returned evidence is intentionally non-authorizing: it proves only that
    update/rollout mutation is excluded while this context remains active.
    """

    path = Path(lock_path)
    _require_secure_directory(path.parent, expected_uid=expected_uid)
    fd = _open_lock(path, expected_uid=expected_uid)
    acquired = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            acquired = True
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise HAUpdateInterlockRejected("update_or_rollout_in_progress") from exc
            raise HAUpdateInterlockRejected("update_lock_unavailable") from exc
        yield UpdateInterlockEvidence(lock_path=str(path), acquired=True)
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
