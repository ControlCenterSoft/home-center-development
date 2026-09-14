#!/usr/bin/env python3
"""Apply Home Center HA listener fencing before the unprivileged service starts."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import sqlite3
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCRIPT = Path(__file__).resolve()
RELEASE_ROOT = SCRIPT.parent.parent
if (RELEASE_ROOT / "home_center").is_dir():
    sys.path.insert(0, str(RELEASE_ROOT))

from home_center.config import Config, load_config  # noqa: E402
from home_center.ha_fence_control import (  # noqa: E402
    COMMANDS,
    FenceOverrideStore,
    execute_fence_command,
)
from home_center.ha_fence_runtime import (  # noqa: E402
    IptablesFirewallAdapter,
    resolve_firewall_binary,
)

STATE_DIR = Path("/var/lib/home-center/ha-fence")
OVERRIDE_FILE = STATE_DIR / "override"
LOCK_DIR = Path("/run/home-center-locks")
LOCK_FILE = LOCK_DIR / "ha-fence.lock"


def _require_root() -> None:
    if os.geteuid() != 0:
        raise SystemExit("ROOT_REQUIRED")


def _secure_root_directory(path: Path, *, mode: int) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        path.mkdir(parents=True, mode=mode)
        info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise RuntimeError(f"UNSAFE_DIRECTORY:{path}")


@contextmanager
def _exclusive_lock() -> Iterator[None]:
    _secure_root_directory(LOCK_DIR, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(LOCK_FILE, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise RuntimeError("UNSAFE_FENCE_LOCK")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


@contextmanager
def _state_connection(config: Config) -> Iterator[sqlite3.Connection | None]:
    path = config.state_db
    try:
        info = path.lstat()
    except FileNotFoundError:
        yield None
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_mode & 0o002
    ):
        raise RuntimeError("UNSAFE_STATE_DB")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        yield connection
    finally:
        connection.close()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="home-center-ha-fence")
    parser.add_argument("command", choices=sorted(COMMANDS))
    return parser.parse_args()


def main() -> int:
    _require_root()
    args = _parse_args()
    config = load_config()
    _secure_root_directory(STATE_DIR, mode=0o700)
    overrides = FenceOverrideStore(OVERRIDE_FILE, expected_uid=0)

    with _exclusive_lock(), _state_connection(config) as connection:
        executable = resolve_firewall_binary(config.management_address)
        firewall = IptablesFirewallAdapter(executable)
        result = execute_fence_command(
            args.command,
            config=config,
            connection=connection,
            firewall=firewall,
            overrides=overrides,
        )

    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        print(
            json.dumps(
                {
                    "schema": "home-center.ha-fence-error.v1",
                    "error": type(exc).__name__,
                    "reason": str(exc)[:300],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        raise SystemExit(70) from exc
