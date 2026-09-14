"""Persistent fail-closed override control for the privileged HA fence helper."""
from __future__ import annotations

import os
import stat
import uuid
from pathlib import Path
from typing import Any

from .config import Config
from .ha_fence import FENCE_OVERRIDES, fence_policy
from .ha_fence_runtime import FirewallAdapter, apply_fence_policy, fence_runtime_status

COMMANDS = frozenset({"apply", "status", "isolate", "standby", "auto"})


class HAFenceControlError(RuntimeError):
    """Persistent fence control state is unsafe or malformed."""


class FenceOverrideStore:
    def __init__(self, path: Path, *, expected_uid: int = 0) -> None:
        self.path = path
        self.expected_uid = expected_uid

    def _ensure_directory(self) -> None:
        directory = self.path.parent
        try:
            info = directory.lstat()
        except FileNotFoundError:
            directory.mkdir(parents=True, mode=0o700)
            info = directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != self.expected_uid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise HAFenceControlError("ha_fence_state_directory_rejected")

    def _fsync_directory(self) -> None:
        fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def read(self) -> str | None:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return None
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != self.expected_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 64
        ):
            raise HAFenceControlError("ha_fence_override_file_rejected")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags)
        try:
            opened = os.fstat(fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != self.expected_uid
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size > 64
                or opened.st_dev != info.st_dev
                or opened.st_ino != info.st_ino
            ):
                raise HAFenceControlError("ha_fence_override_file_changed")
            data = os.read(fd, 65)
        finally:
            os.close(fd)
        if len(data) > 64:
            raise HAFenceControlError("ha_fence_override_file_rejected")
        try:
            value = data.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise HAFenceControlError("ha_fence_override_encoding_rejected") from exc
        if value not in FENCE_OVERRIDES:
            raise HAFenceControlError("ha_fence_override_value_rejected")
        return value

    def write(self, value: str) -> None:
        if value not in FENCE_OVERRIDES:
            raise HAFenceControlError("ha_fence_override_value_rejected")
        self._ensure_directory()
        temporary = self.path.parent / f".{self.path.name}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temporary, flags, 0o600)
        try:
            payload = (value + "\n").encode("ascii")
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            info = temporary.lstat()
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != self.expected_uid
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise HAFenceControlError("ha_fence_override_temporary_rejected")
            os.replace(temporary, self.path)
            self._fsync_directory()
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def clear(self) -> None:
        current = self.read()
        if current is None:
            return
        self.path.unlink()
        self._fsync_directory()


def execute_fence_command(
    command: str,
    *,
    config: Config,
    connection: Any,
    firewall: FirewallAdapter,
    overrides: FenceOverrideStore,
) -> dict[str, Any]:
    """Execute one bounded fence command with persistence ordered fail-closed."""
    if command not in COMMANDS:
        raise HAFenceControlError("ha_fence_command_rejected")

    if command in FENCE_OVERRIDES:
        # Persist restriction before touching firewall so a failed attempt is
        # retried on boot rather than silently reverting to a less strict mode.
        overrides.write(command)
        effective_override = command
        policy = fence_policy(connection, config, override=effective_override)
        runtime = apply_fence_policy(policy, firewall)
    elif command == "auto":
        # Do not remove a restrictive override until durable membership policy
        # has been applied and verified successfully.
        policy = fence_policy(connection, config, override=None)
        runtime = apply_fence_policy(policy, firewall)
        overrides.clear()
        effective_override = None
    else:
        effective_override = overrides.read()
        policy = fence_policy(connection, config, override=effective_override)
        runtime = (
            apply_fence_policy(policy, firewall)
            if command == "apply"
            else fence_runtime_status(policy, firewall)
        )

    return {
        "schema": "home-center.ha-fence-command-result.v1",
        "command": command,
        "override": effective_override,
        "policy": policy.as_dict(),
        "runtime": runtime.as_dict(),
    }
