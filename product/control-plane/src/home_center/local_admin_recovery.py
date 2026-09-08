"""Управляемое root и не содержащее секретов свидетельство восстановления локального администратора."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any

from .util import utc_now


EVIDENCE_SCHEMA = "home-center.local-admin-recovery-evidence.v1"
EVIDENCE_ACTION = "local-admin.password.recover"
EVIDENCE_POLICY = "local-console-recovery-v1"
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
OUTCOMES = frozenset({"requested", "accepted", "denied", "failed"})
SAFE_REASONS = frozenset(
    {
        "recovery_console_verified",
        "operator_confirmation_failed",
        "operator_cancelled",
        "password_confirmation_mismatch",
        "credential_reset_committed",
        "password_too_short",
        "password_letter_required",
        "password_digit_required",
        "password_rejected",
        "credential_path_rejected",
        "credential_directory_unavailable",
        "credential_directory_metadata_rejected",
        "credential_rotation_lock_unavailable",
        "credential_rotation_lock_rejected",
        "credential_file_metadata_rejected",
        "credential_file_read_rejected",
        "credential_file_write_rejected",
        "credential_transaction_file_rejected",
        "credential_rotation_recovery_unavailable",
        "credential_rotation_recovery_failed",
        "credential_rotation_validation_failed",
        "credential_commit_hook_failed",
        "credential_rotation_rollback_failed",
        "credential_rotation_failed",
    }
)
EVENT_KEYS = {
    "schema",
    "sequence",
    "event_id",
    "occurred_at",
    "actor",
    "action",
    "target",
    "outcome",
    "reason",
    "policy",
    "tty",
    "previous_hash",
    "entry_hash",
}


class LocalAdminRecoveryError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise LocalAdminRecoveryError("recovery_evidence_duplicate_key")
        value[key] = item
    return value


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _hash_event(value: dict[str, Any]) -> str:
    material = dict(value)
    material.pop("entry_hash", None)
    return hashlib.sha256(_canonical(material)).hexdigest()


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise LocalAdminRecoveryError("recovery_evidence_write_failed")
        offset += written


class RecoveryEvidenceLog:
    """Добавляет и проверяет ограниченную хеш-цепочку, содержащую только безопасные метаданные."""

    def __init__(
        self,
        path: Path,
        *,
        expected_uid: int = 0,
        expected_gid: int = 0,
        expected_mode: int = 0o600,
        expected_directory_uid: int = 0,
        expected_directory_gid: int = 0,
        expected_directory_mode: int = 0o700,
    ) -> None:
        self.path = Path(path)
        if not self.path.is_absolute() or self.path.name in {"", ".", ".."}:
            raise LocalAdminRecoveryError("recovery_evidence_path_rejected")
        self.expected_uid = expected_uid
        self.expected_gid = expected_gid
        self.expected_mode = expected_mode
        self.expected_directory_uid = expected_directory_uid
        self.expected_directory_gid = expected_directory_gid
        self.expected_directory_mode = expected_directory_mode

    def _open_directory(self) -> int:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(self.path.parent, flags)
        except OSError as exc:
            raise LocalAdminRecoveryError("recovery_evidence_directory_unavailable") from exc
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != self.expected_directory_uid
            or info.st_gid != self.expected_directory_gid
            or stat.S_IMODE(info.st_mode) != self.expected_directory_mode
        ):
            os.close(descriptor)
            raise LocalAdminRecoveryError("recovery_evidence_directory_rejected")
        return descriptor

    def _open_file(self, directory_fd: int) -> int:
        flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        created = False
        try:
            descriptor = os.open(self.path.name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(self.path.name, flags, dir_fd=directory_fd)
            except OSError as exc:
                raise LocalAdminRecoveryError("recovery_evidence_unavailable") from exc
        except OSError as exc:
            raise LocalAdminRecoveryError("recovery_evidence_unavailable") from exc
        try:
            if created:
                os.fchown(descriptor, self.expected_uid, self.expected_gid)
                os.fchmod(descriptor, self.expected_mode)
                os.fsync(descriptor)
                os.fsync(directory_fd)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != self.expected_uid
                or info.st_gid != self.expected_gid
                or stat.S_IMODE(info.st_mode) != self.expected_mode
                or info.st_size > MAX_EVIDENCE_BYTES
            ):
                raise LocalAdminRecoveryError("recovery_evidence_metadata_rejected")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return descriptor
        except (LocalAdminRecoveryError, OSError) as exc:
            os.close(descriptor)
            if isinstance(exc, LocalAdminRecoveryError):
                raise
            raise LocalAdminRecoveryError("recovery_evidence_unavailable") from exc

    @staticmethod
    def _validate_safe_value(value: Any, code: str) -> str:
        if not isinstance(value, str) or SAFE_VALUE.fullmatch(value) is None:
            raise LocalAdminRecoveryError(code)
        return value

    def _read_events(self, descriptor: int) -> list[dict[str, Any]]:
        info = os.fstat(descriptor)
        if info.st_size > MAX_EVIDENCE_BYTES:
            raise LocalAdminRecoveryError("recovery_evidence_too_large")
        os.lseek(descriptor, 0, os.SEEK_SET)
        payload = bytearray()
        while len(payload) <= MAX_EVIDENCE_BYTES:
            chunk = os.read(descriptor, min(64 * 1024, MAX_EVIDENCE_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) != info.st_size or len(payload) > MAX_EVIDENCE_BYTES:
            raise LocalAdminRecoveryError("recovery_evidence_read_rejected")
        if payload and not payload.endswith(b"\n"):
            raise LocalAdminRecoveryError("recovery_evidence_truncated")

        events: list[dict[str, Any]] = []
        previous_hash = "0" * 64
        for sequence, raw in enumerate(bytes(payload).splitlines(), start=1):
            try:
                event = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_strict_object)
            except LocalAdminRecoveryError:
                raise
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
                raise LocalAdminRecoveryError("recovery_evidence_json_rejected") from exc
            if not isinstance(event, dict) or set(event) != EVENT_KEYS:
                raise LocalAdminRecoveryError("recovery_evidence_shape_rejected")
            if event.get("schema") != EVIDENCE_SCHEMA or event.get("action") != EVIDENCE_ACTION:
                raise LocalAdminRecoveryError("recovery_evidence_schema_rejected")
            if event.get("policy") != EVIDENCE_POLICY or event.get("outcome") not in OUTCOMES:
                raise LocalAdminRecoveryError("recovery_evidence_value_rejected")
            if isinstance(event.get("sequence"), bool) or event.get("sequence") != sequence:
                raise LocalAdminRecoveryError("recovery_evidence_sequence_rejected")
            for key in ("event_id", "occurred_at", "actor", "target", "tty"):
                self._validate_safe_value(event.get(key), "recovery_evidence_value_rejected")
            reason = event.get("reason")
            if reason not in SAFE_REASONS:
                raise LocalAdminRecoveryError("recovery_evidence_value_rejected")
            if event.get("previous_hash") != previous_hash or event.get("entry_hash") != _hash_event(event):
                raise LocalAdminRecoveryError("recovery_evidence_chain_rejected")
            previous_hash = event["entry_hash"]
            events.append(event)
        return events

    def append(
        self,
        *,
        actor_uid: int,
        target: str,
        tty: str,
        outcome: str,
        reason: str,
    ) -> str:
        if isinstance(actor_uid, bool) or not isinstance(actor_uid, int) or not 0 <= actor_uid <= 2**31 - 1:
            raise LocalAdminRecoveryError("recovery_actor_rejected")
        if outcome not in OUTCOMES:
            raise LocalAdminRecoveryError("recovery_outcome_rejected")
        target = self._validate_safe_value(target, "recovery_target_rejected")
        tty = self._validate_safe_value(tty, "recovery_tty_rejected")
        if reason not in SAFE_REASONS:
            raise LocalAdminRecoveryError("recovery_reason_rejected")

        directory_fd = self._open_directory()
        descriptor: int | None = None
        try:
            descriptor = self._open_file(directory_fd)
            events = self._read_events(descriptor)
            previous_hash = events[-1]["entry_hash"] if events else "0" * 64
            event: dict[str, Any] = {
                "schema": EVIDENCE_SCHEMA,
                "sequence": len(events) + 1,
                "event_id": str(uuid.uuid4()),
                "occurred_at": utc_now(),
                "actor": f"local-console:uid-{actor_uid}",
                "action": EVIDENCE_ACTION,
                "target": target,
                "outcome": outcome,
                "reason": reason,
                "policy": EVIDENCE_POLICY,
                "tty": tty,
                "previous_hash": previous_hash,
                "entry_hash": "",
            }
            event["entry_hash"] = _hash_event(event)
            payload = _canonical(event) + b"\n"
            if os.fstat(descriptor).st_size + len(payload) > MAX_EVIDENCE_BYTES:
                raise LocalAdminRecoveryError("recovery_evidence_capacity_exhausted")
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            return event["event_id"]
        except LocalAdminRecoveryError:
            raise
        except OSError as exc:
            raise LocalAdminRecoveryError("recovery_evidence_write_failed") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory_fd)
