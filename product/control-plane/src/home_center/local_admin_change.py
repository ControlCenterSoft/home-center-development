"""Bounded client for the privileged local-administrator rotation action."""

from __future__ import annotations

import json
import secrets
import socket
import uuid
from pathlib import Path
from typing import Any


ACTION = "local-admin.password.rotate.v1"
REQUEST_SCHEMA = "home-center.helper.secret-request.v1"
RESULT_SCHEMA = "home-center.helper.secret-result.v1"
DEFAULT_SOCKET = Path("/run/home-center-helper/helper.sock")
MAX_RESULT_BYTES = 16 * 1024


class LocalAdminPasswordChangeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class LocalAdminPasswordChangeClient:
    def __init__(self, socket_path: Path = DEFAULT_SOCKET, timeout_seconds: float = 10.0) -> None:
        self.socket_path = Path(socket_path)
        self.timeout_seconds = timeout_seconds

    def change(self, username: str, current_password: str, new_password: str) -> None:
        request_id = f"password-{uuid.uuid4().hex}"
        request = {
            "schema": REQUEST_SCHEMA,
            "request_id": request_id,
            "action": ACTION,
            "params": {
                "username": username,
                "current_password": current_password,
                "new_password": new_password,
            },
            "nonce": secrets.token_hex(16),
        }
        payload = _canonical(request) + b"\n"
        if len(payload) > 16 * 1024:
            raise LocalAdminPasswordChangeError("password_change_request_rejected")

        data = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(str(self.socket_path))
                connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                while len(data) <= MAX_RESULT_BYTES:
                    chunk = connection.recv(min(4096, MAX_RESULT_BYTES + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if b"\n" in chunk:
                        break
        except (OSError, TimeoutError) as exc:
            raise LocalAdminPasswordChangeError("password_change_unavailable") from exc
        if len(data) > MAX_RESULT_BYTES:
            raise LocalAdminPasswordChangeError("password_change_result_rejected")

        try:
            result = json.loads(bytes(data).split(b"\n", 1)[0].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise LocalAdminPasswordChangeError("password_change_result_rejected") from exc
        required = {"schema", "request_id", "action", "status", "reason", "completed_at"}
        if (
            not isinstance(result, dict)
            or set(result) != required
            or result.get("schema") != RESULT_SCHEMA
            or result.get("request_id") != request_id
            or result.get("action") != ACTION
            or result.get("status") not in {"succeeded", "rejected", "failed"}
            or not isinstance(result.get("completed_at"), str)
            or (result.get("reason") is not None and not isinstance(result.get("reason"), str))
        ):
            raise LocalAdminPasswordChangeError("password_change_result_rejected")
        if result["status"] != "succeeded":
            reason = result.get("reason")
            safe_reason = reason if isinstance(reason, str) and 1 <= len(reason) <= 128 else "password_change_failed"
            raise LocalAdminPasswordChangeError(safe_reason)
