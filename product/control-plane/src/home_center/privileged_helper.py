from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import socket
import stat
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .local_admin_rotation import LocalAdminCredentialRotator, LocalAdminRotationError

REQUEST_SCHEMA = "home-center.helper.request.v1"
RESULT_SCHEMA = "home-center.helper.result.v1"
POLICY_SCHEMA = "home-center.helper.policy.v1"
STATE_SCHEMA = "home-center.helper.state.v1"
MAX_REQUEST_BYTES = 16 * 1024
MAX_OUTPUT_BYTES = 16 * 1024
MAX_HISTORY = 1024
CLIENT_IO_TIMEOUT_SECONDS = 10
DEFAULT_SOCKET = Path("/run/home-center-helper/helper.sock")
DEFAULT_STATE = Path("/var/lib/home-center-helper/state.json")
DEFAULT_POLICY = Path("/etc/home-center/helper-policy.json")
SAFE_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/nonexistent",
}


@dataclass(frozen=True)
class Action:
    permission: str
    executable: str
    argv: tuple[str, ...]
    timeout_seconds: int
    timeout_requires_recovery: bool = False


# P2.2 intentionally admits no production mutation. The table is compile-time fixed;
# policy may enable/disable entries but cannot supply executable paths or argv.
ACTIONS: dict[str, Action] = {
    "helper.probe.v1": Action(
        permission="helper.probe",
        executable="/usr/bin/true",
        argv=(),
        timeout_seconds=5,
    ),
}
SECRET_ACTIONS: dict[str, str] = {
    "local-admin.password.rotate.v1": "local-admin.password.rotate",
}
PERMISSIONS = frozenset(action.permission for action in ACTIONS.values()) | frozenset(SECRET_ACTIONS.values())


class HelperError(Exception):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _atomic_write_json(path: Path, value: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise HelperError("json_root_must_be_object")
    return data


def _validate_root_controlled_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise HelperError("policy_must_be_regular_file")
    if stat.S_ISLNK(info.st_mode):
        raise HelperError("policy_symlink_forbidden")
    if os.geteuid() == 0:
        if info.st_uid != 0:
            raise HelperError("policy_owner_must_be_root")
        if info.st_mode & 0o022:
            raise HelperError("policy_must_not_be_group_or_world_writable")


def _validate_policy(policy: dict[str, Any]) -> None:
    if set(policy) != {"schema", "callers", "enabled_actions"}:
        raise HelperError("invalid_policy_keys")
    if policy.get("schema") != POLICY_SCHEMA:
        raise HelperError("invalid_policy_schema")
    callers = policy.get("callers")
    if not isinstance(callers, dict) or not callers:
        raise HelperError("invalid_policy_callers")
    for name, permissions in callers.items():
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 64
            or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in name)
            or not isinstance(permissions, list)
        ):
            raise HelperError("invalid_policy_caller")
        if any(not isinstance(item, str) or item not in PERMISSIONS for item in permissions):
            raise HelperError("invalid_policy_permission")
        if len(set(permissions)) != len(permissions):
            raise HelperError("duplicate_policy_permission")
    enabled = policy.get("enabled_actions")
    if not isinstance(enabled, list) or any(item not in ACTIONS and item not in SECRET_ACTIONS for item in enabled):
        raise HelperError("invalid_enabled_actions")
    if len(set(enabled)) != len(enabled):
        raise HelperError("duplicate_enabled_action")


def _validate_request(request: dict[str, Any]) -> None:
    if set(request) != {"schema", "request_id", "action", "params", "nonce"}:
        raise HelperError("invalid_request_keys")
    if request.get("schema") != REQUEST_SCHEMA:
        raise HelperError("invalid_request_schema")
    request_id = request.get("request_id")
    if (
        not isinstance(request_id, str)
        or not (8 <= len(request_id) <= 96)
        or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in request_id)
    ):
        raise HelperError("invalid_request_id")
    nonce = request.get("nonce")
    if not isinstance(nonce, str) or len(nonce) != 32 or any(ch not in "0123456789abcdef" for ch in nonce):
        raise HelperError("invalid_request_nonce")
    action = request.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        raise HelperError("unknown_action")
    if request.get("params") != {}:
        raise HelperError("invalid_action_params")


def _validate_secret_request(request: dict[str, Any]) -> None:
    if set(request) != {"schema", "request_id", "action", "params", "nonce"}:
        raise HelperError("invalid_secret_request_keys")
    if request.get("schema") != "home-center.helper.secret-request.v1":
        raise HelperError("invalid_secret_request_schema")
    request_id = request.get("request_id")
    if (
        not isinstance(request_id, str)
        or not 8 <= len(request_id) <= 96
        or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in request_id)
    ):
        raise HelperError("invalid_secret_request_id")
    nonce = request.get("nonce")
    if not isinstance(nonce, str) or len(nonce) != 32 or any(ch not in "0123456789abcdef" for ch in nonce):
        raise HelperError("invalid_secret_request_nonce")
    if request.get("action") != "local-admin.password.rotate.v1":
        raise HelperError("unknown_secret_action")
    params = request.get("params")
    if not isinstance(params, dict) or set(params) != {"username", "current_password", "new_password"}:
        raise HelperError("invalid_secret_action_params")
    if not isinstance(params.get("username"), str):
        raise HelperError("invalid_secret_username")
    for name in ("current_password", "new_password"):
        value = params.get(name)
        if not isinstance(value, str):
            raise HelperError("invalid_secret_password")
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise HelperError("invalid_secret_password") from exc
        # JSON contracts bound character count. Keep the transport bound large
        # enough for 256 UTF-8 characters and let the credential layer enforce
        # its stricter byte policy with a typed, non-secret rejection.
        if not 1 <= len(encoded) <= 1024:
            raise HelperError("invalid_secret_password")


def _secret_result(request: dict[str, Any], *, status: str, reason: str | None) -> dict[str, Any]:
    return {
        "schema": "home-center.helper.secret-result.v1",
        "request_id": request["request_id"],
        "action": request["action"],
        "status": status,
        "reason": reason,
        "completed_at": _utc_now(),
    }


def _execute_secret_request(
    request: dict[str, Any],
    *,
    caller_uid: int,
    caller_name: str,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Execute a credential mutation without durable request hashing or capture."""

    _validate_secret_request(request)
    action = request["action"]
    permission = SECRET_ACTIONS.get(action)
    caller_permissions = policy["callers"].get(caller_name)
    if caller_permissions is None:
        return _secret_result(request, status="rejected", reason="caller_not_allowed")
    if action not in policy["enabled_actions"]:
        return _secret_result(request, status="rejected", reason="action_disabled")
    if permission is None or permission not in caller_permissions:
        return _secret_result(request, status="rejected", reason="permission_denied")
    if os.geteuid() != 0 or caller_uid == 0:
        return _secret_result(request, status="rejected", reason="secret_action_context_rejected")
    try:
        group = pwd.getpwnam("home-center").pw_gid
        params = request["params"]
        rotator = LocalAdminCredentialRotator(
            Path("/etc/home-center/secrets/local-admin.json"),
            expected_uid=0,
            expected_gid=group,
            expected_mode=0o640,
            expected_directory_uid=0,
            expected_directory_gid=group,
            expected_directory_mode=0o750,
        )
        rotator.rotate(params["username"], params["current_password"], params["new_password"])
    except LocalAdminRotationError as exc:
        policy_rejections = {
            "current_password_invalid",
            "password_too_short",
            "password_letter_required",
            "password_digit_required",
            "password_rejected",
        }
        status = "rejected" if exc.code in policy_rejections else "failed"
        return _secret_result(request, status=status, reason=exc.code)
    except (KeyError, OSError):
        return _secret_result(request, status="failed", reason="credential_rotation_unavailable")
    return _secret_result(request, status="succeeded", reason=None)


def _bounded_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
    return raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")


def _classify_bounded_action_failure(action_id: str, stdout: str) -> tuple[str, str]:
    """Map only fixed, non-secret activation outcomes into helper evidence."""
    if action_id != "tls.web.activate.v1":
        return "failed", "action_exit_nonzero"
    try:
        value = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return "unknown", "action_result_unknown_recovery_required"
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "status", "reason"}
        or value.get("schema") != "home-center.tls-activation-result.v1"
        or not isinstance(value.get("status"), str)
        or not isinstance(value.get("reason"), str)
    ):
        return "unknown", "action_result_unknown_recovery_required"
    outcome = (value.get("status"), value.get("reason"))
    if outcome == ("rolled_back", "activation_rolled_back"):
        return "failed", "activation_rolled_back"
    if outcome == ("failed", "activation_preflight_failed"):
        return "failed", "activation_preflight_failed"
    if outcome == ("unknown", "rollback_failed_recovery_required"):
        return "unknown", "rollback_failed_recovery_required"
    if outcome == ("unknown", "activation_switch_outcome_unknown_recovery_required"):
        return "unknown", "activation_switch_outcome_unknown_recovery_required"
    return "unknown", "action_result_unknown_recovery_required"


def _valid_reconcile_result(stdout: str) -> bool:
    try:
        value = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return False
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "status",
        "node_id",
        "mode",
        "release",
        "certificate_sha256",
    }:
        return False
    valid = (
        value.get("schema") == "home-center.tls-reconcile-result.v1"
        and value.get("status") == "reconciled"
        and isinstance(value.get("node_id"), str)
        and 2 <= len(value["node_id"]) <= 128
        and all(character.isalnum() or character in "._:-" for character in value["node_id"])
        and value.get("mode") in {
            "legacy-peer-fallback",
            "separate-web-identity",
            "quarantined-peer-web-identity",
        }
        and isinstance(value.get("release"), str)
        and isinstance(value.get("certificate_sha256"), str)
        and len(value["certificate_sha256"]) == 64
        and all(character in "0123456789abcdef" for character in value["certificate_sha256"])
    )
    if not valid:
        return False
    if value["mode"] == "legacy-peer-fallback":
        return value["release"] == "legacy"
    return (
        len(value["release"]) == 24
        and all(character in "0123456789abcdef" for character in value["release"])
        and value["release"] == value["certificate_sha256"][:24]
    )


class HelperEngine:
    def __init__(
        self,
        policy_path: Path = DEFAULT_POLICY,
        state_path: Path = DEFAULT_STATE,
        *,
        require_root_controlled_policy: bool = False,
    ):
        self.policy_path = Path(policy_path)
        self.state_path = Path(state_path)
        if require_root_controlled_policy:
            _validate_root_controlled_file(self.policy_path)
        self.policy = _load_json(self.policy_path)
        _validate_policy(self.policy)
        self.policy_sha256 = _sha256(self.policy)
        self.state = self._load_state()
        self._recover_interrupted()

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {
                "schema": STATE_SCHEMA,
                "requests": {},
                "conflicts": {},
                "last_evidence_sha256": None,
                "inflight": None,
                "recovery_required": None,
            }
        state = _load_json(self.state_path)
        if state.get("schema") != STATE_SCHEMA:
            raise HelperError("invalid_state_schema")
        if not isinstance(state.get("requests"), dict):
            raise HelperError("invalid_state_requests")
        if not isinstance(state.get("conflicts", {}), dict):
            raise HelperError("invalid_state_conflicts")
        state.setdefault("conflicts", {})
        state.setdefault("last_evidence_sha256", None)
        state.setdefault("inflight", None)
        state.setdefault("recovery_required", None)
        if state["recovery_required"] is not None and not isinstance(state["recovery_required"], dict):
            raise HelperError("invalid_recovery_required_state")
        return state

    def _save(self) -> None:
        _atomic_write_json(self.state_path, self.state, 0o600)

    def _finalize_result(self, result: dict[str, Any]) -> dict[str, Any]:
        result["previous_evidence_sha256"] = self.state.get("last_evidence_sha256")
        evidence = dict(result)
        evidence.pop("evidence_sha256", None)
        result["evidence_sha256"] = _sha256(evidence)
        self.state["last_evidence_sha256"] = result["evidence_sha256"]
        return result

    def _terminal_result(
        self,
        *,
        request_id: str,
        action: str,
        status: str,
        reason: str | None,
        exit_code: int | None,
        stdout: str,
        stderr: str,
        caller_uid: int,
        caller_name: str,
        started_at: str,
        request_sha256: str,
        policy_sha256: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "schema": RESULT_SCHEMA,
            "request_id": request_id,
            "action": action,
            "status": status,
            "reason": reason,
            "exit_code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "caller_uid": caller_uid,
            "caller_name": caller_name,
            "started_at": started_at,
            "completed_at": _utc_now(),
            "request_sha256": request_sha256,
            "policy_sha256": policy_sha256 or self.policy_sha256,
        }
        return self._finalize_result(result)

    def _store_request(self, request_id: str, request_sha256: str, result: dict[str, Any]) -> dict[str, Any]:
        self.state.setdefault("requests", {})[request_id] = {"request_sha256": request_sha256, "result": result}
        self.state["inflight"] = None
        self._prune_history()
        self._save()
        return result

    def _store_conflict(self, request_id: str, request_sha256: str, result: dict[str, Any]) -> dict[str, Any]:
        conflicts = self.state.setdefault("conflicts", {}).setdefault(request_id, {})
        conflicts[request_sha256] = result
        self._prune_history()
        self._save()
        return result

    def _prune_history(self) -> None:
        requests = self.state.setdefault("requests", {})
        if len(requests) > MAX_HISTORY:
            for key in list(requests)[: len(requests) - MAX_HISTORY]:
                requests.pop(key, None)
                self.state.setdefault("conflicts", {}).pop(key, None)
        conflicts = self.state.setdefault("conflicts", {})
        for request_id in list(conflicts):
            if request_id not in requests:
                conflicts.pop(request_id, None)

    def _recover_interrupted(self) -> None:
        inflight = self.state.get("inflight")
        if not inflight:
            return
        request_id = str(inflight.get("request_id"))
        digest = str(inflight.get("request_sha256"))
        action = str(inflight.get("action"))
        caller_uid = int(inflight.get("caller_uid", 0))
        caller_name = str(inflight.get("caller_name", "unknown"))
        started_at = str(inflight.get("started_at", _utc_now()))
        definition = ACTIONS.get(action)
        if definition is not None and definition.timeout_requires_recovery:
            self.state["recovery_required"] = {
                "action": action,
                "request_id": request_id,
                "reason": "interrupted_execution_requires_operator_recovery",
                "observed_at": _utc_now(),
            }
        result = self._terminal_result(
            request_id=request_id,
            action=action,
            status="unknown",
            reason="interrupted_execution_requires_operator_recovery",
            exit_code=None,
            stdout="",
            stderr="",
            caller_uid=caller_uid,
            caller_name=caller_name,
            started_at=started_at,
            request_sha256=digest,
            policy_sha256=str(inflight.get("policy_sha256", self.policy_sha256)),
        )
        self._store_request(request_id, digest, result)

    def _rejection(
        self,
        *,
        request_id: str,
        action: str,
        request_sha256: str,
        caller_uid: int,
        caller_name: str,
        reason: str,
    ) -> dict[str, Any]:
        now = _utc_now()
        return self._terminal_result(
            request_id=request_id,
            action=action,
            status="rejected",
            reason=reason,
            exit_code=None,
            stdout="",
            stderr="",
            caller_uid=caller_uid,
            caller_name=caller_name,
            started_at=now,
            request_sha256=request_sha256,
        )

    def execute(self, request: dict[str, Any], caller_uid: int, caller_name: str | None = None) -> dict[str, Any]:
        _validate_request(request)
        caller_name = caller_name or pwd.getpwuid(caller_uid).pw_name
        request_sha256 = _sha256(request)
        request_id = request["request_id"]
        action_id = request["action"]
        prior = self.state.setdefault("requests", {}).get(request_id)
        if prior:
            if prior.get("request_sha256") == request_sha256:
                return prior["result"]
            prior_conflict = self.state.setdefault("conflicts", {}).get(request_id, {}).get(request_sha256)
            if prior_conflict:
                return prior_conflict
            result = self._rejection(
                request_id=request_id,
                action=action_id,
                request_sha256=request_sha256,
                caller_uid=caller_uid,
                caller_name=caller_name,
                reason="request_id_conflict",
            )
            return self._store_conflict(request_id, request_sha256, result)

        permissions = self.policy["callers"].get(caller_name)
        if permissions is None:
            result = self._rejection(
                request_id=request_id,
                action=action_id,
                request_sha256=request_sha256,
                caller_uid=caller_uid,
                caller_name=caller_name,
                reason="caller_not_allowed",
            )
            return self._store_request(request_id, request_sha256, result)
        if action_id not in self.policy["enabled_actions"]:
            result = self._rejection(
                request_id=request_id,
                action=action_id,
                request_sha256=request_sha256,
                caller_uid=caller_uid,
                caller_name=caller_name,
                reason="action_disabled",
            )
            return self._store_request(request_id, request_sha256, result)
        action = ACTIONS[action_id]
        if action.permission not in permissions:
            result = self._rejection(
                request_id=request_id,
                action=action_id,
                request_sha256=request_sha256,
                caller_uid=caller_uid,
                caller_name=caller_name,
                reason="permission_denied",
            )
            return self._store_request(request_id, request_sha256, result)
        if action.timeout_requires_recovery and self.state.get("recovery_required") is not None:
            result = self._rejection(
                request_id=request_id,
                action=action_id,
                request_sha256=request_sha256,
                caller_uid=caller_uid,
                caller_name=caller_name,
                reason="mutation_recovery_required",
            )
            return self._store_request(request_id, request_sha256, result)

        started_at = _utc_now()
        self.state["inflight"] = {
            "request_id": request_id,
            "request_sha256": request_sha256,
            "action": action_id,
            "caller_uid": caller_uid,
            "caller_name": caller_name,
            "started_at": started_at,
            "policy_sha256": self.policy_sha256,
        }
        self._save()

        status = "succeeded"
        reason = None
        exit_code: int | None = None
        stdout = ""
        stderr = ""
        try:
            completed = subprocess.run(
                [action.executable, *action.argv],
                check=False,
                capture_output=True,
                text=False,
                timeout=action.timeout_seconds,
                env=SAFE_ENV,
                cwd="/",
            )
            exit_code = completed.returncode
            stdout = _bounded_text(completed.stdout)
            stderr = _bounded_text(completed.stderr)
            if completed.returncode != 0:
                status, reason = _classify_bounded_action_failure(action_id, stdout)
                if action.timeout_requires_recovery and status == "failed" and reason == "action_exit_nonzero":
                    status, reason = "unknown", "action_result_unknown_recovery_required"
        except subprocess.TimeoutExpired as exc:
            status = "unknown" if action.timeout_requires_recovery else "failed"
            reason = "action_timeout_recovery_required" if action.timeout_requires_recovery else "action_timeout"
            stdout = _bounded_text(exc.stdout)
            stderr = _bounded_text(exc.stderr)
        except OSError:
            status = "failed"
            reason = "action_exec_error"

        if action_id == "tls.web.reconcile.v1" and status == "succeeded":
            if _valid_reconcile_result(stdout):
                self.state.pop("recovery_required", None)
            else:
                status = "failed"
                reason = "reconcile_result_invalid"

        if status == "unknown" and action.timeout_requires_recovery:
            self.state["recovery_required"] = {
                "action": action_id,
                "request_id": request_id,
                "reason": reason,
                "observed_at": _utc_now(),
            }

        result = self._terminal_result(
            request_id=request_id,
            action=action_id,
            status=status,
            reason=reason,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            caller_uid=caller_uid,
            caller_name=caller_name,
            started_at=started_at,
            request_sha256=request_sha256,
        )
        return self._store_request(request_id, request_sha256, result)


def _peer_identity(conn: socket.socket) -> tuple[int, str]:
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _, uid, _ = struct.unpack("3i", raw)
    return uid, pwd.getpwuid(uid).pw_name


def _protocol_rejection(reason: str) -> dict[str, Any]:
    # Protocol-level failures happen before a valid request id exists and are not
    # entered into the evidence chain. They intentionally disclose no exception text.
    return {
        "schema": "home-center.helper.protocol-error.v1",
        "status": "rejected",
        "reason": reason,
    }


def _receive_request(conn: socket.socket, timeout_seconds: float = CLIENT_IO_TIMEOUT_SECONDS) -> bytes:
    """Read one bounded newline-delimited request without blocking the singleton server."""
    deadline = time.monotonic() + timeout_seconds
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("helper request deadline exceeded")
        conn.settimeout(remaining)
        chunk = conn.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_REQUEST_BYTES:
        raise HelperError("request_too_large")
    return bytes(data).split(b"\n", 1)[0]


def serve(socket_path: Path, policy_path: Path, state_path: Path) -> None:
    engine = HelperEngine(
        policy_path=policy_path,
        state_path=state_path,
        require_root_controlled_policy=True,
    )
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o660)
        try:
            gid = pwd.getpwnam("home-center").pw_gid
            os.chown(socket_path, 0, gid)
        except KeyError:
            pass
        server.listen(16)
        while True:
            conn, _ = server.accept()
            with conn:
                try:
                    uid, name = _peer_identity(conn)
                    line = _receive_request(conn)
                    if not line:
                        raise HelperError("empty_request")
                    request = json.loads(line.decode("utf-8"))
                    if not isinstance(request, dict):
                        raise HelperError("request_root_must_be_object")
                    if request.get("schema") == "home-center.helper.secret-request.v1":
                        result = _execute_secret_request(
                            request,
                            caller_uid=uid,
                            caller_name=name,
                            policy=engine.policy,
                        )
                    else:
                        result = engine.execute(request, caller_uid=uid, caller_name=name)
                except (HelperError, UnicodeDecodeError, json.JSONDecodeError, KeyError, ValueError, TimeoutError):
                    result = _protocol_rejection("invalid_request")
                except Exception:
                    result = _protocol_rejection("internal_error")
                try:
                    conn.sendall(_canonical(result) + b"\n")
                except (BrokenPipeError, ConnectionError, TimeoutError, OSError):
                    pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    args = parser.parse_args()
    if not args.serve:
        parser.error("--serve is required")
    serve(args.socket, args.policy, args.state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
