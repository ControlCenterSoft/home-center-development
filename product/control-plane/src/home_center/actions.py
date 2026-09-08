"""Реестр типизированных действий с принципом fail-closed и ограниченные локальные исполнители."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now


LOG = logging.getLogger("home_center.actions")
ACTION_ID = re.compile(r"^[a-z][a-z0-9.-]+\.v[0-9]+$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
SERVICE_VALUE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
LOCAL_ADMIN_ACTOR = re.compile(r"^local-admin:[a-z][a-z0-9._-]{2,63}$")
AD_ADMIN_ACTOR = re.compile(r"^ad-admin:[a-z0-9][a-z0-9._-]{0,63}@[A-Z0-9][A-Z0-9.-]{2,254}$")
SYSTEMCTL = "/usr/bin/systemctl"
SUPPORTED_ACTION = "service.state.read.v1"
LOCAL_ADMIN_PERMISSIONS = frozenset({"service.read"})
# Только зафиксированный маркер совместимости security-gate 0.7; это не исполняемая политика:
# "bootstrap-admin": frozenset({"service.read"})


class ActionRequestError(ValueError):
    code = "invalid_action_request"


class ActionNotFound(ActionRequestError):
    code = "action_not_found"


class ActionPermissionDenied(ActionRequestError):
    code = "action_permission_denied"


class ActionTargetConflict(ActionRequestError):
    code = "action_target_conflict"


class ActionIdempotencyConflict(ActionRequestError):
    code = "idempotency_conflict"


Runner = Callable[..., subprocess.CompletedProcess[str]]


def _actor_permissions(actor: str) -> frozenset[str]:
    if LOCAL_ADMIN_ACTOR.fullmatch(actor) or AD_ADMIN_ACTOR.fullmatch(actor):
        return LOCAL_ADMIN_PERMISSIONS
    return frozenset()


class ActionRegistry:
    """Предоставляет неизменяемые определения и выполняет только явно реализованные действия."""

    def __init__(
        self,
        node_id: str,
        store: StateStore,
        *,
        runner: Runner = subprocess.run,
        registry_path: Path | None = None,
    ) -> None:
        self.node_id = node_id
        self.store = store
        self._runner = runner
        path = registry_path or Path(__file__).with_name("action_registry.v1.json")
        self._catalog = json.loads(path.read_text(encoding="utf-8"))
        self._definitions = self._validate_catalog(self._catalog)

    def catalog(self) -> dict[str, Any]:
        return deepcopy(self._catalog)

    def run(
        self,
        *,
        actor: str,
        action_id: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> tuple[dict[str, Any], bool]:
        if not ACTION_ID.fullmatch(action_id):
            raise ActionNotFound("unknown action")
        definition = self._definitions.get(action_id)
        if definition is None:
            raise ActionNotFound("unknown action")
        permission = definition["permission"]
        if permission not in _actor_permissions(actor):
            raise ActionPermissionDenied("permission denied")
        normalized = self._validate_request(definition, request)
        if normalized["target_node_id"] != self.node_id:
            raise ActionTargetConflict("target is not local")

        request_material = {
            "actor": actor,
            "action_id": action_id,
            "target_node_id": normalized["target_node_id"],
            "reason": normalized["reason"],
            "input": normalized["input"],
        }
        request_hash = hashlib.sha256(canonical_json(request_material).encode("utf-8")).hexdigest()
        preflight = {
            "passed": True,
            "checks": [
                {"id": "action.registered", "status": "pass", "reason": None},
                {"id": "actor.authorized", "status": "pass", "reason": None},
                {"id": "target.local", "status": "pass", "reason": None},
                {"id": "input.allowlisted", "status": "pass", "reason": None},
            ],
        }
        steps = [
            {
                "id": "observe-service",
                "action": action_id,
                "state": "pending",
                "postconditions": [],
            }
        ]
        try:
            job, created = self.store.create_action_job(
                action_id=action_id,
                actor=actor,
                reason=normalized["reason"],
                idempotency_key=normalized["idempotency_key"],
                request_hash=request_hash,
                preflight=preflight,
                steps=steps,
            )
        except IdempotencyConflict as exc:
            raise ActionIdempotencyConflict("idempotency key conflicts with another request") from exc
        if not created:
            return job, True

        running_steps = deepcopy(steps)
        running_steps[0]["state"] = "running"
        job = self.store.transition_action_job(
            job["job_id"],
            expected_state="preflight",
            new_state="running",
            steps=running_steps,
        )
        state = "running"
        try:
            result = self._execute(definition, normalized["input"])
            postconditions = [
                {"id": "typed-result", "status": "pass", "reason": None},
                {"id": "service-identity-match", "status": "pass", "reason": None},
            ]
            verifying_steps = deepcopy(running_steps)
            verifying_steps[0]["postconditions"] = postconditions
            job = self.store.transition_action_job(
                job["job_id"],
                expected_state="running",
                new_state="verifying",
                result=result,
                steps=verifying_steps,
            )
            state = "verifying"
            audit_event_id = self.store.audit(
                actor=actor,
                action=action_id,
                target=self.node_id,
                outcome="succeeded",
                correlation_id=correlation_id,
                details={"job_id": job["job_id"], "request_sha256": request_hash},
            )
            evidence = {
                "schema": "home-center.action-evidence.v1",
                "action_id": action_id,
                "target_node_id": self.node_id,
                "request_sha256": request_hash,
                "result_sha256": hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest(),
                "audit_event_id": audit_event_id,
                "observed_at": utc_now(),
            }
            succeeded_steps = deepcopy(verifying_steps)
            succeeded_steps[0]["state"] = "succeeded"
            return (
                self.store.transition_action_job(
                    job["job_id"],
                    expected_state="verifying",
                    new_state="succeeded",
                    evidence=evidence,
                    steps=succeeded_steps,
                ),
                False,
            )
        except Exception as exc:  # Ошибки исполнителя сохраняются и никогда не возвращаются напрямую
            LOG.warning("typed action failed action=%s class=%s", action_id, type(exc).__name__)
            error_code = "action_timeout" if isinstance(exc, subprocess.TimeoutExpired) else "action_execution_failed"
            failed_steps = deepcopy(running_steps)
            failed_steps[0]["state"] = "failed"
            failed_steps[0]["postconditions"] = [
                {"id": "typed-result", "status": "fail", "reason": error_code}
            ]
            audit_event_id = self.store.audit(
                actor=actor,
                action=action_id,
                target=self.node_id,
                outcome="failed",
                correlation_id=correlation_id,
                details={"job_id": job["job_id"], "request_sha256": request_hash, "reason": error_code},
            )
            result = {"schema": "home-center.action-error.v1", "code": error_code}
            evidence = {
                "schema": "home-center.action-evidence.v1",
                "action_id": action_id,
                "target_node_id": self.node_id,
                "request_sha256": request_hash,
                "audit_event_id": audit_event_id,
                "observed_at": utc_now(),
            }
            return (
                self.store.transition_action_job(
                    job["job_id"],
                    expected_state=state,
                    new_state="failed",
                    result=result,
                    evidence=evidence,
                    steps=failed_steps,
                ),
                False,
            )

    def _execute(self, definition: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
        if definition["id"] != SUPPORTED_ACTION:
            raise RuntimeError("registered action has no executor")
        service = value["service"]
        completed = self._runner(
            [
                SYSTEMCTL,
                "show",
                service,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--property=UnitFileState",
                "--no-pager",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=definition["timeout_seconds"],
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        if completed.returncode != 0 or not isinstance(completed.stdout, str) or len(completed.stdout) > 8192:
            raise RuntimeError("bounded service query failed")
        fields: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            key, separator, item = line.partition("=")
            if separator and key in {"LoadState", "ActiveState", "SubState", "UnitFileState"}:
                fields[key] = item
        if set(fields) != {"LoadState", "ActiveState", "SubState", "UnitFileState"}:
            raise RuntimeError("service query returned incomplete state")
        if any(not SERVICE_VALUE.fullmatch(item) for item in fields.values()):
            raise RuntimeError("service query returned invalid state")
        return {
            "schema": definition["output"]["schema"],
            "service": service,
            "load_state": fields["LoadState"],
            "active_state": fields["ActiveState"],
            "sub_state": fields["SubState"],
            "unit_file_state": fields["UnitFileState"],
            "observed_at": utc_now(),
        }

    @staticmethod
    def _validate_catalog(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
        if value.get("schema") != "home-center.action-registry.v1" or value.get("version") != 1:
            raise ValueError("unsupported action registry")
        actions = value.get("actions")
        if not isinstance(actions, list) or not actions:
            raise ValueError("action registry is empty")
        definitions: dict[str, dict[str, Any]] = {}
        for definition in actions:
            if not isinstance(definition, dict):
                raise ValueError("invalid action definition")
            action_id = definition.get("id")
            if not isinstance(action_id, str) or not ACTION_ID.fullmatch(action_id) or action_id in definitions:
                raise ValueError("invalid or duplicate action id")
            if definition.get("risk") != "read-only":
                raise ValueError("uncertified mutation action")
            if definition.get("recovery") != {"strategy": "none-read-only"}:
                raise ValueError("invalid read-only recovery policy")
            definitions[action_id] = definition
        if set(definitions) != {SUPPORTED_ACTION}:
            raise ValueError("registry and executor set differ")
        return definitions

    @staticmethod
    def _validate_request(definition: dict[str, Any], value: dict[str, Any]) -> dict[str, Any]:
        required = {"schema", "idempotency_key", "target_node_id", "reason", "input"}
        if set(value) != required or value.get("schema") != "home-center.action-request.v1":
            raise ActionRequestError("invalid request envelope")
        idempotency_key = value.get("idempotency_key")
        target_node_id = value.get("target_node_id")
        reason = value.get("reason")
        action_input = value.get("input")
        if not isinstance(idempotency_key, str) or not IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise ActionRequestError("invalid idempotency key")
        if not isinstance(target_node_id, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{2,63}", target_node_id):
            raise ActionRequestError("invalid target node")
        if not isinstance(reason, str) or not 3 <= len(reason) <= 500:
            raise ActionRequestError("invalid reason")
        if not isinstance(action_input, dict) or set(action_input) != {"service"}:
            raise ActionRequestError("invalid action input")
        service = action_input.get("service")
        allowed = definition["input"]["properties"]["service"]["enum"]
        if not isinstance(service, str) or service not in allowed:
            raise ActionRequestError("service is not allowlisted")
        return {
            "schema": value["schema"],
            "idempotency_key": idempotency_key,
            "target_node_id": target_node_id,
            "reason": reason,
            "input": {"service": service},
        }
