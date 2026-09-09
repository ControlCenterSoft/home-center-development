"""Fail-closed admission contracts for bounded privileged Home Center operations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


SYSTEMCTL = "/usr/bin/systemctl"
ACTION_ID = "service.restart.v1"
ALLOWED_SERVICES = frozenset({"home-center.service"})
IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
AUTHORIZATION_ID = re.compile(r"^opauth-[a-f0-9]{24}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
STATE_VALUE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")


class OperationCommandError(ValueError):
    """A bounded operation command failed admission."""


class OperationJobState(StrEnum):
    PREPARED = "prepared"
    RUNNING = "running"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ServiceStateSnapshot:
    target_node_id: str
    service: str
    load_state: str
    active_state: str
    sub_state: str
    unit_file_state: str

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.target_node_id):
            raise OperationCommandError("invalid_target_node")
        if self.service not in ALLOWED_SERVICES:
            raise OperationCommandError("service_not_allowlisted")
        for value in (
            self.load_state,
            self.active_state,
            self.sub_state,
            self.unit_file_state,
        ):
            if not isinstance(value, str) or not STATE_VALUE.fullmatch(value):
                raise OperationCommandError("invalid_service_state")

    @property
    def sha256(self) -> str:
        return _sha256(
            {
                "target_node_id": self.target_node_id,
                "service": self.service,
                "load_state": self.load_state,
                "active_state": self.active_state,
                "sub_state": self.sub_state,
                "unit_file_state": self.unit_file_state,
            }
        )


@dataclass(frozen=True, slots=True)
class OperationCommandRequest:
    authorization_id: str
    idempotency_key: str
    target_node_id: str
    service: str
    reason: str
    correlation_id: str
    action_id: str = ACTION_ID

    def __post_init__(self) -> None:
        if self.action_id != ACTION_ID:
            raise OperationCommandError("unsupported_action")
        if not AUTHORIZATION_ID.fullmatch(self.authorization_id):
            raise OperationCommandError("invalid_authorization")
        if not IDEMPOTENCY_KEY.fullmatch(self.idempotency_key):
            raise OperationCommandError("invalid_idempotency_key")
        if not IDENTIFIER.fullmatch(self.target_node_id):
            raise OperationCommandError("invalid_target_node")
        if self.service not in ALLOWED_SERVICES:
            raise OperationCommandError("service_not_allowlisted")
        if not isinstance(self.reason, str) or not 3 <= len(self.reason) <= 500:
            raise OperationCommandError("invalid_reason")
        if not isinstance(self.correlation_id, str) or not 8 <= len(self.correlation_id) <= 128:
            raise OperationCommandError("invalid_correlation_id")


@dataclass(frozen=True, slots=True)
class OperationCommandPlan:
    plan_id: str
    request_sha256: str
    request: OperationCommandRequest
    snapshot_sha256: str
    restart_argv: tuple[str, ...]
    verify_argv: tuple[str, ...]
    rollback_argv: tuple[str, ...]
    rollback_expected_active_state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "home-center.operation-command-plan.v1",
            "plan_id": self.plan_id,
            "request_sha256": self.request_sha256,
            "action_id": self.request.action_id,
            "authorization_id": self.request.authorization_id,
            "idempotency_key": self.request.idempotency_key,
            "target_node_id": self.request.target_node_id,
            "service": self.request.service,
            "snapshot_sha256": self.snapshot_sha256,
            "execution": {
                "executable": SYSTEMCTL,
                "argv": list(self.restart_argv),
                "timeout_seconds": 15,
                "shell": False,
            },
            "verification": {
                "argv": list(self.verify_argv),
                "timeout_seconds": 5,
                "required_active_state": "active",
            },
            "recovery": {
                "strategy": "restore-observed-active-state",
                "argv": list(self.rollback_argv),
                "timeout_seconds": 15,
                "expected_active_state": self.rollback_expected_active_state,
                "verification_required": True,
            },
            "audit": {
                "required": True,
                "correlation_id": self.request.correlation_id,
                "reason": self.request.reason,
            },
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "execution_authorized": False,
            "production_mutation_enabled": False,
        }


class OperationCommandAdmission:
    """Build immutable command material without executing it or granting authority."""

    def prepare(
        self,
        snapshot: ServiceStateSnapshot,
        request: OperationCommandRequest,
    ) -> OperationCommandPlan:
        if snapshot.target_node_id != request.target_node_id:
            raise OperationCommandError("target_snapshot_mismatch")
        if snapshot.service != request.service:
            raise OperationCommandError("service_snapshot_mismatch")
        if snapshot.load_state != "loaded":
            raise OperationCommandError("service_not_loaded")
        if snapshot.active_state not in {"active", "inactive"}:
            raise OperationCommandError("unsafe_active_state")

        request_material = {
            "action_id": request.action_id,
            "authorization_id": request.authorization_id,
            "idempotency_key": request.idempotency_key,
            "target_node_id": request.target_node_id,
            "service": request.service,
            "reason": request.reason,
            "correlation_id": request.correlation_id,
            "snapshot_sha256": snapshot.sha256,
        }
        request_sha256 = _sha256(request_material)
        rollback_verb = "start" if snapshot.active_state == "active" else "stop"
        verify_argv = (
            SYSTEMCTL,
            "show",
            request.service,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=UnitFileState",
            "--no-pager",
        )
        return OperationCommandPlan(
            plan_id=f"opcmd-{request_sha256[:24]}",
            request_sha256=request_sha256,
            request=request,
            snapshot_sha256=snapshot.sha256,
            restart_argv=(SYSTEMCTL, "restart", request.service),
            verify_argv=verify_argv,
            rollback_argv=(SYSTEMCTL, rollback_verb, request.service),
            rollback_expected_active_state=snapshot.active_state,
        )


def validate_job_transition(
    current: OperationJobState,
    target: OperationJobState,
    *,
    mutation_may_have_occurred: bool = False,
) -> None:
    """Validate fail-closed state movement for one bounded operation job."""

    allowed: dict[OperationJobState, set[OperationJobState]] = {
        OperationJobState.PREPARED: {OperationJobState.RUNNING, OperationJobState.FAILED},
        OperationJobState.RUNNING: {
            OperationJobState.VERIFYING,
            OperationJobState.ROLLING_BACK,
            OperationJobState.FAILED,
        },
        OperationJobState.VERIFYING: {
            OperationJobState.SUCCEEDED,
            OperationJobState.ROLLING_BACK,
        },
        OperationJobState.ROLLING_BACK: {
            OperationJobState.ROLLED_BACK,
            OperationJobState.FAILED,
        },
    }
    if target not in allowed.get(current, set()):
        raise OperationCommandError("invalid_job_transition")
    if current == OperationJobState.RUNNING and target == OperationJobState.FAILED:
        if mutation_may_have_occurred:
            raise OperationCommandError("rollback_required")
    if target == OperationJobState.ROLLING_BACK and not mutation_may_have_occurred:
        raise OperationCommandError("rollback_without_possible_mutation")


def _sha256(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
