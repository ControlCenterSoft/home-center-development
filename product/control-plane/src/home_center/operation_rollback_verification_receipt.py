"""Fail-closed completion contract for one bounded rollback verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from .operation_commands import (
    ACTION_ID,
    ALLOWED_SERVICES,
    STATE_VALUE,
    SYSTEMCTL,
    OperationJobState,
)
from .operation_job_store import OperationJobPreconditionFailed
from .operation_rollback_execution_receipt import OperationRollbackExecutionReceipt
from .operation_worker_handoff import OperationWorkerIdentity
from .util import canonical_json


SCHEMA = "home-center.operation-rollback-verification-receipt.v1"


class OperationRollbackVerificationReceiptError(RuntimeError):
    """Rollback verification could not be accepted safely."""


class OperationRollbackVerificationStore(Protocol):
    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...

    def transition_operation_job(
        self,
        job_id: str,
        *,
        expected_state: OperationJobState,
        expected_state_version: int,
        target_state: OperationJobState,
        mutation_may_have_occurred: bool = False,
        result: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
        recovery: dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class OperationRollbackVerificationObservation:
    """Sanitized systemd observation; raw output and command material are forbidden."""

    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    load_state: str | None = None
    active_state: str | None = None
    sub_state: str | None = None
    unit_file_state: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.started, bool) or not isinstance(self.timed_out, bool):
            raise OperationRollbackVerificationReceiptError("invalid_verification_flags")
        if (
            not isinstance(self.elapsed_ms, int)
            or isinstance(self.elapsed_ms, bool)
            or not 0 <= self.elapsed_ms <= 5_000
        ):
            raise OperationRollbackVerificationReceiptError("invalid_verification_elapsed_ms")
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int)
            or isinstance(self.exit_code, bool)
            or not -255 <= self.exit_code <= 255
        ):
            raise OperationRollbackVerificationReceiptError("invalid_verification_exit_code")
        states = (self.load_state, self.active_state, self.sub_state, self.unit_file_state)
        if not self.started:
            if self.timed_out or self.exit_code is not None or self.elapsed_ms != 0:
                raise OperationRollbackVerificationReceiptError("invalid_not_started_observation")
            if any(value is not None for value in states):
                raise OperationRollbackVerificationReceiptError("state_without_execution")
            return
        if self.timed_out:
            if self.exit_code is not None or any(value is not None for value in states):
                raise OperationRollbackVerificationReceiptError("invalid_timeout_observation")
            return
        if self.exit_code is None:
            raise OperationRollbackVerificationReceiptError("missing_verification_exit_code")
        if self.exit_code != 0:
            if any(value is not None for value in states):
                raise OperationRollbackVerificationReceiptError("state_from_failed_verification")
            return
        for value in states:
            if not isinstance(value, str) or not STATE_VALUE.fullmatch(value):
                raise OperationRollbackVerificationReceiptError("invalid_service_state")


@dataclass(frozen=True, slots=True)
class OperationRollbackVerificationReceipt:
    receipt_id: str
    rollback_execution_receipt_id: str
    rollback_claim_id: str
    verification_receipt_id: str
    execution_receipt_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    worker_id: str
    target_node_id: str
    recovery_sha256: str
    expected_active_state: str
    verification_sha256: str
    started: bool
    timed_out: bool
    exit_code: int | None
    elapsed_ms: int
    load_state: str | None
    active_state: str | None
    sub_state: str | None
    unit_file_state: str | None
    recovery_verified: bool
    recovery_required: bool
    next_state: str
    from_state_version: int
    to_state_version: int
    schema: str = field(default=SCHEMA, init=False)
    from_state: str = field(default="rolling_back", init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    grants_execution_authority: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "rollback_execution_receipt_id": self.rollback_execution_receipt_id,
            "rollback_claim_id": self.rollback_claim_id,
            "verification_receipt_id": self.verification_receipt_id,
            "execution_receipt_id": self.execution_receipt_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "worker_id": self.worker_id,
            "target_node_id": self.target_node_id,
            "recovery_sha256": self.recovery_sha256,
            "expected_active_state": self.expected_active_state,
            "verification_sha256": self.verification_sha256,
            "started": self.started,
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "elapsed_ms": self.elapsed_ms,
            "load_state": self.load_state,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
            "unit_file_state": self.unit_file_state,
            "recovery_verified": self.recovery_verified,
            "recovery_required": self.recovery_required,
            "from_state": self.from_state,
            "next_state": self.next_state,
            "from_state_version": self.from_state_version,
            "to_state_version": self.to_state_version,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "grants_execution_authority": False,
            "production_mutation_enabled": False,
        }


class OperationRollbackVerificationReceiptCoordinator:
    """CAS-close rollback recovery from one exact bounded state observation."""

    def __init__(self, store: OperationRollbackVerificationStore) -> None:
        if not hasattr(store, "operation_job") or not hasattr(
            store, "transition_operation_job"
        ):
            raise TypeError("store does not provide operation transition primitives")
        self._store = store

    def record(
        self,
        execution: OperationRollbackExecutionReceipt,
        *,
        worker: OperationWorkerIdentity,
        observation: OperationRollbackVerificationObservation,
    ) -> tuple[OperationRollbackVerificationReceipt, bool]:
        if not isinstance(execution, OperationRollbackExecutionReceipt):
            raise TypeError("execution must be OperationRollbackExecutionReceipt")
        if not isinstance(worker, OperationWorkerIdentity):
            raise TypeError("worker must be OperationWorkerIdentity")
        if not isinstance(observation, OperationRollbackVerificationObservation):
            raise TypeError("observation must be OperationRollbackVerificationObservation")
        _validate_execution_receipt(execution, worker)

        job = self._store.operation_job(execution.job_id)
        if job is None:
            raise OperationRollbackVerificationReceiptError("operation_job_not_found")
        replay = _replay_receipt(job, execution, observation)
        if replay is not None:
            return replay, False

        verification_sha256 = _validate_pending_job(job, execution)
        receipt = _build_receipt(execution, verification_sha256, observation)
        evidence = dict(job["evidence"])
        evidence["rollback_verification_receipt"] = receipt.to_dict()
        result = dict(job["result"]) if isinstance(job.get("result"), dict) else {}
        result["rollback_verification"] = _result_value(receipt)
        recovery = dict(job["recovery"])
        recovery["verification"] = {
            "receipt_id": receipt.receipt_id,
            "recovery_verified": receipt.recovery_verified,
            "recovery_required": receipt.recovery_required,
        }
        try:
            updated = self._store.transition_operation_job(
                execution.job_id,
                expected_state=OperationJobState.ROLLING_BACK,
                expected_state_version=execution.to_state_version,
                target_state=OperationJobState(receipt.next_state),
                mutation_may_have_occurred=True,
                result=result,
                evidence=evidence,
                recovery=recovery,
            )
        except OperationJobPreconditionFailed:
            current = self._store.operation_job(execution.job_id)
            if current is not None:
                replay = _replay_receipt(current, execution, observation)
                if replay is not None:
                    return replay, False
            raise OperationRollbackVerificationReceiptError(
                "operation_rollback_verification_stale"
            ) from None
        _validate_final_job(updated, execution, receipt)
        return receipt, True


def revalidate_operation_rollback_verification_receipt(
    store: OperationRollbackVerificationStore,
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
) -> None:
    """Fail closed before a consumer treats rollback recovery as complete."""

    if not isinstance(receipt, OperationRollbackVerificationReceipt):
        raise TypeError("receipt must be OperationRollbackVerificationReceipt")
    if not isinstance(execution, OperationRollbackExecutionReceipt):
        raise TypeError("execution must be OperationRollbackExecutionReceipt")
    _validate_receipt_lineage(receipt, execution)
    job = store.operation_job(receipt.job_id)
    if job is None:
        raise OperationRollbackVerificationReceiptError("operation_job_not_found")
    _validate_final_job(job, execution, receipt)


def _validate_execution_receipt(
    receipt: OperationRollbackExecutionReceipt,
    worker: OperationWorkerIdentity,
) -> None:
    value = receipt.to_dict()
    if worker.worker_id != receipt.worker_id or worker.node_id != receipt.target_node_id:
        raise OperationRollbackVerificationReceiptError("operation_worker_identity_mismatch")
    if receipt.action_id != ACTION_ID:
        raise OperationRollbackVerificationReceiptError("unsupported_operation_action")
    if (
        not receipt.rollback_succeeded
        or receipt.recovery_required
        or not receipt.verification_required
        or receipt.next_state != OperationJobState.ROLLING_BACK.value
    ):
        raise OperationRollbackVerificationReceiptError("rollback_not_verifiable")
    for name in (
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    ):
        if value.get(name) is not False:
            raise OperationRollbackVerificationReceiptError("unsafe_execution_receipt")


def _validate_pending_job(
    job: dict[str, Any],
    execution: OperationRollbackExecutionReceipt,
) -> str:
    if job.get("state") != OperationJobState.ROLLING_BACK.value:
        raise OperationRollbackVerificationReceiptError("operation_job_not_rolling_back")
    if job.get("state_version") != execution.to_state_version:
        raise OperationRollbackVerificationReceiptError("operation_job_state_stale")
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRollbackVerificationReceiptError("mutation_evidence_missing")
    if job.get("recovery_required") is not False:
        raise OperationRollbackVerificationReceiptError("recovery_already_required")
    _validate_job_lineage(job, execution, include_verification=False)
    return _verification_sha256(job, execution)


def _validate_final_job(
    job: dict[str, Any],
    execution: OperationRollbackExecutionReceipt,
    receipt: OperationRollbackVerificationReceipt,
) -> None:
    _validate_receipt_lineage(receipt, execution)
    if job.get("state") != receipt.next_state:
        raise OperationRollbackVerificationReceiptError("final_state_mismatch")
    if job.get("state_version") != receipt.to_state_version:
        raise OperationRollbackVerificationReceiptError("final_state_version_mismatch")
    if job.get("mutation_may_have_occurred") is not True:
        raise OperationRollbackVerificationReceiptError("mutation_evidence_missing")
    if job.get("recovery_required") is not receipt.recovery_required:
        raise OperationRollbackVerificationReceiptError("recovery_state_mismatch")
    _validate_job_lineage(job, execution, include_verification=True, receipt=receipt)
    if _verification_sha256(job, execution) != receipt.verification_sha256:
        raise OperationRollbackVerificationReceiptError("verification_contract_drift")
    result = job.get("result")
    if not isinstance(result, dict) or result.get("rollback_verification") != _result_value(
        receipt
    ):
        raise OperationRollbackVerificationReceiptError("verification_result_mismatch")
    recovery = job.get("recovery")
    expected = {
        "receipt_id": receipt.receipt_id,
        "recovery_verified": receipt.recovery_verified,
        "recovery_required": receipt.recovery_required,
    }
    if not isinstance(recovery, dict) or recovery.get("verification") != expected:
        raise OperationRollbackVerificationReceiptError("recovery_evidence_mismatch")
    audit_event_id = job.get("last_audit_event_id")
    if not isinstance(audit_event_id, str) or not audit_event_id:
        raise OperationRollbackVerificationReceiptError("transition_audit_missing")


def _validate_job_lineage(
    job: dict[str, Any],
    execution: OperationRollbackExecutionReceipt,
    *,
    include_verification: bool,
    receipt: OperationRollbackVerificationReceipt | None = None,
) -> None:
    for name in ("job_id", "action_id", "plan_id", "plan_sha256", "target_node_id"):
        if job.get(name) != getattr(execution, name):
            raise OperationRollbackVerificationReceiptError(f"operation_job_{name}_mismatch")
    evidence = job.get("evidence")
    expected_keys = {
        "worker_claim",
        "execution_receipt",
        "verification_receipt",
        "rollback_claim",
        "rollback_execution_receipt",
    }
    if include_verification:
        expected_keys.add("rollback_verification_receipt")
    if not isinstance(evidence, dict) or set(evidence) != expected_keys:
        raise OperationRollbackVerificationReceiptError("operation_evidence_shape_mismatch")
    if evidence.get("rollback_execution_receipt") != execution.to_dict():
        raise OperationRollbackVerificationReceiptError("rollback_execution_evidence_mismatch")
    _validate_prior_evidence(evidence, execution)
    if include_verification:
        assert receipt is not None
        if evidence.get("rollback_verification_receipt") != receipt.to_dict():
            raise OperationRollbackVerificationReceiptError("verification_evidence_mismatch")


def _validate_prior_evidence(
    evidence: dict[str, Any],
    execution: OperationRollbackExecutionReceipt,
) -> None:
    original = evidence.get("execution_receipt")
    if not isinstance(original, dict):
        raise OperationRollbackVerificationReceiptError("execution_evidence_missing")
    _match(
        original,
        {
            "receipt_id": execution.execution_receipt_id,
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
            "started": True,
            "timed_out": False,
            "exit_code": 0,
            "mutation_may_have_occurred": True,
            "next_state": OperationJobState.VERIFYING.value,
        },
        "execution_receipt",
    )
    claim = evidence.get("worker_claim")
    if not isinstance(claim, dict):
        raise OperationRollbackVerificationReceiptError("worker_claim_missing")
    _match(
        claim,
        {
            "claim_id": original.get("claim_id"),
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
        },
        "worker_claim",
    )
    verification = evidence.get("verification_receipt")
    if not isinstance(verification, dict):
        raise OperationRollbackVerificationReceiptError("verification_evidence_missing")
    _match(
        verification,
        {
            "receipt_id": execution.verification_receipt_id,
            "execution_receipt_id": execution.execution_receipt_id,
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
            "verified": False,
            "next_state": OperationJobState.ROLLING_BACK.value,
        },
        "verification_receipt",
    )
    rollback_claim = evidence.get("rollback_claim")
    if not isinstance(rollback_claim, dict):
        raise OperationRollbackVerificationReceiptError("rollback_claim_missing")
    _match(
        rollback_claim,
        {
            "claim_id": execution.rollback_claim_id,
            "verification_receipt_id": execution.verification_receipt_id,
            "execution_receipt_id": execution.execution_receipt_id,
            "job_id": execution.job_id,
            "action_id": execution.action_id,
            "plan_id": execution.plan_id,
            "plan_sha256": execution.plan_sha256,
            "worker_id": execution.worker_id,
            "target_node_id": execution.target_node_id,
            "recovery_sha256": execution.recovery_sha256,
            "recovery_strategy": execution.recovery_strategy,
            "expected_active_state": execution.expected_active_state,
            "state": OperationJobState.ROLLING_BACK.value,
            "to_state_version": execution.from_state_version,
            "verification_required": True,
        },
        "rollback_claim",
    )
    for prior in (original, claim, verification, rollback_claim):
        for name in (
            "contains_command_material",
            "accepts_caller_argv",
            "accepts_shell",
            "production_mutation_enabled",
        ):
            if prior.get(name) is not False:
                raise OperationRollbackVerificationReceiptError("unsafe_prior_evidence")
    if claim.get("execution_authorized") is not False:
        raise OperationRollbackVerificationReceiptError("unsafe_worker_claim")
    if rollback_claim.get("execution_authorized") is not False:
        raise OperationRollbackVerificationReceiptError("unsafe_rollback_claim")
    if original.get("grants_execution_authority") is not False:
        raise OperationRollbackVerificationReceiptError("unsafe_execution_evidence")
    if verification.get("grants_execution_authority") is not False:
        raise OperationRollbackVerificationReceiptError("unsafe_verification_evidence")


def _verification_sha256(
    job: dict[str, Any],
    execution: OperationRollbackExecutionReceipt,
) -> str:
    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationRollbackVerificationReceiptError("operation_plan_missing")
    if hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest() != execution.plan_sha256:
        raise OperationRollbackVerificationReceiptError("operation_plan_integrity_mismatch")
    if (
        plan.get("action_id") != ACTION_ID
        or plan.get("plan_id") != execution.plan_id
        or plan.get("target_node_id") != execution.target_node_id
        or plan.get("service") not in ALLOWED_SERVICES
        or plan.get("accepts_caller_argv") is not False
        or plan.get("accepts_shell") is not False
        or plan.get("execution_authorized") is not False
        or plan.get("production_mutation_enabled") is not False
    ):
        raise OperationRollbackVerificationReceiptError("unsafe_operation_plan")
    argv = [
        SYSTEMCTL,
        "show",
        job["service"],
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--property=UnitFileState",
        "--no-pager",
    ]
    if plan.get("verification") != {
        "argv": argv,
        "timeout_seconds": 5,
        "required_active_state": "active",
    }:
        raise OperationRollbackVerificationReceiptError("verification_contract_mismatch")
    material = {
        "argv": argv,
        "timeout_seconds": 5,
        "expected_active_state": execution.expected_active_state,
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _build_receipt(
    execution: OperationRollbackExecutionReceipt,
    verification_sha256: str,
    observation: OperationRollbackVerificationObservation,
) -> OperationRollbackVerificationReceipt:
    verified = (
        observation.started
        and not observation.timed_out
        and observation.exit_code == 0
        and observation.load_state == "loaded"
        and observation.active_state == execution.expected_active_state
    )
    next_state = OperationJobState.ROLLED_BACK if verified else OperationJobState.FAILED
    identity = {
        "rollback_execution_receipt_id": execution.receipt_id,
        "verification_sha256": verification_sha256,
        "observation": {
            "started": observation.started,
            "timed_out": observation.timed_out,
            "exit_code": observation.exit_code,
            "elapsed_ms": observation.elapsed_ms,
            "load_state": observation.load_state,
            "active_state": observation.active_state,
            "sub_state": observation.sub_state,
            "unit_file_state": observation.unit_file_state,
        },
        "expected_active_state": execution.expected_active_state,
        "from_state_version": execution.to_state_version,
        "to_state_version": execution.to_state_version + 1,
        "next_state": next_state.value,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationRollbackVerificationReceipt(
        receipt_id=f"oprollbackverify-{digest[:24]}",
        rollback_execution_receipt_id=execution.receipt_id,
        rollback_claim_id=execution.rollback_claim_id,
        verification_receipt_id=execution.verification_receipt_id,
        execution_receipt_id=execution.execution_receipt_id,
        job_id=execution.job_id,
        action_id=execution.action_id,
        plan_id=execution.plan_id,
        plan_sha256=execution.plan_sha256,
        worker_id=execution.worker_id,
        target_node_id=execution.target_node_id,
        recovery_sha256=execution.recovery_sha256,
        expected_active_state=execution.expected_active_state,
        verification_sha256=verification_sha256,
        started=observation.started,
        timed_out=observation.timed_out,
        exit_code=observation.exit_code,
        elapsed_ms=observation.elapsed_ms,
        load_state=observation.load_state,
        active_state=observation.active_state,
        sub_state=observation.sub_state,
        unit_file_state=observation.unit_file_state,
        recovery_verified=verified,
        recovery_required=not verified,
        next_state=next_state.value,
        from_state_version=execution.to_state_version,
        to_state_version=execution.to_state_version + 1,
    )


def _replay_receipt(
    job: dict[str, Any],
    execution: OperationRollbackExecutionReceipt,
    observation: OperationRollbackVerificationObservation,
) -> OperationRollbackVerificationReceipt | None:
    if job.get("state") not in {
        OperationJobState.ROLLED_BACK.value,
        OperationJobState.FAILED.value,
    }:
        return None
    if job.get("state_version") != execution.to_state_version + 1:
        return None
    evidence = job.get("evidence")
    if not isinstance(evidence, dict):
        return None
    value = evidence.get("rollback_verification_receipt")
    if not isinstance(value, dict):
        return None
    receipt = _receipt_from_dict(value)
    verification_sha256 = _verification_sha256(job, execution)
    candidate = _build_receipt(execution, verification_sha256, observation)
    if receipt != candidate:
        raise OperationRollbackVerificationReceiptError("rollback_verification_conflict")
    _validate_final_job(job, execution, receipt)
    return receipt


def _receipt_from_dict(value: dict[str, Any]) -> OperationRollbackVerificationReceipt:
    expected_keys = set(OperationRollbackVerificationReceipt.__dataclass_fields__) - {
        "schema",
        "from_state",
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    }
    fixed_keys = {
        "schema",
        "from_state",
        "contains_command_material",
        "accepts_caller_argv",
        "accepts_shell",
        "grants_execution_authority",
        "production_mutation_enabled",
    }
    if set(value) != expected_keys | fixed_keys:
        raise OperationRollbackVerificationReceiptError("rollback_verification_shape_mismatch")
    receipt = OperationRollbackVerificationReceipt(
        **{name: value[name] for name in expected_keys}
    )
    if receipt.to_dict() != value:
        raise OperationRollbackVerificationReceiptError("rollback_verification_integrity_mismatch")
    return receipt


def _validate_receipt_lineage(
    receipt: OperationRollbackVerificationReceipt,
    execution: OperationRollbackExecutionReceipt,
) -> None:
    expected = {
        "rollback_execution_receipt_id": execution.receipt_id,
        "rollback_claim_id": execution.rollback_claim_id,
        "verification_receipt_id": execution.verification_receipt_id,
        "execution_receipt_id": execution.execution_receipt_id,
        "job_id": execution.job_id,
        "action_id": execution.action_id,
        "plan_id": execution.plan_id,
        "plan_sha256": execution.plan_sha256,
        "worker_id": execution.worker_id,
        "target_node_id": execution.target_node_id,
        "recovery_sha256": execution.recovery_sha256,
        "expected_active_state": execution.expected_active_state,
        "from_state_version": execution.to_state_version,
        "to_state_version": execution.to_state_version + 1,
    }
    for name, value in expected.items():
        if getattr(receipt, name) != value:
            raise OperationRollbackVerificationReceiptError(
                f"rollback_verification_{name}_mismatch"
            )


def _result_value(receipt: OperationRollbackVerificationReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "started": receipt.started,
        "timed_out": receipt.timed_out,
        "exit_code": receipt.exit_code,
        "elapsed_ms": receipt.elapsed_ms,
        "load_state": receipt.load_state,
        "active_state": receipt.active_state,
        "sub_state": receipt.sub_state,
        "unit_file_state": receipt.unit_file_state,
        "recovery_verified": receipt.recovery_verified,
    }


def _match(actual: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    for name, value in expected.items():
        if actual.get(name) != value:
            raise OperationRollbackVerificationReceiptError(f"{label}_{name}_mismatch")
