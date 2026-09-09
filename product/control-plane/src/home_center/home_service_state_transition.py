"""Fail-closed boundary between execution evidence and durable service state.

The objects in this module are inert contracts.  They verify the complete
admission/claim/result/current-state binding and describe a compare-and-swap
commit, but deliberately perform no durable write.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from home_center.home_service_execution_result import HomeServiceExecutionOutcome
from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceInstanceState
from home_center.home_services import HomeServiceCatalogError, _identifier


DECISION_SCHEMA = "home-center.home-service-transition-decision.v1"
COMMIT_SCHEMA = "home-center.home-service-transition-commit.v1"


class ExecutionResultView(Protocol):
    result_id: str
    claim_id: str
    plan_id: str
    job_id: str
    worker_id: str
    instance_id: str
    outcome: HomeServiceExecutionOutcome
    target_state: HomeServiceInstanceState
    observed_generation: int
    observed_resource_version: str
    evidence_digest: str
    verified: bool
    state_transition_authorized: bool
    production_mutation_enabled: bool


class WorkerClaimView(Protocol):
    claim_id: str
    admission_id: str
    plan_id: str
    job_id: str
    worker_id: str
    node_id: str
    instance_id: str
    operation: str
    based_on_generation: int
    based_on_resource_version: str
    claimed: bool
    revalidate_before_execution: bool
    direct_execution: bool
    production_mutation_enabled: bool
    accepts_secret_values: bool


class ExecutionAdmissionView(Protocol):
    admission_id: str
    plan_id: str
    instance_id: str
    operation: str
    based_on_generation: int
    based_on_resource_version: str
    job_id: str
    admitted: bool
    admission_record_only: bool
    worker_claim_authorized: bool
    revalidate_before_claim: bool
    direct_execution: bool
    production_mutation_enabled: bool
    accepts_secret_values: bool


class TransitionDecisionStatus(StrEnum):
    ALLOWED = "allowed"
    REJECTED = "rejected"


class TransitionRejectionCode(StrEnum):
    EVIDENCE_NOT_VERIFIED = "evidence_not_verified"
    EXECUTION_NOT_SUCCEEDED = "execution_not_succeeded"
    UNSAFE_EVIDENCE_BOUNDARY = "unsafe_evidence_boundary"
    UNSAFE_WORKER_CLAIM = "unsafe_worker_claim"
    UNSAFE_EXECUTION_ADMISSION = "unsafe_execution_admission"
    CLAIM_BINDING_MISMATCH = "claim_binding_mismatch"
    ADMISSION_BINDING_MISMATCH = "admission_binding_mismatch"
    PLAN_BINDING_MISMATCH = "plan_binding_mismatch"
    JOB_BINDING_MISMATCH = "job_binding_mismatch"
    WORKER_BINDING_MISMATCH = "worker_binding_mismatch"
    INSTANCE_BINDING_MISMATCH = "instance_binding_mismatch"
    NODE_BINDING_MISMATCH = "node_binding_mismatch"
    OPERATION_BINDING_MISMATCH = "operation_binding_mismatch"
    TARGET_STATE_MISMATCH = "target_state_mismatch"
    GENERATION_BINDING_MISMATCH = "generation_binding_mismatch"
    RESOURCE_VERSION_BINDING_MISMATCH = "resource_version_binding_mismatch"


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionDecision:
    decision_id: str
    result_id: str
    evidence_digest: str
    admission_id: str
    claim_id: str
    plan_id: str
    job_id: str
    worker_id: str
    node_id: str
    instance_id: str
    source_state: HomeServiceInstanceState
    target_state: HomeServiceInstanceState
    expected_generation: int
    expected_resource_version: str
    status: TransitionDecisionStatus
    rejection_codes: tuple[TransitionRejectionCode, ...]
    schema: str = field(default=DECISION_SCHEMA, init=False)
    evidence_record_only: bool = field(default=True, init=False)
    transition_allowed: bool = field(default=False, init=False)
    durable_commit_required: bool = field(default=True, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        allowed = self.status is TransitionDecisionStatus.ALLOWED
        if allowed == bool(self.rejection_codes):
            raise HomeServiceCatalogError("invalid_transition_decision")
        object.__setattr__(self, "transition_allowed", allowed)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "decision_id": self.decision_id,
            "result_id": self.result_id,
            "evidence_digest": self.evidence_digest,
            "admission_id": self.admission_id,
            "claim_id": self.claim_id,
            "plan_id": self.plan_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "source_state": self.source_state.value,
            "target_state": self.target_state.value,
            "expected_generation": self.expected_generation,
            "expected_resource_version": self.expected_resource_version,
            "status": self.status.value,
            "rejection_codes": [code.value for code in self.rejection_codes],
            "evidence_record_only": True,
            "transition_allowed": self.transition_allowed,
            "durable_commit_required": True,
            "production_mutation_enabled": False,
        }


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionCommit:
    commit_id: str
    idempotency_key: str
    decision_id: str
    result_id: str
    evidence_digest: str
    admission_id: str
    claim_id: str
    plan_id: str
    job_id: str
    worker_id: str
    node_id: str
    instance_id: str
    source_state: HomeServiceInstanceState
    target_state: HomeServiceInstanceState
    expected_generation: int
    expected_resource_version: str
    next_generation: int
    next_resource_version: str
    schema: str = field(default=COMMIT_SCHEMA, init=False)
    compare_and_swap_required: bool = field(default=True, init=False)
    idempotent: bool = field(default=True, init=False)
    committed: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "commit_id": self.commit_id,
            "idempotency_key": self.idempotency_key,
            "decision_id": self.decision_id,
            "result_id": self.result_id,
            "evidence_digest": self.evidence_digest,
            "admission_id": self.admission_id,
            "claim_id": self.claim_id,
            "plan_id": self.plan_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "source_state": self.source_state.value,
            "target_state": self.target_state.value,
            "expected_generation": self.expected_generation,
            "expected_resource_version": self.expected_resource_version,
            "next_generation": self.next_generation,
            "next_resource_version": self.next_resource_version,
            "compare_and_swap_required": True,
            "idempotent": True,
            "committed": False,
            "production_mutation_enabled": False,
        }


def decide_state_transition(
    result: ExecutionResultView,
    claim: WorkerClaimView,
    admission: ExecutionAdmissionView,
    snapshot: HomeServiceInstanceSnapshot,
) -> HomeServiceTransitionDecision:
    """Return an inert allow/reject decision for an exact current snapshot."""

    values = _validated_values(result, claim, admission, snapshot)
    rejection_codes: list[TransitionRejectionCode] = []

    def reject_if(condition: bool, code: TransitionRejectionCode) -> None:
        if condition and code not in rejection_codes:
            rejection_codes.append(code)

    reject_if(result.verified is not True, TransitionRejectionCode.EVIDENCE_NOT_VERIFIED)
    reject_if(
        result.outcome is not HomeServiceExecutionOutcome.SUCCEEDED,
        TransitionRejectionCode.EXECUTION_NOT_SUCCEEDED,
    )
    reject_if(
        result.state_transition_authorized is not False
        or result.production_mutation_enabled is not False,
        TransitionRejectionCode.UNSAFE_EVIDENCE_BOUNDARY,
    )
    reject_if(
        claim.claimed is not True
        or claim.revalidate_before_execution is not True
        or claim.direct_execution is not False
        or claim.production_mutation_enabled is not False
        or claim.accepts_secret_values is not False,
        TransitionRejectionCode.UNSAFE_WORKER_CLAIM,
    )
    reject_if(
        admission.admitted is not True
        or admission.admission_record_only is not True
        or admission.worker_claim_authorized is not True
        or admission.revalidate_before_claim is not True
        or admission.direct_execution is not False
        or admission.production_mutation_enabled is not False
        or admission.accepts_secret_values is not False,
        TransitionRejectionCode.UNSAFE_EXECUTION_ADMISSION,
    )
    reject_if(result.claim_id != claim.claim_id, TransitionRejectionCode.CLAIM_BINDING_MISMATCH)
    reject_if(
        claim.admission_id != admission.admission_id,
        TransitionRejectionCode.ADMISSION_BINDING_MISMATCH,
    )
    reject_if(
        len({result.plan_id, claim.plan_id, admission.plan_id}) != 1,
        TransitionRejectionCode.PLAN_BINDING_MISMATCH,
    )
    reject_if(
        len({result.job_id, claim.job_id, admission.job_id}) != 1,
        TransitionRejectionCode.JOB_BINDING_MISMATCH,
    )
    reject_if(result.worker_id != claim.worker_id, TransitionRejectionCode.WORKER_BINDING_MISMATCH)
    reject_if(
        len({result.instance_id, claim.instance_id, admission.instance_id, snapshot.instance_id}) != 1,
        TransitionRejectionCode.INSTANCE_BINDING_MISMATCH,
    )
    reject_if(claim.node_id != snapshot.target_node_id, TransitionRejectionCode.NODE_BINDING_MISMATCH)
    reject_if(claim.operation != admission.operation, TransitionRejectionCode.OPERATION_BINDING_MISMATCH)
    expected_target = _expected_target_state(admission.operation, snapshot.state)
    reject_if(expected_target is None, TransitionRejectionCode.OPERATION_BINDING_MISMATCH)
    reject_if(result.target_state is not expected_target, TransitionRejectionCode.TARGET_STATE_MISMATCH)
    reject_if(
        len(
            {
                result.observed_generation,
                claim.based_on_generation,
                admission.based_on_generation,
                snapshot.generation,
            }
        )
        != 1,
        TransitionRejectionCode.GENERATION_BINDING_MISMATCH,
    )
    reject_if(
        len(
            {
                result.observed_resource_version,
                claim.based_on_resource_version,
                admission.based_on_resource_version,
                snapshot.resource_version,
            }
        )
        != 1,
        TransitionRejectionCode.RESOURCE_VERSION_BINDING_MISMATCH,
    )

    codes = tuple(rejection_codes)
    identity = {
        **values,
        "rejection_codes": [code.value for code in codes],
    }
    digest = _digest(identity)
    status = TransitionDecisionStatus.REJECTED if codes else TransitionDecisionStatus.ALLOWED
    return HomeServiceTransitionDecision(
        decision_id=f"hstd-{digest[:24]}",
        result_id=values["result_id"],
        evidence_digest=values["evidence_digest"],
        admission_id=values["admission_id"],
        claim_id=values["claim_id"],
        plan_id=values["plan_id"],
        job_id=values["job_id"],
        worker_id=values["worker_id"],
        node_id=values["node_id"],
        instance_id=values["instance_id"],
        source_state=snapshot.state,
        target_state=result.target_state,
        expected_generation=snapshot.generation,
        expected_resource_version=snapshot.resource_version,
        status=status,
        rejection_codes=codes,
    )


def prepare_transition_commit(
    decision: HomeServiceTransitionDecision,
) -> HomeServiceTransitionCommit:
    """Build a deterministic CAS envelope without writing durable state."""

    if not isinstance(decision, HomeServiceTransitionDecision):
        raise HomeServiceCatalogError("invalid_transition_decision")
    if (
        decision.status is not TransitionDecisionStatus.ALLOWED
        or decision.transition_allowed is not True
        or decision.rejection_codes
        or decision.evidence_record_only is not True
        or decision.durable_commit_required is not True
        or decision.production_mutation_enabled is not False
    ):
        raise HomeServiceCatalogError("transition_not_allowed")

    next_generation = decision.expected_generation + 1
    material = {
        "decision_id": decision.decision_id,
        "result_id": decision.result_id,
        "evidence_digest": decision.evidence_digest,
        "admission_id": decision.admission_id,
        "claim_id": decision.claim_id,
        "plan_id": decision.plan_id,
        "job_id": decision.job_id,
        "worker_id": decision.worker_id,
        "node_id": decision.node_id,
        "instance_id": decision.instance_id,
        "source_state": decision.source_state.value,
        "target_state": decision.target_state.value,
        "expected_generation": decision.expected_generation,
        "expected_resource_version": decision.expected_resource_version,
        "next_generation": next_generation,
    }
    digest = _digest(material)
    return HomeServiceTransitionCommit(
        commit_id=f"hstc-{digest[:24]}",
        idempotency_key=f"hsti-{_digest({'result_id': decision.result_id})[:24]}",
        decision_id=decision.decision_id,
        result_id=decision.result_id,
        evidence_digest=decision.evidence_digest,
        admission_id=decision.admission_id,
        claim_id=decision.claim_id,
        plan_id=decision.plan_id,
        job_id=decision.job_id,
        worker_id=decision.worker_id,
        node_id=decision.node_id,
        instance_id=decision.instance_id,
        source_state=decision.source_state,
        target_state=decision.target_state,
        expected_generation=decision.expected_generation,
        expected_resource_version=decision.expected_resource_version,
        next_generation=next_generation,
        next_resource_version=f"rv:instance:{digest[:24]}",
    )


def _validated_values(
    result: ExecutionResultView,
    claim: WorkerClaimView,
    admission: ExecutionAdmissionView,
    snapshot: HomeServiceInstanceSnapshot,
) -> dict[str, object]:
    if not isinstance(snapshot, HomeServiceInstanceSnapshot):
        raise HomeServiceCatalogError("invalid_instance_snapshot")
    try:
        values: dict[str, object] = {
            "result_id": _identifier(result.result_id, "invalid_result_id"),
            "evidence_digest": _identifier(result.evidence_digest, "invalid_evidence_digest"),
            "admission_id": _identifier(admission.admission_id, "invalid_admission_id"),
            "claim_id": _identifier(claim.claim_id, "invalid_claim_id"),
            "plan_id": _identifier(result.plan_id, "invalid_plan_id"),
            "job_id": _identifier(result.job_id, "invalid_job_id"),
            "worker_id": _identifier(result.worker_id, "invalid_worker_id"),
            "node_id": _identifier(claim.node_id, "invalid_node_id"),
            "instance_id": _identifier(result.instance_id, "invalid_instance_id"),
            "source_state": snapshot.state.value,
            "target_state": result.target_state.value,
            "expected_generation": snapshot.generation,
            "expected_resource_version": snapshot.resource_version,
        }
        identifiers = (
            claim.admission_id,
            claim.plan_id,
            claim.job_id,
            claim.worker_id,
            claim.instance_id,
            claim.operation,
            claim.based_on_resource_version,
            admission.plan_id,
            admission.instance_id,
            admission.operation,
            admission.based_on_resource_version,
            admission.job_id,
            result.claim_id,
            result.observed_resource_version,
        )
        for value in identifiers:
            _identifier(value, "invalid_transition_binding")
        generations = (
            result.observed_generation,
            claim.based_on_generation,
            admission.based_on_generation,
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 1
            for value in generations
        ):
            raise HomeServiceCatalogError("invalid_transition_generation")
        if not isinstance(result.outcome, HomeServiceExecutionOutcome):
            raise HomeServiceCatalogError("invalid_execution_outcome")
        if not isinstance(result.target_state, HomeServiceInstanceState):
            raise HomeServiceCatalogError("invalid_instance_state")
    except AttributeError as exc:
        raise HomeServiceCatalogError("invalid_transition_binding") from exc
    return values


def _expected_target_state(
    operation: str,
    current_state: HomeServiceInstanceState,
) -> HomeServiceInstanceState | None:
    active = {
        HomeServiceInstanceState.CONFIGURED,
        HomeServiceInstanceState.READY,
        HomeServiceInstanceState.DEGRADED,
    }
    if operation == "install" and current_state is HomeServiceInstanceState.PLANNED:
        return HomeServiceInstanceState.INSTALLED
    if operation == "configure" and current_state is HomeServiceInstanceState.INSTALLED:
        return HomeServiceInstanceState.CONFIGURED
    if operation == "health" and current_state in active:
        return HomeServiceInstanceState.READY
    if operation == "update" and current_state in {
        HomeServiceInstanceState.READY,
        HomeServiceInstanceState.DEGRADED,
    }:
        return HomeServiceInstanceState.READY
    if operation in {"backup", "restore"} and current_state in active:
        return current_state
    if operation == "remove" and current_state is not HomeServiceInstanceState.REMOVED:
        return HomeServiceInstanceState.REMOVED
    return None


def _digest(value: dict[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
