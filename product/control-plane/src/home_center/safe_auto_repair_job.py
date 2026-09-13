"""Transport-neutral Home Center 0.64 safe-repair Job lifecycle.

The model is deliberately execution-agnostic. Admission may create a durable Job in a
later persistence layer, but this state machine never calls an adapter or mutates the
target resource. It prevents false success by requiring a separate post-condition
verification after an accepted effect receipt. Ambiguous outcomes become
reconcile-required and are never automatically retried.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum

from .safe_auto_repair_admission import SafeAutoRepairAdmission
from .util import canonical_json

SAFE_REPAIR_JOB_SCHEMA = "home-center.safe-auto-repair-job.v1"
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9._:-]{8,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SafeRepairJobError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class RepairJobState(StrEnum):
    ADMITTED = "admitted"
    RUNNING = "running"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RECONCILE_REQUIRED = "reconcile-required"


class RepairExecutionOutcome(StrEnum):
    ACCEPTED = "accepted"
    FAILED = "failed"
    AMBIGUOUS = "ambiguous"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise SafeRepairJobError(code)
    return value


def _require_monotonic_update(job: "SafeAutoRepairJob", updated_at_epoch: int) -> int:
    if type(updated_at_epoch) is not int or updated_at_epoch < job.updated_at_epoch:
        raise SafeRepairJobError("safe_repair_job_updated_at_non_monotonic")
    return updated_at_epoch


@dataclass(frozen=True, slots=True)
class SafeAutoRepairJob:
    job_id: str
    admission_id: str
    recommendation_id: str
    recommendation_sha256: str
    idempotency_key_sha256: str
    state: RepairJobState
    created_at_epoch: int
    updated_at_epoch: int
    effect_receipt_sha256: str | None = None
    post_condition_evidence_sha256: str | None = None
    post_condition_verified: bool = False
    schema: str = field(default=SAFE_REPAIR_JOB_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.state, RepairJobState):
            raise SafeRepairJobError("safe_repair_job_state_invalid")
        _sha256(self.recommendation_sha256, "safe_repair_job_recommendation_digest_invalid")
        _sha256(self.idempotency_key_sha256, "safe_repair_job_idempotency_digest_invalid")
        if self.effect_receipt_sha256 is not None:
            _sha256(self.effect_receipt_sha256, "safe_repair_job_effect_receipt_invalid")
        if self.post_condition_evidence_sha256 is not None:
            _sha256(
                self.post_condition_evidence_sha256,
                "safe_repair_job_post_condition_evidence_invalid",
            )
        if type(self.created_at_epoch) is not int or self.created_at_epoch < 0:
            raise SafeRepairJobError("safe_repair_job_created_at_invalid")
        if type(self.updated_at_epoch) is not int or self.updated_at_epoch < self.created_at_epoch:
            raise SafeRepairJobError("safe_repair_job_updated_at_invalid")
        if type(self.post_condition_verified) is not bool:
            raise SafeRepairJobError("safe_repair_job_verified_invalid")
        if self.state is RepairJobState.SUCCEEDED:
            if not self.post_condition_verified or self.post_condition_evidence_sha256 is None:
                raise SafeRepairJobError("safe_repair_job_false_success_rejected")
        elif self.post_condition_verified:
            raise SafeRepairJobError("safe_repair_job_verified_state_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "admission_id": self.admission_id,
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "state": self.state.value,
            "created_at_epoch": self.created_at_epoch,
            "updated_at_epoch": self.updated_at_epoch,
            "effect_receipt_sha256": self.effect_receipt_sha256,
            "post_condition_evidence_sha256": self.post_condition_evidence_sha256,
            "post_condition_verified": self.post_condition_verified,
            "raw_idempotency_key_persisted": False,
            "automatic_retry_authorized": False,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_safe_repair_job(
    *,
    admission: SafeAutoRepairAdmission,
    idempotency_key: str,
    created_at_epoch: int,
) -> SafeAutoRepairJob:
    if not isinstance(admission, SafeAutoRepairAdmission):
        raise TypeError("safe_repair_job_admission_invalid")
    if not admission.admissible_for_job or admission.blockers:
        raise SafeRepairJobError("safe_repair_job_admission_blocked")
    if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.fullmatch(idempotency_key):
        raise SafeRepairJobError("safe_repair_job_idempotency_key_invalid")
    if type(created_at_epoch) is not int or created_at_epoch < 0:
        raise SafeRepairJobError("safe_repair_job_created_at_invalid")
    idempotency_sha = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
    material = {
        "admission_id": admission.admission_id,
        "recommendation_id": admission.recommendation_id,
        "recommendation_sha256": admission.recommendation_sha256,
        "idempotency_key_sha256": idempotency_sha,
    }
    job_id = "hcrpj-" + _digest(material)[:24]
    return SafeAutoRepairJob(
        job_id=job_id,
        admission_id=admission.admission_id,
        recommendation_id=admission.recommendation_id,
        recommendation_sha256=admission.recommendation_sha256,
        idempotency_key_sha256=idempotency_sha,
        state=RepairJobState.ADMITTED,
        created_at_epoch=created_at_epoch,
        updated_at_epoch=created_at_epoch,
    )


def start_safe_repair_job(job: SafeAutoRepairJob, *, updated_at_epoch: int) -> SafeAutoRepairJob:
    if job.state is not RepairJobState.ADMITTED:
        raise SafeRepairJobError("safe_repair_job_start_state_invalid")
    timestamp = _require_monotonic_update(job, updated_at_epoch)
    return replace(job, state=RepairJobState.RUNNING, updated_at_epoch=timestamp)


def record_safe_repair_execution(
    job: SafeAutoRepairJob,
    *,
    outcome: RepairExecutionOutcome,
    effect_receipt_sha256: str,
    updated_at_epoch: int,
) -> SafeAutoRepairJob:
    if job.state is not RepairJobState.RUNNING:
        raise SafeRepairJobError("safe_repair_job_execution_state_invalid")
    if not isinstance(outcome, RepairExecutionOutcome):
        raise SafeRepairJobError("safe_repair_job_execution_outcome_invalid")
    timestamp = _require_monotonic_update(job, updated_at_epoch)
    receipt = _sha256(effect_receipt_sha256, "safe_repair_job_effect_receipt_invalid")
    if outcome is RepairExecutionOutcome.ACCEPTED:
        state = RepairJobState.VERIFYING
    elif outcome is RepairExecutionOutcome.FAILED:
        state = RepairJobState.FAILED
    else:
        state = RepairJobState.RECONCILE_REQUIRED
    return replace(
        job,
        state=state,
        updated_at_epoch=timestamp,
        effect_receipt_sha256=receipt,
    )


def verify_safe_repair_post_condition(
    job: SafeAutoRepairJob,
    *,
    evidence_sha256: str,
    verified: bool,
    updated_at_epoch: int,
) -> SafeAutoRepairJob:
    if job.state is not RepairJobState.VERIFYING:
        raise SafeRepairJobError("safe_repair_job_verification_state_invalid")
    if type(verified) is not bool:
        raise SafeRepairJobError("safe_repair_job_verification_result_invalid")
    timestamp = _require_monotonic_update(job, updated_at_epoch)
    evidence = _sha256(evidence_sha256, "safe_repair_job_post_condition_evidence_invalid")
    return replace(
        job,
        state=RepairJobState.SUCCEEDED if verified else RepairJobState.FAILED,
        updated_at_epoch=timestamp,
        post_condition_evidence_sha256=evidence,
        post_condition_verified=verified,
    )
