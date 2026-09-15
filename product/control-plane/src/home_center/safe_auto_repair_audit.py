"""Privacy-minimized Audit evidence for Home Center 0.64 safe auto-repair.

This module projects already-durable safe-repair Job and recommendation state into
closed Audit details. It never accepts raw idempotency keys, commands, credentials,
provider payloads or generic infrastructure/publication authority. The projection
revalidates the exact recommendation digest before any caller may append it to the
canonical StateStore Audit chain.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .safe_auto_repair import SafeAutoRepairRecommendation
from .safe_auto_repair_job import RepairJobState, SafeAutoRepairJob
from .util import canonical_json

SAFE_REPAIR_AUDIT_DETAILS_SCHEMA = "home-center.safe-auto-repair-audit-details.v1"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SafeRepairAuditEvidenceError(ValueError):
    """Stable fail-closed code for malformed or cross-bound repair evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SafeRepairAuditEvidenceError(code)
    return value


def _sha256(value: object, code: str, *, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SafeRepairAuditEvidenceError(code)
    return value


def _recommendation_digest(recommendation: SafeAutoRepairRecommendation) -> str:
    return hashlib.sha256(
        canonical_json(recommendation.to_dict()).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class SafeRepairAuditDetails:
    """Closed Audit payload derived only from durable, content-addressed evidence."""

    job_id: str
    admission_id: str
    recommendation_id: str
    recommendation_sha256: str
    household_id: str
    resource_id: str
    resource_generation: int
    action: str
    risk: str
    job_state: RepairJobState
    updated_at_epoch: int
    recovery_proven: bool
    effect_receipt_sha256: str | None
    post_condition_evidence_sha256: str | None
    post_condition_verified: bool
    schema: str = field(default=SAFE_REPAIR_AUDIT_DETAILS_SCHEMA, init=False)

    def __post_init__(self) -> None:
        for value, code in (
            (self.job_id, "safe_repair_audit_job_id_invalid"),
            (self.admission_id, "safe_repair_audit_admission_id_invalid"),
            (self.recommendation_id, "safe_repair_audit_recommendation_id_invalid"),
            (self.household_id, "safe_repair_audit_household_id_invalid"),
            (self.resource_id, "safe_repair_audit_resource_id_invalid"),
            (self.action, "safe_repair_audit_action_invalid"),
            (self.risk, "safe_repair_audit_risk_invalid"),
        ):
            _identifier(value, code)
        _sha256(
            self.recommendation_sha256,
            "safe_repair_audit_recommendation_digest_invalid",
        )
        _sha256(
            self.effect_receipt_sha256,
            "safe_repair_audit_effect_receipt_invalid",
            optional=True,
        )
        _sha256(
            self.post_condition_evidence_sha256,
            "safe_repair_audit_post_condition_evidence_invalid",
            optional=True,
        )
        if type(self.resource_generation) is not int or self.resource_generation < 0:
            raise SafeRepairAuditEvidenceError(
                "safe_repair_audit_resource_generation_invalid"
            )
        if not isinstance(self.job_state, RepairJobState):
            raise SafeRepairAuditEvidenceError("safe_repair_audit_job_state_invalid")
        if type(self.updated_at_epoch) is not int or self.updated_at_epoch < 0:
            raise SafeRepairAuditEvidenceError("safe_repair_audit_updated_at_invalid")
        if type(self.recovery_proven) is not bool:
            raise SafeRepairAuditEvidenceError(
                "safe_repair_audit_recovery_proven_invalid"
            )
        if type(self.post_condition_verified) is not bool:
            raise SafeRepairAuditEvidenceError(
                "safe_repair_audit_post_condition_verified_invalid"
            )
        if self.job_state is RepairJobState.SUCCEEDED:
            if (
                not self.post_condition_verified
                or self.post_condition_evidence_sha256 is None
                or self.effect_receipt_sha256 is None
            ):
                raise SafeRepairAuditEvidenceError(
                    "safe_repair_audit_false_success_rejected"
                )
        elif self.post_condition_verified:
            raise SafeRepairAuditEvidenceError(
                "safe_repair_audit_verified_state_invalid"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "admission_id": self.admission_id,
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "resource_generation": self.resource_generation,
            "action": self.action,
            "risk": self.risk,
            "job_state": self.job_state.value,
            "updated_at_epoch": self.updated_at_epoch,
            "recovery_proven": self.recovery_proven,
            "effect_receipt_sha256": self.effect_receipt_sha256,
            "post_condition_evidence_sha256": self.post_condition_evidence_sha256,
            "post_condition_verified": self.post_condition_verified,
            "raw_idempotency_key_persisted": False,
            "credential_value_access_authorized": False,
            "provider_execution_authorized": False,
            "generic_infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
            "automatic_retry_authorized": False,
        }


def safe_repair_audit_details(
    *,
    job: SafeAutoRepairJob,
    recommendation: SafeAutoRepairRecommendation,
) -> SafeRepairAuditDetails:
    """Bind a Job to the exact recommendation before creating Audit evidence."""

    if not isinstance(job, SafeAutoRepairJob):
        raise TypeError("safe_repair_audit_job_invalid")
    if not isinstance(recommendation, SafeAutoRepairRecommendation):
        raise TypeError("safe_repair_audit_recommendation_invalid")

    recommendation_id = _identifier(
        recommendation.recommendation_id,
        "safe_repair_audit_recommendation_id_invalid",
    )
    job_recommendation_id = _identifier(
        job.recommendation_id,
        "safe_repair_audit_job_recommendation_id_invalid",
    )
    if recommendation_id != job_recommendation_id:
        raise SafeRepairAuditEvidenceError(
            "safe_repair_audit_recommendation_mismatch"
        )

    recommendation_sha256 = _recommendation_digest(recommendation)
    if job.recommendation_sha256 != recommendation_sha256:
        raise SafeRepairAuditEvidenceError(
            "safe_repair_audit_recommendation_digest_mismatch"
        )

    candidate = recommendation.candidate
    return SafeRepairAuditDetails(
        job_id=job.job_id,
        admission_id=job.admission_id,
        recommendation_id=recommendation_id,
        recommendation_sha256=recommendation_sha256,
        household_id=candidate.household_id,
        resource_id=candidate.resource_id,
        resource_generation=candidate.resource_generation,
        action=candidate.action.value,
        risk=candidate.risk.value,
        job_state=job.state,
        updated_at_epoch=job.updated_at_epoch,
        recovery_proven=candidate.recovery_proven,
        effect_receipt_sha256=job.effect_receipt_sha256,
        post_condition_evidence_sha256=job.post_condition_evidence_sha256,
        post_condition_verified=job.post_condition_verified,
    )


__all__ = [
    "SAFE_REPAIR_AUDIT_DETAILS_SCHEMA",
    "SafeRepairAuditDetails",
    "SafeRepairAuditEvidenceError",
    "safe_repair_audit_details",
]
