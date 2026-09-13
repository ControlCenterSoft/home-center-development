"""Fail-closed Home Center 0.64 repair-admission revalidation.

Admission remains side-effect free. It proves only that a previously reviewed
recommendation is still identical under the current candidate evidence and current
policy. A positive decision may be consumed by a later authenticated/RBAC-gated
Job-admission service, but never grants execution or mutation authority itself.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from .safe_auto_repair import (
    RepairCandidate,
    SafeAutoRepairRecommendation,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from .util import canonical_json

SAFE_REPAIR_ADMISSION_SCHEMA = "home-center.safe-auto-repair-admission.v1"


class RepairAdmissionBlocker(StrEnum):
    REVIEWED_RECOMMENDATION_NOT_ELIGIBLE = "reviewed-recommendation-not-eligible"
    CURRENT_RECOMMENDATION_CHANGED = "current-recommendation-changed"
    CURRENT_RECOMMENDATION_NOT_ELIGIBLE = "current-recommendation-not-eligible"


@dataclass(frozen=True, slots=True)
class SafeAutoRepairAdmission:
    admission_id: str
    recommendation_id: str
    current_recommendation_id: str
    recommendation_sha256: str
    current_recommendation_sha256: str
    admissible_for_job: bool
    blockers: tuple[RepairAdmissionBlocker, ...]
    schema: str = field(default=SAFE_REPAIR_ADMISSION_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "admission_id": self.admission_id,
            "recommendation_id": self.recommendation_id,
            "current_recommendation_id": self.current_recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "current_recommendation_sha256": self.current_recommendation_sha256,
            "admissible_for_job": self.admissible_for_job,
            "blockers": [item.value for item in self.blockers],
            "fresh_current_state_revalidation": True,
            "durable_job_required": True,
            "action_specific_adapter_required": True,
            "post_condition_verification_required": True,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def evaluate_safe_auto_repair_admission(
    *,
    reviewed: SafeAutoRepairRecommendation,
    current_candidate: RepairCandidate,
    current_policy: SafeRepairPolicy,
) -> SafeAutoRepairAdmission:
    """Revalidate reviewed evidence against current state without mutating anything."""

    if not isinstance(reviewed, SafeAutoRepairRecommendation):
        raise TypeError("safe_auto_repair_reviewed_recommendation_invalid")
    if not isinstance(current_candidate, RepairCandidate):
        raise TypeError("safe_auto_repair_current_candidate_invalid")
    if not isinstance(current_policy, SafeRepairPolicy):
        raise TypeError("safe_auto_repair_current_policy_invalid")

    current = evaluate_safe_auto_repair(candidate=current_candidate, policy=current_policy)
    reviewed_payload = reviewed.to_dict()
    current_payload = current.to_dict()
    reviewed_sha = _digest(reviewed_payload)
    current_sha = _digest(current_payload)

    blockers: list[RepairAdmissionBlocker] = []
    if not reviewed.eligible_for_auto_repair:
        blockers.append(RepairAdmissionBlocker.REVIEWED_RECOMMENDATION_NOT_ELIGIBLE)
    if reviewed.recommendation_id != current.recommendation_id or reviewed_sha != current_sha:
        blockers.append(RepairAdmissionBlocker.CURRENT_RECOMMENDATION_CHANGED)
    if not current.eligible_for_auto_repair:
        blockers.append(RepairAdmissionBlocker.CURRENT_RECOMMENDATION_NOT_ELIGIBLE)

    material = {
        "recommendation_id": reviewed.recommendation_id,
        "current_recommendation_id": current.recommendation_id,
        "recommendation_sha256": reviewed_sha,
        "current_recommendation_sha256": current_sha,
    }
    admission_id = "hcrpa-" + _digest(material)[:24]
    return SafeAutoRepairAdmission(
        admission_id=admission_id,
        recommendation_id=reviewed.recommendation_id,
        current_recommendation_id=current.recommendation_id,
        recommendation_sha256=reviewed_sha,
        current_recommendation_sha256=current_sha,
        admissible_for_job=not blockers,
        blockers=tuple(blockers),
    )
