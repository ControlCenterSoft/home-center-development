"""Durable non-executing safe auto-repair Job admission for Home Center 0.64.

This boundary accepts only an already eligible recommendation, re-evaluates the exact
current candidate against the exact current policy immediately before admission, and
persists a typed durable Job. Admission never executes the repair and never claims a
post-condition success. Provider execution, generic infrastructure mutation and
external publication remain unauthorized.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    SafeAutoRepairRecommendation,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

SAFE_AUTO_REPAIR_ADMISSION_SCHEMA = "home-center.safe-auto-repair-admission.v1"
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_JOB_TYPES = {
    RepairAction.RECONCILE_DERIVED_STATE: "safe-auto-repair-reconcile-derived-state-job",
    RepairAction.REBUILD_DERIVED_INDEX: "safe-auto-repair-rebuild-derived-index-job",
    RepairAction.REFRESH_LOCAL_READ_MODEL: "safe-auto-repair-refresh-local-read-model-job",
}


class SafeAutoRepairAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class SafeAutoRepairAdmission:
    job_id: str
    recommendation_id: str
    required_job_type: str
    household_id: str
    resource_id: str
    resource_generation: int
    action: str
    policy_id: str
    policy_sha256: str
    state: str = field(default="preflight", init=False)
    schema: str = field(default=SAFE_AUTO_REPAIR_ADMISSION_SCHEMA, init=False)
    execution_authorized: bool = field(default=False, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    repair_success_claimed: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "recommendation_id": self.recommendation_id,
            "required_job_type": self.required_job_type,
            "household_id": self.household_id,
            "resource_id": self.resource_id,
            "resource_generation": self.resource_generation,
            "action": self.action,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "state": "preflight",
            "execution_authorized": False,
            "post_condition_verified": False,
            "repair_success_claimed": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _recommendation_sha256(recommendation: SafeAutoRepairRecommendation) -> str:
    return hashlib.sha256(canonical_json(recommendation.to_dict()).encode("utf-8")).hexdigest()


def _require_exact_current_recommendation(
    *,
    recommendation: SafeAutoRepairRecommendation,
    current_candidate: RepairCandidate,
    current_policy: SafeRepairPolicy,
) -> SafeAutoRepairRecommendation:
    if not isinstance(recommendation, SafeAutoRepairRecommendation):
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recommendation_invalid")
    if not recommendation.eligible_for_auto_repair or recommendation.blockers:
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recommendation_blocked")
    if not isinstance(current_candidate, RepairCandidate) or not isinstance(current_policy, SafeRepairPolicy):
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_current_state_invalid")

    current = evaluate_safe_auto_repair(candidate=current_candidate, policy=current_policy)
    if not current.eligible_for_auto_repair or current.blockers:
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_current_state_blocked")
    if current.to_dict() != recommendation.to_dict():
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recommendation_stale")
    return current


def _receipt_from_job(job: dict[str, object]) -> SafeAutoRepairAdmission:
    preflight = job.get("preflight")
    if not isinstance(preflight, dict):
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_preflight_missing")
    recommendation = preflight.get("recommendation")
    if not isinstance(recommendation, dict):
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_recommendation_missing")
    required = {
        "schema": "home-center.safe-auto-repair-admission-preflight.v1",
        "execution_authorized": False,
        "post_condition_verification_required": True,
        "repair_history_required": True,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    if any(preflight.get(key) != value for key, value in required.items()):
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_binding_mismatch")
    if recommendation.get("eligible_for_auto_repair") is not True or recommendation.get("blockers") != []:
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_recommendation_blocked")
    recommendation_id = recommendation.get("recommendation_id")
    household_id = recommendation.get("household_id")
    resource_id = recommendation.get("resource_id")
    resource_generation = recommendation.get("resource_generation")
    action = recommendation.get("action")
    policy_id = recommendation.get("policy_id")
    policy_sha256 = recommendation.get("policy_sha256")
    required_job_type = preflight.get("required_job_type")
    job_id = job.get("job_id")
    if not all(isinstance(value, str) and value for value in (
        recommendation_id,
        household_id,
        resource_id,
        action,
        policy_id,
        policy_sha256,
        required_job_type,
        job_id,
    )):
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_identity_invalid")
    if type(resource_generation) is not int or resource_generation < 0:
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_generation_invalid")
    if job.get("job_type") != required_job_type or job.get("state") != "preflight":
        raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_job_state_invalid")
    return SafeAutoRepairAdmission(
        job_id=job_id,
        recommendation_id=recommendation_id,
        required_job_type=required_job_type,
        household_id=household_id,
        resource_id=resource_id,
        resource_generation=resource_generation,
        action=action,
        policy_id=policy_id,
        policy_sha256=policy_sha256,
    )


class SafeAutoRepairAdmissionService:
    def __init__(self, store: StateStore) -> None:
        self.store = store

    def recover(self, job_id: str) -> SafeAutoRepairAdmission:
        """Recover exact admission evidence without creating or executing work."""
        if not isinstance(job_id, str) or not job_id:
            raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_job_invalid")
        job = self.store.job(job_id)
        if job is None:
            raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_recovery_job_missing")
        return _receipt_from_job(job)

    def admit(
        self,
        *,
        actor: str,
        correlation_id: str,
        recommendation: SafeAutoRepairRecommendation,
        current_candidate: RepairCandidate,
        current_policy: SafeRepairPolicy,
        idempotency_key: str,
    ) -> SafeAutoRepairAdmission:
        if not isinstance(actor, str) or not actor or not isinstance(correlation_id, str) or not correlation_id:
            raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_actor_or_correlation_invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_idempotency_key_invalid")

        current = _require_exact_current_recommendation(
            recommendation=recommendation,
            current_candidate=current_candidate,
            current_policy=current_policy,
        )
        required_job_type = _JOB_TYPES[current.candidate.action]
        recommendation_sha256 = _recommendation_sha256(current)
        request_hash = hashlib.sha256(
            canonical_json(
                {
                    "recommendation_id": current.recommendation_id,
                    "recommendation_sha256": recommendation_sha256,
                    "required_job_type": required_job_type,
                    "resource_generation": current.candidate.resource_generation,
                    "policy_sha256": current.policy_sha256,
                }
            ).encode("utf-8")
        ).hexdigest()
        preflight = {
            "schema": "home-center.safe-auto-repair-admission-preflight.v1",
            "recommendation_id": current.recommendation_id,
            "recommendation_sha256": recommendation_sha256,
            "recommendation": current.to_dict(),
            "required_job_type": required_job_type,
            "execution_authorized": False,
            "post_condition_verification_required": True,
            "repair_history_required": True,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
        try:
            job, _created = self.store.create_action_job(
                action_id=required_job_type,
                actor=actor,
                reason="exact safe auto-repair recommendation admission",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                preflight=preflight,
                steps=[
                    {"step": "recommendation-revalidate", "state": "succeeded"},
                    {"step": "typed-repair-execute", "state": "pending"},
                    {"step": "authoritative-readback", "state": "pending"},
                    {"step": "post-condition-verify", "state": "pending"},
                    {"step": "repair-history-record", "state": "pending"},
                ],
            )
        except IdempotencyConflict as exc:
            raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_idempotency_conflict") from exc

        if job.get("job_type") != required_job_type or job.get("state") != "preflight":
            raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_job_state_invalid")
        persisted = job.get("preflight")
        if not isinstance(persisted, dict) or persisted != preflight:
            raise SafeAutoRepairAdmissionError("safe_auto_repair_admission_persistence_mismatch")

        receipt = SafeAutoRepairAdmission(
            job_id=job["job_id"],
            recommendation_id=current.recommendation_id,
            required_job_type=required_job_type,
            household_id=current.candidate.household_id,
            resource_id=current.candidate.resource_id,
            resource_generation=current.candidate.resource_generation,
            action=current.candidate.action.value,
            policy_id=current.policy_id,
            policy_sha256=current.policy_sha256,
        )
        self.store.audit(
            actor=actor,
            action="automation.safe-auto-repair.admit",
            target=current.candidate.resource_id,
            outcome="admitted",
            correlation_id=correlation_id,
            details={
                "job_id": receipt.job_id,
                "recommendation_id": receipt.recommendation_id,
                "required_job_type": receipt.required_job_type,
                "household_id": receipt.household_id,
                "resource_id": receipt.resource_id,
                "resource_generation": receipt.resource_generation,
                "execution_authorized": False,
                "post_condition_verified": False,
                "repair_success_claimed": False,
                "provider_execution_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )
        return receipt
