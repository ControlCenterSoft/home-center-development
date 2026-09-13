"""Fail-closed exact-bound post-condition decision for Home Center 0.64 repairs.

Adapter acceptance and an adapter-labelled `matched` observation are not sufficient by
themselves. This evaluator binds the exact Job, recommendation, effect receipt, target
resource/generation and observation before emitting verification evidence. It does not
transition the durable Job or claim repair success.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .safe_auto_repair import SafeAutoRepairRecommendation
from .safe_auto_repair_adapter import (
    PostConditionState,
    SafeRepairAdapterResult,
    SafeRepairPostConditionObservation,
)
from .safe_auto_repair_job import RepairExecutionOutcome, RepairJobState, SafeAutoRepairJob
from .util import canonical_json

SCHEMA = "home-center.safe-auto-repair-verification-decision.v1"


class SafeRepairVerificationError(ValueError):
    pass


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SafeRepairVerificationDecision:
    job_id: str
    recommendation_id: str
    verified: bool
    blockers: tuple[str, ...]
    verification_evidence_sha256: str
    schema: str = field(default=SCHEMA, init=False)
    repair_success_claimed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    generic_infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "recommendation_id": self.recommendation_id,
            "verified": self.verified,
            "blockers": list(self.blockers),
            "verification_evidence_sha256": self.verification_evidence_sha256,
            "repair_success_claimed": False,
            "execution_authorized": False,
            "provider_execution_authorized": False,
            "generic_infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def evaluate_safe_repair_post_condition(
    *,
    job: SafeAutoRepairJob,
    recommendation: SafeAutoRepairRecommendation,
    result: SafeRepairAdapterResult,
    observation: SafeRepairPostConditionObservation,
) -> SafeRepairVerificationDecision:
    if not isinstance(job, SafeAutoRepairJob):
        raise TypeError("safe_repair_verification_job_invalid")
    if not isinstance(recommendation, SafeAutoRepairRecommendation):
        raise TypeError("safe_repair_verification_recommendation_invalid")
    if not isinstance(result, SafeRepairAdapterResult):
        raise TypeError("safe_repair_verification_result_invalid")
    if not isinstance(observation, SafeRepairPostConditionObservation):
        raise TypeError("safe_repair_verification_observation_invalid")

    blockers: list[str] = []
    recommendation_sha256 = _digest(recommendation.to_dict())
    candidate = recommendation.candidate

    if job.state is not RepairJobState.VERIFYING:
        blockers.append("job_not_verifying")
    if job.recommendation_id != recommendation.recommendation_id:
        blockers.append("job_recommendation_identity_mismatch")
    if job.recommendation_sha256 != recommendation_sha256:
        blockers.append("job_recommendation_digest_mismatch")

    if result.job_id != job.job_id:
        blockers.append("result_job_mismatch")
    if result.recommendation_id != recommendation.recommendation_id:
        blockers.append("result_recommendation_mismatch")
    if result.action is not candidate.action:
        blockers.append("result_action_mismatch")
    if result.outcome is not RepairExecutionOutcome.ACCEPTED:
        blockers.append("result_not_accepted")
    if job.effect_receipt_sha256 != result.effect_receipt_sha256:
        blockers.append("effect_receipt_mismatch")

    if observation.job_id != job.job_id:
        blockers.append("observation_job_mismatch")
    if observation.recommendation_id != recommendation.recommendation_id:
        blockers.append("observation_recommendation_mismatch")
    if observation.household_id != candidate.household_id:
        blockers.append("observation_household_mismatch")
    if observation.resource_id != candidate.resource_id:
        blockers.append("observation_resource_mismatch")
    if observation.observed_generation != candidate.resource_generation:
        blockers.append("observation_generation_mismatch")
    if observation.state is not PostConditionState.MATCHED:
        blockers.append("post_condition_not_matched")

    material = {
        "job_id": job.job_id,
        "recommendation_id": recommendation.recommendation_id,
        "recommendation_sha256": recommendation_sha256,
        "effect_receipt_sha256": result.effect_receipt_sha256,
        "adapter_outcome": result.outcome.value,
        "household_id": candidate.household_id,
        "resource_id": candidate.resource_id,
        "resource_generation": candidate.resource_generation,
        "observation_sha256": observation.observation_sha256,
        "observation_state": observation.state.value,
        "blockers": blockers,
    }
    return SafeRepairVerificationDecision(
        job_id=job.job_id,
        recommendation_id=recommendation.recommendation_id,
        verified=not blockers,
        blockers=tuple(blockers),
        verification_evidence_sha256=_digest(material),
    )
