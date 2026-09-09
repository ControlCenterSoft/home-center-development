"""Verified execution-result records for Home Center home-service jobs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum

from home_center.home_service_operations import HomeServiceInstanceState
from home_center.home_service_worker_claim import HomeServiceWorkerClaim
from home_center.home_services import HomeServiceCatalogError, _identifier


SCHEMA = "home-center.home-service-execution-result.v1"


class HomeServiceExecutionOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class HomeServiceExecutionResult:
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
    schema: str = field(default=SCHEMA, init=False)
    verified: bool = field(default=True, init=False)
    state_transition_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "result_id": self.result_id,
            "claim_id": self.claim_id,
            "plan_id": self.plan_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "instance_id": self.instance_id,
            "outcome": self.outcome.value,
            "target_state": self.target_state.value,
            "observed_generation": self.observed_generation,
            "observed_resource_version": self.observed_resource_version,
            "evidence_digest": self.evidence_digest,
            "verified": True,
            "state_transition_authorized": False,
            "production_mutation_enabled": False,
        }


def record_execution_result(
    claim: HomeServiceWorkerClaim,
    *,
    outcome: HomeServiceExecutionOutcome,
    target_state: HomeServiceInstanceState,
    observed_generation: int,
    observed_resource_version: str,
    evidence_digest: str,
) -> HomeServiceExecutionResult:
    """Create an inert result record after revalidating the worker claim boundary."""

    if not isinstance(claim, HomeServiceWorkerClaim):
        raise HomeServiceCatalogError("invalid_worker_claim")
    if not isinstance(outcome, HomeServiceExecutionOutcome):
        raise HomeServiceCatalogError("invalid_execution_outcome")
    if not isinstance(target_state, HomeServiceInstanceState):
        raise HomeServiceCatalogError("invalid_instance_state")
    if not isinstance(observed_generation, int) or isinstance(observed_generation, bool) or observed_generation < 1:
        raise HomeServiceCatalogError("invalid_observed_generation")
    observed_resource_version = _identifier(observed_resource_version, "invalid_observed_resource_version")
    evidence_digest = _identifier(evidence_digest, "invalid_evidence_digest")
    if (
        claim.claimed is not True
        or claim.revalidate_before_execution is not True
        or claim.direct_execution is not False
        or claim.production_mutation_enabled is not False
    ):
        raise HomeServiceCatalogError("unsafe_worker_claim")
    if (
        observed_generation != claim.based_on_generation
        or observed_resource_version != claim.based_on_resource_version
    ):
        raise HomeServiceCatalogError("execution_result_precondition_failed")

    identity = {
        "claim_id": claim.claim_id,
        "plan_id": claim.plan_id,
        "job_id": claim.job_id,
        "worker_id": claim.worker_id,
        "instance_id": claim.instance_id,
        "outcome": outcome.value,
        "target_state": target_state.value,
        "generation": observed_generation,
        "resource_version": observed_resource_version,
        "evidence_digest": evidence_digest,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return HomeServiceExecutionResult(
        result_id=f"hser-{digest[:24]}",
        claim_id=claim.claim_id,
        plan_id=claim.plan_id,
        job_id=claim.job_id,
        worker_id=claim.worker_id,
        instance_id=claim.instance_id,
        outcome=outcome,
        target_state=target_state,
        observed_generation=observed_generation,
        observed_resource_version=observed_resource_version,
        evidence_digest=evidence_digest,
    )
