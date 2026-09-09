"""Compare-and-swap revalidation for claimed home-service operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from home_center.home_service_admission import HomeServiceExecutionAdmission
from home_center.home_service_operations import HomeServiceInstanceSnapshot
from home_center.home_service_worker_claim import HomeServiceWorkerClaim
from home_center.home_services import HomeServiceCatalogError, _identifier


SCHEMA = "home-center.home-service-execution-revalidation.v1"
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class HomeServiceExecutionJobState(StrEnum):
    """Durable job states observed by the execution fence."""

    REQUESTED = "requested"
    PREFLIGHT = "preflight"
    BLOCKED = "blocked"
    QUEUED = "queued"
    RUNNING = "running"
    VERIFYING = "verifying"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    RECOVERING = "recovering"
    RECOVERED = "recovered"
    CANCELLED = "cancelled"


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise HomeServiceCatalogError(code)
    return value


@dataclass(frozen=True, slots=True)
class HomeServiceExecutionJobSnapshot:
    """Current non-secret execution fence persisted with the durable job."""

    job_id: str
    state: HomeServiceExecutionJobState
    admission_id: str
    admission_sha256: str
    claim_id: str
    claim_token_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _identifier(self.job_id, "invalid_job_id"))
        if not isinstance(self.state, HomeServiceExecutionJobState):
            raise HomeServiceCatalogError("invalid_job_state")
        object.__setattr__(
            self,
            "admission_id",
            _identifier(self.admission_id, "invalid_admission_id"),
        )
        object.__setattr__(
            self,
            "admission_sha256",
            _sha256(self.admission_sha256, "invalid_admission_digest"),
        )
        object.__setattr__(self, "claim_id", _identifier(self.claim_id, "invalid_claim_id"))
        object.__setattr__(
            self,
            "claim_token_sha256",
            _sha256(self.claim_token_sha256, "invalid_claim_token_digest"),
        )


@dataclass(frozen=True, slots=True)
class HomeServiceClaimTokenEvidence:
    """Digest-only proof for a presented worker claim token."""

    claim_id: str
    claim_token_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "claim_id", _identifier(self.claim_id, "invalid_claim_id"))
        object.__setattr__(
            self,
            "claim_token_sha256",
            _sha256(self.claim_token_sha256, "invalid_claim_token_digest"),
        )


@dataclass(frozen=True, slots=True)
class HomeServiceExecutionRevalidation:
    revalidation_id: str
    admission_id: str
    admission_sha256: str
    claim_id: str
    claim_token_sha256: str
    plan_id: str
    job_id: str
    worker_id: str
    node_id: str
    instance_id: str
    operation: str
    observed_job_state: HomeServiceExecutionJobState
    observed_generation: int
    observed_resource_version: str
    schema: str = field(default=SCHEMA, init=False)
    revalidated: bool = field(default=True, init=False)
    compare_and_swap_matched: bool = field(default=True, init=False)
    revalidation_record_only: bool = field(default=True, init=False)
    execution_authorized: bool = field(default=False, init=False)
    direct_execution: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)
    accepts_secret_values: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "revalidation_id": self.revalidation_id,
            "admission_id": self.admission_id,
            "admission_sha256": self.admission_sha256,
            "claim_id": self.claim_id,
            "claim_token_sha256": self.claim_token_sha256,
            "plan_id": self.plan_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "operation": self.operation,
            "observed_job_state": self.observed_job_state.value,
            "observed_generation": self.observed_generation,
            "observed_resource_version": self.observed_resource_version,
            "revalidated": True,
            "compare_and_swap_matched": True,
            "revalidation_record_only": True,
            "execution_authorized": False,
            "direct_execution": False,
            "production_mutation_enabled": False,
            "accepts_secret_values": False,
        }


def execution_admission_sha256(admission: HomeServiceExecutionAdmission) -> str:
    """Return the canonical digest stored alongside a durable execution job."""

    if not isinstance(admission, HomeServiceExecutionAdmission):
        raise HomeServiceCatalogError("invalid_execution_admission")
    _validate_admission_safety(admission)
    encoded = json.dumps(
        admission.to_dict(),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def revalidate_execution(
    admission: HomeServiceExecutionAdmission,
    claim: HomeServiceWorkerClaim,
    snapshot: HomeServiceInstanceSnapshot,
    job: HomeServiceExecutionJobSnapshot,
    token: HomeServiceClaimTokenEvidence,
) -> HomeServiceExecutionRevalidation:
    """Create an inert CAS record after checking the immediate execution fence."""

    if not isinstance(admission, HomeServiceExecutionAdmission):
        raise HomeServiceCatalogError("invalid_execution_admission")
    if not isinstance(claim, HomeServiceWorkerClaim):
        raise HomeServiceCatalogError("invalid_worker_claim")
    if not isinstance(snapshot, HomeServiceInstanceSnapshot):
        raise HomeServiceCatalogError("invalid_instance_snapshot")
    if not isinstance(job, HomeServiceExecutionJobSnapshot):
        raise HomeServiceCatalogError("invalid_execution_job_snapshot")
    if not isinstance(token, HomeServiceClaimTokenEvidence):
        raise HomeServiceCatalogError("invalid_claim_token_evidence")

    _validate_admission_safety(admission)
    _validate_claim_safety(claim)
    if job.state is not HomeServiceExecutionJobState.QUEUED:
        raise HomeServiceCatalogError("invalid_job_state_for_revalidation")

    if (
        claim.admission_id != admission.admission_id
        or claim.plan_id != admission.plan_id
        or claim.job_id != admission.job_id
        or claim.instance_id != admission.instance_id
        or claim.operation != admission.operation
        or claim.based_on_generation != admission.based_on_generation
        or claim.based_on_resource_version != admission.based_on_resource_version
        or job.job_id != claim.job_id
        or job.admission_id != admission.admission_id
        or job.claim_id != claim.claim_id
        or token.claim_id != claim.claim_id
    ):
        raise HomeServiceCatalogError("execution_binding_mismatch")

    admission_sha256 = execution_admission_sha256(admission)
    if not hmac.compare_digest(job.admission_sha256, admission_sha256):
        raise HomeServiceCatalogError("admission_digest_precondition_failed")
    if not hmac.compare_digest(token.claim_token_sha256, job.claim_token_sha256):
        raise HomeServiceCatalogError("claim_token_precondition_failed")
    if (
        snapshot.instance_id != claim.instance_id
        or snapshot.target_node_id != claim.node_id
        or snapshot.generation != claim.based_on_generation
        or snapshot.resource_version != claim.based_on_resource_version
    ):
        raise HomeServiceCatalogError("execution_revalidation_precondition_failed")

    identity = {
        "admission_id": admission.admission_id,
        "admission_sha256": admission_sha256,
        "claim_id": claim.claim_id,
        "claim_token_sha256": token.claim_token_sha256,
        "plan_id": claim.plan_id,
        "job_id": claim.job_id,
        "worker_id": claim.worker_id,
        "node_id": claim.node_id,
        "instance_id": claim.instance_id,
        "operation": claim.operation,
        "job_state": job.state.value,
        "generation": snapshot.generation,
        "resource_version": snapshot.resource_version,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return HomeServiceExecutionRevalidation(
        revalidation_id=f"hsrv-{digest[:24]}",
        admission_id=admission.admission_id,
        admission_sha256=admission_sha256,
        claim_id=claim.claim_id,
        claim_token_sha256=token.claim_token_sha256,
        plan_id=claim.plan_id,
        job_id=claim.job_id,
        worker_id=claim.worker_id,
        node_id=claim.node_id,
        instance_id=claim.instance_id,
        operation=claim.operation,
        observed_job_state=job.state,
        observed_generation=snapshot.generation,
        observed_resource_version=snapshot.resource_version,
    )


def _validate_admission_safety(admission: HomeServiceExecutionAdmission) -> None:
    if (
        admission.admitted is not True
        or admission.admission_record_only is not True
        or admission.worker_claim_authorized is not True
        or admission.revalidate_before_claim is not True
        or admission.direct_execution is not False
        or admission.production_mutation_enabled is not False
        or admission.accepts_secret_values is not False
    ):
        raise HomeServiceCatalogError("unsafe_execution_admission")
    _sha256(admission.plan_sha256, "invalid_plan_digest")


def _validate_claim_safety(claim: HomeServiceWorkerClaim) -> None:
    if (
        claim.claimed is not True
        or claim.revalidate_before_execution is not True
        or claim.direct_execution is not False
        or claim.production_mutation_enabled is not False
        or claim.accepts_secret_values is not False
    ):
        raise HomeServiceCatalogError("unsafe_worker_claim")
