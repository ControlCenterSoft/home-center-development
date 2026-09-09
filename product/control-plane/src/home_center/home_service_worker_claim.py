"""Fail-closed worker claims for admitted home-service operations."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from home_center.home_service_admission import HomeServiceExecutionAdmission
from home_center.home_service_operations import HomeServiceInstanceSnapshot
from home_center.home_services import HomeServiceCatalogError, _identifier


SCHEMA = "home-center.home-service-worker-claim.v1"


@dataclass(frozen=True, slots=True)
class HomeServiceWorkerIdentity:
    worker_id: str
    node_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "worker_id", _identifier(self.worker_id, "invalid_worker_id"))
        object.__setattr__(self, "node_id", _identifier(self.node_id, "invalid_node_id"))


@dataclass(frozen=True, slots=True)
class HomeServiceWorkerClaim:
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
    schema: str = field(default=SCHEMA, init=False)
    claimed: bool = field(default=True, init=False)
    revalidate_before_execution: bool = field(default=True, init=False)
    direct_execution: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)
    accepts_secret_values: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "claim_id": self.claim_id,
            "admission_id": self.admission_id,
            "plan_id": self.plan_id,
            "job_id": self.job_id,
            "worker_id": self.worker_id,
            "node_id": self.node_id,
            "instance_id": self.instance_id,
            "operation": self.operation,
            "based_on_generation": self.based_on_generation,
            "based_on_resource_version": self.based_on_resource_version,
            "claimed": True,
            "revalidate_before_execution": True,
            "direct_execution": False,
            "production_mutation_enabled": False,
            "accepts_secret_values": False,
        }


def claim_execution(
    admission: HomeServiceExecutionAdmission,
    snapshot: HomeServiceInstanceSnapshot,
    worker: HomeServiceWorkerIdentity,
    *,
    job_state: str,
) -> HomeServiceWorkerClaim:
    """Bind an admitted plan to its target-node worker without executing it."""

    if not isinstance(admission, HomeServiceExecutionAdmission):
        raise HomeServiceCatalogError("invalid_execution_admission")
    if not isinstance(snapshot, HomeServiceInstanceSnapshot):
        raise HomeServiceCatalogError("invalid_instance_snapshot")
    if not isinstance(worker, HomeServiceWorkerIdentity):
        raise HomeServiceCatalogError("invalid_worker_identity")
    if job_state != "preflight":
        raise HomeServiceCatalogError("invalid_job_state_for_claim")
    if (
        admission.admitted is not True
        or admission.worker_claim_authorized is not True
        or admission.revalidate_before_claim is not True
        or admission.direct_execution is not False
        or admission.production_mutation_enabled is not False
        or admission.accepts_secret_values is not False
    ):
        raise HomeServiceCatalogError("unsafe_execution_admission")
    if (
        snapshot.instance_id != admission.instance_id
        or snapshot.generation != admission.based_on_generation
        or snapshot.resource_version != admission.based_on_resource_version
    ):
        raise HomeServiceCatalogError("worker_claim_precondition_failed")
    if worker.node_id != snapshot.target_node_id:
        raise HomeServiceCatalogError("worker_target_mismatch")

    identity = {
        "admission_id": admission.admission_id,
        "plan_id": admission.plan_id,
        "job_id": admission.job_id,
        "worker_id": worker.worker_id,
        "node_id": worker.node_id,
        "instance_id": snapshot.instance_id,
        "operation": admission.operation,
        "generation": snapshot.generation,
        "resource_version": snapshot.resource_version,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return HomeServiceWorkerClaim(
        claim_id=f"hswc-{digest[:24]}",
        admission_id=_identifier(admission.admission_id, "invalid_admission_id"),
        plan_id=_identifier(admission.plan_id, "invalid_plan_id"),
        job_id=_identifier(admission.job_id, "invalid_job_id"),
        worker_id=worker.worker_id,
        node_id=worker.node_id,
        instance_id=snapshot.instance_id,
        operation=_identifier(admission.operation, "invalid_operation"),
        based_on_generation=snapshot.generation,
        based_on_resource_version=snapshot.resource_version,
    )
