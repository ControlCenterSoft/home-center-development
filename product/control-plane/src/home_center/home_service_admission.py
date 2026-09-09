"""Fail-closed admission records for approved home-service operation plans."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from home_center.home_service_operations import HomeServiceInstanceSnapshot, HomeServiceOperationPlan
from home_center.home_services import HomeServiceCatalogError, _identifier


SCHEMA = "home-center.home-service-execution-admission.v1"


@dataclass(frozen=True, slots=True)
class ApprovalEvidence:
    approval_id: str
    plan_id: str
    approved_by: str
    reason: str

    def __post_init__(self) -> None:
        for name in ("approval_id", "plan_id", "approved_by"):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"invalid_{name}"))
        if not isinstance(self.reason, str) or not 1 <= len(self.reason.strip()) <= 512:
            raise HomeServiceCatalogError("invalid_approval_reason")
        object.__setattr__(self, "reason", self.reason.strip())


@dataclass(frozen=True, slots=True)
class DurableJobBinding:
    job_id: str
    plan_id: str
    state: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_id", _identifier(self.job_id, "invalid_job_id"))
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "invalid_plan_id"))
        if self.state != "preflight":
            raise HomeServiceCatalogError("invalid_job_state")


@dataclass(frozen=True, slots=True)
class HomeServiceExecutionAdmission:
    admission_id: str
    plan_id: str
    plan_sha256: str
    instance_id: str
    operation: str
    based_on_generation: int
    based_on_resource_version: str
    approval_id: str
    job_id: str
    audit_correlation_id: str
    secret_references: tuple[str, ...]
    schema: str = field(default=SCHEMA, init=False)
    admitted: bool = field(default=True, init=False)
    admission_record_only: bool = field(default=True, init=False)
    worker_claim_authorized: bool = field(default=True, init=False)
    revalidate_before_claim: bool = field(default=True, init=False)
    direct_execution: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)
    accepts_secret_values: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "admission_id": self.admission_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "instance_id": self.instance_id,
            "operation": self.operation,
            "based_on_generation": self.based_on_generation,
            "based_on_resource_version": self.based_on_resource_version,
            "approval_id": self.approval_id,
            "job_id": self.job_id,
            "audit_correlation_id": self.audit_correlation_id,
            "secret_references": list(self.secret_references),
            "admitted": True,
            "admission_record_only": True,
            "worker_claim_authorized": True,
            "revalidate_before_claim": True,
            "direct_execution": False,
            "production_mutation_enabled": False,
            "accepts_secret_values": False,
        }


def admit_operation(
    plan: HomeServiceOperationPlan,
    snapshot: HomeServiceInstanceSnapshot,
    approval: ApprovalEvidence,
    job: DurableJobBinding,
    *,
    audit_correlation_id: str,
) -> HomeServiceExecutionAdmission:
    if not isinstance(plan, HomeServiceOperationPlan) or not isinstance(snapshot, HomeServiceInstanceSnapshot):
        raise HomeServiceCatalogError("invalid_admission_input")
    if not isinstance(approval, ApprovalEvidence) or not isinstance(job, DurableJobBinding):
        raise HomeServiceCatalogError("invalid_admission_evidence")
    audit_correlation_id = _identifier(audit_correlation_id, "invalid_audit_correlation_id")
    if approval.plan_id != plan.plan_id or job.plan_id != plan.plan_id:
        raise HomeServiceCatalogError("plan_binding_mismatch")
    if (
        snapshot.instance_id != plan.instance_id
        or snapshot.service_id != plan.service_id
        or snapshot.target_node_id != plan.target_node_id
        or snapshot.state != plan.from_state
        or snapshot.generation != plan.based_on_generation
        or snapshot.resource_version != plan.based_on_resource_version
    ):
        raise HomeServiceCatalogError("admission_precondition_failed")
    value = plan.to_dict()
    if (
        value["approval_required"] is not True
        or value["durable_job_required"] is not True
        or value["audit_required"] is not True
        or value["plan_only"] is not True
        or value["execution_authorized"] is not False
        or value["production_mutation_enabled"] is not False
        or value["accepts_secret_values"] is not False
    ):
        raise HomeServiceCatalogError("unsafe_operation_plan")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    plan_hash = hashlib.sha256(encoded).hexdigest()
    identity = {
        "plan_sha256": plan_hash,
        "approval_id": approval.approval_id,
        "job_id": job.job_id,
        "audit_correlation_id": audit_correlation_id,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return HomeServiceExecutionAdmission(
        admission_id=f"hsea-{digest[:24]}",
        plan_id=plan.plan_id,
        plan_sha256=plan_hash,
        instance_id=plan.instance_id,
        operation=plan.operation.value,
        based_on_generation=plan.based_on_generation,
        based_on_resource_version=plan.based_on_resource_version,
        approval_id=approval.approval_id,
        job_id=job.job_id,
        audit_correlation_id=audit_correlation_id,
        secret_references=plan.secret_references,
    )
