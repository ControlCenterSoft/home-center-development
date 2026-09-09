"""Fail-closed worker handoff for durable bounded operation jobs."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from .util import canonical_json


SCHEMA = "home-center.operation-worker-handoff.v1"
JOB_SCHEMA = "home-center.operation-job-record.v1"
JOB_ID = re.compile(r"^opjob-[a-f0-9]{24}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{2,63}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
AUTHORIZATION_ID = re.compile(r"^opauth-[a-f0-9]{24}$")
PLAN_ID = re.compile(r"^opcmd-[a-f0-9]{24}$")


class OperationWorkerHandoffError(ValueError):
    """A durable operation job cannot be handed to a worker safely."""


class OperationJobLookup(Protocol):
    def operation_job(self, job_id: str) -> dict[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class OperationWorkerIdentity:
    worker_id: str
    node_id: str

    def __post_init__(self) -> None:
        if not IDENTIFIER.fullmatch(self.worker_id):
            raise OperationWorkerHandoffError("invalid_worker_id")
        if not IDENTIFIER.fullmatch(self.node_id):
            raise OperationWorkerHandoffError("invalid_worker_node")


@dataclass(frozen=True, slots=True)
class OperationWorkerHandoff:
    handoff_id: str
    job_id: str
    action_id: str
    plan_id: str
    plan_sha256: str
    request_sha256: str
    snapshot_sha256: str
    authorization_id: str
    target_node_id: str
    worker_id: str
    expected_state_version: int
    schema: str = field(default=SCHEMA, init=False)
    expected_state: str = field(default="prepared", init=False)
    revalidate_before_execution: bool = field(default=True, init=False)
    audit_required: bool = field(default=True, init=False)
    contains_command_material: bool = field(default=False, init=False)
    accepts_caller_argv: bool = field(default=False, init=False)
    accepts_shell: bool = field(default=False, init=False)
    direct_execution: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "handoff_id": self.handoff_id,
            "job_id": self.job_id,
            "action_id": self.action_id,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "request_sha256": self.request_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "authorization_id": self.authorization_id,
            "target_node_id": self.target_node_id,
            "worker_id": self.worker_id,
            "expected_state": self.expected_state,
            "expected_state_version": self.expected_state_version,
            "revalidate_before_execution": True,
            "audit_required": True,
            "contains_command_material": False,
            "accepts_caller_argv": False,
            "accepts_shell": False,
            "direct_execution": False,
            "production_mutation_enabled": False,
        }


def prepare_operation_worker_handoff(
    store: OperationJobLookup,
    *,
    job_id: str,
    expected_state_version: int,
    worker: OperationWorkerIdentity,
) -> OperationWorkerHandoff:
    """Read authoritative job state and return only exact non-executable handoff evidence."""

    if not JOB_ID.fullmatch(job_id):
        raise OperationWorkerHandoffError("invalid_job_id")
    if (
        not isinstance(expected_state_version, int)
        or isinstance(expected_state_version, bool)
        or expected_state_version < 1
    ):
        raise OperationWorkerHandoffError("invalid_state_version")
    if not isinstance(worker, OperationWorkerIdentity):
        raise TypeError("worker must be OperationWorkerIdentity")
    lookup = getattr(store, "operation_job", None)
    if not callable(lookup):
        raise TypeError("store must provide operation_job")

    job = lookup(job_id)
    if job is None:
        raise OperationWorkerHandoffError("operation_job_not_found")
    _validate_job(job, job_id=job_id, expected_state_version=expected_state_version)
    if worker.node_id != job["target_node_id"]:
        raise OperationWorkerHandoffError("worker_target_mismatch")

    identity = {
        "job_id": job_id,
        "action_id": job["action_id"],
        "plan_id": job["plan_id"],
        "plan_sha256": job["plan_sha256"],
        "request_sha256": job["request_sha256"],
        "snapshot_sha256": job["snapshot_sha256"],
        "authorization_id": job["authorization_id"],
        "target_node_id": job["target_node_id"],
        "worker_id": worker.worker_id,
        "expected_state": "prepared",
        "expected_state_version": expected_state_version,
    }
    digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()
    return OperationWorkerHandoff(
        handoff_id=f"ophandoff-{digest[:24]}",
        job_id=job_id,
        action_id=job["action_id"],
        plan_id=job["plan_id"],
        plan_sha256=job["plan_sha256"],
        request_sha256=job["request_sha256"],
        snapshot_sha256=job["snapshot_sha256"],
        authorization_id=job["authorization_id"],
        target_node_id=job["target_node_id"],
        worker_id=worker.worker_id,
        expected_state_version=expected_state_version,
    )


def revalidate_operation_worker_handoff(
    store: OperationJobLookup,
    handoff: OperationWorkerHandoff,
) -> None:
    """Fail closed when durable state or immutable admission material changed after handoff."""

    if not isinstance(handoff, OperationWorkerHandoff):
        raise TypeError("handoff must be OperationWorkerHandoff")
    lookup = getattr(store, "operation_job", None)
    if not callable(lookup):
        raise TypeError("store must provide operation_job")
    job = lookup(handoff.job_id)
    if job is None:
        raise OperationWorkerHandoffError("operation_job_not_found")
    _validate_job(
        job,
        job_id=handoff.job_id,
        expected_state_version=handoff.expected_state_version,
    )
    expected = prepare_operation_worker_handoff(
        store,
        job_id=handoff.job_id,
        expected_state_version=handoff.expected_state_version,
        worker=OperationWorkerIdentity(
            worker_id=handoff.worker_id,
            node_id=handoff.target_node_id,
        ),
    )
    if expected != handoff:
        raise OperationWorkerHandoffError("operation_handoff_stale")


def _validate_job(
    job: dict[str, Any],
    *,
    job_id: str,
    expected_state_version: int,
) -> None:
    if not isinstance(job, dict) or job.get("schema") != JOB_SCHEMA:
        raise OperationWorkerHandoffError("invalid_operation_job_record")
    if job.get("job_id") != job_id:
        raise OperationWorkerHandoffError("operation_job_identity_mismatch")
    if job.get("state") != "prepared":
        raise OperationWorkerHandoffError("operation_job_not_prepared")
    if job.get("state_version") != expected_state_version:
        raise OperationWorkerHandoffError("operation_job_state_stale")
    if job.get("mutation_may_have_occurred") is not False:
        raise OperationWorkerHandoffError("unsafe_operation_job_state")
    if job.get("recovery_required") is not False:
        raise OperationWorkerHandoffError("operation_recovery_required")

    for field_name in ("plan_sha256", "request_sha256", "snapshot_sha256"):
        value = job.get(field_name)
        if not isinstance(value, str) or not SHA256.fullmatch(value):
            raise OperationWorkerHandoffError(f"invalid_{field_name}")
    if not isinstance(job.get("plan_id"), str) or not PLAN_ID.fullmatch(job["plan_id"]):
        raise OperationWorkerHandoffError("invalid_plan_id")
    if not isinstance(job.get("authorization_id"), str) or not AUTHORIZATION_ID.fullmatch(
        job["authorization_id"]
    ):
        raise OperationWorkerHandoffError("invalid_authorization_id")
    if not isinstance(job.get("target_node_id"), str) or not IDENTIFIER.fullmatch(
        job["target_node_id"]
    ):
        raise OperationWorkerHandoffError("invalid_target_node")
    if not isinstance(job.get("action_id"), str) or not IDENTIFIER.fullmatch(job["action_id"]):
        raise OperationWorkerHandoffError("invalid_action_id")

    plan = job.get("plan")
    if not isinstance(plan, dict):
        raise OperationWorkerHandoffError("operation_plan_missing")
    plan_sha256 = hashlib.sha256(canonical_json(plan).encode("utf-8")).hexdigest()
    if plan_sha256 != job["plan_sha256"]:
        raise OperationWorkerHandoffError("operation_plan_integrity_mismatch")
    for field_name in (
        "action_id",
        "plan_id",
        "request_sha256",
        "snapshot_sha256",
        "authorization_id",
        "target_node_id",
    ):
        if plan.get(field_name) != job[field_name]:
            raise OperationWorkerHandoffError(f"operation_plan_{field_name}_mismatch")
    if (
        plan.get("execution_authorized") is not False
        or plan.get("production_mutation_enabled") is not False
        or plan.get("accepts_caller_argv") is not False
        or plan.get("accepts_shell") is not False
    ):
        raise OperationWorkerHandoffError("unsafe_operation_plan")
