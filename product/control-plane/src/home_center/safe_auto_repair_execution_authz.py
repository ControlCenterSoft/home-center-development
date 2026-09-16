"""Exact-bound authenticated/RBAC authorization for Home Center 0.64 safe-repair.

This boundary is side-effect free. It authorizes only invocation of the bounded
safe-repair worker for one already-durable admitted Job and exact recommendation.
It does not call the worker, register an adapter, retry a Job, grant provider
execution, generic infrastructure mutation, or external-publication authority.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from .authorization_0180 import EffectiveAccess, SubjectRef
from .household import Household, HouseholdRole
from .safe_auto_repair import SafeAutoRepairRecommendation
from .safe_auto_repair_job import RepairJobState, SafeAutoRepairJob
from .util import canonical_json


SAFE_REPAIR_EXECUTE_PERMISSION = "household.safe-repair.execute.v1"
SAFE_REPAIR_EXECUTION_AUTHORIZATION_SCHEMA = (
    "home-center.safe-repair-execution-authorization.v1"
)


class SafeRepairExecutionAuthorizationError(ValueError):
    """Stable rejection for malformed authorization inputs."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SafeRepairExecutionBlocker(StrEnum):
    AUTHENTICATION_REQUIRED = "authentication-required"
    ACTOR_SUBJECT_ACCESS_MISMATCH = "actor-subject-access-mismatch"
    ACTOR_MEMBER_UNAVAILABLE = "actor-member-unavailable"
    ACTOR_MEMBER_DISABLED = "actor-member-disabled"
    PARENT_REQUIRED = "parent-required"
    RBAC_SCOPE_MISMATCH = "rbac-scope-mismatch"
    RBAC_PERMISSION_MISSING = "rbac-permission-missing"
    HOUSEHOLD_MISMATCH = "household-mismatch"
    RECOMMENDATION_NOT_ELIGIBLE = "recommendation-not-eligible"
    JOB_NOT_ADMITTED = "job-not-admitted"
    JOB_RECOMMENDATION_MISMATCH = "job-recommendation-mismatch"
    JOB_RECOMMENDATION_DIGEST_MISMATCH = "job-recommendation-digest-mismatch"


def _recommendation_sha256(recommendation: SafeAutoRepairRecommendation) -> str:
    payload = canonical_json(recommendation.to_dict()).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class SafeRepairExecutionAuthorization:
    household_id: str
    actor_subject: SubjectRef
    actor_member_id: str
    job_id: str
    recommendation_id: str
    recommendation_sha256: str
    permission: str
    worker_invocation_authorized: bool
    blockers: tuple[SafeRepairExecutionBlocker, ...]
    schema: str = field(default=SAFE_REPAIR_EXECUTION_AUTHORIZATION_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.actor_subject, SubjectRef):
            raise SafeRepairExecutionAuthorizationError(
                "safe_repair_execution_actor_subject_invalid"
            )
        if type(self.worker_invocation_authorized) is not bool:
            raise SafeRepairExecutionAuthorizationError(
                "safe_repair_execution_authorized_invalid"
            )
        if type(self.blockers) is not tuple or any(
            not isinstance(item, SafeRepairExecutionBlocker) for item in self.blockers
        ):
            raise SafeRepairExecutionAuthorizationError(
                "safe_repair_execution_blockers_invalid"
            )
        if self.worker_invocation_authorized == bool(self.blockers):
            raise SafeRepairExecutionAuthorizationError(
                "safe_repair_execution_decision_inconsistent"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "household_id": self.household_id,
            "actor_subject": self.actor_subject.to_dict(),
            "actor_member_id": self.actor_member_id,
            "job_id": self.job_id,
            "recommendation_id": self.recommendation_id,
            "recommendation_sha256": self.recommendation_sha256,
            "permission": self.permission,
            "worker_invocation_authorized": self.worker_invocation_authorized,
            "blockers": [item.value for item in self.blockers],
            "authenticated_actor_required": True,
            "enabled_parent_required": True,
            "exact_rbac_permission_required": True,
            "exact_job_recommendation_binding_required": True,
            "automatic_retry_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def evaluate_safe_repair_execution_authorization(
    *,
    authenticated: bool,
    actor_subject: SubjectRef,
    actor_member_id: str,
    household: Household,
    access: EffectiveAccess,
    job: SafeAutoRepairJob,
    recommendation: SafeAutoRepairRecommendation,
) -> SafeRepairExecutionAuthorization:
    """Evaluate exact worker-invocation authority without performing any mutation."""

    if type(authenticated) is not bool:
        raise SafeRepairExecutionAuthorizationError(
            "safe_repair_execution_authentication_evidence_invalid"
        )
    if not isinstance(actor_subject, SubjectRef):
        raise SafeRepairExecutionAuthorizationError(
            "safe_repair_execution_actor_subject_invalid"
        )
    if not isinstance(actor_member_id, str) or not actor_member_id:
        raise SafeRepairExecutionAuthorizationError(
            "safe_repair_execution_actor_member_id_invalid"
        )
    if not isinstance(household, Household):
        raise SafeRepairExecutionAuthorizationError(
            "safe_repair_execution_household_invalid"
        )
    if not isinstance(access, EffectiveAccess):
        raise SafeRepairExecutionAuthorizationError(
            "safe_repair_execution_access_invalid"
        )
    if not isinstance(job, SafeAutoRepairJob):
        raise SafeRepairExecutionAuthorizationError(
            "safe_repair_execution_job_invalid"
        )
    if not isinstance(recommendation, SafeAutoRepairRecommendation):
        raise SafeRepairExecutionAuthorizationError(
            "safe_repair_execution_recommendation_invalid"
        )

    blockers: list[SafeRepairExecutionBlocker] = []
    if not authenticated:
        blockers.append(SafeRepairExecutionBlocker.AUTHENTICATION_REQUIRED)
    if access.subject != actor_subject:
        blockers.append(SafeRepairExecutionBlocker.ACTOR_SUBJECT_ACCESS_MISMATCH)

    member = None
    try:
        member = household.member(actor_member_id)
    except Exception:
        blockers.append(SafeRepairExecutionBlocker.ACTOR_MEMBER_UNAVAILABLE)
    if member is not None:
        if not member.enabled:
            blockers.append(SafeRepairExecutionBlocker.ACTOR_MEMBER_DISABLED)
        if member.role is not HouseholdRole.PARENT:
            blockers.append(SafeRepairExecutionBlocker.PARENT_REQUIRED)

    if access.scope_id not in {"global", household.household_id}:
        blockers.append(SafeRepairExecutionBlocker.RBAC_SCOPE_MISMATCH)
    if SAFE_REPAIR_EXECUTE_PERMISSION not in access.permissions:
        blockers.append(SafeRepairExecutionBlocker.RBAC_PERMISSION_MISSING)

    if recommendation.candidate.household_id != household.household_id:
        blockers.append(SafeRepairExecutionBlocker.HOUSEHOLD_MISMATCH)
    if not recommendation.eligible_for_auto_repair or recommendation.blockers:
        blockers.append(SafeRepairExecutionBlocker.RECOMMENDATION_NOT_ELIGIBLE)
    if job.state is not RepairJobState.ADMITTED:
        blockers.append(SafeRepairExecutionBlocker.JOB_NOT_ADMITTED)
    if job.recommendation_id != recommendation.recommendation_id:
        blockers.append(SafeRepairExecutionBlocker.JOB_RECOMMENDATION_MISMATCH)

    recommendation_sha = _recommendation_sha256(recommendation)
    if job.recommendation_sha256 != recommendation_sha:
        blockers.append(
            SafeRepairExecutionBlocker.JOB_RECOMMENDATION_DIGEST_MISMATCH
        )

    return SafeRepairExecutionAuthorization(
        household_id=household.household_id,
        actor_subject=actor_subject,
        actor_member_id=actor_member_id,
        job_id=job.job_id,
        recommendation_id=recommendation.recommendation_id,
        recommendation_sha256=recommendation_sha,
        permission=SAFE_REPAIR_EXECUTE_PERMISSION,
        worker_invocation_authorized=not blockers,
        blockers=tuple(blockers),
    )


__all__ = [
    "SAFE_REPAIR_EXECUTE_PERMISSION",
    "SAFE_REPAIR_EXECUTION_AUTHORIZATION_SCHEMA",
    "SafeRepairExecutionAuthorization",
    "SafeRepairExecutionAuthorizationError",
    "SafeRepairExecutionBlocker",
    "evaluate_safe_repair_execution_authorization",
]
