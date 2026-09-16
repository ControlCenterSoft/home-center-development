from dataclasses import replace

from home_center.authorization_0180 import EffectiveAccess, SubjectProvider, SubjectRef
from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_execution_authz import (
    SAFE_REPAIR_EXECUTE_PERMISSION,
    SafeRepairExecutionBlocker,
    evaluate_safe_repair_execution_authorization,
)
from home_center.safe_auto_repair_job import (
    RepairJobState,
    build_safe_repair_job,
)


def _household(*members: FamilyMember, household_id: str = "home-main") -> Household:
    return Household(household_id=household_id, members=members, devices=())


def _recommendation_and_job(household_id: str = "home-main"):
    candidate = RepairCandidate(
        household_id=household_id,
        resource_id="read-model-main",
        resource_generation=7,
        evidence_sha256="a" * 64,
        action=RepairAction.REFRESH_LOCAL_READ_MODEL,
        risk=RepairRisk.LOW,
        recovery_proven=True,
        post_condition_verifiable=True,
    )
    policy = SafeRepairPolicy(
        policy_id="repair-policy-main",
        policy_sha256="b" * 64,
        allowed_actions=frozenset({RepairAction.REFRESH_LOCAL_READ_MODEL}),
    )
    recommendation = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    admission = evaluate_safe_auto_repair_admission(
        reviewed=recommendation,
        current_candidate=candidate,
        current_policy=policy,
    )
    job = build_safe_repair_job(
        admission=admission,
        idempotency_key="repair-key-0001",
        created_at_epoch=100,
    )
    return recommendation, job


def _access(
    subject: SubjectRef,
    *,
    permission: bool = True,
    scope_id: str = "global",
) -> EffectiveAccess:
    permissions = (SAFE_REPAIR_EXECUTE_PERMISSION,) if permission else ()
    return EffectiveAccess(
        subject=subject,
        scope_id=scope_id,
        permissions=permissions,
        decision_source=("role-parent",),
    )


def test_exact_authenticated_parent_with_permission_authorizes_only_worker_invocation() -> None:
    subject = SubjectRef(SubjectProvider.LOCAL, "admin")
    parent = FamilyMember("member-parent", "Parent", HouseholdRole.PARENT)
    household = _household(parent)
    recommendation, job = _recommendation_and_job()

    decision = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(subject),
        job=job,
        recommendation=recommendation,
    )

    assert decision.worker_invocation_authorized is True
    assert decision.blockers == ()
    payload = decision.to_dict()
    assert payload["permission"] == SAFE_REPAIR_EXECUTE_PERMISSION
    assert payload["automatic_retry_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False


def test_authentication_subject_parent_and_permission_fail_closed_independently() -> None:
    subject = SubjectRef(SubjectProvider.LOCAL, "admin")
    other_subject = SubjectRef(SubjectProvider.LOCAL, "other-admin")
    parent = FamilyMember("member-parent", "Parent", HouseholdRole.PARENT)
    child = FamilyMember("member-child", "Child", HouseholdRole.CHILD)
    household = _household(parent, child)
    recommendation, job = _recommendation_and_job()

    unauthenticated = evaluate_safe_repair_execution_authorization(
        authenticated=False,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(subject),
        job=job,
        recommendation=recommendation,
    )
    assert unauthenticated.worker_invocation_authorized is False
    assert SafeRepairExecutionBlocker.AUTHENTICATION_REQUIRED in unauthenticated.blockers

    subject_drift = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(other_subject),
        job=job,
        recommendation=recommendation,
    )
    assert SafeRepairExecutionBlocker.ACTOR_SUBJECT_ACCESS_MISMATCH in subject_drift.blockers

    child_actor = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=child.member_id,
        household=household,
        access=_access(subject),
        job=job,
        recommendation=recommendation,
    )
    assert SafeRepairExecutionBlocker.PARENT_REQUIRED in child_actor.blockers

    disabled_parent = FamilyMember(
        "member-disabled",
        "Disabled Parent",
        HouseholdRole.PARENT,
        enabled=False,
    )
    disabled_household = _household(parent, disabled_parent)
    disabled_actor = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=disabled_parent.member_id,
        household=disabled_household,
        access=_access(subject),
        job=job,
        recommendation=recommendation,
    )
    assert SafeRepairExecutionBlocker.ACTOR_MEMBER_DISABLED in disabled_actor.blockers

    missing_actor = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id="member-missing",
        household=household,
        access=_access(subject),
        job=job,
        recommendation=recommendation,
    )
    assert SafeRepairExecutionBlocker.ACTOR_MEMBER_UNAVAILABLE in missing_actor.blockers

    no_permission = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(subject, permission=False),
        job=job,
        recommendation=recommendation,
    )
    assert SafeRepairExecutionBlocker.RBAC_PERMISSION_MISSING in no_permission.blockers


def test_scope_and_household_drift_are_rejected() -> None:
    subject = SubjectRef(SubjectProvider.LOCAL, "admin")
    parent = FamilyMember("member-parent", "Parent", HouseholdRole.PARENT)
    household = _household(parent)
    recommendation, job = _recommendation_and_job()

    scope_drift = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(subject, scope_id="other-home"),
        job=job,
        recommendation=recommendation,
    )
    assert scope_drift.worker_invocation_authorized is False
    assert SafeRepairExecutionBlocker.RBAC_SCOPE_MISMATCH in scope_drift.blockers

    other_recommendation, other_job = _recommendation_and_job("other-home")
    household_drift = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(subject),
        job=other_job,
        recommendation=other_recommendation,
    )
    assert household_drift.worker_invocation_authorized is False
    assert SafeRepairExecutionBlocker.HOUSEHOLD_MISMATCH in household_drift.blockers


def test_job_state_and_exact_recommendation_digest_are_required() -> None:
    subject = SubjectRef(SubjectProvider.LOCAL, "admin")
    parent = FamilyMember("member-parent", "Parent", HouseholdRole.PARENT)
    household = _household(parent)
    recommendation, job = _recommendation_and_job()

    running_job = replace(job, state=RepairJobState.RUNNING)
    running = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(subject),
        job=running_job,
        recommendation=recommendation,
    )
    assert running.worker_invocation_authorized is False
    assert SafeRepairExecutionBlocker.JOB_NOT_ADMITTED in running.blockers

    digest_drift_job = replace(job, recommendation_sha256="f" * 64)
    digest_drift = evaluate_safe_repair_execution_authorization(
        authenticated=True,
        actor_subject=subject,
        actor_member_id=parent.member_id,
        household=household,
        access=_access(subject),
        job=digest_drift_job,
        recommendation=recommendation,
    )
    assert digest_drift.worker_invocation_authorized is False
    assert (
        SafeRepairExecutionBlocker.JOB_RECOMMENDATION_DIGEST_MISMATCH
        in digest_drift.blockers
    )
