from __future__ import annotations

import pytest

from home_center.device_management_enrollment_cleanup import build_failed_enrollment_cleanup_plan
from home_center.device_management_enrollment_deenrollment import (
    DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
    DeviceManagementEnrollmentDeenrollmentError,
    build_deenrollment_adapter_request,
    build_deenrollment_plan,
    build_deenrollment_receipt,
    confirm_deenrollment,
    deenrollment_adapter_result_from_dict,
)
from home_center.device_management_enrollment_verification import (
    VERIFICATION_RESULT_SCHEMA,
    build_verification_request,
    evaluate_verification_result,
    verification_result_from_dict,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import build_household_replacement, build_household_snapshot


def _snapshot():
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-child",
                display_name="Phone",
                managed=False,
            ),
        ),
    )
    return build_household_snapshot(household, generation=1, previous_snapshot_id=None)


def _execution_receipt():
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": "job-enrollment-1",
        "retry_of_job_id": None,
        "plan_id": "dmpexec-0123456789abcdef01234567",
        "selection_proposal_id": "dmpsel-0123456789abcdef01234567",
        "provider_id": "provider-mdm",
        "provider_operation_id": "provider-op-1",
        "device_id": "device-phone",
        "member_id": "member-child",
        "one_time_artifact": None,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _cleanup(snapshot, *, residual: bool = True):
    request = build_verification_request(execution_receipt=_execution_receipt(), snapshot=snapshot)
    result = verification_result_from_dict(
        {
            "schema": VERIFICATION_RESULT_SCHEMA,
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "certificate_present": residual,
            "profile_present": False,
            "agent_present": residual,
            "management_active": False,
            "observed_at": "2026-09-12T03:31:00Z",
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        },
        request=request,
    )
    evidence = evaluate_verification_result(request=request, result=result)
    return build_failed_enrollment_cleanup_plan(evidence)


def _plan(snapshot):
    return build_deenrollment_plan(
        _cleanup(snapshot),
        current=snapshot,
        actor_member_id="member-parent",
    )


def _confirmation(plan):
    return confirm_deenrollment(
        plan,
        actor_member_id="member-parent",
        confirmed=True,
        idempotency_key="cleanup-request-0001",
        confirmed_at="2026-09-12T03:32:00Z",
    )


def test_deenrollment_requires_admin_and_exact_cleanup_snapshot():
    snapshot = _snapshot()
    plan = _plan(snapshot)
    assert plan.confirmation_required is True
    assert plan.provider_mutation_authorized is False
    assert plan.retry_planning_allowed is False
    assert plan.retry_execution_authorized is False
    assert plan.managed_state_change_authorized is False

    with pytest.raises(DeviceManagementEnrollmentDeenrollmentError, match="forbidden"):
        build_deenrollment_plan(
            _cleanup(snapshot),
            current=snapshot,
            actor_member_id="member-child",
        )


def test_no_provider_cleanup_does_not_open_deenrollment_boundary():
    snapshot = _snapshot()
    cleanup = _cleanup(snapshot, residual=False)
    assert cleanup.action == "no-provider-cleanup"
    with pytest.raises(DeviceManagementEnrollmentDeenrollmentError, match="not_required"):
        build_deenrollment_plan(cleanup, current=snapshot, actor_member_id="member-parent")


def test_stale_household_snapshot_blocks_provider_cleanup_plan():
    snapshot = _snapshot()
    cleanup = _cleanup(snapshot)
    changed = Household(
        household_id=snapshot.household_id,
        members=snapshot.household.members,
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-child",
                display_name="Phone renamed",
                managed=False,
            ),
        ),
    )
    newer, _commit = build_household_replacement(
        snapshot,
        changed,
        expected_resource_version=snapshot.resource_version,
    )
    with pytest.raises(DeviceManagementEnrollmentDeenrollmentError, match="stale"):
        build_deenrollment_plan(cleanup, current=newer, actor_member_id="member-parent")


def test_confirmation_is_explicit_deterministic_and_actor_bound():
    plan = _plan(_snapshot())
    first = _confirmation(plan)
    second = _confirmation(plan)
    assert first == second
    assert first.provider_mutation_authorized is True
    assert first.retry_execution_authorized is False

    with pytest.raises(DeviceManagementEnrollmentDeenrollmentError, match="confirmation_required"):
        confirm_deenrollment(
            plan,
            actor_member_id="member-parent",
            confirmed=False,
            idempotency_key="cleanup-request-0001",
            confirmed_at="2026-09-12T03:32:00Z",
        )

    with pytest.raises(DeviceManagementEnrollmentDeenrollmentError, match="actor_mismatch"):
        confirm_deenrollment(
            plan,
            actor_member_id="member-child",
            confirmed=True,
            idempotency_key="cleanup-request-0001",
            confirmed_at="2026-09-12T03:32:00Z",
        )


def test_adapter_request_grants_only_bounded_cleanup_authority():
    plan = _plan(_snapshot())
    request = build_deenrollment_adapter_request(
        plan,
        _confirmation(plan),
        job_id="job-cleanup-1",
        deadline_at="2026-09-12T03:37:00Z",
    )
    assert request.provider_mutation_authorized is True
    assert request.credential_value_access_authorized is False
    assert request.retry_execution_authorized is False
    assert request.managed_state_change_authorized is False
    assert request.policy_application_authorized is False
    assert request.infrastructure_mutation_authorized is False
    assert request.external_publication_authorized is False


def test_provider_acceptance_is_not_cleanup_success_or_retry_authority():
    plan = _plan(_snapshot())
    request = build_deenrollment_adapter_request(
        plan,
        _confirmation(plan),
        job_id="job-cleanup-1",
        deadline_at="2026-09-12T03:37:00Z",
    )
    result = deenrollment_adapter_result_from_dict(
        {
            "schema": DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
            "state": "accepted",
            "cleanup_operation_id": "provider-cleanup-1",
            "post_cleanup_verified": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
        }
    )
    receipt = build_deenrollment_receipt(request, result)
    assert receipt.state == "provider-cleanup-accepted"
    assert receipt.post_cleanup_verified is False
    assert receipt.retry_planning_allowed is False
    assert receipt.retry_execution_authorized is False
    assert receipt.managed_state_change_authorized is False
    assert receipt.policy_application_authorized is False
    assert receipt.infrastructure_mutation_authorized is False
    assert receipt.external_publication_authorized is False


def test_adapter_result_rejects_false_success_and_extra_fields():
    base = {
        "schema": DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
        "state": "accepted",
        "cleanup_operation_id": "provider-cleanup-1",
        "post_cleanup_verified": False,
        "retry_planning_allowed": False,
        "retry_execution_authorized": False,
        "managed_state_change_authorized": False,
    }
    with pytest.raises(DeviceManagementEnrollmentDeenrollmentError, match="result_rejected"):
        deenrollment_adapter_result_from_dict(dict(base, retry_planning_allowed=True))
    extra = dict(base)
    extra["unexpected"] = "value"
    with pytest.raises(DeviceManagementEnrollmentDeenrollmentError, match="result_rejected"):
        deenrollment_adapter_result_from_dict(extra)
