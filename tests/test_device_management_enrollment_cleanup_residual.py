from __future__ import annotations

from home_center.device_management_enrollment_cleanup import (
    assess_retry_after_cleanup,
    build_failed_enrollment_cleanup_plan,
)
from home_center.device_management_enrollment_verification import (
    VERIFICATION_RESULT_SCHEMA,
    build_verification_request,
    evaluate_verification_result,
    verification_result_from_dict,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import build_household_snapshot


def _snapshot():
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember(
                member_id="member-parent",
                display_name="Parent",
                role=HouseholdRole.PARENT,
            ),
        ),
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-parent",
                display_name="Phone",
                managed=False,
            ),
        ),
    )
    return build_household_snapshot(
        household,
        generation=1,
        previous_snapshot_id=None,
    )


def _request(snapshot):
    return build_verification_request(
        execution_receipt={
            "schema": "home-center.device-management-enrollment-execution-receipt.v1",
            "state": "provider-accepted",
            "job_id": "job-enrollment-1",
            "retry_of_job_id": None,
            "plan_id": "dmpexec-0123456789abcdef01234567",
            "selection_proposal_id": "dmpsel-0123456789abcdef01234567",
            "provider_id": "provider-mdm",
            "provider_operation_id": "provider-op-1",
            "device_id": "device-phone",
            "member_id": "member-parent",
            "one_time_artifact": None,
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        },
        snapshot=snapshot,
    )


def _evidence(request, *, observed_at: str, flags: tuple[bool, bool, bool, bool]):
    certificate, profile, agent, active = flags
    result = verification_result_from_dict(
        {
            "schema": VERIFICATION_RESULT_SCHEMA,
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "certificate_present": certificate,
            "profile_present": profile,
            "agent_present": agent,
            "management_active": active,
            "observed_at": observed_at,
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        },
        request=request,
    )
    return evaluate_verification_result(request=request, result=result)


def test_fully_residual_post_cleanup_state_is_valid_but_retry_remains_denied():
    request = _request(_snapshot())
    initial = _evidence(
        request,
        observed_at="2026-09-12T05:00:00Z",
        flags=(True, False, True, False),
    )
    cleanup = build_failed_enrollment_cleanup_plan(initial)
    assert cleanup.action == "de-enroll-required"

    still_fully_enrolled = _evidence(
        request,
        observed_at="2026-09-12T05:10:00Z",
        flags=(True, True, True, True),
    )
    assert still_fully_enrolled.verified is True

    assessment = assess_retry_after_cleanup(cleanup, still_fully_enrolled)
    assert assessment.residual_provider_state is True
    assert assessment.retry_planning_allowed is False
    assert assessment.retry_execution_authorized is False
    assert assessment.reason == "residual-provider-state"
