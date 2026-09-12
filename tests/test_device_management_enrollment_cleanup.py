from __future__ import annotations

from dataclasses import replace

import pytest

from home_center.device_management_enrollment_cleanup import (
    DeviceManagementEnrollmentCleanupError,
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
            FamilyMember(
                member_id="member-child",
                display_name="Child",
                role=HouseholdRole.CHILD,
            ),
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


def _receipt():
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
        "one_time_artifact": {
            "kind": "token",
            "reference": "secret://enrollment/device-phone",
            "expires_at": "2026-09-12T03:30:00Z",
            "single_use": True,
        },
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _evidence(
    *,
    observed_at: str,
    certificate_present: bool,
    profile_present: bool,
    agent_present: bool,
    management_active: bool,
):
    snapshot = _snapshot()
    request = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)
    result = verification_result_from_dict(
        {
            "schema": VERIFICATION_RESULT_SCHEMA,
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "certificate_present": certificate_present,
            "profile_present": profile_present,
            "agent_present": agent_present,
            "management_active": management_active,
            "observed_at": observed_at,
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        },
        request=request,
    )
    return evaluate_verification_result(request=request, result=result)


def test_clean_negative_readback_builds_non_authorizing_cleanup_plan():
    evidence = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=False,
        profile_present=False,
        agent_present=False,
        management_active=False,
    )

    first = build_failed_enrollment_cleanup_plan(evidence)
    second = build_failed_enrollment_cleanup_plan(evidence)

    assert first == second
    assert first.action == "no-provider-cleanup"
    assert first.explicit_confirmation_required is False
    assert first.provider_mutation_authorized is False
    assert first.retry_planning_allowed is False
    assert first.retry_execution_authorized is False
    assert first.managed_state_change_authorized is False
    assert "secret://" not in repr(first.to_dict())


def test_residual_provider_state_requires_separate_confirmed_deenrollment_path():
    evidence = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=True,
        profile_present=False,
        agent_present=True,
        management_active=False,
    )

    plan = build_failed_enrollment_cleanup_plan(evidence)

    assert plan.action == "de-enroll-required"
    assert plan.explicit_confirmation_required is True
    assert plan.provider_mutation_authorized is False
    assert plan.retry_planning_allowed is False
    assert plan.retry_execution_authorized is False


def test_verified_device_does_not_enter_failed_cleanup_flow():
    evidence = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=True,
        profile_present=True,
        agent_present=True,
        management_active=True,
    )

    with pytest.raises(
        DeviceManagementEnrollmentCleanupError,
        match="device_management_enrollment_verification_evidence_invalid",
    ):
        build_failed_enrollment_cleanup_plan(evidence)


def test_cleanup_rejects_tampered_failure_reason_set():
    evidence = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=False,
        profile_present=False,
        agent_present=False,
        management_active=False,
    )
    tampered = replace(evidence, failure_reasons=("certificate-missing",))

    with pytest.raises(
        DeviceManagementEnrollmentCleanupError,
        match="device_management_enrollment_verification_evidence_invalid",
    ):
        build_failed_enrollment_cleanup_plan(tampered)


def test_retry_planning_requires_fresh_readback_with_no_residual_provider_state():
    initial = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=True,
        profile_present=False,
        agent_present=True,
        management_active=False,
    )
    plan = build_failed_enrollment_cleanup_plan(initial)
    clean_readback = _evidence(
        observed_at="2026-09-12T03:32:00Z",
        certificate_present=False,
        profile_present=False,
        agent_present=False,
        management_active=False,
    )

    assessment = assess_retry_after_cleanup(plan, clean_readback)

    assert assessment.retry_planning_allowed is True
    assert assessment.retry_execution_authorized is False
    assert assessment.residual_provider_state is False
    assert assessment.reason == "cleanup-verified-no-residual-state"
    assert assessment.provider_mutation_authorized is False
    assert assessment.managed_state_change_authorized is False


def test_retry_planning_stays_closed_while_provider_traces_remain():
    initial = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=True,
        profile_present=False,
        agent_present=False,
        management_active=False,
    )
    plan = build_failed_enrollment_cleanup_plan(initial)
    residual = _evidence(
        observed_at="2026-09-12T03:32:00Z",
        certificate_present=False,
        profile_present=True,
        agent_present=False,
        management_active=False,
    )

    assessment = assess_retry_after_cleanup(plan, residual)

    assert assessment.retry_planning_allowed is False
    assert assessment.retry_execution_authorized is False
    assert assessment.residual_provider_state is True
    assert assessment.reason == "residual-provider-state"


def test_retry_assessment_rejects_non_fresh_or_mismatched_readback():
    initial = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=True,
        profile_present=False,
        agent_present=False,
        management_active=False,
    )
    plan = build_failed_enrollment_cleanup_plan(initial)
    same_time = _evidence(
        observed_at="2026-09-12T03:31:00Z",
        certificate_present=False,
        profile_present=False,
        agent_present=False,
        management_active=False,
    )

    with pytest.raises(
        DeviceManagementEnrollmentCleanupError,
        match="device_management_enrollment_cleanup_readback_not_fresh",
    ):
        assess_retry_after_cleanup(plan, same_time)

    fresh = _evidence(
        observed_at="2026-09-12T03:32:00Z",
        certificate_present=False,
        profile_present=False,
        agent_present=False,
        management_active=False,
    )
    mismatched = replace(fresh, provider_operation_id="different-operation")
    with pytest.raises(
        DeviceManagementEnrollmentCleanupError,
        match="device_management_enrollment_cleanup_binding_mismatch",
    ):
        assess_retry_after_cleanup(plan, mismatched)
