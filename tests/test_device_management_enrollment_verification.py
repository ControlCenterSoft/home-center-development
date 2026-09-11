from __future__ import annotations

import pytest

from home_center.device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationError,
    build_enrollment_verification_plan,
    evaluate_enrollment_post_condition,
)


def _receipt() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": "job-057-start",
        "retry_of_job_id": None,
        "plan_id": "dmpexec-1234567890abcdef12345678",
        "selection_proposal_id": "dmpsel-1234567890abcdef12345678",
        "provider_id": "android-mdm",
        "provider_operation_id": "op-123",
        "device_id": "device-1",
        "member_id": "member-1",
        "one_time_artifact": None,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _plan():
    return build_enrollment_verification_plan(
        execution_receipt=_receipt(),
        household_id="household-1",
        snapshot_id="snapshot-10",
        resource_version="rv-10",
        generation=10,
        actor_member_id="member-parent",
        required_checks=["profile", "agent"],
    )


def _observation(
    *,
    provider_state: str = "enrolled",
    profile: str = "present",
    agent: str = "present",
    certificate: str = "not-applicable",
) -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-provider-observation.v1",
        "provider_id": "android-mdm",
        "provider_operation_id": "op-123",
        "device_id": "device-1",
        "provider_state": provider_state,
        "checks": {
            "certificate": certificate,
            "profile": profile,
            "agent": agent,
        },
        "observed_at": "2026-09-12T00:00:00Z",
        "read_only": True,
    }


def test_verified_result_is_the_only_path_that_authorizes_managed_state_change() -> None:
    result = evaluate_enrollment_post_condition(_plan(), _observation()).to_dict()
    assert result["state"] == "verified"
    assert result["enrollment_completed"] is True
    assert result["post_condition_verified"] is True
    assert result["managed_state_change_authorized"] is True
    assert result["policy_application_authorized"] is False
    assert result["infrastructure_mutation_authorized"] is False
    assert result["external_publication_authorized"] is False


@pytest.mark.parametrize("status", ["missing", "unknown", "not-applicable"])
def test_required_evidence_fails_closed(status: str) -> None:
    result = evaluate_enrollment_post_condition(
        _plan(), _observation(profile=status)
    ).to_dict()
    assert result["state"] == "not-verified"
    assert result["managed_state_change_authorized"] is False
    assert result["policy_application_authorized"] is False


@pytest.mark.parametrize("provider_state", ["unknown", "not-enrolled", "cancelled"])
def test_provider_state_must_be_enrolled(provider_state: str) -> None:
    result = evaluate_enrollment_post_condition(
        _plan(), _observation(provider_state=provider_state)
    ).to_dict()
    assert result["state"] == "not-verified"
    assert result["managed_state_change_authorized"] is False


def test_provider_observation_is_exactly_bound_to_the_057_operation() -> None:
    observation = _observation()
    observation["provider_operation_id"] = "op-other"
    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_binding_mismatch",
    ):
        evaluate_enrollment_post_condition(_plan(), observation)


def test_057_receipt_cannot_claim_early_completion_or_managed_authority() -> None:
    receipt = _receipt()
    receipt["managed_state_change_authorized"] = True
    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_execution_receipt_invalid",
    ):
        build_enrollment_verification_plan(
            execution_receipt=receipt,
            household_id="household-1",
            snapshot_id="snapshot-10",
            resource_version="rv-10",
            generation=10,
            actor_member_id="member-parent",
            required_checks=["profile"],
        )


def test_verification_identity_changes_with_exact_household_state() -> None:
    first = _plan()
    second = build_enrollment_verification_plan(
        execution_receipt=_receipt(),
        household_id="household-1",
        snapshot_id="snapshot-11",
        resource_version="rv-11",
        generation=11,
        actor_member_id="member-parent",
        required_checks=["profile", "agent"],
    )
    assert first.verification_id != second.verification_id
