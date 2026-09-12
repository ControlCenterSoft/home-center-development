from __future__ import annotations

import pytest

from home_center.device_management_enrollment_verification import (
    VERIFICATION_RESULT_SCHEMA,
    DeviceManagementEnrollmentVerificationError,
    build_managed_state_replacement,
    build_verification_request,
    evaluate_verification_result,
    verification_result_from_dict,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import build_household_replacement, build_household_snapshot


def _snapshot(*, managed: bool = False):
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
                managed=managed,
            ),
        ),
    )
    return build_household_snapshot(household, generation=1, previous_snapshot_id=None)


def _receipt(**overrides):
    value = {
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
    value.update(overrides)
    return value


def _result(request, **overrides):
    value = {
        "schema": VERIFICATION_RESULT_SCHEMA,
        "provider_operation_id": request.provider_operation_id,
        "device_id": request.device_id,
        "certificate_present": True,
        "profile_present": True,
        "agent_present": True,
        "management_active": True,
        "observed_at": "2026-09-12T03:31:00Z",
        "secret_material_present": False,
        "infrastructure_mutation_authorized": False,
    }
    value.update(overrides)
    return value


def test_verified_readback_is_bound_and_allows_only_managed_state_transition():
    snapshot = _snapshot()
    request = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)

    assert "one_time_artifact" not in request.to_dict()
    assert "secret://" not in repr(request.to_dict())
    assert request.provider_readback_authorized is True
    assert request.managed_state_change_authorized is False

    result = verification_result_from_dict(_result(request), request=request)
    evidence = evaluate_verification_result(request=request, result=result)

    assert evidence.verified is True
    assert evidence.failure_reasons == ()
    assert evidence.to_dict()["post_condition_verified"] is True
    assert evidence.to_dict()["managed_state_change_authorized"] is True
    assert evidence.to_dict()["policy_application_authorized"] is False

    replacement, commit = build_managed_state_replacement(snapshot, evidence)
    managed = next(item for item in replacement.household.devices if item.device_id == "device-phone")
    assert managed.managed is True
    assert replacement.generation == snapshot.generation + 1
    assert replacement.previous_snapshot_id == snapshot.snapshot_id
    assert commit.previous_resource_version == snapshot.resource_version


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        ("certificate_present", "certificate-missing"),
        ("profile_present", "profile-missing"),
        ("agent_present", "agent-missing"),
        ("management_active", "management-inactive"),
    ],
)
def test_partial_readback_never_authorizes_managed_true(field, reason):
    snapshot = _snapshot()
    request = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)
    result = verification_result_from_dict(_result(request, **{field: False}), request=request)
    evidence = evaluate_verification_result(request=request, result=result)

    assert evidence.verified is False
    assert reason in evidence.failure_reasons
    assert evidence.to_dict()["managed_state_change_authorized"] is False
    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_post_condition_not_verified",
    ):
        build_managed_state_replacement(snapshot, evidence)


def test_result_binding_mismatch_is_rejected_fail_closed():
    snapshot = _snapshot()
    request = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_result_rejected",
    ):
        verification_result_from_dict(_result(request, provider_operation_id="different-operation"), request=request)

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_result_rejected",
    ):
        verification_result_from_dict(_result(request, device_id="different-device"), request=request)


def test_secret_material_claim_and_unknown_result_fields_are_rejected():
    snapshot = _snapshot()
    request = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_result_rejected",
    ):
        verification_result_from_dict(_result(request, secret_material_present=True), request=request)

    value = _result(request)
    value["credential"] = "must-not-cross-boundary"
    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_result_rejected",
    ):
        verification_result_from_dict(value, request=request)


def test_stale_household_snapshot_cannot_be_mutated_after_verification():
    snapshot = _snapshot()
    request = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)
    result = verification_result_from_dict(_result(request), request=request)
    evidence = evaluate_verification_result(request=request, result=result)

    changed_household = Household(
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
        changed_household,
        expected_resource_version=snapshot.resource_version,
    )

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_stale",
    ):
        build_managed_state_replacement(newer, evidence)


def test_verification_request_is_deterministic_and_rejects_false_success_receipt():
    snapshot = _snapshot()
    first = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)
    second = build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)
    assert first == second

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_execution_receipt_invalid",
    ):
        build_verification_request(
            execution_receipt=_receipt(post_condition_verified=True),
            snapshot=snapshot,
        )

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_execution_receipt_invalid",
    ):
        build_verification_request(
            execution_receipt=_receipt(managed_state_change_authorized=True),
            snapshot=snapshot,
        )


def test_already_managed_device_requires_existing_evidence_path_not_new_verification():
    snapshot = _snapshot(managed=True)
    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_already_managed",
    ):
        build_verification_request(execution_receipt=_receipt(), snapshot=snapshot)
