from __future__ import annotations

import pytest

from home_center.device_management_enrollment_execution import DeviceManagementEnrollmentExecutionPlan
from home_center.device_management_enrollment_verification import (
    DeviceManagementEnrollmentAdapterVerifyResult,
    DeviceManagementEnrollmentVerificationError,
    adapter_request_for_plan,
    adapter_verification_result_from_dict,
    apply_verified_managed_state,
    build_enrollment_verification_plan,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import build_household_replacement, build_household_snapshot


PLAN_ID = "dmpexec-" + "1" * 24
SELECTION_ID = "dmpsel-" + "2" * 24
ENROLLMENT_ID = "hdenroll-" + "3" * 24
CATALOG_ID = "dmpcat-" + "4" * 24
JOB_ID = "job-enrollment-0001"
OPERATION_ID = "provider-op-0001"


def _snapshot(*, managed: bool = False):
    household = Household(
        household_id="home",
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
                managed=managed,
            ),
        ),
    )
    return build_household_snapshot(household, generation=1, previous_snapshot_id=None)


def _execution_plan(snapshot):
    return DeviceManagementEnrollmentExecutionPlan(
        plan_id=PLAN_ID,
        selection_proposal_id=SELECTION_ID,
        enrollment_proposal_id=ENROLLMENT_ID,
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id="member-parent",
        device_id="device-phone",
        member_id="member-parent",
        catalog_id=CATALOG_ID,
        provider_id="provider-mdm",
        enrollment_mode="mdm",
        credential_references=(),
        timeout_seconds=120,
        one_time_artifact="none",
    ).to_dict()


def _execution_receipt():
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": JOB_ID,
        "retry_of_job_id": None,
        "plan_id": PLAN_ID,
        "selection_proposal_id": SELECTION_ID,
        "provider_id": "provider-mdm",
        "provider_operation_id": OPERATION_ID,
        "device_id": "device-phone",
        "member_id": "member-parent",
        "one_time_artifact": None,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _verified_result(request):
    return {
        "schema": "home-center.device-management-enrollment-adapter-verify-result.v1",
        "state": "verified",
        "verification_id": request.verification_id,
        "provider_operation_id": request.provider_operation_id,
        "device_id": request.device_id,
        "provider_device_reference": "opaque-device/provider-42",
        "enrollment_completed": True,
        "post_condition_verified": True,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def test_verified_provider_postcondition_is_the_only_path_to_managed_true() -> None:
    snapshot = _snapshot()
    plan = build_enrollment_verification_plan(
        snapshot=snapshot,
        execution_plan=_execution_plan(snapshot),
        execution_receipt=_execution_receipt(),
    )
    request = adapter_request_for_plan(plan)
    result = adapter_verification_result_from_dict(_verified_result(request), expected=request)

    next_snapshot, commit, receipt = apply_verified_managed_state(
        snapshot=snapshot,
        plan=plan,
        adapter_result=result,
    )

    device = next_snapshot.household.devices[0]
    assert device.managed is True
    assert next_snapshot.generation == 2
    assert commit.previous_resource_version == snapshot.resource_version
    assert receipt["state"] == "managed-state-applied"
    assert receipt["enrollment_completed"] is True
    assert receipt["post_condition_verified"] is True
    assert receipt["managed_state_change_authorized"] is True
    assert receipt["policy_application_authorized"] is False
    assert receipt["infrastructure_mutation_authorized"] is False
    assert receipt["external_publication_authorized"] is False


def test_provider_cannot_grant_managed_state_authority() -> None:
    snapshot = _snapshot()
    plan = build_enrollment_verification_plan(
        snapshot=snapshot,
        execution_plan=_execution_plan(snapshot),
        execution_receipt=_execution_receipt(),
    )
    request = adapter_request_for_plan(plan)
    result = _verified_result(request)
    result["managed_state_change_authorized"] = True

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_adapter_verification_rejected",
    ):
        adapter_verification_result_from_dict(result, expected=request)


def test_provider_operation_binding_is_fail_closed() -> None:
    snapshot = _snapshot()
    plan = build_enrollment_verification_plan(
        snapshot=snapshot,
        execution_plan=_execution_plan(snapshot),
        execution_receipt=_execution_receipt(),
    )
    request = adapter_request_for_plan(plan)
    result = _verified_result(request)
    result["provider_operation_id"] = "provider-op-other"

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_adapter_verification_rejected",
    ):
        adapter_verification_result_from_dict(result, expected=request)


def test_execution_receipt_cannot_preclaim_completion() -> None:
    snapshot = _snapshot()
    receipt = _execution_receipt()
    receipt["enrollment_completed"] = True

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_execution_receipt_invalid",
    ):
        build_enrollment_verification_plan(
            snapshot=snapshot,
            execution_plan=_execution_plan(snapshot),
            execution_receipt=receipt,
        )


def test_verification_plan_rejects_already_managed_device() -> None:
    snapshot = _snapshot(managed=True)
    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_device_already_managed",
    ):
        build_enrollment_verification_plan(
            snapshot=snapshot,
            execution_plan=_execution_plan(snapshot),
            execution_receipt=_execution_receipt(),
        )


def test_household_change_makes_verification_plan_stale() -> None:
    snapshot = _snapshot()
    plan = build_enrollment_verification_plan(
        snapshot=snapshot,
        execution_plan=_execution_plan(snapshot),
        execution_receipt=_execution_receipt(),
    )
    request = adapter_request_for_plan(plan)
    result = adapter_verification_result_from_dict(_verified_result(request), expected=request)

    changed = Household(
        household_id=snapshot.household.household_id,
        members=snapshot.household.members,
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-parent",
                display_name="Renamed Phone",
                managed=False,
            ),
        ),
    )
    newer, _commit = build_household_replacement(
        snapshot,
        changed,
        expected_resource_version=snapshot.resource_version,
    )

    with pytest.raises(
        DeviceManagementEnrollmentVerificationError,
        match="device_management_enrollment_verification_stale",
    ):
        apply_verified_managed_state(
            snapshot=newer,
            plan=plan,
            adapter_result=result,
        )


def test_adapter_result_dataclass_never_carries_mutation_authority() -> None:
    value = DeviceManagementEnrollmentAdapterVerifyResult(
        verification_id="dmpverify-" + "a" * 24,
        provider_operation_id=OPERATION_ID,
        device_id="device-phone",
        provider_device_reference="opaque-device/provider-42",
    ).to_dict()
    assert value["post_condition_verified"] is True
    assert value["managed_state_change_authorized"] is False
