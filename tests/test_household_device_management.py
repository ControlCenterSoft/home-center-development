from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_management import (
    DeviceManagementStatus,
    HouseholdDeviceManagementError,
    evaluate_device_management,
    management_report_from_runtime_status,
)


def _household(*devices: ManagedDevice) -> Household:
    return Household(
        household_id="home",
        members=(
            FamilyMember(member_id="parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child", display_name="Child", role=HouseholdRole.CHILD),
            FamilyMember(member_id="guest", display_name="Guest", role=HouseholdRole.GUEST),
        ),
        devices=devices,
    )


def test_management_status_is_required_for_unmanaged_child_device() -> None:
    assessments = evaluate_device_management(
        _household(ManagedDevice(device_id="tablet", member_id="child", display_name="Tablet", managed=False))
    )
    assert len(assessments) == 1
    item = assessments[0]
    assert item.status is DeviceManagementStatus.REQUIRED
    assert item.management_required is True
    assert item.managed is False
    assert item.to_dict()["provider_selected"] is False
    assert item.to_dict()["policy_application_authorized"] is False


def test_management_status_is_satisfied_only_when_required_management_is_present() -> None:
    assessments = evaluate_device_management(
        _household(ManagedDevice(device_id="tablet", member_id="child", display_name="Tablet", managed=True))
    )
    assert assessments[0].status is DeviceManagementStatus.SATISFIED
    assert assessments[0].management_required is True
    assert assessments[0].managed is True


def test_management_status_is_optional_when_role_does_not_require_management() -> None:
    assessments = evaluate_device_management(
        _household(
            ManagedDevice(device_id="phone", member_id="parent", display_name="Phone", managed=False),
            ManagedDevice(device_id="guest-phone", member_id="guest", display_name="Guest phone", managed=True),
        )
    )
    assert [item.status for item in assessments] == [
        DeviceManagementStatus.OPTIONAL,
        DeviceManagementStatus.OPTIONAL,
    ]
    assert all(item.management_required is False for item in assessments)


def test_runtime_report_is_plan_only_and_contains_no_provider_authority() -> None:
    household = _household(
        ManagedDevice(device_id="tablet", member_id="child", display_name="Tablet", managed=False)
    )
    value = {
        "schema": "home-center.household-runtime.v1",
        "configured": True,
        "snapshot": {
            "schema": "home-center.household-snapshot.v1",
            "snapshot_id": "hsnap-example",
            "resource_version": "hrv-example",
            "household_id": "home",
            "generation": 2,
            "previous_snapshot_id": "hsnap-previous",
            "household": household.to_dict(),
        },
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    report = management_report_from_runtime_status(value)
    assert report["schema"] == "home-center.household-device-management-report.v1"
    assert report["devices"][0]["status"] == "required"
    assert report["plan_only"] is True
    assert report["provider_selected"] is False
    assert report["provider_execution_authorized"] is False
    assert report["infrastructure_mutation_authorized"] is False
    assert report["external_publication_authorized"] is False


def test_unconfigured_runtime_returns_empty_plan_only_report() -> None:
    report = management_report_from_runtime_status(
        {
            "schema": "home-center.household-runtime.v1",
            "configured": False,
            "snapshot": None,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
    )
    assert report["configured"] is False
    assert report["devices"] == []
    assert report["provider_selected"] is False


def test_malformed_runtime_state_is_rejected_fail_closed() -> None:
    with pytest.raises(HouseholdDeviceManagementError, match="household_management_state_invalid"):
        management_report_from_runtime_status(
            {
                "schema": "home-center.household-runtime.v1",
                "configured": True,
                "snapshot": {"household": {"members": [], "devices": []}},
            }
        )
