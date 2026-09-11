"""Provider-free assessment of whether registered Household devices need management.

Home Center 0.52 only evaluates product state. It does not choose a provider,
enroll a device, apply policy, mutate infrastructure or claim a post-condition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from .home_services import HomeServiceCatalogError
from .household import FamilyMember, Household, HouseholdRole, ManagedDevice, ROLE_PRESETS


DEVICE_MANAGEMENT_ASSESSMENT_SCHEMA = "home-center.household-device-management-assessment.v1"
DEVICE_MANAGEMENT_REPORT_SCHEMA = "home-center.household-device-management-report.v1"


class HouseholdDeviceManagementError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceManagementStatus(StrEnum):
    SATISFIED = "satisfied"
    REQUIRED = "required"
    OPTIONAL = "optional"


@dataclass(frozen=True, slots=True)
class DeviceManagementAssessment:
    device_id: str
    member_id: str
    member_role: HouseholdRole
    subject_enabled: bool
    managed: bool
    management_required: bool
    status: DeviceManagementStatus
    schema: str = field(default=DEVICE_MANAGEMENT_ASSESSMENT_SCHEMA, init=False)
    plan_only: bool = field(default=True, init=False)
    provider_selected: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "member_role": self.member_role.value,
            "subject_enabled": self.subject_enabled,
            "managed": self.managed,
            "management_required": self.management_required,
            "status": self.status.value,
            "plan_only": True,
            "provider_selected": False,
            "policy_application_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def evaluate_device_management(household: Household) -> tuple[DeviceManagementAssessment, ...]:
    """Return deterministic management necessity for every registered device."""

    if not isinstance(household, Household):
        raise TypeError("invalid_household")
    assessments: list[DeviceManagementAssessment] = []
    for device in household.devices:
        try:
            member = household.member(device.member_id)
        except HomeServiceCatalogError as exc:
            raise HouseholdDeviceManagementError(exc.code) from exc
        required = bool(member.enabled and ROLE_PRESETS[member.role].managed_device_required)
        if not required:
            status = DeviceManagementStatus.OPTIONAL
        elif device.managed:
            status = DeviceManagementStatus.SATISFIED
        else:
            status = DeviceManagementStatus.REQUIRED
        assessments.append(
            DeviceManagementAssessment(
                device_id=device.device_id,
                member_id=member.member_id,
                member_role=member.role,
                subject_enabled=member.enabled,
                managed=device.managed,
                management_required=required,
                status=status,
            )
        )
    return tuple(assessments)


def _household_from_snapshot(value: object) -> tuple[Household, dict[str, object]]:
    if not isinstance(value, dict):
        raise HouseholdDeviceManagementError("household_management_state_invalid")
    household_raw = value.get("household")
    if not isinstance(household_raw, dict):
        raise HouseholdDeviceManagementError("household_management_state_invalid")
    members_raw = household_raw.get("members")
    devices_raw = household_raw.get("devices")
    if not isinstance(members_raw, list) or not isinstance(devices_raw, list):
        raise HouseholdDeviceManagementError("household_management_state_invalid")
    try:
        members = tuple(
            FamilyMember(
                member_id=item["member_id"],
                display_name=item["display_name"],
                role=HouseholdRole(item["role"]),
                enabled=item["enabled"],
            )
            for item in members_raw
            if isinstance(item, dict)
        )
        devices = tuple(
            ManagedDevice(
                device_id=item["device_id"],
                member_id=item["member_id"],
                display_name=item["display_name"],
                managed=item["managed"],
            )
            for item in devices_raw
            if isinstance(item, dict)
        )
        if len(members) != len(members_raw) or len(devices) != len(devices_raw):
            raise HouseholdDeviceManagementError("household_management_state_invalid")
        household = Household(
            household_id=household_raw["household_id"],
            members=members,
            devices=devices,
        )
    except HouseholdDeviceManagementError:
        raise
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError) as exc:
        raise HouseholdDeviceManagementError("household_management_state_invalid") from exc
    return household, value


def management_report_from_runtime_status(value: object) -> dict[str, object]:
    """Convert the already integrity-checked Household runtime view into a plan-only report."""

    if not isinstance(value, dict) or value.get("schema") != "home-center.household-runtime.v1":
        raise HouseholdDeviceManagementError("household_management_state_invalid")
    configured = value.get("configured")
    if configured is False:
        if value.get("snapshot") is not None:
            raise HouseholdDeviceManagementError("household_management_state_invalid")
        return {
            "schema": DEVICE_MANAGEMENT_REPORT_SCHEMA,
            "configured": False,
            "household_id": None,
            "snapshot_id": None,
            "resource_version": None,
            "generation": None,
            "devices": [],
            "plan_only": True,
            "provider_selected": False,
            "policy_application_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
    if configured is not True:
        raise HouseholdDeviceManagementError("household_management_state_invalid")
    household, snapshot = _household_from_snapshot(value.get("snapshot"))
    snapshot_id = snapshot.get("snapshot_id")
    resource_version = snapshot.get("resource_version")
    generation = snapshot.get("generation")
    if (
        not isinstance(snapshot_id, str)
        or not isinstance(resource_version, str)
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
    ):
        raise HouseholdDeviceManagementError("household_management_state_invalid")
    return {
        "schema": DEVICE_MANAGEMENT_REPORT_SCHEMA,
        "configured": True,
        "household_id": household.household_id,
        "snapshot_id": snapshot_id,
        "resource_version": resource_version,
        "generation": generation,
        "devices": [item.to_dict() for item in evaluate_device_management(household)],
        "plan_only": True,
        "provider_selected": False,
        "policy_application_authorized": False,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
