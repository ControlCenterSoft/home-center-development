"""Provider-neutral management planning for registered Household devices.

This module describes whether management is required or already satisfied and
can recommend a future enrollment action. It never selects credentials, invokes
an MDM/provider, changes a device's managed flag or mutates infrastructure.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum

from .home_services import HomeServiceCatalogError, _identifier
from .household import HouseholdRole, effective_policy
from .household_store import HouseholdSnapshot


DEVICE_MANAGEMENT_PLAN_SCHEMA = "home-center.household-device-management-plan.v1"


class DeviceManagementState(StrEnum):
    SATISFIED = "satisfied"
    REQUIRED = "required"
    OPTIONAL = "optional"


class HouseholdDeviceManagementError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementAction:
    action_type: str
    device_id: str
    member_id: str
    provider_resolution_required: bool
    confirmation_required: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "action_type": self.action_type,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "provider_resolution_required": self.provider_resolution_required,
            "confirmation_required": self.confirmation_required,
        }


@dataclass(frozen=True, slots=True)
class HouseholdDeviceManagementPlan:
    plan_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    member_role: HouseholdRole
    management_required: bool
    managed: bool
    state: DeviceManagementState
    actions: tuple[DeviceManagementAction, ...]
    schema: str = field(default=DEVICE_MANAGEMENT_PLAN_SCHEMA, init=False)
    provider_selected: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "member_role": self.member_role.value,
            "management_required": self.management_required,
            "managed": self.managed,
            "state": self.state.value,
            "actions": [action.to_dict() for action in self.actions],
            "provider_selected": False,
            "provider_execution_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def plan_device_management(
    snapshot: HouseholdSnapshot,
    *,
    actor_member_id: str,
    device_id: str,
) -> HouseholdDeviceManagementPlan:
    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    target_device_id = _identifier(device_id, "invalid_household_device_id")
    try:
        actor = snapshot.household.member(actor_id)
        actor_policy = effective_policy(snapshot.household, actor_id)
    except HomeServiceCatalogError as exc:
        raise HouseholdDeviceManagementError(exc.code) from exc
    if actor.role is not HouseholdRole.PARENT or not actor_policy.administration_allowed:
        raise HouseholdDeviceManagementError("household_device_management_not_authorized")

    device = next((item for item in snapshot.household.devices if item.device_id == target_device_id), None)
    if device is None:
        raise HouseholdDeviceManagementError("household_device_not_found")
    try:
        member = snapshot.household.member(device.member_id)
        policy = effective_policy(snapshot.household, member.member_id)
    except HomeServiceCatalogError as exc:
        raise HouseholdDeviceManagementError(exc.code) from exc

    required = policy.managed_device_required
    if device.managed:
        state = DeviceManagementState.SATISFIED
        actions: tuple[DeviceManagementAction, ...] = ()
    elif required:
        state = DeviceManagementState.REQUIRED
        actions = (
            DeviceManagementAction(
                action_type="household.device.management.enroll",
                device_id=device.device_id,
                member_id=member.member_id,
                provider_resolution_required=True,
                confirmation_required=True,
            ),
        )
    else:
        state = DeviceManagementState.OPTIONAL
        actions = ()

    canonical = {
        "household_id": snapshot.household_id,
        "snapshot_id": snapshot.snapshot_id,
        "resource_version": snapshot.resource_version,
        "generation": snapshot.generation,
        "actor_member_id": actor_id,
        "device_id": device.device_id,
        "member_id": member.member_id,
        "member_role": member.role.value,
        "management_required": required,
        "managed": device.managed,
        "state": state.value,
        "actions": [action.to_dict() for action in actions],
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    plan_id = "hdmplan-" + hashlib.sha256(encoded).hexdigest()[:24]
    return HouseholdDeviceManagementPlan(
        plan_id=plan_id,
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        device_id=device.device_id,
        member_id=member.member_id,
        member_role=member.role,
        management_required=required,
        managed=device.managed,
        state=state,
        actions=actions,
    )
