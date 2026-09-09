"""Household domain foundation for the Home Center Cozy interface."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping

from home_center.home_services import HomeServiceCatalogError, _identifier


HOUSEHOLD_SCHEMA = "home-center.household.v1"
EFFECTIVE_POLICY_SCHEMA = "home-center.household-effective-policy.v1"
MAX_MEMBERS = 128
MAX_DEVICES = 1024


class HouseholdRole(StrEnum):
    PARENT = "parent"
    CHILD = "child"
    GUEST = "guest"


class InternetPolicy(StrEnum):
    FULL = "full"
    FILTERED = "filtered"
    GUEST = "guest"


@dataclass(frozen=True, slots=True)
class RolePreset:
    role: HouseholdRole
    internet_policy: InternetPolicy
    vpn_allowed: bool
    managed_device_required: bool
    home_files_allowed: bool
    smart_home_control_allowed: bool
    administration_allowed: bool
    external_publication_allowed: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "role": self.role.value,
            "internet_policy": self.internet_policy.value,
            "vpn_allowed": self.vpn_allowed,
            "managed_device_required": self.managed_device_required,
            "home_files_allowed": self.home_files_allowed,
            "smart_home_control_allowed": self.smart_home_control_allowed,
            "administration_allowed": self.administration_allowed,
            "external_publication_allowed": False,
        }


ROLE_PRESETS: Mapping[HouseholdRole, RolePreset] = MappingProxyType(
    {
        HouseholdRole.PARENT: RolePreset(
            role=HouseholdRole.PARENT,
            internet_policy=InternetPolicy.FULL,
            vpn_allowed=True,
            managed_device_required=False,
            home_files_allowed=True,
            smart_home_control_allowed=True,
            administration_allowed=True,
        ),
        HouseholdRole.CHILD: RolePreset(
            role=HouseholdRole.CHILD,
            internet_policy=InternetPolicy.FILTERED,
            vpn_allowed=False,
            managed_device_required=True,
            home_files_allowed=True,
            smart_home_control_allowed=False,
            administration_allowed=False,
        ),
        HouseholdRole.GUEST: RolePreset(
            role=HouseholdRole.GUEST,
            internet_policy=InternetPolicy.GUEST,
            vpn_allowed=False,
            managed_device_required=False,
            home_files_allowed=False,
            smart_home_control_allowed=False,
            administration_allowed=False,
        ),
    }
)


@dataclass(frozen=True, slots=True)
class FamilyMember:
    member_id: str
    display_name: str
    role: HouseholdRole
    enabled: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "member_id", _identifier(self.member_id, "invalid_household_member_id"))
        name = self.display_name.strip() if isinstance(self.display_name, str) else ""
        if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
            raise HomeServiceCatalogError("invalid_household_member_name")
        object.__setattr__(self, "display_name", name)
        if not isinstance(self.role, HouseholdRole):
            raise HomeServiceCatalogError("invalid_household_role")
        if not isinstance(self.enabled, bool):
            raise HomeServiceCatalogError("invalid_household_member_enabled")

    def to_dict(self) -> dict[str, object]:
        return {
            "member_id": self.member_id,
            "display_name": self.display_name,
            "role": self.role.value,
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True)
class ManagedDevice:
    device_id: str
    member_id: str
    display_name: str
    managed: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "device_id", _identifier(self.device_id, "invalid_household_device_id"))
        object.__setattr__(self, "member_id", _identifier(self.member_id, "invalid_household_device_member_id"))
        name = self.display_name.strip() if isinstance(self.display_name, str) else ""
        if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
            raise HomeServiceCatalogError("invalid_household_device_name")
        object.__setattr__(self, "display_name", name)
        if not isinstance(self.managed, bool):
            raise HomeServiceCatalogError("invalid_household_device_managed")

    def to_dict(self) -> dict[str, object]:
        return {
            "device_id": self.device_id,
            "member_id": self.member_id,
            "display_name": self.display_name,
            "managed": self.managed,
        }


@dataclass(frozen=True, slots=True)
class Household:
    household_id: str
    members: tuple[FamilyMember, ...]
    devices: tuple[ManagedDevice, ...]
    schema: str = field(default=HOUSEHOLD_SCHEMA, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "household_id", _identifier(self.household_id, "invalid_household_id"))
        if not 1 <= len(self.members) <= MAX_MEMBERS:
            raise HomeServiceCatalogError("invalid_household_members")
        if len(self.devices) > MAX_DEVICES:
            raise HomeServiceCatalogError("invalid_household_devices")
        if any(not isinstance(member, FamilyMember) for member in self.members):
            raise HomeServiceCatalogError("invalid_household_members")
        if any(not isinstance(device, ManagedDevice) for device in self.devices):
            raise HomeServiceCatalogError("invalid_household_devices")

        members = tuple(sorted(self.members, key=lambda member: member.member_id))
        devices = tuple(sorted(self.devices, key=lambda device: device.device_id))
        member_ids = [member.member_id for member in members]
        device_ids = [device.device_id for device in devices]
        if len(member_ids) != len(set(member_ids)):
            raise HomeServiceCatalogError("duplicate_household_member")
        if len(device_ids) != len(set(device_ids)):
            raise HomeServiceCatalogError("duplicate_household_device")
        if not any(member.enabled and member.role is HouseholdRole.PARENT for member in members):
            raise HomeServiceCatalogError("household_parent_required")
        known_members = set(member_ids)
        if any(device.member_id not in known_members for device in devices):
            raise HomeServiceCatalogError("household_device_member_not_found")

        object.__setattr__(self, "members", members)
        object.__setattr__(self, "devices", devices)

    def member(self, member_id: str) -> FamilyMember:
        normalized = _identifier(member_id, "invalid_household_member_id")
        for member in self.members:
            if member.member_id == normalized:
                return member
        raise HomeServiceCatalogError("household_member_not_found")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "household_id": self.household_id,
            "members": [member.to_dict() for member in self.members],
            "devices": [device.to_dict() for device in self.devices],
        }


@dataclass(frozen=True, slots=True)
class EffectivePolicy:
    policy_id: str
    household_id: str
    member_id: str
    role: HouseholdRole
    internet_policy: InternetPolicy
    vpn_allowed: bool
    managed_device_required: bool
    home_files_allowed: bool
    smart_home_control_allowed: bool
    administration_allowed: bool
    external_publication_allowed: bool
    schema: str = field(default=EFFECTIVE_POLICY_SCHEMA, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "role": self.role.value,
            "internet_policy": self.internet_policy.value,
            "vpn_allowed": self.vpn_allowed,
            "managed_device_required": self.managed_device_required,
            "home_files_allowed": self.home_files_allowed,
            "smart_home_control_allowed": self.smart_home_control_allowed,
            "administration_allowed": self.administration_allowed,
            "external_publication_allowed": self.external_publication_allowed,
            "production_mutation_enabled": False,
        }


def effective_policy(household: Household, member_id: str) -> EffectivePolicy:
    """Resolve the fixed household role preset without mutating infrastructure."""

    if not isinstance(household, Household):
        raise TypeError("invalid_household")
    member = household.member(member_id)
    if not member.enabled:
        raise HomeServiceCatalogError("household_member_disabled")
    preset = ROLE_PRESETS[member.role]
    canonical = {
        "household_id": household.household_id,
        "member_id": member.member_id,
        "preset": preset.to_dict(),
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    policy_id = "hpol-" + hashlib.sha256(encoded).hexdigest()[:24]
    return EffectivePolicy(
        policy_id=policy_id,
        household_id=household.household_id,
        member_id=member.member_id,
        role=member.role,
        internet_policy=preset.internet_policy,
        vpn_allowed=preset.vpn_allowed,
        managed_device_required=preset.managed_device_required,
        home_files_allowed=preset.home_files_allowed,
        smart_home_control_allowed=preset.smart_home_control_allowed,
        administration_allowed=preset.administration_allowed,
        external_publication_allowed=False,
    )
