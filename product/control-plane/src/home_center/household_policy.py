"""Explicit household PolicyBundle composition for role-driven Home Center policy."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from home_center.home_services import HomeServiceCatalogError
from home_center.household import HouseholdRole, InternetPolicy, ROLE_PRESETS


POLICY_BUNDLE_SCHEMA = "home-center.household-policy-bundle.v1"


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    bundle_id: str
    role: HouseholdRole
    internet_policy: InternetPolicy
    vpn_allowed: bool
    managed_device_required: bool
    home_files_allowed: bool
    smart_home_control_allowed: bool
    administration_allowed: bool
    external_publication_allowed: bool
    schema: str = field(default=POLICY_BUNDLE_SCHEMA, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "bundle_id": self.bundle_id,
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


def policy_bundle_for_role(role: HouseholdRole) -> PolicyBundle:
    """Resolve the immutable household bundle for a fixed domestic role."""

    if not isinstance(role, HouseholdRole):
        raise HomeServiceCatalogError("invalid_household_role")
    preset = ROLE_PRESETS[role]
    payload = preset.to_dict()
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    bundle_id = "hpb-" + hashlib.sha256(encoded).hexdigest()[:24]
    return PolicyBundle(
        bundle_id=bundle_id,
        role=role,
        internet_policy=preset.internet_policy,
        vpn_allowed=preset.vpn_allowed,
        managed_device_required=preset.managed_device_required,
        home_files_allowed=preset.home_files_allowed,
        smart_home_control_allowed=preset.smart_home_control_allowed,
        administration_allowed=preset.administration_allowed,
        external_publication_allowed=False,
    )
