"""Semantic integrity checks for persisted Home Center 0.59 policy bundles.

History hashes and Audit evidence prove that bytes did not change after archival.
This module additionally proves that those bytes still describe the deterministic
RolePreset-derived policy they claim to represent. It deliberately grants no
write, provider, infrastructure or publication authority.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .home_services import HomeServiceCatalogError, _identifier
from .household import EFFECTIVE_POLICY_SCHEMA, ROLE_PRESETS, HouseholdRole
from .household_policy_composer import POLICY_BUNDLE_SCHEMA


BUNDLE_KEYS = {
    "schema",
    "bundle_id",
    "policy_id",
    "household_id",
    "member_id",
    "role",
    "source",
    "technical_policy",
    "explanation",
    "desired_state_resource_key",
    "desired_state_write_authorized",
    "infrastructure_mutation_authorized",
    "external_publication_authorized",
}
TECHNICAL_POLICY_KEYS = {
    "schema",
    "policy_id",
    "household_id",
    "member_id",
    "role",
    "internet_policy",
    "vpn_allowed",
    "managed_device_required",
    "home_files_allowed",
    "smart_home_control_allowed",
    "administration_allowed",
    "external_publication_allowed",
    "production_mutation_enabled",
}


class HouseholdPolicyEvidenceError(ValueError):
    def __init__(self, code: str = "household_policy_history_evidence_mismatch") -> None:
        super().__init__(code)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _expected_explanation(*, internet_policy: str, vpn_allowed: bool, managed_device_required: bool, home_files_allowed: bool, smart_home_control_allowed: bool, administration_allowed: bool) -> list[str]:
    internet = {
        "full": "Интернет: полный доступ согласно роли.",
        "filtered": "Интернет: фильтруемый доступ согласно роли.",
        "guest": "Интернет: гостевой профиль согласно роли.",
    }.get(internet_policy)
    if internet is None:
        raise HouseholdPolicyEvidenceError()
    return [
        internet,
        "VPN: разрешён." if vpn_allowed else "VPN: не разрешён.",
        "Управляемое устройство: обязательно." if managed_device_required else "Управляемое устройство: не обязательно.",
        "Домашние файлы: доступны." if home_files_allowed else "Домашние файлы: недоступны.",
        "Умный дом: управление разрешено." if smart_home_control_allowed else "Умный дом: управление не разрешено.",
        "Администрирование Home Center: разрешено." if administration_allowed else "Администрирование Home Center: не разрешено.",
        "Внешняя публикация: выключена.",
    ]


def validate_policy_bundle_evidence(value: object, *, expected_resource_key: str | None = None) -> dict[str, Any]:
    """Return a closed, semantically verified policy bundle or fail closed."""

    if not isinstance(value, dict) or set(value) != BUNDLE_KEYS:
        raise HouseholdPolicyEvidenceError()
    if value.get("schema") != POLICY_BUNDLE_SCHEMA or value.get("source") != "role-preset":
        raise HouseholdPolicyEvidenceError()
    if (
        value.get("desired_state_write_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyEvidenceError()

    try:
        household_id = _identifier(value.get("household_id"), "invalid_household_id")
        member_id = _identifier(value.get("member_id"), "invalid_household_member_id")
        role = HouseholdRole(value.get("role"))
    except (HomeServiceCatalogError, TypeError, ValueError) as exc:
        raise HouseholdPolicyEvidenceError() from exc

    resource_key = f"household-policy:{household_id}:{member_id}"
    if value.get("desired_state_resource_key") != resource_key:
        raise HouseholdPolicyEvidenceError()
    if expected_resource_key is not None and resource_key != expected_resource_key:
        raise HouseholdPolicyEvidenceError()

    technical = value.get("technical_policy")
    if not isinstance(technical, dict) or set(technical) != TECHNICAL_POLICY_KEYS:
        raise HouseholdPolicyEvidenceError()
    preset = ROLE_PRESETS[role]
    policy_material = {
        "household_id": household_id,
        "member_id": member_id,
        "preset": preset.to_dict(),
    }
    policy_id = "hpol-" + hashlib.sha256(_canonical(policy_material)).hexdigest()[:24]
    expected_technical = {
        "schema": EFFECTIVE_POLICY_SCHEMA,
        "policy_id": policy_id,
        "household_id": household_id,
        "member_id": member_id,
        "role": role.value,
        "internet_policy": preset.internet_policy.value,
        "vpn_allowed": preset.vpn_allowed,
        "managed_device_required": preset.managed_device_required,
        "home_files_allowed": preset.home_files_allowed,
        "smart_home_control_allowed": preset.smart_home_control_allowed,
        "administration_allowed": preset.administration_allowed,
        "external_publication_allowed": False,
        "production_mutation_enabled": False,
    }
    if technical != expected_technical:
        raise HouseholdPolicyEvidenceError()
    if (
        value.get("policy_id") != policy_id
        or value.get("household_id") != household_id
        or value.get("member_id") != member_id
        or value.get("role") != role.value
    ):
        raise HouseholdPolicyEvidenceError()

    expected_bundle_id = "hpb-" + hashlib.sha256(
        _canonical(
            {
                "policy": expected_technical,
                "desired_state_resource_key": resource_key,
                "source": "role-preset",
            }
        )
    ).hexdigest()[:24]
    if value.get("bundle_id") != expected_bundle_id:
        raise HouseholdPolicyEvidenceError()

    explanation = _expected_explanation(
        internet_policy=preset.internet_policy.value,
        vpn_allowed=preset.vpn_allowed,
        managed_device_required=preset.managed_device_required,
        home_files_allowed=preset.home_files_allowed,
        smart_home_control_allowed=preset.smart_home_control_allowed,
        administration_allowed=preset.administration_allowed,
    )
    if value.get("explanation") != explanation:
        raise HouseholdPolicyEvidenceError()

    return value
