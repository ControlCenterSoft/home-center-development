"""Home Center 0.59 Policy Composer domain foundation.

Policy Composer may only tighten the fixed Household role preset.  It creates a
technical policy and a user-facing explanation, but never claims that any backend
has enforced the policy.  External publication is always closed in this version.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .home_services import HomeServiceCatalogError, _identifier
from .household import EffectivePolicy, HouseholdRole, InternetPolicy, ROLE_PRESETS
from .util import canonical_json

POLICY_BUNDLE_SCHEMA = "home-center.household-policy-bundle.v1"
COMPOSED_POLICY_SCHEMA = "home-center.household-composed-policy.v1"
INTERNET_STRICTNESS = {
    InternetPolicy.FULL: 0,
    InternetPolicy.FILTERED: 1,
    InternetPolicy.GUEST: 2,
}


class HouseholdPolicyComposerError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _bool(value: object, code: str) -> bool:
    if type(value) is not bool:
        raise HouseholdPolicyComposerError(code)
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


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
    schema: str = field(default=POLICY_BUNDLE_SCHEMA, init=False)
    external_publication_allowed: bool = field(default=False, init=False)

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
            "external_publication_allowed": False,
        }


@dataclass(frozen=True, slots=True)
class ComposedPolicy:
    policy_id: str
    household_id: str
    member_id: str
    role: HouseholdRole
    base_policy_id: str
    bundle_id: str
    internet_policy: InternetPolicy
    vpn_allowed: bool
    managed_device_required: bool
    home_files_allowed: bool
    smart_home_control_allowed: bool
    administration_allowed: bool
    explanation_ru: str
    schema: str = field(default=COMPOSED_POLICY_SCHEMA, init=False)
    external_publication_allowed: bool = field(default=False, init=False)
    enforcement_verified: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "policy_id": self.policy_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "role": self.role.value,
            "base_policy_id": self.base_policy_id,
            "bundle_id": self.bundle_id,
            "internet_policy": self.internet_policy.value,
            "vpn_allowed": self.vpn_allowed,
            "managed_device_required": self.managed_device_required,
            "home_files_allowed": self.home_files_allowed,
            "smart_home_control_allowed": self.smart_home_control_allowed,
            "administration_allowed": self.administration_allowed,
            "external_publication_allowed": False,
            "enforcement_verified": False,
            "production_mutation_enabled": False,
            "explanation_ru": self.explanation_ru,
        }


def _reject_escalation(*, role: HouseholdRole, bundle: dict[str, object]) -> None:
    preset = ROLE_PRESETS[role]
    internet = InternetPolicy(str(bundle["internet_policy"]))
    if INTERNET_STRICTNESS[internet] < INTERNET_STRICTNESS[preset.internet_policy]:
        raise HouseholdPolicyComposerError("policy_bundle_internet_escalation_rejected")

    for field_name in (
        "vpn_allowed",
        "home_files_allowed",
        "smart_home_control_allowed",
        "administration_allowed",
    ):
        requested = _bool(bundle[field_name], "policy_bundle_boolean_rejected")
        if requested and not getattr(preset, field_name):
            raise HouseholdPolicyComposerError("policy_bundle_capability_escalation_rejected")

    managed_required = _bool(bundle["managed_device_required"], "policy_bundle_boolean_rejected")
    if preset.managed_device_required and not managed_required:
        raise HouseholdPolicyComposerError("policy_bundle_managed_device_relaxation_rejected")

    if bundle.get("external_publication_allowed") is not False:
        raise HouseholdPolicyComposerError("policy_bundle_external_publication_rejected")


def build_policy_bundle(*, role: HouseholdRole, value: dict[str, object]) -> PolicyBundle:
    expected = {
        "internet_policy",
        "vpn_allowed",
        "managed_device_required",
        "home_files_allowed",
        "smart_home_control_allowed",
        "administration_allowed",
        "external_publication_allowed",
    }
    if not isinstance(role, HouseholdRole) or not isinstance(value, dict) or set(value) != expected:
        raise HouseholdPolicyComposerError("policy_bundle_rejected")
    try:
        _reject_escalation(role=role, bundle=value)
        internet = InternetPolicy(str(value["internet_policy"]))
    except HouseholdPolicyComposerError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise HouseholdPolicyComposerError("policy_bundle_rejected") from exc

    canonical = {
        "schema": POLICY_BUNDLE_SCHEMA,
        "role": role.value,
        **value,
    }
    bundle_id = "hpb-" + _digest(canonical)[:24]
    return PolicyBundle(
        bundle_id=bundle_id,
        role=role,
        internet_policy=internet,
        vpn_allowed=_bool(value["vpn_allowed"], "policy_bundle_boolean_rejected"),
        managed_device_required=_bool(
            value["managed_device_required"], "policy_bundle_boolean_rejected"
        ),
        home_files_allowed=_bool(
            value["home_files_allowed"], "policy_bundle_boolean_rejected"
        ),
        smart_home_control_allowed=_bool(
            value["smart_home_control_allowed"], "policy_bundle_boolean_rejected"
        ),
        administration_allowed=_bool(
            value["administration_allowed"], "policy_bundle_boolean_rejected"
        ),
    )


def policy_bundle_from_dict(value: object) -> PolicyBundle:
    if not isinstance(value, dict):
        raise HouseholdPolicyComposerError("policy_bundle_rejected")
    expected = {
        "schema",
        "bundle_id",
        "role",
        "internet_policy",
        "vpn_allowed",
        "managed_device_required",
        "home_files_allowed",
        "smart_home_control_allowed",
        "administration_allowed",
        "external_publication_allowed",
    }
    if set(value) != expected or value.get("schema") != POLICY_BUNDLE_SCHEMA:
        raise HouseholdPolicyComposerError("policy_bundle_rejected")
    try:
        role = HouseholdRole(value["role"])
    except (TypeError, ValueError) as exc:
        raise HouseholdPolicyComposerError("policy_bundle_rejected") from exc
    built = build_policy_bundle(
        role=role,
        value={key: value[key] for key in expected if key not in {"schema", "bundle_id", "role"}},
    )
    if built.bundle_id != value.get("bundle_id") or built.to_dict() != value:
        raise HouseholdPolicyComposerError("policy_bundle_rejected")
    return built


def _explanation(policy: dict[str, object]) -> str:
    internet = {
        InternetPolicy.FULL.value: "интернет без дополнительного семейного фильтра",
        InternetPolicy.FILTERED.value: "интернет с семейной фильтрацией",
        InternetPolicy.GUEST.value: "гостевой режим интернета",
    }[str(policy["internet_policy"])]
    parts = [internet]
    parts.append("VPN разрешён" if policy["vpn_allowed"] else "VPN запрещён")
    if policy["managed_device_required"]:
        parts.append("нужно управляемое устройство")
    if policy["home_files_allowed"]:
        parts.append("домашние файлы доступны")
    if policy["smart_home_control_allowed"]:
        parts.append("управление умным домом разрешено")
    if policy["administration_allowed"]:
        parts.append("администрирование разрешено")
    parts.append("внешняя публикация запрещена")
    return "; ".join(parts) + "."


def compose_policy(*, base: EffectivePolicy, bundle: PolicyBundle) -> ComposedPolicy:
    if not isinstance(base, EffectivePolicy) or not isinstance(bundle, PolicyBundle):
        raise TypeError("invalid_household_policy_composition")
    if base.role is not bundle.role:
        raise HouseholdPolicyComposerError("policy_bundle_role_mismatch")
    canonical = {
        "household_id": base.household_id,
        "member_id": base.member_id,
        "role": base.role.value,
        "base_policy_id": base.policy_id,
        "bundle_id": bundle.bundle_id,
        "internet_policy": bundle.internet_policy.value,
        "vpn_allowed": bundle.vpn_allowed,
        "managed_device_required": bundle.managed_device_required,
        "home_files_allowed": bundle.home_files_allowed,
        "smart_home_control_allowed": bundle.smart_home_control_allowed,
        "administration_allowed": bundle.administration_allowed,
        "external_publication_allowed": False,
    }
    policy_id = "hcpol-" + _digest(canonical)[:24]
    return ComposedPolicy(
        policy_id=policy_id,
        household_id=base.household_id,
        member_id=base.member_id,
        role=base.role,
        base_policy_id=base.policy_id,
        bundle_id=bundle.bundle_id,
        internet_policy=bundle.internet_policy,
        vpn_allowed=bundle.vpn_allowed,
        managed_device_required=bundle.managed_device_required,
        home_files_allowed=bundle.home_files_allowed,
        smart_home_control_allowed=bundle.smart_home_control_allowed,
        administration_allowed=bundle.administration_allowed,
        explanation_ru=_explanation(canonical),
    )


def technical_policy_projection(policy: ComposedPolicy) -> dict[str, Any]:
    if not isinstance(policy, ComposedPolicy):
        raise TypeError("invalid_composed_policy")
    return {
        "policy_id": policy.policy_id,
        "internet_policy": policy.internet_policy.value,
        "vpn_allowed": policy.vpn_allowed,
        "managed_device_required": policy.managed_device_required,
        "home_files_allowed": policy.home_files_allowed,
        "smart_home_control_allowed": policy.smart_home_control_allowed,
        "administration_allowed": policy.administration_allowed,
        "external_publication_allowed": False,
        "enforcement_verified": False,
    }
