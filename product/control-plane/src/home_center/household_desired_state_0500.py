"""Безопасная проекция Household EffectivePolicy в защищённое Desired State для HC 0.50."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.household import EffectivePolicy, HouseholdRole, InternetPolicy


DESIRED_STATE_PLAN_SCHEMA = "home-center.household-desired-state-plan.v1"
MAX_GENERATION = 2_147_483_647


@dataclass(frozen=True, slots=True)
class HouseholdDesiredStatePlan:
    """Детерминированная non-authorizing проекция policy в следующий Desired State."""

    plan_id: str
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
    expected_generation: int
    next_generation: int
    schema: str = field(default=DESIRED_STATE_PLAN_SCHEMA, init=False)
    approval_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    provider_execution_enabled: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "invalid_household_desired_state_plan_id"))
        object.__setattr__(self, "policy_id", _identifier(self.policy_id, "invalid_household_policy_id"))
        object.__setattr__(self, "household_id", _identifier(self.household_id, "invalid_household_id"))
        object.__setattr__(self, "member_id", _identifier(self.member_id, "invalid_household_member_id"))
        if not isinstance(self.role, HouseholdRole):
            raise HomeServiceCatalogError("invalid_household_role")
        if not isinstance(self.internet_policy, InternetPolicy):
            raise HomeServiceCatalogError("invalid_household_internet_policy")
        for field_name in (
            "vpn_allowed",
            "managed_device_required",
            "home_files_allowed",
            "smart_home_control_allowed",
            "administration_allowed",
            "external_publication_allowed",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise HomeServiceCatalogError("invalid_household_desired_state_boolean")
        if self.external_publication_allowed:
            raise HomeServiceCatalogError("household_external_publication_forbidden")
        _generation(self.expected_generation, "invalid_household_desired_state_generation")
        _generation(self.next_generation, "invalid_household_desired_state_generation")
        if self.expected_generation >= MAX_GENERATION:
            raise HomeServiceCatalogError("household_desired_state_generation_exhausted")
        if self.next_generation != self.expected_generation + 1:
            raise HomeServiceCatalogError("household_desired_state_generation_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
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
            "external_publication_allowed": False,
            "expected_generation": self.expected_generation,
            "next_generation": self.next_generation,
            "approval_required": True,
            "mutation_authorized": False,
            "provider_execution_enabled": False,
            "production_mutation_enabled": False,
        }


def _generation(value: object, error: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_GENERATION:
        raise HomeServiceCatalogError(error)
    return value


def _canonical_policy(policy: EffectivePolicy) -> dict[str, object]:
    if not isinstance(policy, EffectivePolicy):
        raise TypeError("invalid_effective_policy")
    if policy.production_mutation_enabled:
        raise HomeServiceCatalogError("household_policy_mutation_authority_forbidden")
    if policy.external_publication_allowed:
        raise HomeServiceCatalogError("household_external_publication_forbidden")
    return {
        "policy_id": _identifier(policy.policy_id, "invalid_household_policy_id"),
        "household_id": _identifier(policy.household_id, "invalid_household_id"),
        "member_id": _identifier(policy.member_id, "invalid_household_member_id"),
        "role": policy.role.value,
        "internet_policy": policy.internet_policy.value,
        "vpn_allowed": policy.vpn_allowed,
        "managed_device_required": policy.managed_device_required,
        "home_files_allowed": policy.home_files_allowed,
        "smart_home_control_allowed": policy.smart_home_control_allowed,
        "administration_allowed": policy.administration_allowed,
        "external_publication_allowed": False,
    }


def plan_household_desired_state(
    policy: EffectivePolicy,
    *,
    current_generation: int,
) -> HouseholdDesiredStatePlan:
    """Собрать следующий Desired State без выдачи полномочий на его применение."""

    generation = _generation(current_generation, "invalid_household_desired_state_generation")
    if generation >= MAX_GENERATION:
        raise HomeServiceCatalogError("household_desired_state_generation_exhausted")
    canonical = _canonical_policy(policy)
    identity = {
        "schema": DESIRED_STATE_PLAN_SCHEMA,
        "policy": canonical,
        "expected_generation": generation,
        "next_generation": generation + 1,
    }
    encoded = json.dumps(identity, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    plan_id = "hdsp-" + hashlib.sha256(encoded).hexdigest()[:24]
    return HouseholdDesiredStatePlan(
        plan_id=plan_id,
        policy_id=canonical["policy_id"],
        household_id=canonical["household_id"],
        member_id=canonical["member_id"],
        role=policy.role,
        internet_policy=policy.internet_policy,
        vpn_allowed=policy.vpn_allowed,
        managed_device_required=policy.managed_device_required,
        home_files_allowed=policy.home_files_allowed,
        smart_home_control_allowed=policy.smart_home_control_allowed,
        administration_allowed=policy.administration_allowed,
        external_publication_allowed=False,
        expected_generation=generation,
        next_generation=generation + 1,
    )


def validate_household_desired_state_plan(
    plan: HouseholdDesiredStatePlan,
    policy: EffectivePolicy,
    *,
    current_generation: int,
) -> None:
    """Fail closed при stale generation, подмене policy или изменённом плане."""

    if not isinstance(plan, HouseholdDesiredStatePlan):
        raise TypeError("invalid_household_desired_state_plan")
    expected = plan_household_desired_state(policy, current_generation=current_generation)
    if plan.to_dict() != expected.to_dict():
        raise HomeServiceCatalogError("household_desired_state_plan_mismatch")
