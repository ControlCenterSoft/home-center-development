"""Policy Composer v1 for Home Center 0.59.

The composer produces exact-state, confirmation-gated policy proposals. It does
not execute providers or infrastructure changes. Confirmation authorizes only a
later protected Desired State write; provider execution remains a separate gate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .home_services import _identifier
from .household import ROLE_PRESETS, HouseholdRole, InternetPolicy, effective_policy
from .household_store import HouseholdSnapshot


POLICY_BUNDLE_SCHEMA = "home-center.policy-bundle.v1"
POLICY_DESIRED_STATE_SCHEMA = "home-center.policy-desired-state.v1"
POLICY_CHANGE_PLAN_SCHEMA = "home-center.policy-change-plan.v1"
POLICY_CHANGE_CONFIRMATION_SCHEMA = "home-center.policy-change-confirmation.v1"


class PolicyComposerError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _require_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise PolicyComposerError("invalid_policy_boolean")
    return value


def _require_role(value: object) -> HouseholdRole:
    if not isinstance(value, HouseholdRole):
        raise PolicyComposerError("invalid_policy_role")
    return value


def _require_internet_policy(value: object) -> InternetPolicy:
    if not isinstance(value, InternetPolicy):
        raise PolicyComposerError("invalid_policy_internet_policy")
    return value


def _bundle_canonical(
    role: HouseholdRole,
    internet_policy: InternetPolicy,
    vpn_allowed: bool,
    managed_device_required: bool,
    home_files_allowed: bool,
    smart_home_control_allowed: bool,
    administration_allowed: bool,
) -> dict[str, object]:
    return {
        "role": role.value,
        "internet_policy": internet_policy.value,
        "vpn_allowed": vpn_allowed,
        "managed_device_required": managed_device_required,
        "home_files_allowed": home_files_allowed,
        "smart_home_control_allowed": smart_home_control_allowed,
        "administration_allowed": administration_allowed,
        "external_publication_allowed": False,
    }


def _desired_state_canonical(
    *,
    household_id: str,
    member_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    bundle_id: str,
) -> dict[str, object]:
    return {
        "household_id": household_id,
        "member_id": member_id,
        "snapshot_id": snapshot_id,
        "resource_version": resource_version,
        "generation": generation,
        "bundle_id": bundle_id,
    }


def _plan_canonical(
    *,
    household_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    actor_member_id: str,
    target_member_id: str,
    current_policy_id: str,
    current_bundle_id: str,
    desired_state_id: str,
    cozy_summary_ru: tuple[str, ...],
) -> dict[str, object]:
    return {
        "household_id": household_id,
        "snapshot_id": snapshot_id,
        "resource_version": resource_version,
        "generation": generation,
        "actor_member_id": actor_member_id,
        "target_member_id": target_member_id,
        "current_policy_id": current_policy_id,
        "current_bundle_id": current_bundle_id,
        "desired_state_id": desired_state_id,
        "cozy_summary_ru": list(cozy_summary_ru),
    }


def _confirmation_digest(
    *,
    plan_id: str,
    actor_member_id: str,
    target_member_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    desired_state_id: str,
) -> str:
    return _digest(
        {
            "plan_id": plan_id,
            "actor_member_id": actor_member_id,
            "target_member_id": target_member_id,
            "snapshot_id": snapshot_id,
            "resource_version": resource_version,
            "generation": generation,
            "desired_state_id": desired_state_id,
        }
    )


_INTERNET_PERMISSIVENESS = {
    InternetPolicy.GUEST: 0,
    InternetPolicy.FILTERED: 1,
    InternetPolicy.FULL: 2,
}


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

    def __post_init__(self) -> None:
        role = _require_role(self.role)
        internet = _require_internet_policy(self.internet_policy)
        values = (
            _require_bool(self.vpn_allowed),
            _require_bool(self.managed_device_required),
            _require_bool(self.home_files_allowed),
            _require_bool(self.smart_home_control_allowed),
            _require_bool(self.administration_allowed),
        )
        canonical = _bundle_canonical(role, internet, *values)
        if self.bundle_id != "hpb-" + _digest(canonical)[:24]:
            raise PolicyComposerError("policy_bundle_evidence_mismatch")

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
class PolicyDesiredState:
    desired_state_id: str
    household_id: str
    member_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    bundle: PolicyBundle
    schema: str = field(default=POLICY_DESIRED_STATE_SCHEMA, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 1:
            raise PolicyComposerError("invalid_policy_generation")
        desired_state_id = _identifier(self.desired_state_id, "invalid_policy_desired_state_id")
        household_id = _identifier(self.household_id, "invalid_household_id")
        member_id = _identifier(self.member_id, "invalid_household_member_id")
        snapshot_id = _identifier(self.snapshot_id, "invalid_household_snapshot_id")
        resource_version = _identifier(self.resource_version, "invalid_household_resource_version")
        if not isinstance(self.bundle, PolicyBundle):
            raise PolicyComposerError("invalid_policy_bundle")
        canonical = _desired_state_canonical(
            household_id=household_id,
            member_id=member_id,
            snapshot_id=snapshot_id,
            resource_version=resource_version,
            generation=self.generation,
            bundle_id=self.bundle.bundle_id,
        )
        if desired_state_id != "hpds-" + _digest(canonical)[:24]:
            raise PolicyComposerError("policy_desired_state_evidence_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "desired_state_id": self.desired_state_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "bundle": self.bundle.to_dict(),
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class PolicyChangePlan:
    plan_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    target_member_id: str
    current_policy_id: str
    current_bundle_id: str
    desired_state: PolicyDesiredState
    cozy_summary_ru: tuple[str, ...]
    schema: str = field(default=POLICY_CHANGE_PLAN_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    desired_state_write_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 1:
            raise PolicyComposerError("invalid_policy_generation")
        plan_id = _identifier(self.plan_id, "invalid_policy_plan_id")
        household_id = _identifier(self.household_id, "invalid_household_id")
        snapshot_id = _identifier(self.snapshot_id, "invalid_household_snapshot_id")
        resource_version = _identifier(self.resource_version, "invalid_household_resource_version")
        actor_member_id = _identifier(self.actor_member_id, "invalid_household_member_id")
        target_member_id = _identifier(self.target_member_id, "invalid_household_member_id")
        current_policy_id = _identifier(self.current_policy_id, "invalid_policy_id")
        current_bundle_id = _identifier(self.current_bundle_id, "invalid_policy_bundle_id")
        if not isinstance(self.desired_state, PolicyDesiredState):
            raise PolicyComposerError("invalid_policy_desired_state")
        if (
            self.desired_state.household_id != household_id
            or self.desired_state.member_id != target_member_id
            or self.desired_state.snapshot_id != snapshot_id
            or self.desired_state.resource_version != resource_version
            or self.desired_state.generation != self.generation
        ):
            raise PolicyComposerError("policy_desired_state_binding_mismatch")
        if not self.cozy_summary_ru or any(not isinstance(item, str) or not item.strip() for item in self.cozy_summary_ru):
            raise PolicyComposerError("invalid_policy_summary")
        canonical = _plan_canonical(
            household_id=household_id,
            snapshot_id=snapshot_id,
            resource_version=resource_version,
            generation=self.generation,
            actor_member_id=actor_member_id,
            target_member_id=target_member_id,
            current_policy_id=current_policy_id,
            current_bundle_id=current_bundle_id,
            desired_state_id=self.desired_state.desired_state_id,
            cozy_summary_ru=self.cozy_summary_ru,
        )
        if plan_id != "hpplan-" + _digest(canonical)[:24]:
            raise PolicyComposerError("policy_change_evidence_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "target_member_id": self.target_member_id,
            "current_policy_id": self.current_policy_id,
            "current_bundle_id": self.current_bundle_id,
            "desired_state": self.desired_state.to_dict(),
            "cozy_summary_ru": list(self.cozy_summary_ru),
            "recovery_bundle_id": self.current_bundle_id,
            "confirmation_required": True,
            "desired_state_write_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class PolicyChangeConfirmation:
    confirmation_id: str
    plan_id: str
    actor_member_id: str
    target_member_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    desired_state_id: str
    audit_event_id: str
    schema: str = field(default=POLICY_CHANGE_CONFIRMATION_SCHEMA, init=False)
    desired_state_write_authorized: bool = field(default=True, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)
    automatic_recovery_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 1:
            raise PolicyComposerError("invalid_policy_generation")
        confirmation_id = _identifier(self.confirmation_id, "invalid_policy_confirmation_id")
        plan_id = _identifier(self.plan_id, "invalid_policy_plan_id")
        actor_member_id = _identifier(self.actor_member_id, "invalid_household_member_id")
        target_member_id = _identifier(self.target_member_id, "invalid_household_member_id")
        snapshot_id = _identifier(self.snapshot_id, "invalid_household_snapshot_id")
        resource_version = _identifier(self.resource_version, "invalid_household_resource_version")
        desired_state_id = _identifier(self.desired_state_id, "invalid_policy_desired_state_id")
        audit_event_id = _identifier(self.audit_event_id, "invalid_audit_event_id")
        digest = _confirmation_digest(
            plan_id=plan_id,
            actor_member_id=actor_member_id,
            target_member_id=target_member_id,
            snapshot_id=snapshot_id,
            resource_version=resource_version,
            generation=self.generation,
            desired_state_id=desired_state_id,
        )
        if confirmation_id != "hpconfirm-" + digest[:24] or audit_event_id != "audit-hp-" + digest[24:48]:
            raise PolicyComposerError("policy_confirmation_evidence_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "confirmation_id": self.confirmation_id,
            "plan_id": self.plan_id,
            "actor_member_id": self.actor_member_id,
            "target_member_id": self.target_member_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "desired_state_id": self.desired_state_id,
            "audit_event_id": self.audit_event_id,
            "desired_state_write_authorized": True,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
            "automatic_recovery_authorized": False,
        }


def build_policy_bundle(
    role: HouseholdRole,
    *,
    internet_policy: InternetPolicy | None = None,
    vpn_allowed: bool | None = None,
    managed_device_required: bool | None = None,
    home_files_allowed: bool | None = None,
    smart_home_control_allowed: bool | None = None,
    administration_allowed: bool | None = None,
) -> PolicyBundle:
    role = _require_role(role)
    preset = ROLE_PRESETS[role]
    internet = preset.internet_policy if internet_policy is None else _require_internet_policy(internet_policy)
    vpn = preset.vpn_allowed if vpn_allowed is None else _require_bool(vpn_allowed)
    managed = preset.managed_device_required if managed_device_required is None else _require_bool(managed_device_required)
    files = preset.home_files_allowed if home_files_allowed is None else _require_bool(home_files_allowed)
    smart = preset.smart_home_control_allowed if smart_home_control_allowed is None else _require_bool(smart_home_control_allowed)
    admin = preset.administration_allowed if administration_allowed is None else _require_bool(administration_allowed)
    if _INTERNET_PERMISSIVENESS[internet] > _INTERNET_PERMISSIVENESS[preset.internet_policy]:
        raise PolicyComposerError("policy_role_ceiling_exceeded")
    if (vpn and not preset.vpn_allowed) or (files and not preset.home_files_allowed):
        raise PolicyComposerError("policy_role_ceiling_exceeded")
    if (smart and not preset.smart_home_control_allowed) or (admin and not preset.administration_allowed):
        raise PolicyComposerError("policy_role_ceiling_exceeded")
    if preset.managed_device_required and not managed:
        raise PolicyComposerError("policy_role_ceiling_exceeded")
    canonical = _bundle_canonical(role, internet, vpn, managed, files, smart, admin)
    return PolicyBundle("hpb-" + _digest(canonical)[:24], role, internet, vpn, managed, files, smart, admin)


def _summary(bundle: PolicyBundle) -> tuple[str, ...]:
    internet = {
        InternetPolicy.FULL: "Интернет: полный доступ.",
        InternetPolicy.FILTERED: "Интернет: фильтрованный доступ.",
        InternetPolicy.GUEST: "Интернет: гостевой ограниченный доступ.",
    }[bundle.internet_policy]
    return (
        internet,
        "VPN: разрешён." if bundle.vpn_allowed else "VPN: запрещён.",
        "Управляемое устройство: обязательно." if bundle.managed_device_required else "Управляемое устройство: не обязательно.",
        "Домашние файлы: доступны." if bundle.home_files_allowed else "Домашние файлы: недоступны.",
        "Умный дом: управление разрешено." if bundle.smart_home_control_allowed else "Умный дом: управление запрещено.",
        "Администрирование: разрешено." if bundle.administration_allowed else "Администрирование: запрещено.",
        "Внешняя публикация: запрещена.",
    )


def compose_policy_change_plan(
    snapshot: HouseholdSnapshot,
    *,
    actor_member_id: str,
    target_member_id: str,
    target_bundle: PolicyBundle,
) -> PolicyChangePlan:
    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(target_bundle, PolicyBundle):
        raise TypeError("invalid_policy_bundle")
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    target_id = _identifier(target_member_id, "invalid_household_member_id")
    actor = snapshot.household.member(actor_id)
    target = snapshot.household.member(target_id)
    if not actor.enabled or actor.role is not HouseholdRole.PARENT:
        raise PolicyComposerError("policy_actor_not_authorized")
    if not target.enabled:
        raise PolicyComposerError("policy_target_disabled")
    if target.role is not target_bundle.role:
        raise PolicyComposerError("policy_target_role_mismatch")
    guarded = build_policy_bundle(
        target.role,
        internet_policy=target_bundle.internet_policy,
        vpn_allowed=target_bundle.vpn_allowed,
        managed_device_required=target_bundle.managed_device_required,
        home_files_allowed=target_bundle.home_files_allowed,
        smart_home_control_allowed=target_bundle.smart_home_control_allowed,
        administration_allowed=target_bundle.administration_allowed,
    )
    if guarded != target_bundle:
        raise PolicyComposerError("policy_bundle_evidence_mismatch")
    current = effective_policy(snapshot.household, target_id)
    current_bundle = build_policy_bundle(current.role)
    if current_bundle == target_bundle:
        raise PolicyComposerError("policy_change_noop")

    desired_canonical = _desired_state_canonical(
        household_id=snapshot.household_id,
        member_id=target_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        bundle_id=target_bundle.bundle_id,
    )
    desired_state = PolicyDesiredState(
        desired_state_id="hpds-" + _digest(desired_canonical)[:24],
        household_id=snapshot.household_id,
        member_id=target_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        bundle=target_bundle,
    )
    summary = _summary(target_bundle)
    plan_canonical = _plan_canonical(
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        target_member_id=target_id,
        current_policy_id=current.policy_id,
        current_bundle_id=current_bundle.bundle_id,
        desired_state_id=desired_state.desired_state_id,
        cozy_summary_ru=summary,
    )
    return PolicyChangePlan(
        plan_id="hpplan-" + _digest(plan_canonical)[:24],
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        target_member_id=target_id,
        current_policy_id=current.policy_id,
        current_bundle_id=current_bundle.bundle_id,
        desired_state=desired_state,
        cozy_summary_ru=summary,
    )


def revalidate_policy_change_plan(current: HouseholdSnapshot, plan: PolicyChangePlan, *, actor_member_id: str) -> None:
    if not isinstance(current, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(plan, PolicyChangePlan):
        raise TypeError("invalid_policy_change_plan")
    if current.household_id != plan.household_id:
        raise PolicyComposerError("policy_change_stale")
    if current.snapshot_id != plan.snapshot_id or current.resource_version != plan.resource_version or current.generation != plan.generation:
        raise PolicyComposerError("policy_change_stale")
    rebuilt = compose_policy_change_plan(
        current,
        actor_member_id=actor_member_id,
        target_member_id=plan.target_member_id,
        target_bundle=plan.desired_state.bundle,
    )
    if rebuilt != plan:
        raise PolicyComposerError("policy_change_evidence_mismatch")


def confirm_policy_change_plan(current: HouseholdSnapshot, plan: PolicyChangePlan, *, actor_member_id: str) -> PolicyChangeConfirmation:
    revalidate_policy_change_plan(current, plan, actor_member_id=actor_member_id)
    digest = _confirmation_digest(
        plan_id=plan.plan_id,
        actor_member_id=plan.actor_member_id,
        target_member_id=plan.target_member_id,
        snapshot_id=plan.snapshot_id,
        resource_version=plan.resource_version,
        generation=plan.generation,
        desired_state_id=plan.desired_state.desired_state_id,
    )
    return PolicyChangeConfirmation(
        confirmation_id="hpconfirm-" + digest[:24],
        plan_id=plan.plan_id,
        actor_member_id=plan.actor_member_id,
        target_member_id=plan.target_member_id,
        snapshot_id=plan.snapshot_id,
        resource_version=plan.resource_version,
        generation=plan.generation,
        desired_state_id=plan.desired_state.desired_state_id,
        audit_event_id="audit-hp-" + digest[24:48],
    )
