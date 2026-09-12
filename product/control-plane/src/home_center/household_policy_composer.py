"""Home Center 0.59 Household Policy Composer domain foundation.

The composer materializes the current RolePreset/EffectivePolicy as a deterministic
PolicyBundle and binds a proposed Desired State write to an exact Household
snapshot.  This module is intentionally pure: it never writes Desired State,
starts Jobs, calls providers or changes infrastructure.  Runtime plan/confirm,
Audit and recovery are separate boundaries and must revalidate this proposal
before a protected Desired State write can be authorized.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .home_services import HomeServiceCatalogError, _identifier
from .household import EffectivePolicy, HouseholdRole, effective_policy
from .household_store import HouseholdSnapshot


POLICY_BUNDLE_SCHEMA = "home-center.household-policy-bundle.v1"
POLICY_COMPOSITION_PROPOSAL_SCHEMA = "home-center.household-policy-composition-proposal.v1"


class HouseholdPolicyComposerError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def _resource_key(household_id: str, member_id: str) -> str:
    return f"household-policy:{household_id}:{member_id}"


def _policy_explanation(policy: EffectivePolicy) -> tuple[str, ...]:
    internet = {
        "full": "Интернет: полный доступ согласно роли.",
        "filtered": "Интернет: фильтруемый доступ согласно роли.",
        "guest": "Интернет: гостевой профиль согласно роли.",
    }[policy.internet_policy.value]
    return (
        internet,
        "VPN: разрешён." if policy.vpn_allowed else "VPN: не разрешён.",
        (
            "Управляемое устройство: обязательно."
            if policy.managed_device_required
            else "Управляемое устройство: не обязательно."
        ),
        "Домашние файлы: доступны." if policy.home_files_allowed else "Домашние файлы: недоступны.",
        (
            "Умный дом: управление разрешено."
            if policy.smart_home_control_allowed
            else "Умный дом: управление не разрешено."
        ),
        (
            "Администрирование Home Center: разрешено."
            if policy.administration_allowed
            else "Администрирование Home Center: не разрешено."
        ),
        "Внешняя публикация: выключена.",
    )


@dataclass(frozen=True, slots=True)
class PolicyBundle:
    bundle_id: str
    policy: EffectivePolicy
    explanation: tuple[str, ...]
    desired_state_resource_key: str
    schema: str = field(default=POLICY_BUNDLE_SCHEMA, init=False)
    source: str = field(default="role-preset", init=False)
    desired_state_write_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    @property
    def household_id(self) -> str:
        return self.policy.household_id

    @property
    def member_id(self) -> str:
        return self.policy.member_id

    @property
    def role(self) -> HouseholdRole:
        return self.policy.role

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "bundle_id": self.bundle_id,
            "policy_id": self.policy.policy_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "role": self.role.value,
            "source": "role-preset",
            "technical_policy": self.policy.to_dict(),
            "explanation": list(self.explanation),
            "desired_state_resource_key": self.desired_state_resource_key,
            "desired_state_write_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class PolicyCompositionProposal:
    proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    member_id: str
    bundle: PolicyBundle
    schema: str = field(default=POLICY_COMPOSITION_PROPOSAL_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    desired_state_write_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "member_id": self.member_id,
            "bundle": self.bundle.to_dict(),
            "confirmation_required": True,
            "desired_state_write_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def compose_policy_bundle(snapshot: HouseholdSnapshot, *, member_id: str) -> PolicyBundle:
    """Materialize the role-derived EffectivePolicy without authorizing a write."""

    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    try:
        member = _identifier(member_id, "invalid_household_member_id")
        policy = effective_policy(snapshot.household, member)
    except HomeServiceCatalogError as exc:
        raise HouseholdPolicyComposerError(exc.code) from exc

    resource_key = _resource_key(snapshot.household_id, member)
    canonical = {
        "policy": policy.to_dict(),
        "desired_state_resource_key": resource_key,
        "source": "role-preset",
    }
    bundle_id = "hpb-" + hashlib.sha256(_canonical(canonical)).hexdigest()[:24]
    return PolicyBundle(
        bundle_id=bundle_id,
        policy=policy,
        explanation=_policy_explanation(policy),
        desired_state_resource_key=resource_key,
    )


def build_policy_composition_proposal(
    snapshot: HouseholdSnapshot,
    *,
    actor_member_id: str,
    member_id: str,
) -> PolicyCompositionProposal:
    """Build an exact-state, confirmation-gated policy materialization proposal."""

    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    try:
        actor = _identifier(actor_member_id, "invalid_household_member_id")
        target = _identifier(member_id, "invalid_household_member_id")
        actor_policy = effective_policy(snapshot.household, actor)
    except HomeServiceCatalogError as exc:
        raise HouseholdPolicyComposerError(exc.code) from exc
    if not actor_policy.administration_allowed:
        raise HouseholdPolicyComposerError("household_policy_composition_not_authorized")

    bundle = compose_policy_bundle(snapshot, member_id=target)
    canonical = {
        "household_id": snapshot.household_id,
        "snapshot_id": snapshot.snapshot_id,
        "resource_version": snapshot.resource_version,
        "generation": snapshot.generation,
        "actor_member_id": actor,
        "member_id": target,
        "bundle": bundle.to_dict(),
    }
    proposal_id = "hpc-" + hashlib.sha256(_canonical(canonical)).hexdigest()[:24]
    return PolicyCompositionProposal(
        proposal_id=proposal_id,
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor,
        member_id=target,
        bundle=bundle,
    )


def revalidate_policy_composition_proposal(
    current: HouseholdSnapshot,
    proposal: PolicyCompositionProposal,
    *,
    actor_member_id: str,
) -> PolicyBundle:
    """Fail closed if Household or actor state changed after the proposal was shown."""

    if not isinstance(current, HouseholdSnapshot) or not isinstance(proposal, PolicyCompositionProposal):
        raise TypeError("invalid_household_policy_composition")
    try:
        actor = _identifier(actor_member_id, "invalid_household_member_id")
    except HomeServiceCatalogError as exc:
        raise HouseholdPolicyComposerError(exc.code) from exc
    if actor != proposal.actor_member_id:
        raise HouseholdPolicyComposerError("household_policy_composition_actor_mismatch")
    if (
        current.household_id != proposal.household_id
        or current.snapshot_id != proposal.snapshot_id
        or current.resource_version != proposal.resource_version
        or current.generation != proposal.generation
    ):
        raise HouseholdPolicyComposerError("household_policy_composition_stale")

    rebuilt = build_policy_composition_proposal(
        current,
        actor_member_id=actor,
        member_id=proposal.member_id,
    )
    if rebuilt != proposal:
        raise HouseholdPolicyComposerError("household_policy_composition_evidence_mismatch")
    return rebuilt.bundle
