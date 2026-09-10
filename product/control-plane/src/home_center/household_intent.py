"""Side-effect-free Household/Intent planning for the Home Center Cozy interface."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum

from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.household import Household, HouseholdRole, effective_policy


HOUSEHOLD_INTENT_SCHEMA = "home-center.household-intent.v1"
HOUSEHOLD_INTENT_PLAN_SCHEMA = "home-center.household-intent-plan.v1"


class HouseholdIntentKind(StrEnum):
    ONBOARD_MEMBER = "onboard-member"
    ENROLL_DEVICE = "enroll-device"


@dataclass(frozen=True, slots=True)
class HouseholdIntent:
    intent_id: str
    actor_member_id: str
    kind: HouseholdIntentKind
    target_id: str
    requested_role: HouseholdRole | None = None
    subject_member_id: str | None = None
    schema: str = field(default=HOUSEHOLD_INTENT_SCHEMA, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "intent_id", _identifier(self.intent_id, "invalid_household_intent_id"))
        object.__setattr__(
            self,
            "actor_member_id",
            _identifier(self.actor_member_id, "invalid_household_intent_actor"),
        )
        object.__setattr__(self, "target_id", _identifier(self.target_id, "invalid_household_intent_target"))
        if not isinstance(self.kind, HouseholdIntentKind):
            raise HomeServiceCatalogError("invalid_household_intent_kind")
        if self.kind is HouseholdIntentKind.ONBOARD_MEMBER:
            if not isinstance(self.requested_role, HouseholdRole):
                raise HomeServiceCatalogError("household_intent_role_required")
            if self.subject_member_id is not None:
                raise HomeServiceCatalogError("household_intent_subject_not_allowed")
        else:
            if self.requested_role is not None:
                raise HomeServiceCatalogError("household_intent_role_not_allowed")
            object.__setattr__(
                self,
                "subject_member_id",
                _identifier(self.subject_member_id, "household_intent_subject_required"),
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "intent_id": self.intent_id,
            "actor_member_id": self.actor_member_id,
            "kind": self.kind.value,
            "target_id": self.target_id,
            "requested_role": self.requested_role.value if self.requested_role is not None else None,
            "subject_member_id": self.subject_member_id,
        }


@dataclass(frozen=True, slots=True)
class RecommendedAction:
    action_type: str
    target_id: str
    subject_member_id: str
    requires_confirmation: bool
    risk: str

    def to_dict(self) -> dict[str, object]:
        return {
            "action_type": self.action_type,
            "target_id": self.target_id,
            "subject_member_id": self.subject_member_id,
            "requires_confirmation": self.requires_confirmation,
            "risk": self.risk,
        }


@dataclass(frozen=True, slots=True)
class HouseholdIntentPlan:
    plan_id: str
    household_id: str
    intent_id: str
    actor_member_id: str
    actions: tuple[RecommendedAction, ...]
    schema: str = field(default=HOUSEHOLD_INTENT_PLAN_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "intent_id": self.intent_id,
            "actor_member_id": self.actor_member_id,
            "actions": [action.to_dict() for action in self.actions],
            "confirmation_required": True,
            "mutation_authorized": False,
            "production_mutation_enabled": False,
        }


def plan_household_intent(household: Household, intent: HouseholdIntent) -> HouseholdIntentPlan:
    """Translate a household intent to typed recommendations without executing them."""

    if not isinstance(household, Household):
        raise TypeError("invalid_household")
    if not isinstance(intent, HouseholdIntent):
        raise TypeError("invalid_household_intent")

    actor = household.member(intent.actor_member_id)
    if not actor.enabled:
        raise HomeServiceCatalogError("household_intent_actor_disabled")
    actor_policy = effective_policy(household, actor.member_id)
    if not actor_policy.administration_allowed or actor.role is not HouseholdRole.PARENT:
        raise HomeServiceCatalogError("household_intent_not_authorized")

    member_ids = {member.member_id for member in household.members}
    device_ids = {device.device_id for device in household.devices}
    if intent.kind is HouseholdIntentKind.ONBOARD_MEMBER:
        if intent.target_id in member_ids:
            raise HomeServiceCatalogError("household_intent_target_exists")
        role = intent.requested_role
        assert role is not None
        actions = (
            RecommendedAction(
                action_type="household.member.create",
                target_id=intent.target_id,
                subject_member_id=intent.target_id,
                requires_confirmation=True,
                risk="low" if role is not HouseholdRole.PARENT else "elevated",
            ),
            RecommendedAction(
                action_type="household.policy.compose",
                target_id=intent.target_id,
                subject_member_id=intent.target_id,
                requires_confirmation=True,
                risk="low" if role is not HouseholdRole.PARENT else "elevated",
            ),
        )
    else:
        if intent.target_id in device_ids:
            raise HomeServiceCatalogError("household_intent_target_exists")
        subject_member_id = intent.subject_member_id
        assert subject_member_id is not None
        subject = household.member(subject_member_id)
        if not subject.enabled:
            raise HomeServiceCatalogError("household_intent_subject_disabled")
        actions = (
            RecommendedAction(
                action_type="household.device.enroll",
                target_id=intent.target_id,
                subject_member_id=subject.member_id,
                requires_confirmation=True,
                risk="low",
            ),
            RecommendedAction(
                action_type="household.device.apply-effective-policy",
                target_id=intent.target_id,
                subject_member_id=subject.member_id,
                requires_confirmation=True,
                risk="low",
            ),
        )

    canonical = {
        "household_id": household.household_id,
        "intent": intent.to_dict(),
        "actions": [action.to_dict() for action in actions],
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    plan_id = "hint-" + hashlib.sha256(encoded).hexdigest()[:24]
    return HouseholdIntentPlan(
        plan_id=plan_id,
        household_id=household.household_id,
        intent_id=intent.intent_id,
        actor_member_id=intent.actor_member_id,
        actions=actions,
    )
