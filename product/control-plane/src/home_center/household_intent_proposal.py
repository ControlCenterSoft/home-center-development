"""Exact-state Household/Intent proposal boundary for Home Center.

This module binds a side-effect-free Household intent plan to one exact
HouseholdSnapshot. It deliberately does not authorize provider, infrastructure,
external-publication, or other production mutation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.household import effective_policy
from home_center.household_intent import (
    HouseholdIntent,
    HouseholdIntentPlan,
    plan_household_intent,
)
from home_center.household_store import HouseholdSnapshot, MAX_GENERATION


HOUSEHOLD_INTENT_PROPOSAL_SCHEMA = "home-center.household-intent-proposal.v1"


@dataclass(frozen=True, slots=True)
class HouseholdIntentProposal:
    proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    intent: HouseholdIntent
    plan: HouseholdIntentPlan
    actor_policy_id: str
    schema: str = field(default=HOUSEHOLD_INTENT_PROPOSAL_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "proposal_id",
            _identifier(
                self.proposal_id,
                "invalid_household_intent_proposal_id",
            ),
        )
        object.__setattr__(
            self,
            "household_id",
            _identifier(self.household_id, "invalid_household_id"),
        )
        object.__setattr__(
            self,
            "snapshot_id",
            _identifier(self.snapshot_id, "invalid_household_snapshot_id"),
        )
        object.__setattr__(
            self,
            "resource_version",
            _identifier(
                self.resource_version,
                "invalid_household_resource_version",
            ),
        )
        object.__setattr__(
            self,
            "actor_policy_id",
            _identifier(self.actor_policy_id, "invalid_household_policy_id"),
        )
        if (
            isinstance(self.generation, bool)
            or not isinstance(self.generation, int)
            or not 1 <= self.generation <= MAX_GENERATION
        ):
            raise HomeServiceCatalogError("invalid_household_generation")
        if not isinstance(self.intent, HouseholdIntent):
            raise TypeError("invalid_household_intent")
        if not isinstance(self.plan, HouseholdIntentPlan):
            raise TypeError("invalid_household_intent_plan")
        if self.plan.household_id != self.household_id:
            raise HomeServiceCatalogError(
                "household_intent_proposal_household_mismatch"
            )
        if self.plan.intent_id != self.intent.intent_id:
            raise HomeServiceCatalogError(
                "household_intent_proposal_intent_mismatch"
            )
        if self.plan.actor_member_id != self.intent.actor_member_id:
            raise HomeServiceCatalogError(
                "household_intent_proposal_actor_mismatch"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "intent": self.intent.to_dict(),
            "plan": self.plan.to_dict(),
            "actor_policy_id": self.actor_policy_id,
            "confirmation_required": True,
            "mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_household_intent_proposal(
    snapshot: HouseholdSnapshot,
    intent: HouseholdIntent,
) -> HouseholdIntentProposal:
    """Build a deterministic proposal bound to one exact household snapshot."""

    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(intent, HouseholdIntent):
        raise TypeError("invalid_household_intent")

    plan = plan_household_intent(snapshot.household, intent)
    actor_policy = effective_policy(snapshot.household, intent.actor_member_id)
    canonical = {
        "household_id": snapshot.household_id,
        "snapshot_id": snapshot.snapshot_id,
        "resource_version": snapshot.resource_version,
        "generation": snapshot.generation,
        "intent": intent.to_dict(),
        "plan": plan.to_dict(),
        "actor_policy_id": actor_policy.policy_id,
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    proposal_id = "hprop-" + hashlib.sha256(encoded).hexdigest()[:24]
    return HouseholdIntentProposal(
        proposal_id=proposal_id,
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        intent=intent,
        plan=plan,
        actor_policy_id=actor_policy.policy_id,
    )


def revalidate_household_intent_proposal(
    current_snapshot: HouseholdSnapshot,
    proposal: HouseholdIntentProposal,
) -> HouseholdIntentProposal:
    """Reject stale or tampered proposal evidence and return fresh exact evidence."""

    if not isinstance(current_snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(proposal, HouseholdIntentProposal):
        raise TypeError("invalid_household_intent_proposal")

    if (
        proposal.household_id != current_snapshot.household_id
        or proposal.snapshot_id != current_snapshot.snapshot_id
        or proposal.resource_version != current_snapshot.resource_version
        or proposal.generation != current_snapshot.generation
    ):
        raise HomeServiceCatalogError("household_intent_proposal_stale")

    expected = build_household_intent_proposal(
        current_snapshot,
        proposal.intent,
    )
    if expected != proposal:
        raise HomeServiceCatalogError(
            "household_intent_proposal_evidence_mismatch"
        )
    return expected
