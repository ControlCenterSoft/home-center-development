"""Shared Cozy/Full presentation model for Home Center 0.59 Policy Composer.

Both interfaces render the same exact PolicyCompositionProposal. The Cozy view is
human-oriented and mobile-friendly; the Full view exposes immutable evidence and
the exact technical policy. Neither view grants or performs mutation authority.
"""

from __future__ import annotations

from .household import HouseholdRole
from .household_policy_composer import PolicyCompositionProposal, compose_policy_bundle
from .household_store import HouseholdSnapshot


POLICY_PRESENTATION_SCHEMA = "home-center.household-policy-presentation.v1"
COZY_POLICY_CARD_SCHEMA = "home-center.cozy-policy-card.v1"
FULL_POLICY_INSPECTOR_SCHEMA = "home-center.full-policy-inspector.v1"


class HouseholdPolicyPresentationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


ROLE_LABELS = {
    HouseholdRole.PARENT: "Родитель",
    HouseholdRole.CHILD: "Ребёнок",
    HouseholdRole.GUEST: "Гость",
}


def build_policy_presentation(
    snapshot: HouseholdSnapshot,
    proposal: PolicyCompositionProposal,
) -> dict[str, object]:
    """Render Cozy and Full views from one exact-state confirmation proposal."""

    if not isinstance(snapshot, HouseholdSnapshot) or not isinstance(proposal, PolicyCompositionProposal):
        raise TypeError("invalid_household_policy_presentation")
    if (
        snapshot.household_id != proposal.household_id
        or snapshot.snapshot_id != proposal.snapshot_id
        or snapshot.resource_version != proposal.resource_version
        or snapshot.generation != proposal.generation
    ):
        raise HouseholdPolicyPresentationError("household_policy_presentation_stale")

    member = next(
        (item for item in snapshot.household.members if item.member_id == proposal.member_id),
        None,
    )
    if member is None or not member.enabled:
        raise HouseholdPolicyPresentationError("household_policy_presentation_member_unavailable")

    rebuilt = compose_policy_bundle(snapshot, member_id=proposal.member_id)
    if rebuilt != proposal.bundle:
        raise HouseholdPolicyPresentationError("household_policy_presentation_evidence_mismatch")

    cozy = {
        "schema": COZY_POLICY_CARD_SCHEMA,
        "title": f"Правила для {member.display_name}",
        "member_id": member.member_id,
        "role": member.role.value,
        "role_label": ROLE_LABELS[member.role],
        "summary": list(proposal.bundle.explanation),
        "status": "ready-for-confirmation",
        "confirmation_required": True,
        "confirmation_label": "Применить правила",
        "mutation_started": False,
        "technical_details_available": True,
        "external_publication_enabled": False,
    }
    full = {
        "schema": FULL_POLICY_INSPECTOR_SCHEMA,
        "proposal_id": proposal.proposal_id,
        "bundle_id": proposal.bundle.bundle_id,
        "source": proposal.bundle.source,
        "household_id": proposal.household_id,
        "member_id": proposal.member_id,
        "role": proposal.bundle.role.value,
        "snapshot_id": proposal.snapshot_id,
        "resource_version": proposal.resource_version,
        "generation": proposal.generation,
        "desired_state_resource_key": proposal.bundle.desired_state_resource_key,
        "expected_desired_state_generation": proposal.expected_desired_state_generation,
        "expected_desired_state_bundle_id": proposal.expected_desired_state_bundle_id,
        "technical_policy": proposal.bundle.policy.to_dict(),
        "confirmation_required": True,
        "desired_state_write_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    return {
        "schema": POLICY_PRESENTATION_SCHEMA,
        "proposal_id": proposal.proposal_id,
        "bundle_id": proposal.bundle.bundle_id,
        "cozy": cozy,
        "full": full,
        "same_policy_evidence": True,
        "confirmation_required": True,
        "mutation_started": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
