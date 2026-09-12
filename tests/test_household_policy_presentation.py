from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_composer import build_policy_composition_proposal
from home_center.household_policy_presentation import (
    HouseholdPolicyPresentationError,
    build_policy_presentation,
)
from home_center.household_store import build_household_snapshot


def _snapshot(generation: int = 1, previous_snapshot_id: str | None = None):
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember(member_id="parent", display_name="Павел", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child", display_name="Ребёнок", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    return build_household_snapshot(
        household,
        generation=generation,
        previous_snapshot_id=previous_snapshot_id,
    )


def test_cozy_and_full_views_share_the_same_exact_policy_evidence() -> None:
    snapshot = _snapshot()
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="child",
    )

    presentation = build_policy_presentation(snapshot, proposal)
    cozy = presentation["cozy"]
    full = presentation["full"]

    assert presentation["same_policy_evidence"] is True
    assert presentation["proposal_id"] == proposal.proposal_id
    assert presentation["bundle_id"] == proposal.bundle.bundle_id
    assert presentation["confirmation_required"] is True
    assert presentation["mutation_started"] is False

    assert cozy["title"] == "Правила для Ребёнок"
    assert cozy["role_label"] == "Ребёнок"
    assert cozy["confirmation_label"] == "Применить правила"
    assert cozy["status"] == "ready-for-confirmation"
    assert any(item.startswith("Интернет:") for item in cozy["summary"])
    assert cozy["external_publication_enabled"] is False

    assert full["proposal_id"] == proposal.proposal_id
    assert full["bundle_id"] == proposal.bundle.bundle_id
    assert full["technical_policy"] == proposal.bundle.policy.to_dict()
    assert full["desired_state_resource_key"] == proposal.bundle.desired_state_resource_key
    assert full["desired_state_write_authorized"] is False
    assert full["infrastructure_mutation_authorized"] is False
    assert full["external_publication_authorized"] is False


def test_policy_presentation_fails_closed_for_stale_household_snapshot() -> None:
    snapshot = _snapshot()
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="child",
    )
    newer = _snapshot(generation=2, previous_snapshot_id=snapshot.snapshot_id)

    with pytest.raises(HouseholdPolicyPresentationError, match="household_policy_presentation_stale"):
        build_policy_presentation(newer, proposal)
