from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_composer import (
    HouseholdPolicyComposerError,
    build_policy_composition_proposal,
    compose_policy_bundle,
    revalidate_policy_composition_proposal,
)
from home_center.household_store import build_household_snapshot


def _snapshot():
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember(member_id="parent", display_name="Родитель", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child", display_name="Ребёнок", role=HouseholdRole.CHILD),
            FamilyMember(member_id="guest", display_name="Гость", role=HouseholdRole.GUEST),
        ),
        devices=(),
    )
    return build_household_snapshot(household, generation=1, previous_snapshot_id=None)


def test_policy_bundle_materializes_exact_role_policy_without_authority() -> None:
    snapshot = _snapshot()
    bundle = compose_policy_bundle(snapshot, member_id="child")
    value = bundle.to_dict()

    assert value["bundle_id"].startswith("hpb-")
    assert value["household_id"] == "home-main"
    assert value["member_id"] == "child"
    assert value["role"] == "child"
    assert value["source"] == "role-preset"
    assert value["desired_state_resource_key"] == "household-policy:home-main:child"
    assert value["desired_state_write_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False

    technical = value["technical_policy"]
    assert technical["internet_policy"] == "filtered"
    assert technical["vpn_allowed"] is False
    assert technical["managed_device_required"] is True
    assert technical["administration_allowed"] is False
    assert technical["external_publication_allowed"] is False
    assert technical["production_mutation_enabled"] is False
    assert any(item.startswith("Интернет:") for item in value["explanation"])
    assert any(item == "Внешняя публикация: выключена." for item in value["explanation"])


def test_policy_bundle_identity_is_deterministic() -> None:
    snapshot = _snapshot()
    first = compose_policy_bundle(snapshot, member_id="child")
    second = compose_policy_bundle(snapshot, member_id="child")
    assert first == second
    assert first.to_dict() == second.to_dict()


def test_policy_composition_requires_administrative_household_role() -> None:
    snapshot = _snapshot()
    with pytest.raises(HouseholdPolicyComposerError, match="household_policy_composition_not_authorized"):
        build_policy_composition_proposal(
            snapshot,
            actor_member_id="child",
            member_id="child",
        )


def test_policy_composition_proposal_is_confirmation_gated_and_exact_state_bound() -> None:
    snapshot = _snapshot()
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="child",
    )
    value = proposal.to_dict()

    assert value["proposal_id"].startswith("hpc-")
    assert value["snapshot_id"] == snapshot.snapshot_id
    assert value["resource_version"] == snapshot.resource_version
    assert value["generation"] == 1
    assert value["expected_desired_state_generation"] == 0
    assert value["expected_desired_state_bundle_id"] is None
    assert value["confirmation_required"] is True
    assert value["desired_state_write_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False
    assert revalidate_policy_composition_proposal(
        snapshot,
        proposal,
        actor_member_id="parent",
    ) == proposal.bundle


def test_policy_composition_rejects_actor_household_and_desired_state_changes() -> None:
    snapshot = _snapshot()
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="child",
    )

    with pytest.raises(HouseholdPolicyComposerError, match="household_policy_composition_actor_mismatch"):
        revalidate_policy_composition_proposal(
            snapshot,
            proposal,
            actor_member_id="child",
        )

    newer = build_household_snapshot(
        snapshot.household,
        generation=2,
        previous_snapshot_id=snapshot.snapshot_id,
    )
    with pytest.raises(HouseholdPolicyComposerError, match="household_policy_composition_stale"):
        revalidate_policy_composition_proposal(
            newer,
            proposal,
            actor_member_id="parent",
        )

    with pytest.raises(HouseholdPolicyComposerError, match="household_policy_composition_stale"):
        revalidate_policy_composition_proposal(
            snapshot,
            proposal,
            actor_member_id="parent",
            current_desired_state_generation=1,
            current_desired_state_bundle_id="hpb-0123456789abcdef01234567",
        )


def test_policy_composition_can_bind_an_existing_desired_state_revision() -> None:
    snapshot = _snapshot()
    previous_bundle_id = "hpb-0123456789abcdef01234567"
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="child",
        expected_desired_state_generation=7,
        expected_desired_state_bundle_id=previous_bundle_id,
    )
    assert proposal.expected_desired_state_generation == 7
    assert proposal.expected_desired_state_bundle_id == previous_bundle_id
    assert revalidate_policy_composition_proposal(
        snapshot,
        proposal,
        actor_member_id="parent",
        current_desired_state_generation=7,
        current_desired_state_bundle_id=previous_bundle_id,
    ) == proposal.bundle


def test_policy_composition_rejects_invalid_desired_state_preconditions() -> None:
    snapshot = _snapshot()
    with pytest.raises(HouseholdPolicyComposerError, match="invalid_household_policy_desired_state_precondition"):
        build_policy_composition_proposal(
            snapshot,
            actor_member_id="parent",
            member_id="child",
            expected_desired_state_generation=0,
            expected_desired_state_bundle_id="hpb-0123456789abcdef01234567",
        )
    with pytest.raises(HouseholdPolicyComposerError, match="invalid_household_policy_desired_state_precondition"):
        build_policy_composition_proposal(
            snapshot,
            actor_member_id="parent",
            member_id="child",
            expected_desired_state_generation=1,
            expected_desired_state_bundle_id=None,
        )


def test_guest_bundle_remains_default_deny_for_privileged_capabilities() -> None:
    snapshot = _snapshot()
    bundle = compose_policy_bundle(snapshot, member_id="guest").to_dict()
    policy = bundle["technical_policy"]
    assert policy["internet_policy"] == "guest"
    assert policy["vpn_allowed"] is False
    assert policy["managed_device_required"] is False
    assert policy["home_files_allowed"] is False
    assert policy["smart_home_control_allowed"] is False
    assert policy["administration_allowed"] is False
    assert policy["external_publication_allowed"] is False
