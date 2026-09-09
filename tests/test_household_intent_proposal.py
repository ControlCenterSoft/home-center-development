from __future__ import annotations

from dataclasses import replace
import unittest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import (
    FamilyMember,
    Household,
    HouseholdRole,
    ManagedDevice,
)
from home_center.household_intent import HouseholdIntent, HouseholdIntentKind
from home_center.household_intent_proposal import (
    build_household_intent_proposal,
    revalidate_household_intent_proposal,
)
from home_center.household_store import HouseholdStore


def _household(*, child_enabled: bool = True) -> Household:
    return Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
            FamilyMember(
                "child-1",
                "Child",
                HouseholdRole.CHILD,
                enabled=child_enabled,
            ),
        ),
        devices=(
            ManagedDevice(
                "tablet-1",
                "child-1",
                "Tablet",
                managed=True,
            ),
        ),
    )


def _intent() -> HouseholdIntent:
    return HouseholdIntent(
        intent_id="intent-new-child",
        actor_member_id="parent-1",
        kind=HouseholdIntentKind.ONBOARD_MEMBER,
        target_id="child-2",
        requested_role=HouseholdRole.CHILD,
    )


class HouseholdIntentProposalTests(unittest.TestCase):
    def test_proposal_is_deterministic_and_exact_snapshot_bound(self) -> None:
        store = HouseholdStore()
        store.create(_household())
        snapshot = store.read("home-main")

        first = build_household_intent_proposal(snapshot, _intent())
        second = build_household_intent_proposal(snapshot, _intent())

        self.assertEqual(first, second)
        self.assertTrue(first.proposal_id.startswith("hprop-"))
        self.assertEqual(first.snapshot_id, snapshot.snapshot_id)
        self.assertEqual(first.resource_version, snapshot.resource_version)
        self.assertEqual(first.generation, snapshot.generation)
        self.assertTrue(first.actor_policy_id.startswith("hpol-"))
        self.assertTrue(first.confirmation_required)
        self.assertFalse(first.mutation_authorized)
        self.assertFalse(first.infrastructure_mutation_authorized)
        self.assertFalse(first.external_publication_authorized)
        self.assertEqual(
            revalidate_household_intent_proposal(snapshot, first),
            first,
        )

    def test_state_change_invalidates_existing_proposal(self) -> None:
        store = HouseholdStore()
        first_commit = store.create(_household())
        first_snapshot = store.read("home-main")
        proposal = build_household_intent_proposal(
            first_snapshot,
            _intent(),
        )

        store.replace(
            _household(child_enabled=False),
            expected_resource_version=first_commit.resource_version,
        )
        current_snapshot = store.read("home-main")

        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_intent_proposal_stale",
        ):
            revalidate_household_intent_proposal(
                current_snapshot,
                proposal,
            )

    def test_same_snapshot_tamper_fails_closed(self) -> None:
        store = HouseholdStore()
        store.create(_household())
        snapshot = store.read("home-main")
        proposal = build_household_intent_proposal(snapshot, _intent())
        tampered = replace(
            proposal,
            actor_policy_id="hpol-000000000000000000000000",
        )

        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_intent_proposal_evidence_mismatch",
        ):
            revalidate_household_intent_proposal(snapshot, tampered)

    def test_cross_household_snapshot_is_stale(self) -> None:
        left = HouseholdStore()
        left.create(_household())
        proposal = build_household_intent_proposal(
            left.read("home-main"),
            _intent(),
        )

        other = Household(
            household_id="home-other",
            members=(
                FamilyMember(
                    "parent-1",
                    "Parent",
                    HouseholdRole.PARENT,
                ),
            ),
            devices=(),
        )
        right = HouseholdStore()
        right.create(other)

        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_intent_proposal_stale",
        ):
            revalidate_household_intent_proposal(
                right.read("home-other"),
                proposal,
            )


if __name__ == "__main__":
    unittest.main()
