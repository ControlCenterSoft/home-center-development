from __future__ import annotations

import unittest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore


def _household(*, child_enabled: bool = True) -> Household:
    return Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
            FamilyMember("child-1", "Child", HouseholdRole.CHILD, enabled=child_enabled),
        ),
        devices=(ManagedDevice("tablet-1", "child-1", "Tablet", managed=True),),
    )


class HouseholdStoreTests(unittest.TestCase):
    def test_create_is_deterministic_and_non_mutating(self) -> None:
        left = HouseholdStore()
        right = HouseholdStore()

        left_commit = left.create(_household())
        right_commit = right.create(_household())

        self.assertEqual(left_commit, right_commit)
        snapshot = left.read("home-main")
        self.assertEqual(1, snapshot.generation)
        self.assertIsNone(snapshot.previous_snapshot_id)
        self.assertTrue(snapshot.snapshot_id.startswith("hsnap-"))
        self.assertTrue(snapshot.resource_version.startswith("hrv-"))
        self.assertIs(snapshot.infrastructure_mutation_authorized, False)
        self.assertIs(left_commit.infrastructure_mutation_authorized, False)
        self.assertIs(left_commit.external_publication_authorized, False)

    def test_replace_requires_exact_resource_version(self) -> None:
        store = HouseholdStore()
        first = store.create(_household())

        second = store.replace(
            _household(child_enabled=False),
            expected_resource_version=first.resource_version,
        )
        snapshot = store.read("home-main")

        self.assertEqual(2, second.generation)
        self.assertEqual(first.resource_version, second.previous_resource_version)
        self.assertEqual(2, snapshot.generation)
        self.assertEqual(first.snapshot_id, snapshot.previous_snapshot_id)
        self.assertIs(snapshot.household.member("child-1").enabled, False)

    def test_stale_replace_fails_closed_without_changing_state(self) -> None:
        store = HouseholdStore()
        first = store.create(_household())
        store.replace(
            _household(child_enabled=False),
            expected_resource_version=first.resource_version,
        )
        before = store.read("home-main")

        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_resource_version_conflict",
        ):
            store.replace(
                _household(),
                expected_resource_version=first.resource_version,
            )

        self.assertEqual(before, store.read("home-main"))

    def test_duplicate_create_and_missing_read_fail_closed(self) -> None:
        store = HouseholdStore()
        store.create(_household())

        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_already_exists",
        ):
            store.create(_household())
        with self.assertRaisesRegex(
            HomeServiceCatalogError,
            "household_not_found",
        ):
            store.read("another-home")


if __name__ == "__main__":
    unittest.main()
