from __future__ import annotations

import pytest

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


def test_create_is_deterministic_and_non_mutating() -> None:
    left = HouseholdStore()
    right = HouseholdStore()

    left_commit = left.create(_household())
    right_commit = right.create(_household())

    assert left_commit == right_commit
    snapshot = left.read("home-main")
    assert snapshot.generation == 1
    assert snapshot.previous_snapshot_id is None
    assert snapshot.snapshot_id.startswith("hsnap-")
    assert snapshot.resource_version.startswith("hrv-")
    assert snapshot.infrastructure_mutation_authorized is False
    assert left_commit.infrastructure_mutation_authorized is False
    assert left_commit.external_publication_authorized is False


def test_replace_requires_exact_resource_version() -> None:
    store = HouseholdStore()
    first = store.create(_household())

    second = store.replace(_household(child_enabled=False), expected_resource_version=first.resource_version)
    snapshot = store.read("home-main")

    assert second.generation == 2
    assert second.previous_resource_version == first.resource_version
    assert snapshot.generation == 2
    assert snapshot.previous_snapshot_id == first.snapshot_id
    assert snapshot.household.member("child-1").enabled is False


def test_stale_replace_fails_closed_without_changing_state() -> None:
    store = HouseholdStore()
    first = store.create(_household())
    store.replace(_household(child_enabled=False), expected_resource_version=first.resource_version)
    before = store.read("home-main")

    with pytest.raises(HomeServiceCatalogError, match="household_resource_version_conflict"):
        store.replace(_household(), expected_resource_version=first.resource_version)

    assert store.read("home-main") == before


def test_duplicate_create_and_missing_read_fail_closed() -> None:
    store = HouseholdStore()
    store.create(_household())

    with pytest.raises(HomeServiceCatalogError, match="household_already_exists"):
        store.create(_household())
    with pytest.raises(HomeServiceCatalogError, match="household_not_found"):
        store.read("another-home")
