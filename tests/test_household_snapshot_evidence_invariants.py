from __future__ import annotations

import pytest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_member_change import build_member_add_proposal
from home_center.household_store import (
    HouseholdCommit,
    HouseholdSnapshot,
    build_household_commit,
    build_household_snapshot,
)


def _household() -> Household:
    return Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id="member-parent",
                display_name="Parent",
                role=HouseholdRole.PARENT,
            ),
        ),
        devices=(),
    )


def _snapshot() -> HouseholdSnapshot:
    return build_household_snapshot(
        _household(),
        generation=1,
        previous_snapshot_id=None,
    )


def test_snapshot_value_object_accepts_builder_generated_evidence() -> None:
    snapshot = _snapshot()
    rebuilt = HouseholdSnapshot(
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        household_id=snapshot.household_id,
        generation=snapshot.generation,
        previous_snapshot_id=snapshot.previous_snapshot_id,
        household=snapshot.household,
    )
    assert rebuilt == snapshot


def test_snapshot_value_object_rejects_forged_snapshot_id() -> None:
    snapshot = _snapshot()
    forged_snapshot_id = snapshot.snapshot_id[:-1] + ("0" if snapshot.snapshot_id[-1] != "0" else "1")
    with pytest.raises(HomeServiceCatalogError, match="household_snapshot_evidence_mismatch"):
        HouseholdSnapshot(
            snapshot_id=forged_snapshot_id,
            resource_version=snapshot.resource_version,
            household_id=snapshot.household_id,
            generation=snapshot.generation,
            previous_snapshot_id=snapshot.previous_snapshot_id,
            household=snapshot.household,
        )


def test_snapshot_value_object_rejects_forged_resource_version() -> None:
    snapshot = _snapshot()
    forged_resource_version = snapshot.resource_version[:-1] + (
        "0" if snapshot.resource_version[-1] != "0" else "1"
    )
    with pytest.raises(HomeServiceCatalogError, match="household_snapshot_evidence_mismatch"):
        HouseholdSnapshot(
            snapshot_id=snapshot.snapshot_id,
            resource_version=forged_resource_version,
            household_id=snapshot.household_id,
            generation=snapshot.generation,
            previous_snapshot_id=snapshot.previous_snapshot_id,
            household=snapshot.household,
        )


def test_snapshot_value_object_rejects_household_identity_mismatch() -> None:
    snapshot = _snapshot()
    with pytest.raises(HomeServiceCatalogError, match="household_identity_conflict"):
        HouseholdSnapshot(
            snapshot_id=snapshot.snapshot_id,
            resource_version=snapshot.resource_version,
            household_id="other",
            generation=snapshot.generation,
            previous_snapshot_id=snapshot.previous_snapshot_id,
            household=snapshot.household,
        )


def test_member_plan_only_accepts_integrity_checked_snapshot_evidence() -> None:
    snapshot = _snapshot()
    proposal = build_member_add_proposal(
        snapshot,
        actor_member_id="member-parent",
        member_id="member-child",
        display_name="Child",
        role=HouseholdRole.CHILD,
    )
    assert proposal.snapshot_id == snapshot.snapshot_id
    assert proposal.resource_version == snapshot.resource_version
    assert proposal.generation == snapshot.generation


def test_commit_value_object_accepts_builder_generated_create_evidence() -> None:
    snapshot = _snapshot()
    commit = build_household_commit("create", None, snapshot)
    rebuilt = HouseholdCommit(
        commit_id=commit.commit_id,
        operation=commit.operation,
        household_id=commit.household_id,
        previous_resource_version=commit.previous_resource_version,
        resource_version=commit.resource_version,
        generation=commit.generation,
        snapshot_id=commit.snapshot_id,
    )
    assert rebuilt == commit


def test_commit_value_object_rejects_forged_commit_id() -> None:
    snapshot = _snapshot()
    commit = build_household_commit("create", None, snapshot)
    forged_commit_id = commit.commit_id[:-1] + ("0" if commit.commit_id[-1] != "0" else "1")
    with pytest.raises(HomeServiceCatalogError, match="household_commit_evidence_mismatch"):
        HouseholdCommit(
            commit_id=forged_commit_id,
            operation=commit.operation,
            household_id=commit.household_id,
            previous_resource_version=commit.previous_resource_version,
            resource_version=commit.resource_version,
            generation=commit.generation,
            snapshot_id=commit.snapshot_id,
        )


def test_commit_builder_rejects_invalid_create_and_replace_transitions() -> None:
    first = _snapshot()
    second = build_household_snapshot(
        _household(),
        generation=2,
        previous_snapshot_id=first.snapshot_id,
    )

    with pytest.raises(HomeServiceCatalogError, match="invalid_household_commit_transition"):
        build_household_commit("create", first.resource_version, first)
    with pytest.raises(HomeServiceCatalogError, match="invalid_household_commit_transition"):
        build_household_commit("create", None, second)
    with pytest.raises(HomeServiceCatalogError, match="invalid_household_commit_transition"):
        build_household_commit("replace", None, second)
    with pytest.raises(HomeServiceCatalogError, match="invalid_household_commit_transition"):
        build_household_commit("replace", first.resource_version, first)


def test_commit_value_object_rejects_operation_generation_mismatch() -> None:
    first = _snapshot()
    second = build_household_snapshot(
        _household(),
        generation=2,
        previous_snapshot_id=first.snapshot_id,
    )
    replace_commit = build_household_commit("replace", first.resource_version, second)

    with pytest.raises(HomeServiceCatalogError, match="invalid_household_commit_transition"):
        HouseholdCommit(
            commit_id=replace_commit.commit_id,
            operation="create",
            household_id=replace_commit.household_id,
            previous_resource_version=None,
            resource_version=replace_commit.resource_version,
            generation=replace_commit.generation,
            snapshot_id=replace_commit.snapshot_id,
        )
