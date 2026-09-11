from __future__ import annotations

import pytest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_member_change import build_member_add_proposal
from home_center.household_store import HouseholdSnapshot, build_household_snapshot


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
