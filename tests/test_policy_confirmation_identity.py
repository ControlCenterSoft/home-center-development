from __future__ import annotations

from dataclasses import replace

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import build_household_snapshot
from home_center.policy_composer import (
    PolicyComposerError,
    build_policy_bundle,
    compose_policy_change_plan,
    confirm_policy_change_plan,
)


def _confirmation():
    household = Household(
        household_id="home-confirm",
        members=(
            FamilyMember("parent-confirm", "Родитель", HouseholdRole.PARENT),
            FamilyMember("child-confirm", "Ребёнок", HouseholdRole.CHILD),
        ),
        devices=(),
    )
    snapshot = build_household_snapshot(household, generation=1, previous_snapshot_id=None)
    plan = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-confirm",
        target_member_id="child-confirm",
        target_bundle=build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False),
    )
    return confirm_policy_change_plan(snapshot, plan, actor_member_id="parent-confirm")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target_member_id", "child-other"),
        ("resource_version", "hrv-000000000000000000000000"),
        ("generation", 2),
        ("desired_state_id", "hpds-000000000000000000000000"),
        ("audit_event_id", "audit-hp-000000000000000000000000"),
    ],
)
def test_confirmation_identity_rejects_exact_state_tampering(field: str, value: object) -> None:
    confirmation = _confirmation()
    with pytest.raises(PolicyComposerError, match="policy_confirmation_evidence_mismatch"):
        replace(confirmation, **{field: value})
