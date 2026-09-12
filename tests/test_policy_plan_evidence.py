from __future__ import annotations

from dataclasses import replace

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import build_household_snapshot
from home_center.policy_composer import PolicyComposerError, build_policy_bundle, compose_policy_change_plan


def test_cozy_summary_is_bound_to_policy_plan_identity() -> None:
    household = Household(
        household_id="home-summary",
        members=(
            FamilyMember("parent-summary", "Родитель", HouseholdRole.PARENT),
            FamilyMember("child-summary", "Ребёнок", HouseholdRole.CHILD),
        ),
        devices=(),
    )
    snapshot = build_household_snapshot(household, generation=1, previous_snapshot_id=None)
    plan = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-summary",
        target_member_id="child-summary",
        target_bundle=build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False),
    )

    tampered = tuple("Интернет: полный доступ." if item.startswith("Интернет:") else item for item in plan.cozy_summary_ru)
    with pytest.raises(PolicyComposerError, match="policy_change_evidence_mismatch"):
        replace(plan, cozy_summary_ru=tampered)
