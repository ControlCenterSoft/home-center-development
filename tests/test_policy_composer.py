from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, InternetPolicy
from home_center.household_store import build_household_snapshot
from home_center.policy_composer import (
    PolicyComposerError,
    build_policy_bundle,
    compose_policy_change_plan,
    confirm_policy_change_plan,
    revalidate_policy_change_plan,
)


def _household() -> Household:
    return Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-main", "Родитель", HouseholdRole.PARENT),
            FamilyMember("child-main", "Ребёнок", HouseholdRole.CHILD),
            FamilyMember("guest-main", "Гость", HouseholdRole.GUEST),
        ),
        devices=(),
    )


def _snapshot(generation: int = 1):
    previous = None if generation == 1 else "hsnap-previous00000000000000"
    return build_household_snapshot(_household(), generation=generation, previous_snapshot_id=previous)


def test_child_policy_can_only_tighten_role_ceiling() -> None:
    bundle = build_policy_bundle(
        HouseholdRole.CHILD,
        internet_policy=InternetPolicy.GUEST,
        home_files_allowed=False,
    )
    assert bundle.role is HouseholdRole.CHILD
    assert bundle.internet_policy is InternetPolicy.GUEST
    assert bundle.vpn_allowed is False
    assert bundle.managed_device_required is True
    assert bundle.home_files_allowed is False
    assert bundle.administration_allowed is False
    assert bundle.external_publication_allowed is False


@pytest.mark.parametrize(
    "override",
    [
        {"internet_policy": InternetPolicy.FULL},
        {"vpn_allowed": True},
        {"managed_device_required": False},
        {"smart_home_control_allowed": True},
        {"administration_allowed": True},
    ],
)
def test_child_policy_cannot_broaden_role_ceiling(override: dict[str, object]) -> None:
    with pytest.raises(PolicyComposerError, match="policy_role_ceiling_exceeded"):
        build_policy_bundle(HouseholdRole.CHILD, **override)


def test_policy_plan_is_exact_state_explainable_and_non_executing() -> None:
    snapshot = _snapshot()
    bundle = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)

    plan = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-main",
        target_member_id="child-main",
        target_bundle=bundle,
    )

    assert plan.household_id == snapshot.household_id
    assert plan.snapshot_id == snapshot.snapshot_id
    assert plan.resource_version == snapshot.resource_version
    assert plan.generation == snapshot.generation
    assert plan.confirmation_required is True
    assert plan.desired_state_write_authorized is False
    assert plan.provider_execution_authorized is False
    assert plan.external_publication_authorized is False
    assert plan.recovery_bundle_id == plan.current_bundle_id
    assert "Домашние файлы: недоступны." in plan.cozy_summary_ru
    assert "Внешняя публикация: запрещена." in plan.cozy_summary_ru

    repeated = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-main",
        target_member_id="child-main",
        target_bundle=bundle,
    )
    assert repeated == plan


def test_policy_plan_requires_enabled_parent_actor() -> None:
    snapshot = _snapshot()
    bundle = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)
    with pytest.raises(PolicyComposerError, match="policy_actor_not_authorized"):
        compose_policy_change_plan(
            snapshot,
            actor_member_id="child-main",
            target_member_id="child-main",
            target_bundle=bundle,
        )


def test_policy_plan_revalidation_rejects_snapshot_drift() -> None:
    first = _snapshot()
    bundle = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)
    plan = compose_policy_change_plan(
        first,
        actor_member_id="parent-main",
        target_member_id="child-main",
        target_bundle=bundle,
    )
    second = build_household_snapshot(
        first.household,
        generation=2,
        previous_snapshot_id=first.snapshot_id,
    )

    with pytest.raises(PolicyComposerError, match="policy_change_stale"):
        revalidate_policy_change_plan(second, plan, actor_member_id="parent-main")


def test_confirmation_authorizes_only_protected_desired_state_write() -> None:
    snapshot = _snapshot()
    bundle = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)
    plan = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-main",
        target_member_id="child-main",
        target_bundle=bundle,
    )

    confirmation = confirm_policy_change_plan(snapshot, plan, actor_member_id="parent-main")

    assert confirmation.plan_id == plan.plan_id
    assert confirmation.desired_state_write_authorized is True
    assert confirmation.provider_execution_authorized is False
    assert confirmation.external_publication_authorized is False
    assert confirmation.audit_event_id.startswith("audit-hp-")
