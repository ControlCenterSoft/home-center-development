from __future__ import annotations

from dataclasses import replace

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, InternetPolicy
from home_center.household_store import build_household_snapshot
from home_center.policy_composer import (
    PolicyBundle,
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


def _snapshot():
    return build_household_snapshot(_household(), generation=1, previous_snapshot_id=None)


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
    assert bundle.to_dict()["external_publication_allowed"] is False


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


def test_direct_policy_bundle_construction_rejects_forged_identity() -> None:
    valid = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)
    with pytest.raises(PolicyComposerError, match="policy_bundle_evidence_mismatch"):
        PolicyBundle(
            bundle_id="hpb-000000000000000000000000",
            role=valid.role,
            internet_policy=valid.internet_policy,
            vpn_allowed=valid.vpn_allowed,
            managed_device_required=valid.managed_device_required,
            home_files_allowed=valid.home_files_allowed,
            smart_home_control_allowed=valid.smart_home_control_allowed,
            administration_allowed=valid.administration_allowed,
        )


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
    assert plan.current_bundle_id == plan.to_dict()["recovery_bundle_id"]
    assert "Домашние файлы: недоступны." in plan.cozy_summary_ru
    assert "Внешняя публикация: запрещена." in plan.cozy_summary_ru

    repeated = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-main",
        target_member_id="child-main",
        target_bundle=bundle,
    )
    assert repeated == plan

    with pytest.raises(PolicyComposerError, match="policy_change_evidence_mismatch"):
        replace(plan, plan_id="hpplan-000000000000000000000000")


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


def test_policy_plan_revalidation_rejects_actor_substitution() -> None:
    snapshot = _snapshot()
    bundle = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)
    plan = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-main",
        target_member_id="child-main",
        target_bundle=bundle,
    )

    with pytest.raises(PolicyComposerError, match="policy_actor_not_authorized"):
        revalidate_policy_change_plan(snapshot, plan, actor_member_id="child-main")


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
    value = confirmation.to_dict()

    assert confirmation.plan_id == plan.plan_id
    assert confirmation.desired_state_write_authorized is True
    assert confirmation.provider_execution_authorized is False
    assert confirmation.external_publication_authorized is False
    assert confirmation.audit_event_id.startswith("audit-hp-")
    assert value["desired_state_write_authorized"] is True
    assert value["provider_execution_authorized"] is False
    assert value["external_publication_authorized"] is False

    with pytest.raises(PolicyComposerError, match="policy_confirmation_evidence_mismatch"):
        replace(confirmation, audit_event_id="audit-hp-000000000000000000000000")
