from __future__ import annotations

import pytest

from home_center.device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationResult,
)
from home_center.device_management_managed_transition import (
    DeviceManagementManagedTransitionError,
    apply_managed_transition,
    build_managed_transition_plan,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import build_household_snapshot


def _snapshot(*, managed: bool = False):
    household = Household(
        household_id="home-a",
        members=(
            FamilyMember(
                member_id="parent-a",
                display_name="Родитель",
                role=HouseholdRole.PARENT,
            ),
            FamilyMember(
                member_id="child-a",
                display_name="Ребёнок",
                role=HouseholdRole.CHILD,
            ),
        ),
        devices=(
            ManagedDevice(
                device_id="device-a",
                member_id="child-a",
                display_name="Планшет",
                managed=managed,
            ),
        ),
    )
    return build_household_snapshot(
        household,
        generation=7,
        previous_snapshot_id="hsnap-previous",
    )


def _result(snapshot, *, state: str = "verified"):
    return DeviceManagementEnrollmentVerificationResult(
        verification_id="dmpverify-" + "a" * 24,
        execution_job_id="job-a",
        execution_plan_id="plan-a",
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        device_id="device-a",
        member_id="child-a",
        provider_id="provider-a",
        provider_operation_id="operation-a",
        observed_at="2026-09-12T00:00:00Z",
        state=state,
        reason="all-required-evidence-present" if state == "verified" else "provider-not-enrolled",
        required_checks=("agent", "profile"),
    )


def _managed(snapshot):
    return next(
        device.managed
        for device in snapshot.household.devices
        if device.device_id == "device-a"
    )


def test_verified_post_condition_prepares_exact_managed_state_cas() -> None:
    current = _snapshot()
    result = _result(current)

    plan = build_managed_transition_plan(
        current,
        result,
        actor_member_id="parent-a",
    )
    updated, commit, receipt = apply_managed_transition(
        current,
        plan,
        result,
        actor_member_id="parent-a",
    )

    assert plan.post_condition_verified is True
    assert plan.managed_before is False
    assert plan.managed_after is True
    assert plan.policy_application_authorized is False
    assert plan.infrastructure_mutation_authorized is False
    assert plan.external_publication_authorized is False

    assert updated.generation == current.generation + 1
    assert updated.previous_snapshot_id == current.snapshot_id
    assert commit.previous_resource_version == current.resource_version
    assert commit.resource_version == updated.resource_version
    assert _managed(current) is False
    assert _managed(updated) is True

    evidence = receipt.to_dict()
    assert evidence["managed"] is True
    assert evidence["post_condition_verified"] is True
    assert evidence["policy_application_authorized"] is False
    assert evidence["provider_mutation_authorized"] is False
    assert evidence["infrastructure_mutation_authorized"] is False
    assert evidence["external_publication_authorized"] is False


def test_not_verified_result_never_authorizes_managed_transition() -> None:
    current = _snapshot()

    with pytest.raises(
        DeviceManagementManagedTransitionError,
        match="device_management_enrollment_not_verified",
    ):
        build_managed_transition_plan(
            current,
            _result(current, state="not-verified"),
            actor_member_id="parent-a",
        )


def test_stale_household_snapshot_is_rejected_before_transition() -> None:
    current = _snapshot()
    result = _result(current)
    plan = build_managed_transition_plan(
        current,
        result,
        actor_member_id="parent-a",
    )
    changed_household = Household(
        household_id=current.household_id,
        members=current.household.members,
        devices=(
            ManagedDevice(
                device_id="device-a",
                member_id="child-a",
                display_name="Планшет 2",
                managed=False,
            ),
        ),
    )
    changed = build_household_snapshot(
        changed_household,
        generation=current.generation + 1,
        previous_snapshot_id=current.snapshot_id,
    )

    with pytest.raises(
        DeviceManagementManagedTransitionError,
        match="device_management_enrollment_managed_transition_stale",
    ):
        apply_managed_transition(
            changed,
            plan,
            result,
            actor_member_id="parent-a",
        )


def test_non_admin_member_cannot_authorize_managed_transition() -> None:
    current = _snapshot()

    with pytest.raises(
        DeviceManagementManagedTransitionError,
        match="device_management_enrollment_managed_transition_not_authorized",
    ):
        build_managed_transition_plan(
            current,
            _result(current),
            actor_member_id="child-a",
        )


def test_replay_against_already_managed_state_fails_closed_without_receipt() -> None:
    current = _snapshot(managed=True)

    with pytest.raises(
        DeviceManagementManagedTransitionError,
        match="device_management_enrollment_managed_transition_already_managed",
    ):
        build_managed_transition_plan(
            current,
            _result(current),
            actor_member_id="parent-a",
        )
