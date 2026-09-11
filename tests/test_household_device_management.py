from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_management import (
    DeviceManagementState,
    HouseholdDeviceManagementError,
    plan_device_management,
)
from home_center.household_device_management_runtime import (
    HouseholdDeviceManagementRuntimeError,
    HouseholdDeviceManagementRuntimeService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore


def _snapshot():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
            FamilyMember(member_id="member-guest", display_name="Guest", role=HouseholdRole.GUEST),
        ),
        devices=(
            ManagedDevice(device_id="device-child-new", member_id="member-child", display_name="Child phone", managed=False),
            ManagedDevice(device_id="device-child-managed", member_id="member-child", display_name="Child tablet", managed=True),
            ManagedDevice(device_id="device-parent", member_id="member-parent", display_name="Parent phone", managed=False),
        ),
    )
    store = HouseholdStore()
    store.create(household)
    return store.read("home")


def _state_store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"q" * 32, "cluster-test")


def test_child_unmanaged_device_requires_future_enrollment_without_authority() -> None:
    plan = plan_device_management(
        _snapshot(),
        actor_member_id="member-parent",
        device_id="device-child-new",
    )
    assert plan.state is DeviceManagementState.REQUIRED
    assert plan.management_required is True
    assert plan.managed is False
    assert len(plan.actions) == 1
    assert plan.actions[0].action_type == "household.device.management.enroll"
    assert plan.actions[0].provider_resolution_required is True
    assert plan.actions[0].confirmation_required is True
    value = plan.to_dict()
    assert value["provider_selected"] is False
    assert value["provider_execution_authorized"] is False
    assert value["policy_application_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False


def test_managed_child_device_is_satisfied_without_action() -> None:
    plan = plan_device_management(
        _snapshot(),
        actor_member_id="member-parent",
        device_id="device-child-managed",
    )
    assert plan.state is DeviceManagementState.SATISFIED
    assert plan.management_required is True
    assert plan.managed is True
    assert plan.actions == ()


def test_parent_unmanaged_device_is_optional() -> None:
    plan = plan_device_management(
        _snapshot(),
        actor_member_id="member-parent",
        device_id="device-parent",
    )
    assert plan.state is DeviceManagementState.OPTIONAL
    assert plan.management_required is False
    assert plan.managed is False
    assert plan.actions == ()


def test_non_parent_cannot_plan_device_management() -> None:
    with pytest.raises(HouseholdDeviceManagementError, match="household_device_management_not_authorized"):
        plan_device_management(
            _snapshot(),
            actor_member_id="member-child",
            device_id="device-child-new",
        )


def test_unknown_device_is_rejected() -> None:
    with pytest.raises(HouseholdDeviceManagementError, match="household_device_not_found"):
        plan_device_management(
            _snapshot(),
            actor_member_id="member-parent",
            device_id="device-missing",
        )


def test_runtime_resolves_actor_binding_and_audits_plan_without_mutation(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        snapshot = _snapshot()
        store.set_meta(
            HOUSEHOLD_STATE_KEY,
            _persisted(snapshot, (ActorBinding(actor="local-admin:admin", member_id="member-parent"),)),
        )
        service = HouseholdDeviceManagementRuntimeService(store)
        before = store.get_meta(HOUSEHOLD_STATE_KEY)
        result = service.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.household-device-management-plan-request.v1",
                "device_id": "device-child-new",
            },
            correlation_id="corr-management-plan",
        )
        after = store.get_meta(HOUSEHOLD_STATE_KEY)
        assert result["state"] == "required"
        assert result["managed"] is False
        assert result["provider_selected"] is False
        assert result["provider_execution_authorized"] is False
        assert before == after
        events = store.audit_events(20)
        event = next(item for item in events if item["action"] == "household.device.management.plan")
        assert event["target"] == "device-child-new"
        assert event["outcome"] == "accepted"
    finally:
        store.close()


def test_runtime_requires_authenticated_household_binding(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        snapshot = _snapshot()
        store.set_meta(
            HOUSEHOLD_STATE_KEY,
            _persisted(snapshot, (ActorBinding(actor="local-admin:admin", member_id="member-parent"),)),
        )
        service = HouseholdDeviceManagementRuntimeService(store)
        with pytest.raises(HouseholdDeviceManagementRuntimeError, match="household_actor_not_bound"):
            service.plan(
                actor="local-admin:other",
                request={
                    "schema": "home-center.household-device-management-plan-request.v1",
                    "device_id": "device-child-new",
                },
                correlation_id="corr-unbound",
            )
    finally:
        store.close()


def test_runtime_rejects_open_or_malformed_request(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        service = HouseholdDeviceManagementRuntimeService(store)
        with pytest.raises(HouseholdDeviceManagementRuntimeError, match="invalid_household_device_management_request"):
            service.plan(
                actor="local-admin:admin",
                request={
                    "schema": "home-center.household-device-management-plan-request.v1",
                    "device_id": "device-child-new",
                    "provider": "example",
                },
                correlation_id="corr-invalid",
            )
    finally:
        store.close()
