from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_change import (
    HouseholdDeviceChangeError,
    apply_device_add_proposal,
    build_device_add_proposal,
    device_add_proposal_from_dict,
)
from home_center.household_device_runtime import (
    HouseholdDeviceRuntimeError,
    HouseholdDeviceRuntimeService,
)
from home_center.household_runtime import HouseholdRuntimeService
from home_center.household_store import HouseholdStore, build_household_replacement
from home_center.store import StateStore


def _snapshot_with_child():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    return store.read("home")


def _state_store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"d" * 32, "cluster-device-test")


def _configured_runtime(store: StateStore) -> tuple[HouseholdRuntimeService, HouseholdDeviceRuntimeService, str]:
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor="local-admin:admin",
        request={"schema": "home-center.household-bootstrap.v1", "display_name": "Parent"},
        correlation_id="corr-bootstrap",
    )
    member = household.plan_member_add(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-member-add-plan.v1",
            "display_name": "Child",
            "role": "child",
        },
        correlation_id="corr-member-plan",
    )
    household.confirm_member_add(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-member-add-confirm.v1",
            "proposal_id": member["proposal_id"],
            "confirmed": True,
        },
        correlation_id="corr-member-confirm",
    )
    child_id = next(
        item["member_id"]
        for item in household.status()["snapshot"]["household"]["members"]
        if item["role"] == "child"
    )
    return household, HouseholdDeviceRuntimeService(store), child_id


def _plan(service: HouseholdDeviceRuntimeService, child_id: str, name: str = "Child phone") -> dict[str, object]:
    return service.plan_device_add(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-device-add-plan.v1",
            "subject_member_id": child_id,
            "display_name": name,
        },
        correlation_id="corr-device-plan",
    )


def _confirm(service: HouseholdDeviceRuntimeService, proposal_id: str) -> dict[str, object]:
    return service.confirm_device_add(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-device-add-confirm.v1",
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="corr-device-confirm",
    )


def test_child_device_plan_requires_management_but_never_claims_it_applied() -> None:
    snapshot = _snapshot_with_child()
    proposal = build_device_add_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-child-phone",
        subject_member_id="member-child",
        display_name="Child phone",
    )
    assert proposal.management_required is True
    assert proposal.device.managed is False
    assert proposal.managed_after_registration is False
    assert proposal.policy_application_authorized is False
    assert proposal.provider_execution_authorized is False
    assert proposal.infrastructure_mutation_authorized is False
    assert proposal.external_publication_authorized is False
    assert device_add_proposal_from_dict(proposal.to_dict()) == proposal


def test_parent_device_plan_does_not_require_management() -> None:
    snapshot = _snapshot_with_child()
    proposal = build_device_add_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-parent-phone",
        subject_member_id="member-parent",
        display_name="Parent phone",
    )
    assert proposal.management_required is False
    assert proposal.device.managed is False


def test_non_parent_cannot_register_device() -> None:
    snapshot = _snapshot_with_child()
    with pytest.raises(HouseholdDeviceChangeError, match="household_device_change_not_authorized"):
        build_device_add_proposal(
            snapshot,
            actor_member_id="member-child",
            device_id="device-child-phone",
            subject_member_id="member-child",
            display_name="Child phone",
        )


def test_managed_or_tampered_proposal_is_rejected() -> None:
    snapshot = _snapshot_with_child()
    value = build_device_add_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-child-phone",
        subject_member_id="member-child",
        display_name="Child phone",
    ).to_dict()
    value["device"]["managed"] = True
    with pytest.raises(HouseholdDeviceChangeError, match="household_device_false_managed_claim"):
        device_add_proposal_from_dict(value)


def test_apply_rejects_stale_household() -> None:
    base = _snapshot_with_child()
    proposal = build_device_add_proposal(
        base,
        actor_member_id="member-parent",
        device_id="device-child-phone",
        subject_member_id="member-child",
        display_name="Child phone",
    )
    changed = Household(
        household_id="home",
        members=base.household.members,
        devices=(
            ManagedDevice(
                device_id="device-other",
                member_id="member-parent",
                display_name="Other",
                managed=False,
            ),
        ),
    )
    newer, _ = build_household_replacement(base, changed, expected_resource_version=base.resource_version)
    with pytest.raises(HouseholdDeviceChangeError, match="household_device_change_stale"):
        apply_device_add_proposal(newer, proposal, actor_member_id="member-parent")


def test_runtime_plan_does_not_mutate_and_confirm_keeps_managed_false(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        household, devices, child_id = _configured_runtime(store)
        before = household.status()["snapshot"]
        proposal = _plan(devices, child_id)
        assert household.status()["snapshot"] == before
        assert proposal["management_required"] is True
        assert proposal["managed_after_registration"] is False

        receipt = _confirm(devices, proposal["proposal_id"])
        assert receipt["outcome"] == "applied"
        assert receipt["management_required"] is True
        assert receipt["managed"] is False
        assert receipt["device"]["managed"] is False
        assert receipt["provider_execution_authorized"] is False
        state = household.status()["snapshot"]
        registered = next(item for item in state["household"]["devices"] if item["device_id"] == receipt["device"]["device_id"])
        assert registered["member_id"] == child_id
        assert registered["managed"] is False
        actions = [event["action"] for event in store.audit_events(40)]
        assert "household.device.plan" in actions
        assert "household.device.register.requested" in actions
        assert "household.device.register" in actions
    finally:
        store.close()


def test_runtime_confirm_replay_is_idempotent(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        household, devices, child_id = _configured_runtime(store)
        proposal = _plan(devices, child_id)
        first = _confirm(devices, proposal["proposal_id"])
        second = _confirm(devices, proposal["proposal_id"])
        assert first["outcome"] == "applied"
        assert second["outcome"] == "already-applied"
        assert first["snapshot_id"] == second["snapshot_id"]
        assert len(household.status()["snapshot"]["household"]["devices"]) == 1
    finally:
        store.close()


def test_second_device_plan_becomes_stale_after_first_confirm(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        household, devices, child_id = _configured_runtime(store)
        first = _plan(devices, child_id, "Phone")
        second = _plan(devices, child_id, "Tablet")
        _confirm(devices, first["proposal_id"])
        with pytest.raises(HouseholdDeviceRuntimeError, match="household_device_change_stale"):
            _confirm(devices, second["proposal_id"])
        assert len(household.status()["snapshot"]["household"]["devices"]) == 1
    finally:
        store.close()


def test_confirmation_must_be_explicit_true(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        household, devices, child_id = _configured_runtime(store)
        proposal = _plan(devices, child_id)
        before = household.status()["snapshot"]
        with pytest.raises(HouseholdDeviceRuntimeError, match="invalid_household_device_confirm_request"):
            devices.confirm_device_add(
                actor="local-admin:admin",
                request={
                    "schema": "home-center.household-device-add-confirm.v1",
                    "proposal_id": proposal["proposal_id"],
                    "confirmed": False,
                },
                correlation_id="corr-no",
            )
        assert household.status()["snapshot"] == before
    finally:
        store.close()
