from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_enrollment import (
    HouseholdDeviceEnrollmentError,
    build_device_enrollment_proposal,
    device_enrollment_proposal_from_dict,
    revalidate_device_enrollment_proposal,
)
from home_center.household_device_enrollment_runtime import (
    HouseholdDeviceEnrollmentRuntimeError,
    HouseholdDeviceEnrollmentRuntimeService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore, build_household_replacement
from home_center.store import StateStore


def _snapshot(*, managed: bool = False, owner_role: HouseholdRole = HouseholdRole.CHILD):
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-owner", display_name="Owner", role=owner_role),
        ),
        devices=(ManagedDevice(device_id="device-phone", member_id="member-owner", display_name="Phone", managed=managed),),
    )
    ref = HouseholdStore()
    ref.create(household)
    return ref.read("home")


def _state_store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"e" * 32, "cluster-test")


def _seed(store: StateStore, snapshot) -> None:
    store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(snapshot, (ActorBinding(actor="local-admin:admin", member_id="member-parent"),)))


def test_required_unmanaged_device_builds_confirmation_gated_proposal() -> None:
    proposal = build_device_enrollment_proposal(_snapshot(), actor_member_id="member-parent", device_id="device-phone")
    value = proposal.to_dict()
    assert value["confirmation_required"] is True
    assert value["provider_resolution_required"] is True
    assert value["provider_selected"] is False
    assert value["provider_execution_authorized"] is False
    assert value["policy_application_authorized"] is False
    assert value["managed_state_change_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False
    assert device_enrollment_proposal_from_dict(value) == proposal


def test_optional_or_satisfied_device_cannot_create_enrollment_proposal() -> None:
    with pytest.raises(HouseholdDeviceEnrollmentError, match="household_device_enrollment_not_required"):
        build_device_enrollment_proposal(_snapshot(owner_role=HouseholdRole.PARENT), actor_member_id="member-parent", device_id="device-phone")
    with pytest.raises(HouseholdDeviceEnrollmentError, match="household_device_enrollment_not_required"):
        build_device_enrollment_proposal(_snapshot(managed=True), actor_member_id="member-parent", device_id="device-phone")


def test_tampered_proposal_is_rejected() -> None:
    value = build_device_enrollment_proposal(_snapshot(), actor_member_id="member-parent", device_id="device-phone").to_dict()
    value["member_id"] = "member-other"
    with pytest.raises(HouseholdDeviceEnrollmentError, match="household_device_enrollment_evidence_mismatch"):
        device_enrollment_proposal_from_dict(value)


def test_revalidation_rejects_stale_household_snapshot() -> None:
    base = _snapshot()
    proposal = build_device_enrollment_proposal(base, actor_member_id="member-parent", device_id="device-phone")
    changed = Household(
        household_id="home",
        members=base.household.members,
        devices=(*base.household.devices, ManagedDevice(device_id="device-extra", member_id="member-parent", display_name="Extra", managed=False)),
    )
    newer, _ = build_household_replacement(base, changed, expected_resource_version=base.resource_version)
    with pytest.raises(HouseholdDeviceEnrollmentError, match="household_device_enrollment_stale"):
        revalidate_device_enrollment_proposal(newer, proposal, actor_member_id="member-parent")


def test_runtime_plan_and_confirm_never_mutate_household(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed(store, _snapshot())
        service = HouseholdDeviceEnrollmentRuntimeService(store)
        before = store.get_meta(HOUSEHOLD_STATE_KEY)
        proposal = service.plan(actor="local-admin:admin", request={"schema": "home-center.household-device-enrollment-plan-request.v1", "device_id": "device-phone"}, correlation_id="corr-plan")
        after_plan = store.get_meta(HOUSEHOLD_STATE_KEY)
        receipt = service.confirm(actor="local-admin:admin", request={"schema": "home-center.household-device-enrollment-confirm-request.v1", "proposal_id": proposal["proposal_id"], "confirmed": True}, correlation_id="corr-confirm")
        after_confirm = store.get_meta(HOUSEHOLD_STATE_KEY)
        assert before == after_plan == after_confirm
        assert after_confirm["snapshot"]["household"]["devices"][0]["managed"] is False
        assert receipt["outcome"] == "confirmed-for-provider-resolution"
        assert receipt["provider_selected"] is False
        assert receipt["provider_execution_authorized"] is False
        assert receipt["managed_state_change_authorized"] is False
    finally:
        store.close()


def test_runtime_confirm_retry_is_idempotent_on_same_exact_state(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed(store, _snapshot())
        service = HouseholdDeviceEnrollmentRuntimeService(store)
        proposal = service.plan(actor="local-admin:admin", request={"schema": "home-center.household-device-enrollment-plan-request.v1", "device_id": "device-phone"}, correlation_id="corr-plan")
        request = {"schema": "home-center.household-device-enrollment-confirm-request.v1", "proposal_id": proposal["proposal_id"], "confirmed": True}
        first = service.confirm(actor="local-admin:admin", request=request, correlation_id="corr-confirm-1")
        second = service.confirm(actor="local-admin:admin", request=request, correlation_id="corr-confirm-2")
        assert first["outcome"] == "confirmed-for-provider-resolution"
        assert second["outcome"] == "already-confirmed"
        assert first["audit_event_id"] == second["audit_event_id"]
        confirms = [e for e in store.audit_events(50) if e["action"] == "household.device.enrollment.confirm"]
        assert len(confirms) == 1
    finally:
        store.close()


def test_runtime_confirm_requires_explicit_true(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed(store, _snapshot())
        service = HouseholdDeviceEnrollmentRuntimeService(store)
        proposal = service.plan(actor="local-admin:admin", request={"schema": "home-center.household-device-enrollment-plan-request.v1", "device_id": "device-phone"}, correlation_id="corr-plan")
        with pytest.raises(HouseholdDeviceEnrollmentRuntimeError, match="invalid_household_device_enrollment_confirm_request"):
            service.confirm(actor="local-admin:admin", request={"schema": "home-center.household-device-enrollment-confirm-request.v1", "proposal_id": proposal["proposal_id"], "confirmed": False}, correlation_id="corr-no")
    finally:
        store.close()


def test_runtime_confirm_rejects_stale_state_after_plan(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        base = _snapshot()
        _seed(store, base)
        service = HouseholdDeviceEnrollmentRuntimeService(store)
        proposal = service.plan(actor="local-admin:admin", request={"schema": "home-center.household-device-enrollment-plan-request.v1", "device_id": "device-phone"}, correlation_id="corr-plan")
        changed = Household(household_id="home", members=base.household.members, devices=(*base.household.devices, ManagedDevice(device_id="device-extra", member_id="member-parent", display_name="Extra", managed=False)))
        newer, _ = build_household_replacement(base, changed, expected_resource_version=base.resource_version)
        _seed(store, newer)
        with pytest.raises(HouseholdDeviceEnrollmentRuntimeError, match="household_device_enrollment_stale"):
            service.confirm(actor="local-admin:admin", request={"schema": "home-center.household-device-enrollment-confirm-request.v1", "proposal_id": proposal["proposal_id"], "confirmed": True}, correlation_id="corr-confirm")
    finally:
        store.close()
