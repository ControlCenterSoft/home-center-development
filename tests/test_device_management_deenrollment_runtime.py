from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_deenrollment_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    STATE_SCHEMA,
    DeviceManagementDeenrollmentRuntimeError,
    DeviceManagementDeenrollmentRuntimeService,
    _key as deenrollment_key,
)
from home_center.device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted, _state_from_dict
from home_center.household_store import build_household_replacement, build_household_snapshot
from home_center.step_up import StepUpGrantManager
from home_center.store import StateStore

NOW = "2026-09-12T09:30:00Z"
ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
VERIFICATION_ID = "dmpverify-" + "a" * 24
EXECUTION_PLAN_ID = "dmpexec-" + "b" * 24


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"d" * 32, "cluster-test")


def _seed(store: StateStore, *, verification_status: str = "applied", managed: bool = True) -> None:
    household = Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id=PARENT,
                display_name="Parent",
                role=HouseholdRole.PARENT,
                enabled=True,
            ),
            FamilyMember(
                member_id=CHILD,
                display_name="Child",
                role=HouseholdRole.CHILD,
                enabled=True,
            ),
        ),
        devices=(
            ManagedDevice(
                device_id=DEVICE,
                member_id=CHILD,
                display_name="Phone",
                managed=managed,
            ),
        ),
    )
    snapshot = build_household_snapshot(household, generation=2, previous_snapshot_id=None)
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=ACTOR, member_id=PARENT),)),
    )
    receipt = {
        "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
        "state": "verified",
        "job_id": "job-verify-1",
        "plan_id": EXECUTION_PLAN_ID,
        "provider_id": "android.mdm",
        "provider_operation_id": "provider-op-1",
        "device_id": DEVICE,
        "member_id": CHILD,
        "execution_generation": 1,
        "evidence_sha256": "c" * 64,
        "enrollment_completed": True,
        "post_condition_verified": True,
        "managed_state_change_authorized": True,
        "cleanup_required": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    store.set_meta(
        verification_key(VERIFICATION_ID),
        {
            "schema": VERIFICATION_STATE_SCHEMA,
            "status": verification_status,
            "receipt": receipt,
        },
    )


def _plan(service: DeviceManagementDeenrollmentRuntimeService) -> dict[str, object]:
    return service.plan(
        actor=ACTOR,
        correlation_id="test-plan",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "max_observed_age_seconds": 300,
        },
    )


def test_plan_is_bound_to_applied_verification_and_keeps_all_mutation_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementDeenrollmentRuntimeService(
        store,
        StepUpGrantManager(),
        now=lambda: NOW,
    )

    plan = _plan(service)

    assert str(plan["plan_id"]).startswith("dmdel-")
    assert plan["provider_id"] == "android.mdm"
    assert plan["device_id"] == DEVICE
    assert plan["confirmation_required"] is True
    assert plan["provider_mutation_authorized"] is False
    assert plan["managed_state_change_authorized"] is False
    assert plan["device_record_removal_authorized"] is False
    envelope = store.get_meta(deenrollment_key(plan["plan_id"]))
    assert envelope["schema"] == STATE_SCHEMA
    assert envelope["status"] == "planned"
    store.close()


def test_confirm_requires_single_use_step_up_and_never_changes_managed_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    step_up = StepUpGrantManager()
    service = DeviceManagementDeenrollmentRuntimeService(store, step_up, now=lambda: NOW)
    plan = _plan(service)
    request = {
        "schema": CONFIRM_REQUEST_SCHEMA,
        "plan_id": plan["plan_id"],
        "confirmed": True,
    }

    with pytest.raises(DeviceManagementDeenrollmentRuntimeError) as exc:
        service.confirm(
            actor=ACTOR,
            request=request,
            step_up_token=None,
            correlation_id="test-confirm-no-step-up",
        )
    assert exc.value.code == "step_up_required"

    token, _expires = step_up.issue(actor=ACTOR, scope=service.step_up_scope(plan["plan_id"]))
    confirmation = service.confirm(
        actor=ACTOR,
        request=request,
        step_up_token=token,
        correlation_id="test-confirm",
    )
    assert confirmation["provider_mutation_authorized"] is True
    assert confirmation["managed_state_change_authorized"] is False
    assert confirmation["automatic_retry_authorized"] is False
    assert confirmation["credential_value_access_authorized"] is False

    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = next(item for item in snapshot.household.devices if item.device_id == DEVICE)
    assert device.managed is True

    replay = service.confirm(
        actor=ACTOR,
        request=request,
        step_up_token=None,
        correlation_id="test-confirm-replay",
    )
    assert replay == confirmation
    store.close()


def test_stale_household_blocks_confirmation_before_step_up_is_consumed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    step_up = StepUpGrantManager()
    service = DeviceManagementDeenrollmentRuntimeService(store, step_up, now=lambda: NOW)
    plan = _plan(service)

    base, bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    renamed_devices = tuple(
        ManagedDevice(
            device_id=device.device_id,
            member_id=device.member_id,
            display_name="Phone renamed" if device.device_id == DEVICE else device.display_name,
            managed=device.managed,
        )
        for device in base.household.devices
    )
    household = Household(
        household_id=base.household.household_id,
        members=base.household.members,
        devices=renamed_devices,
    )
    changed, _commit = build_household_replacement(
        base,
        household,
        expected_resource_version=base.resource_version,
    )
    store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(changed, bindings))

    scope = service.step_up_scope(plan["plan_id"])
    token, _expires = step_up.issue(actor=ACTOR, scope=scope)
    with pytest.raises(DeviceManagementDeenrollmentRuntimeError) as exc:
        service.confirm(
            actor=ACTOR,
            request={
                "schema": CONFIRM_REQUEST_SCHEMA,
                "plan_id": plan["plan_id"],
                "confirmed": True,
            },
            step_up_token=token,
            correlation_id="test-stale",
        )
    assert exc.value.code == "device_management_deenrollment_stale"

    # Revalidation runs before step-up consumption; the same grant remains valid.
    step_up.consume(actor=ACTOR, scope=scope, token=token)
    store.close()


def test_plan_rejects_unapplied_verification_or_unmanaged_device(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store, verification_status="verified")
    service = DeviceManagementDeenrollmentRuntimeService(
        store,
        StepUpGrantManager(),
        now=lambda: NOW,
    )
    with pytest.raises(DeviceManagementDeenrollmentRuntimeError) as exc:
        _plan(service)
    assert exc.value.code == "device_management_deenrollment_verification_not_applied"
    store.close()

    second = tmp_path / "second"
    second.mkdir()
    store = _store(second)
    _seed(store, managed=False)
    service = DeviceManagementDeenrollmentRuntimeService(
        store,
        StepUpGrantManager(),
        now=lambda: NOW,
    )
    with pytest.raises(DeviceManagementDeenrollmentRuntimeError) as exc:
        _plan(service)
    assert exc.value.code == "device_management_deenrollment_device_not_managed"
    store.close()
