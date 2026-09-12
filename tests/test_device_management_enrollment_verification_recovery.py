from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from home_center.device_management_enrollment_verification_recovery import (
    RecoverableDeviceManagementEnrollmentVerificationRuntimeService,
)
from home_center.device_management_enrollment_verification_runtime import (
    DeviceManagementEnrollmentVerificationRuntimeError,
    VERIFY_ACTION,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import (
    ActorBinding,
    HOUSEHOLD_STATE_KEY,
    _persisted,
    _state_from_dict,
)
from home_center.household_store import HouseholdStore, build_household_replacement
from home_center.store import StateStore


ACTOR = "local-admin:admin"
VERIFICATION_ID = "dmpverify-" + "a" * 24
STATE_KEY = "cozy.household.device-enrollment-verification." + VERIFICATION_ID


def _base_snapshot():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id="member-parent",
                display_name="Parent",
                role=HouseholdRole.PARENT,
            ),
        ),
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-parent",
                display_name="Phone",
                managed=False,
            ),
        ),
    )
    reference = HouseholdStore()
    reference.create(household)
    return reference.read("home")


def _expected(base):
    managed = Household(
        household_id=base.household.household_id,
        members=base.household.members,
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-parent",
                display_name="Phone",
                managed=True,
            ),
        ),
    )
    return build_household_replacement(
        base,
        managed,
        expected_resource_version=base.resource_version,
    )


def _store(tmp_path: Path):
    store = StateStore(tmp_path / "state.db", b"r" * 32, "cluster-test")
    base = _base_snapshot()
    bindings = (ActorBinding(actor=ACTOR, member_id="member-parent"),)
    store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(base, bindings))
    return store, base, bindings


def _verifying_job(store: StateStore):
    job, created = store.create_action_job(
        action_id=VERIFY_ACTION,
        actor=ACTOR,
        reason="test",
        idempotency_key="verify-once",
        request_hash="a" * 64,
        preflight={
            "verification_id": VERIFICATION_ID,
            "provider_operation_id": "provider-op-1",
        },
        steps=[],
    )
    assert created is True
    job = store.transition_action_job(
        job["job_id"],
        expected_state="preflight",
        new_state="running",
    )
    return store.transition_action_job(
        job["job_id"],
        expected_state="running",
        new_state="verifying",
        result={
            "schema": "home-center.device-management-enrollment-adapter-verify-result.v1",
            "state": "verified",
            "verification_id": VERIFICATION_ID,
            "provider_operation_id": "provider-op-1",
            "device_id": "device-phone",
            "provider_device_reference": "provider-device/1",
            "enrollment_completed": True,
            "post_condition_verified": True,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        },
    )


def _envelope(base, expected, commit):
    return {
        "schema": "home-center.device-management-enrollment-verification-state.v1",
        "status": "applying",
        "base_snapshot": base.to_dict(),
        "expected_snapshot": expected.to_dict(),
        "commit": commit.to_dict(),
        "receipt": {
            "schema": "home-center.device-management-enrollment-verification-receipt.v1",
            "state": "managed-state-applied",
            "verification_id": VERIFICATION_ID,
            "snapshot_id": expected.snapshot_id,
            "resource_version": expected.resource_version,
            "managed_state_change_authorized": True,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        },
    }


def _plan():
    return SimpleNamespace(
        verification_id=VERIFICATION_ID,
        device_id="device-phone",
        provider_id="provider-mdm",
        provider_operation_id="provider-op-1",
    )


def test_finish_apply_uses_compare_and_set_and_completes_job(tmp_path: Path) -> None:
    store, base, _bindings = _store(tmp_path)
    expected, commit = _expected(base)
    envelope = _envelope(base, expected, commit)
    store.set_meta(STATE_KEY, envelope)
    job = _verifying_job(store)
    service = RecoverableDeviceManagementEnrollmentVerificationRuntimeService(store)

    receipt = service._finish_apply(
        actor=ACTOR,
        correlation_id="cas-success",
        key=STATE_KEY,
        envelope=envelope,
        plan=_plan(),
        job=job,
    )

    current, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    assert current == expected
    assert current.household.devices[0].managed is True
    completed = store.job(job["job_id"])
    assert completed is not None
    assert completed["state"] == "succeeded"
    assert completed["evidence"]["compare_and_set_commit"] is True
    assert receipt["snapshot_id"] == expected.snapshot_id
    assert store.get_meta(STATE_KEY)["status"] == "applied"
    store.close()


def test_finish_apply_rejects_concurrent_household_change_without_overwrite(tmp_path: Path) -> None:
    store, base, bindings = _store(tmp_path)
    expected, commit = _expected(base)
    envelope = _envelope(base, expected, commit)
    store.set_meta(STATE_KEY, envelope)
    job = _verifying_job(store)

    changed_household = Household(
        household_id=base.household.household_id,
        members=base.household.members,
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-parent",
                display_name="Phone renamed elsewhere",
                managed=False,
            ),
        ),
    )
    changed, _changed_commit = build_household_replacement(
        base,
        changed_household,
        expected_resource_version=base.resource_version,
    )
    store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(changed, bindings))

    service = RecoverableDeviceManagementEnrollmentVerificationRuntimeService(store)
    with pytest.raises(
        DeviceManagementEnrollmentVerificationRuntimeError,
        match="device_management_enrollment_verification_stale",
    ):
        service._finish_apply(
            actor=ACTOR,
            correlation_id="cas-stale",
            key=STATE_KEY,
            envelope=envelope,
            plan=_plan(),
            job=job,
        )

    current, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    assert current == changed
    assert current.household.devices[0].managed is False
    failed = store.job(job["job_id"])
    assert failed is not None
    assert failed["state"] == "failed"
    assert store.get_meta(STATE_KEY)["status"] == "failed"
    store.close()
