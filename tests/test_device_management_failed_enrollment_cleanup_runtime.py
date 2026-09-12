from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_failed_enrollment_cleanup_runtime import (
    EVALUATE_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    STATE_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupRuntimeError,
    DeviceManagementFailedEnrollmentCleanupRuntimeService,
    _key as cleanup_key,
)
from home_center.device_management_enrollment_post_condition_runtime import (
    PLAN_SCHEMA as VERIFICATION_PLAN_SCHEMA,
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted, _state_from_dict
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore

NOW = "2026-09-12T09:30:00Z"
ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
VERIFICATION_ID = "dmpverify-" + "a" * 24
EXECUTION_PLAN_ID = "dmpexec-" + "b" * 24


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"f" * 32, "cluster-test")


def _seed(
    store: StateStore,
    *,
    verification_status: str = "rejected",
    cleanup_required: bool = True,
    managed: bool = False,
) -> None:
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
    snapshot = build_household_snapshot(household, generation=1, previous_snapshot_id=None)
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=ACTOR, member_id=PARENT),)),
    )
    plan = {
        "schema": VERIFICATION_PLAN_SCHEMA,
        "verification_id": VERIFICATION_ID,
        "execution_plan_id": EXECUTION_PLAN_ID,
        "provider_id": "android.mdm",
        "provider_operation_id": "provider-op-1",
        "device_id": DEVICE,
        "member_id": CHILD,
    }
    receipt = {
        "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
        "state": "rejected",
        "job_id": "job-verify-1",
        "plan_id": EXECUTION_PLAN_ID,
        "provider_id": "android.mdm",
        "provider_operation_id": "provider-op-1",
        "device_id": DEVICE,
        "member_id": CHILD,
        "execution_generation": 1,
        "evidence_sha256": "c" * 64,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "cleanup_required": cleanup_required,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    store.set_meta(
        verification_key(VERIFICATION_ID),
        {
            "schema": VERIFICATION_STATE_SCHEMA,
            "status": verification_status,
            "plan": plan,
            "receipt": receipt,
        },
    )


def _plan(service: DeviceManagementFailedEnrollmentCleanupRuntimeService) -> dict[str, object]:
    return service.plan(
        actor=ACTOR,
        correlation_id="cleanup-plan",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "cleanup_generation": 1,
            "max_observed_age_seconds": 300,
        },
    )


def _readback(plan_id: str, *, state: str = "unmanaged") -> dict[str, object]:
    return {
        "schema": "home-center.device-management-failed-enrollment-cleanup-readback-result.v1",
        "plan_id": plan_id,
        "provider_id": "android.mdm",
        "provider_operation_id": "provider-op-1",
        "device_id": DEVICE,
        "member_id": CHILD,
        "observed_at": "2026-09-12T09:29:55Z",
        "state": state,
        "provider_read_performed": True,
    }


def _evaluate(
    service: DeviceManagementFailedEnrollmentCleanupRuntimeService,
    plan_id: str,
    *,
    state: str,
) -> dict[str, object]:
    return service.evaluate(
        actor=ACTOR,
        correlation_id=f"cleanup-evaluate-{state}",
        request={
            "schema": EVALUATE_REQUEST_SCHEMA,
            "plan_id": plan_id,
            "readback": _readback(plan_id, state=state),
        },
    )


def test_plan_requires_rejected_verification_and_keeps_all_mutation_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)

    plan = _plan(service)

    assert str(plan["plan_id"]).startswith("dmclean-")
    assert plan["provider_read_required"] is True
    assert plan["transient_cleanup_authorized"] is False
    assert plan["managed_state_change_authorized"] is False
    assert plan["provider_mutation_authorized"] is False
    envelope = store.get_meta(cleanup_key(plan["plan_id"]))
    assert envelope["schema"] == STATE_SCHEMA
    assert envelope["status"] == "planned"
    store.close()


@pytest.mark.parametrize(
    ("verification_status", "cleanup_required", "managed", "code"),
    [
        ("verified", True, False, "device_management_failed_enrollment_cleanup_verification_not_rejected"),
        ("rejected", False, False, "device_management_failed_enrollment_cleanup_verification_invalid"),
        ("rejected", True, True, "device_management_failed_enrollment_cleanup_device_already_managed"),
    ],
)
def test_plan_rejects_non_cleanup_sources(
    tmp_path: Path,
    verification_status: str,
    cleanup_required: bool,
    managed: bool,
    code: str,
) -> None:
    store = _store(tmp_path)
    _seed(
        store,
        verification_status=verification_status,
        cleanup_required=cleanup_required,
        managed=managed,
    )
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)

    with pytest.raises(DeviceManagementFailedEnrollmentCleanupRuntimeError) as exc:
        _plan(service)
    assert exc.value.code == code
    store.close()


@pytest.mark.parametrize("state", ["unmanaged", "absent"])
def test_evaluate_authorizes_only_bounded_transient_cleanup(
    tmp_path: Path,
    state: str,
) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    plan = _plan(service)

    receipt = _evaluate(service, str(plan["plan_id"]), state=state)

    assert receipt["state"] == "authorized"
    assert receipt["transient_cleanup_authorized"] is True
    assert receipt["escalation_to_deenrollment_required"] is False
    assert receipt["managed_state_change_authorized"] is False
    assert receipt["provider_mutation_authorized"] is False
    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = next(item for item in snapshot.household.devices if item.device_id == DEVICE)
    assert device.managed is False
    store.close()


def test_provider_still_managed_requires_explicit_deenrollment(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    plan = _plan(service)

    receipt = _evaluate(service, str(plan["plan_id"]), state="managed")

    assert receipt["state"] == "blocked"
    assert receipt["transient_cleanup_authorized"] is False
    assert receipt["escalation_to_deenrollment_required"] is True
    store.close()


@pytest.mark.parametrize("state", ["unknown", "ambiguous"])
def test_unknown_provider_state_remains_fail_closed(tmp_path: Path, state: str) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    plan = _plan(service)

    receipt = _evaluate(service, str(plan["plan_id"]), state=state)

    assert receipt["state"] == "blocked"
    assert receipt["transient_cleanup_authorized"] is False
    assert receipt["escalation_to_deenrollment_required"] is False
    store.close()


def test_evaluation_is_idempotent_for_same_readback_and_rejects_rewrite(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    plan = _plan(service)
    plan_id = str(plan["plan_id"])

    first = _evaluate(service, plan_id, state="unmanaged")
    second = _evaluate(service, plan_id, state="unmanaged")
    assert second == first

    with pytest.raises(DeviceManagementFailedEnrollmentCleanupRuntimeError) as exc:
        _evaluate(service, plan_id, state="absent")
    assert exc.value.code == "device_management_failed_enrollment_cleanup_already_evaluated"
    store.close()


def test_evaluation_rechecks_current_household_and_never_flips_managed_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    plan = _plan(service)

    snapshot, bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    changed = Household(
        household_id=snapshot.household.household_id,
        members=snapshot.household.members,
        devices=(
            ManagedDevice(
                device_id=DEVICE,
                member_id=CHILD,
                display_name="Phone",
                managed=True,
            ),
        ),
    )
    changed_snapshot = build_household_snapshot(
        changed,
        generation=snapshot.generation + 1,
        previous_snapshot_id=snapshot.snapshot_id,
    )
    store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(changed_snapshot, bindings))

    with pytest.raises(DeviceManagementFailedEnrollmentCleanupRuntimeError) as exc:
        _evaluate(service, str(plan["plan_id"]), state="unmanaged")
    assert exc.value.code == "device_management_failed_enrollment_cleanup_device_already_managed"
    store.close()
