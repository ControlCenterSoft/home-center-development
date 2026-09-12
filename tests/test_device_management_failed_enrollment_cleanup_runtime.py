from __future__ import annotations

from pathlib import Path

import pytest

from home_center.api_v4 import RuntimeRequestHandlerV4
from home_center.device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from home_center.device_management_failed_enrollment_cleanup_runtime import (
    PLAN_REQUEST_SCHEMA,
    VERIFY_REQUEST_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupRuntimeError,
    DeviceManagementFailedEnrollmentCleanupRuntimeService,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted, _state_from_dict
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore

NOW = "2026-09-12T10:20:00Z"
ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
VERIFICATION_ID = "dmpverify-" + "a" * 24
EXECUTION_PLAN_ID = "dmpexec-" + "b" * 24


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"e" * 32, "cluster-test")


def _seed(store: StateStore, *, managed: bool = False, verification_status: str = "rejected") -> None:
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
    store.set_meta(
        verification_key(VERIFICATION_ID),
        {
            "schema": VERIFICATION_STATE_SCHEMA,
            "status": verification_status,
            "receipt": {
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
                "cleanup_required": True,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        },
    )


def _plan(service: DeviceManagementFailedEnrollmentCleanupRuntimeService) -> dict[str, object]:
    return service.plan(
        actor=ACTOR,
        correlation_id="cleanup-plan",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "max_observed_age_seconds": 300,
        },
    )


class _ReadBack:
    verification_read_only = True

    def __init__(self, state: str, *, observed_at: str = NOW) -> None:
        self.state = state
        self.observed_at = observed_at
        self.requests: list[dict[str, object]] = []

    def read_back(self, request: dict[str, object]) -> dict[str, object]:
        self.requests.append(dict(request))
        return {
            "schema": "home-center.device-management-failed-enrollment-cleanup-readback-result.v1",
            "plan_id": request["plan_id"],
            "provider_id": request["provider_id"],
            "provider_operation_id": request["provider_operation_id"],
            "device_id": request["device_id"],
            "member_id": request["member_id"],
            "observed_at": self.observed_at,
            "state": self.state,
            "provider_read_performed": True,
        }


def test_cleanup_plan_requires_rejected_nr1_evidence_and_unmanaged_local_device(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)

    plan = _plan(service)

    assert str(plan["plan_id"]).startswith("dmclean-")
    assert plan["provider_id"] == "android.mdm"
    assert plan["provider_read_required"] is True
    assert plan["transient_cleanup_authorized"] is False
    assert plan["managed_state_change_authorized"] is False
    assert plan["provider_mutation_authorized"] is False

    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = next(item for item in snapshot.household.devices if item.device_id == DEVICE)
    assert device.managed is False
    store.close()


def test_cleanup_verify_fails_closed_without_read_only_adapter(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    plan = _plan(service)

    with pytest.raises(DeviceManagementFailedEnrollmentCleanupRuntimeError) as exc:
        service.verify(
            actor=ACTOR,
            correlation_id="cleanup-no-adapter",
            request={
                "schema": VERIFY_REQUEST_SCHEMA,
                "plan_id": plan["plan_id"],
                "confirmed": True,
                "idempotency_key": "cleanup-no-adapter-1",
            },
        )
    assert exc.value.code == "device_management_cleanup_adapter_unavailable"
    store.close()


def test_unmanaged_readback_authorizes_only_transient_cleanup(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    adapter = _ReadBack("unmanaged")
    service.register_adapter("android.mdm", adapter)
    plan = _plan(service)

    receipt = service.verify(
        actor=ACTOR,
        correlation_id="cleanup-verify",
        request={
            "schema": VERIFY_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
            "idempotency_key": "cleanup-verify-1",
        },
    )

    assert receipt["state"] == "authorized"
    assert receipt["provider_state"] == "unmanaged"
    assert receipt["transient_cleanup_authorized"] is True
    assert receipt["escalation_to_deenrollment_required"] is False
    assert receipt["managed_state_change_authorized"] is False
    assert receipt["provider_mutation_authorized"] is False
    assert receipt["policy_mutation_authorized"] is False
    assert receipt["device_record_removal_authorized"] is False
    assert len(adapter.requests) == 1

    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = next(item for item in snapshot.household.devices if item.device_id == DEVICE)
    assert device.managed is False
    store.close()


def test_managed_or_unknown_readback_never_authorizes_cleanup(tmp_path: Path) -> None:
    for provider_state, escalation in (("managed", True), ("unknown", False)):
        case = tmp_path / provider_state
        case.mkdir()
        store = _store(case)
        _seed(store)
        service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
        service.register_adapter("android.mdm", _ReadBack(provider_state))
        plan = _plan(service)

        receipt = service.verify(
            actor=ACTOR,
            correlation_id=f"cleanup-{provider_state}",
            request={
                "schema": VERIFY_REQUEST_SCHEMA,
                "plan_id": plan["plan_id"],
                "confirmed": True,
                "idempotency_key": f"cleanup-{provider_state}-1",
            },
        )

        assert receipt["state"] == "blocked"
        assert receipt["transient_cleanup_authorized"] is False
        assert receipt["escalation_to_deenrollment_required"] is escalation
        assert receipt["managed_state_change_authorized"] is False
        store.close()


def test_stale_readback_stays_blocked_and_cleanup_api_routes_are_explicit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    service.register_adapter("android.mdm", _ReadBack("unmanaged", observed_at="2026-09-12T10:00:00Z"))
    plan = _plan(service)

    receipt = service.verify(
        actor=ACTOR,
        correlation_id="cleanup-stale",
        request={
            "schema": VERIFY_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
            "idempotency_key": "cleanup-stale-1",
        },
    )
    assert receipt["state"] == "blocked"
    assert receipt["transient_cleanup_authorized"] is False

    assert RuntimeRequestHandlerV4.CLEANUP_POSTS == {
        "/api/v1/household/devices/enrollment/cleanup/plan",
        "/api/v1/household/devices/enrollment/cleanup/verify",
    }
    store.close()
