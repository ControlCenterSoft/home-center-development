from __future__ import annotations

from pathlib import Path

import pytest

from home_center.api_v5 import RuntimeRequestHandlerV5
from home_center.device_management_deenrollment import DEENROLLMENT_READBACK_SCHEMA
from home_center.device_management_deenrollment_execution_runtime import (
    EXECUTE_REQUEST_SCHEMA,
    MUTATION_RESULT_SCHEMA,
    RECONCILE_REQUEST_SCHEMA,
    DeviceManagementDeenrollmentExecutionRuntimeError,
    DeviceManagementDeenrollmentExecutionRuntimeService,
)
from home_center.device_management_deenrollment_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    DeviceManagementDeenrollmentRuntimeService,
)
from home_center.device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted, _state_from_dict
from home_center.household_store import build_household_snapshot
from home_center.step_up import StepUpGrantManager
from home_center.store import StateStore

NOW = "2026-09-12T10:35:00Z"
ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
VERIFICATION_ID = "dmpverify-" + "a" * 24
EXECUTION_PLAN_ID = "dmpexec-" + "b" * 24


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"f" * 32, "cluster-test")


def _seed(store: StateStore) -> None:
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
                managed=True,
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
            "status": "applied",
            "receipt": {
                "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
                "state": "verified",
                "job_id": "job-verify-1",
                "plan_id": EXECUTION_PLAN_ID,
                "provider_id": "android.mdm",
                "provider_operation_id": "provider-enrollment-op-1",
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
            },
        },
    )


def _confirmed(store: StateStore):
    step_up = StepUpGrantManager()
    planning = DeviceManagementDeenrollmentRuntimeService(store, step_up, now=lambda: NOW)
    plan = planning.plan(
        actor=ACTOR,
        correlation_id="plan",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "max_observed_age_seconds": 300,
        },
    )
    token, _expires = step_up.issue(actor=ACTOR, scope=planning.step_up_scope(plan["plan_id"]))
    planning.confirm(
        actor=ACTOR,
        correlation_id="confirm",
        step_up_token=token,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
    )
    return planning, plan


class _Provider:
    mutation_capable = True

    def __init__(self, *, mutation_state: str = "accepted", read_state: str = "unmanaged") -> None:
        self.mutation_state = mutation_state
        self.read_state = read_state
        self.mutations: list[dict[str, object]] = []
        self.reads: list[dict[str, object]] = []

    def deenroll(self, request: dict[str, object]) -> dict[str, object]:
        self.mutations.append(dict(request))
        return {
            "schema": MUTATION_RESULT_SCHEMA,
            "plan_id": request["plan_id"],
            "provider_id": request["provider_id"],
            "provider_operation_id": request["provider_operation_id"],
            "device_id": request["device_id"],
            "member_id": request["member_id"],
            "execution_job_id": request["execution_job_id"],
            "state": self.mutation_state,
        }

    def read_back(self, request: dict[str, object]) -> dict[str, object]:
        self.reads.append(dict(request))
        return {
            "schema": DEENROLLMENT_READBACK_SCHEMA,
            "plan_id": request["plan_id"],
            "provider_id": request["provider_id"],
            "provider_operation_id": request["provider_operation_id"],
            "device_id": request["device_id"],
            "member_id": request["member_id"],
            "observed_at": NOW,
            "state": self.read_state,
            "provider_read_performed": True,
        }


def _execute(service: DeviceManagementDeenrollmentExecutionRuntimeService, plan_id: str):
    return service.execute(
        actor=ACTOR,
        correlation_id="execute",
        request={
            "schema": EXECUTE_REQUEST_SCHEMA,
            "plan_id": plan_id,
            "confirmed": True,
            "idempotency_key": "deenroll-execute-1",
        },
    )


def test_verified_unmanaged_readback_clears_only_local_managed_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    planning, plan = _confirmed(store)
    provider = _Provider()
    service = DeviceManagementDeenrollmentExecutionRuntimeService(store, planning, now=lambda: NOW)
    service.register_adapter("android.mdm", provider)

    completed = _execute(service, plan["plan_id"])

    assert completed["state"] == "applied"
    assert completed["verification"]["managed_state_change_authorized"] is True
    assert completed["managed_state_apply"]["managed_state_applied"] is True
    assert completed["managed_state_apply"]["policy_mutation_authorized"] is False
    assert completed["managed_state_apply"]["device_record_removal_authorized"] is False
    assert len(provider.mutations) == 1
    assert len(provider.reads) == 1
    assert provider.mutations[0]["automatic_retry_authorized"] is False

    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = next(item for item in snapshot.household.devices if item.device_id == DEVICE)
    assert device.managed is False
    store.close()


def test_ambiguous_mutation_is_never_retried_and_read_only_reconcile_can_finish(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    planning, plan = _confirmed(store)
    provider = _Provider(mutation_state="ambiguous", read_state="unmanaged")
    service = DeviceManagementDeenrollmentExecutionRuntimeService(store, planning, now=lambda: NOW)
    service.register_adapter("android.mdm", provider)

    with pytest.raises(DeviceManagementDeenrollmentExecutionRuntimeError) as exc:
        _execute(service, plan["plan_id"])
    assert exc.value.code == "device_management_deenrollment_provider_outcome_ambiguous"
    assert len(provider.mutations) == 1
    assert len(provider.reads) == 0

    with pytest.raises(DeviceManagementDeenrollmentExecutionRuntimeError) as replay:
        _execute(service, plan["plan_id"])
    assert replay.value.code == "device_management_deenrollment_reconciliation_required"
    assert len(provider.mutations) == 1

    completed = service.reconcile(
        actor=ACTOR,
        correlation_id="reconcile",
        request={
            "schema": RECONCILE_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "idempotency_key": "deenroll-reconcile-1",
        },
    )
    assert completed["state"] == "applied"
    assert len(provider.mutations) == 1
    assert len(provider.reads) == 1
    store.close()


def test_provider_still_managed_never_clears_local_state_and_reconcile_is_read_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    planning, plan = _confirmed(store)
    provider = _Provider(read_state="managed")
    service = DeviceManagementDeenrollmentExecutionRuntimeService(store, planning, now=lambda: NOW)
    service.register_adapter("android.mdm", provider)

    with pytest.raises(DeviceManagementDeenrollmentExecutionRuntimeError) as exc:
        _execute(service, plan["plan_id"])
    assert exc.value.code == "device_management_deenrollment_verification_rejected"
    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    assert next(item for item in snapshot.household.devices if item.device_id == DEVICE).managed is True
    assert len(provider.mutations) == 1

    blocked = service.reconcile(
        actor=ACTOR,
        correlation_id="reconcile-managed",
        request={
            "schema": RECONCILE_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "idempotency_key": "deenroll-reconcile-managed",
        },
    )
    assert blocked["state"] == "rejected"
    assert blocked["observed_state"] == "managed"
    assert blocked["managed_state_change_authorized"] is False
    assert len(provider.mutations) == 1

    provider.read_state = "unmanaged"
    completed = service.reconcile(
        actor=ACTOR,
        correlation_id="reconcile-unmanaged",
        request={
            "schema": RECONCILE_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "idempotency_key": "deenroll-reconcile-unmanaged",
        },
    )
    assert completed["state"] == "applied"
    assert len(provider.mutations) == 1
    store.close()


def test_missing_execution_adapter_fails_before_provider_job_and_v5_routes_are_explicit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed(store)
    planning, plan = _confirmed(store)
    service = DeviceManagementDeenrollmentExecutionRuntimeService(store, planning, now=lambda: NOW)

    with pytest.raises(DeviceManagementDeenrollmentExecutionRuntimeError) as exc:
        _execute(service, plan["plan_id"])
    assert exc.value.code == "device_management_deenrollment_execution_adapter_unavailable"

    assert RuntimeRequestHandlerV5.DEENROLLMENT_EXECUTION_POSTS == {
        "/api/v1/household/devices/deenrollment/execute",
        "/api/v1/household/devices/deenrollment/reconcile",
    }
    store.close()
