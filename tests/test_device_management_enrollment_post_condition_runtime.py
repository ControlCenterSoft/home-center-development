from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_execution import (
    DeviceManagementEnrollmentExecutionPlan,
    _plan_identity,
)
from home_center.device_management_enrollment_execution_runtime import (
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
    _key as execution_key,
)
from home_center.device_management_enrollment_post_condition_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    PLAN_REQUEST_SCHEMA,
    DeviceManagementEnrollmentPostConditionRuntimeError,
)
from home_center.device_management_enrollment_post_condition_runtime_safe import (
    SafeDeviceManagementEnrollmentPostConditionRuntimeService,
)
from home_center.device_management_enrollment_verification import RESULT_SCHEMA
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import (
    ActorBinding,
    HOUSEHOLD_STATE_KEY,
    _persisted,
    _state_from_dict,
)
from home_center.household_store import build_household_snapshot
from home_center.step_up import StepUpGrantManager
from home_center.store import StateStore


NOW = "2026-09-12T08:00:00Z"
ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"


class ReadOnlyVerifier:
    verification_read_only = True

    def __init__(self) -> None:
        self.calls = 0

    def read_back(self, request: dict[str, object]) -> object:
        self.calls += 1
        return {
            "schema": RESULT_SCHEMA,
            "plan_id": request["plan_id"],
            "provider_id": request["provider_id"],
            "provider_operation_id": request["provider_operation_id"],
            "device_id": request["device_id"],
            "member_id": request["member_id"],
            "execution_generation": request["execution_generation"],
            "observed_at": request["requested_at"],
            "status": "verified",
            "signals": dict(request["expected_signals"]),  # type: ignore[arg-type]
            "provider_read_performed": True,
        }


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"v" * 32, "cluster-test")


def _seed(store: StateStore) -> DeviceManagementEnrollmentExecutionPlan:
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
                managed=False,
            ),
        ),
    )
    snapshot = build_household_snapshot(
        household,
        generation=1,
        previous_snapshot_id=None,
    )
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=ACTOR, member_id=PARENT),)),
    )

    selection = {
        "proposal_id": "dmpsel-" + "1" * 24,
        "enrollment_proposal_id": "enrollment-proposal-1",
        "snapshot_id": snapshot.snapshot_id,
        "resource_version": snapshot.resource_version,
        "generation": snapshot.generation,
        "device_id": DEVICE,
        "member_id": CHILD,
        "catalog_id": "dmpcat-" + "2" * 24,
    }
    plan_id = _plan_identity(
        selection=selection,
        household_id=household.household_id,
        actor_member_id=PARENT,
        provider_id="android.mdm",
        enrollment_mode="android-enterprise",
        credential_references=(),
        timeout_seconds=300,
        one_time_artifact="none",
    )
    plan = DeviceManagementEnrollmentExecutionPlan(
        plan_id=plan_id,
        selection_proposal_id=selection["proposal_id"],
        enrollment_proposal_id=selection["enrollment_proposal_id"],
        household_id=household.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=PARENT,
        device_id=DEVICE,
        member_id=CHILD,
        catalog_id=selection["catalog_id"],
        provider_id="android.mdm",
        enrollment_mode="android-enterprise",
        credential_references=(),
        timeout_seconds=300,
        one_time_artifact="none",
    )
    receipt = {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": "job-start-1",
        "retry_of_job_id": None,
        "plan_id": plan.plan_id,
        "selection_proposal_id": plan.selection_proposal_id,
        "provider_id": plan.provider_id,
        "provider_operation_id": "provider-op-1",
        "device_id": plan.device_id,
        "member_id": plan.member_id,
        "one_time_artifact": None,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    store.set_meta(
        execution_key(plan.plan_id),
        {
            "schema": EXECUTION_STATE_SCHEMA,
            "status": "provider-accepted",
            "plan": plan.to_dict(),
            "receipt": receipt,
            "cancel_receipt": None,
        },
    )
    return plan


def _verification_plan(
    service: SafeDeviceManagementEnrollmentPostConditionRuntimeService,
    execution: DeviceManagementEnrollmentExecutionPlan,
) -> dict[str, object]:
    return service.plan(
        actor=ACTOR,
        correlation_id="test-plan",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "execution_plan_id": execution.plan_id,
            "max_observed_age_seconds": 300,
            "expected_signals": {
                "certificate": "present",
                "profile": "present",
                "agent": "present",
            },
        },
    )


def test_verified_readback_applies_managed_state_once_and_replay_is_read_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    execution = _seed(store)
    service = SafeDeviceManagementEnrollmentPostConditionRuntimeService(
        store,
        StepUpGrantManager(),
        now=lambda: NOW,
    )
    verifier = ReadOnlyVerifier()
    service.register_adapter("android.mdm", verifier)
    plan = _verification_plan(service, execution)
    scope = service.step_up_scope(plan["verification_id"])  # type: ignore[arg-type]
    token, _ = service.step_up.issue(actor=ACTOR, scope=scope)
    request = {
        "schema": CONFIRM_REQUEST_SCHEMA,
        "verification_id": plan["verification_id"],
        "idempotency_key": "verification-idem-0001",
        "confirmed": True,
    }

    first = service.confirm(
        actor=ACTOR,
        request=request,
        step_up_token=token,
        correlation_id="test-confirm",
    )
    assert first["state"] == "applied"
    assert verifier.calls == 1
    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = next(item for item in snapshot.household.devices if item.device_id == DEVICE)
    assert device.managed is True
    assert snapshot.generation == 2

    replay = service.confirm(
        actor=ACTOR,
        request=request,
        step_up_token=None,
        correlation_id="test-replay",
    )
    assert replay == first
    assert verifier.calls == 1
    store.close()


def test_missing_verifier_fails_before_job_and_does_not_consume_step_up(tmp_path: Path) -> None:
    store = _store(tmp_path)
    execution = _seed(store)
    service = SafeDeviceManagementEnrollmentPostConditionRuntimeService(
        store,
        StepUpGrantManager(),
        now=lambda: NOW,
    )
    plan = _verification_plan(service, execution)
    scope = service.step_up_scope(plan["verification_id"])  # type: ignore[arg-type]
    token, _ = service.step_up.issue(actor=ACTOR, scope=scope)
    request = {
        "schema": CONFIRM_REQUEST_SCHEMA,
        "verification_id": plan["verification_id"],
        "idempotency_key": "verification-idem-0002",
        "confirmed": True,
    }

    with pytest.raises(
        DeviceManagementEnrollmentPostConditionRuntimeError,
        match="device_management_enrollment_verification_adapter_unavailable",
    ):
        service.confirm(
            actor=ACTOR,
            request=request,
            step_up_token=token,
            correlation_id="test-no-adapter",
        )
    assert store.jobs(20) == []

    verifier = ReadOnlyVerifier()
    service.register_adapter("android.mdm", verifier)
    result = service.confirm(
        actor=ACTOR,
        request=request,
        step_up_token=token,
        correlation_id="test-adapter-restored",
    )
    assert result["state"] == "applied"
    assert verifier.calls == 1
    store.close()
