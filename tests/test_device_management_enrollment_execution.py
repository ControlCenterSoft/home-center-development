from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_execution import (
    DeviceManagementEnrollmentExecutionError,
    execution_plan_from_dict,
)
from home_center.device_management_enrollment_execution_runtime import (
    DeviceManagementEnrollmentAdapterFailure,
    DeviceManagementEnrollmentExecutionRuntimeError,
    DeviceManagementEnrollmentExecutionRuntimeService,
)
from home_center.device_management_provider_runtime import PROVIDER_CATALOG_STATE_KEY, DeviceManagementProviderRuntimeService
from home_center.device_management_provider_selection_runtime import DeviceManagementProviderSelectionRuntimeService
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_enrollment_runtime import HouseholdDeviceEnrollmentRuntimeService
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

ACTOR = "local-admin:admin"


def _snapshot():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(ManagedDevice(device_id="device-phone", member_id="member-child", display_name="Phone", managed=False),),
    )
    ref = HouseholdStore()
    ref.create(household)
    return ref.read("home")


def _catalog_raw():
    return {
        "schema": "home-center.device-management-provider-catalog.v1",
        "source": "local-trusted-registry",
        "providers": [{
            "provider_id": "android-mdm-primary",
            "display_name": "Android MDM Primary",
            "supported_platforms": ["android"],
            "enrollment_modes": ["qr"],
            "ready": True,
        }],
    }


def _store(tmp_path: Path) -> StateStore:
    store = StateStore(tmp_path / "state.db", b"x" * 32, "cluster-test")
    store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(_snapshot(), (ActorBinding(actor=ACTOR, member_id="member-parent"),)))
    store.set_meta(PROVIDER_CATALOG_STATE_KEY, _catalog_raw())
    return store


def _confirmed_selection(store: StateStore) -> dict[str, object]:
    enrollment_service = HouseholdDeviceEnrollmentRuntimeService(store)
    enrollment = enrollment_service.plan(
        actor=ACTOR,
        request={"schema": "home-center.household-device-enrollment-plan-request.v1", "device_id": "device-phone"},
        correlation_id="enroll-plan",
    )
    enrollment_service.confirm(
        actor=ACTOR,
        request={"schema": "home-center.household-device-enrollment-confirm-request.v1", "proposal_id": enrollment["proposal_id"], "confirmed": True},
        correlation_id="enroll-confirm",
    )
    resolution = DeviceManagementProviderRuntimeService(store).plan(
        actor=ACTOR,
        request={"schema": "home-center.device-management-provider-resolution-request.v1", "enrollment_proposal_id": enrollment["proposal_id"], "device_platform": "android"},
        correlation_id="resolve",
    )
    selection_service = DeviceManagementProviderSelectionRuntimeService(store)
    selection = selection_service.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-provider-selection-plan-request.v1",
            "resolution_plan_id": resolution["plan_id"],
            "enrollment_proposal_id": enrollment["proposal_id"],
            "device_platform": "android",
            "provider_id": "android-mdm-primary",
        },
        correlation_id="select-plan",
    )
    return selection_service.confirm(
        actor=ACTOR,
        request={"schema": "home-center.device-management-provider-selection-confirm-request.v1", "proposal_id": selection["proposal_id"], "confirmed": True},
        correlation_id="select-confirm",
    )


class AcceptingAdapter:
    def __init__(self) -> None:
        self.starts = 0
        self.cancels: list[tuple[str, str]] = []

    def start(self, request):
        self.starts += 1
        assert request.provider_execution_authorized is True
        assert request.credential_value_access_authorized is False
        assert request.managed_state_change_authorized is False
        assert request.credential_references[0].reference.startswith("secret://")
        return {
            "schema": "home-center.device-management-enrollment-adapter-start-result.v1",
            "state": "accepted",
            "provider_operation_id": f"op-{self.starts}",
            "one_time_artifact": {"kind": "qr", "reference": "secret://enrollment/qr-1", "expires_at": "2026-09-12T00:05:00Z", "single_use": True},
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        }

    def cancel(self, *, provider_operation_id: str, job_id: str):
        self.cancels.append((provider_operation_id, job_id))


class RetryOnceAdapter(AcceptingAdapter):
    def start(self, request):
        if self.starts == 0:
            self.starts += 1
            raise DeviceManagementEnrollmentAdapterFailure("provider_not_reached", retry_safe=True)
        return super().start(request)


class TimeoutAdapter(AcceptingAdapter):
    def start(self, request):
        raise TimeoutError("ambiguous timeout")


def _execution_plan(service: DeviceManagementEnrollmentExecutionRuntimeService, selection: dict[str, object]):
    return service.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-enrollment-execution-plan-request.v1",
            "selection_proposal_id": selection["proposal_id"],
            "enrollment_mode": "qr",
            "credential_references": [{"name": "provider-credential", "reference": "secret://providers/android-mdm-primary"}],
            "timeout_seconds": 600,
            "one_time_artifact": "qr",
        },
        correlation_id="exec-plan",
    )


def test_execution_plan_is_closed_content_addressed_and_never_authorizes_execution(tmp_path: Path) -> None:
    store = _store(tmp_path)
    selection = _confirmed_selection(store)
    service = DeviceManagementEnrollmentExecutionRuntimeService(store, now=lambda: "2026-09-12T00:00:00Z")
    plan = _execution_plan(service, selection)
    assert plan["confirmation_required"] is True
    assert plan["durable_job_required"] is True
    assert plan["provider_execution_authorized"] is False
    assert plan["credential_value_access_authorized"] is False
    assert plan["managed_state_change_authorized"] is False
    assert execution_plan_from_dict(plan).plan_id == plan["plan_id"]
    tampered = dict(plan)
    tampered["timeout_seconds"] = 601
    with pytest.raises(DeviceManagementEnrollmentExecutionError, match="plan_rejected"):
        execution_plan_from_dict(tampered)
    store.close()


def test_execution_rejects_raw_credential_values(tmp_path: Path) -> None:
    store = _store(tmp_path)
    selection = _confirmed_selection(store)
    service = DeviceManagementEnrollmentExecutionRuntimeService(store, now=lambda: "2026-09-12T00:00:00Z")
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="credential_reference"):
        service.plan(
            actor=ACTOR,
            request={
                "schema": "home-center.device-management-enrollment-execution-plan-request.v1",
                "selection_proposal_id": selection["proposal_id"], "enrollment_mode": "qr",
                "credential_references": [{"name": "password", "reference": "plaintext-secret"}],
                "timeout_seconds": 600, "one_time_artifact": "qr",
            },
            correlation_id="bad-secret",
        )
    store.close()


def test_provider_acceptance_is_durable_but_does_not_mark_device_managed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    selection = _confirmed_selection(store)
    service = DeviceManagementEnrollmentExecutionRuntimeService(store, now=lambda: "2026-09-12T00:00:00Z")
    adapter = AcceptingAdapter()
    service.register_adapter("android-mdm-primary", adapter)
    plan = _execution_plan(service, selection)
    request = {"schema": "home-center.device-management-enrollment-execution-start-request.v1", "plan_id": plan["plan_id"], "confirmed": True, "idempotency_key": "start-1"}
    receipt = service.start(actor=ACTOR, request=request, correlation_id="exec-start")
    assert receipt["state"] == "provider-accepted"
    assert receipt["enrollment_completed"] is False
    assert receipt["post_condition_verified"] is False
    assert receipt["managed_state_change_authorized"] is False
    assert receipt["one_time_artifact"]["reference"].startswith("secret://")
    assert store.job(receipt["job_id"])["evidence"]["scope"] == "provider-command-accepted-only"
    assert service.start(actor=ACTOR, request=request, correlation_id="exec-replay") == receipt
    assert adapter.starts == 1
    cancel = service.cancel(
        actor=ACTOR,
        request={"schema": "home-center.device-management-enrollment-execution-cancel-request.v1", "plan_id": plan["plan_id"], "start_job_id": receipt["job_id"], "confirmed": True, "idempotency_key": "cancel-1"},
        correlation_id="exec-cancel",
    )
    assert cancel["state"] == "cancel-requested"
    assert cancel["post_condition_verified"] is False
    assert adapter.cancels == [(receipt["provider_operation_id"], receipt["job_id"])]
    store.close()


def test_retry_requires_proof_previous_failure_had_no_side_effect(tmp_path: Path) -> None:
    store = _store(tmp_path)
    selection = _confirmed_selection(store)
    service = DeviceManagementEnrollmentExecutionRuntimeService(store, now=lambda: "2026-09-12T00:00:00Z")
    adapter = RetryOnceAdapter()
    service.register_adapter("android-mdm-primary", adapter)
    plan = _execution_plan(service, selection)
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="provider_not_reached"):
        service.start(actor=ACTOR, request={"schema": "home-center.device-management-enrollment-execution-start-request.v1", "plan_id": plan["plan_id"], "confirmed": True, "idempotency_key": "start-retryable"}, correlation_id="start-fail")
    failed = next(job for job in store.jobs() if job["job_type"] == "household.device.management.enrollment.start")
    assert failed["result"]["retry_safe"] is True
    receipt = service.retry(actor=ACTOR, request={"schema": "home-center.device-management-enrollment-execution-retry-request.v1", "plan_id": plan["plan_id"], "failed_job_id": failed["job_id"], "confirmed": True, "idempotency_key": "retry-1"}, correlation_id="retry")
    assert receipt["state"] == "provider-accepted"
    assert receipt["retry_of_job_id"] == failed["job_id"]
    store.close()


def test_timeout_is_ambiguous_and_cannot_be_automatically_retried(tmp_path: Path) -> None:
    store = _store(tmp_path)
    selection = _confirmed_selection(store)
    service = DeviceManagementEnrollmentExecutionRuntimeService(store, now=lambda: "2026-09-12T00:00:00Z")
    service.register_adapter("android-mdm-primary", TimeoutAdapter())
    plan = _execution_plan(service, selection)
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="provider_timeout"):
        service.start(actor=ACTOR, request={"schema": "home-center.device-management-enrollment-execution-start-request.v1", "plan_id": plan["plan_id"], "confirmed": True, "idempotency_key": "start-timeout"}, correlation_id="timeout")
    failed = next(job for job in store.jobs() if job["job_type"] == "household.device.management.enrollment.start")
    assert failed["result"]["retry_safe"] is False
    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="retry_not_safe"):
        service.retry(actor=ACTOR, request={"schema": "home-center.device-management-enrollment-execution-retry-request.v1", "plan_id": plan["plan_id"], "failed_job_id": failed["job_id"], "confirmed": True, "idempotency_key": "retry-timeout"}, correlation_id="retry-timeout")
    store.close()
