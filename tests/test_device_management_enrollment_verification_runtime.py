from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_execution_runtime import (
    DeviceManagementEnrollmentExecutionRuntimeService,
)
from home_center.device_management_enrollment_verification_runtime import (
    DeviceManagementEnrollmentVerificationRuntimeError,
    DeviceManagementEnrollmentVerificationRuntimeService,
)
from home_center.device_management_provider_runtime import (
    PROVIDER_CATALOG_STATE_KEY,
    DeviceManagementProviderRuntimeService,
)
from home_center.device_management_provider_selection_runtime import (
    DeviceManagementProviderSelectionRuntimeService,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_enrollment_runtime import HouseholdDeviceEnrollmentRuntimeService
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted, _state_from_dict
from home_center.household_store import HouseholdStore, build_household_replacement
from home_center.store import StateStore


ACTOR = "local-admin:admin"


def _snapshot():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-child",
                display_name="Phone",
                managed=False,
            ),
        ),
    )
    reference = HouseholdStore()
    reference.create(household)
    return reference.read("home")


def _catalog_raw():
    return {
        "schema": "home-center.device-management-provider-catalog.v1",
        "source": "local-trusted-registry",
        "providers": [
            {
                "provider_id": "android-mdm-primary",
                "display_name": "Android MDM Primary",
                "supported_platforms": ["android"],
                "enrollment_modes": ["qr"],
                "ready": True,
            }
        ],
    }


def _store(tmp_path: Path) -> StateStore:
    store = StateStore(tmp_path / "state.db", b"x" * 32, "cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(_snapshot(), (ActorBinding(actor=ACTOR, member_id="member-parent"),)),
    )
    store.set_meta(PROVIDER_CATALOG_STATE_KEY, _catalog_raw())
    return store


def _confirmed_selection(store: StateStore) -> dict[str, object]:
    enrollment_service = HouseholdDeviceEnrollmentRuntimeService(store)
    enrollment = enrollment_service.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.household-device-enrollment-plan-request.v1",
            "device_id": "device-phone",
        },
        correlation_id="enroll-plan",
    )
    enrollment_service.confirm(
        actor=ACTOR,
        request={
            "schema": "home-center.household-device-enrollment-confirm-request.v1",
            "proposal_id": enrollment["proposal_id"],
            "confirmed": True,
        },
        correlation_id="enroll-confirm",
    )
    resolution = DeviceManagementProviderRuntimeService(store).plan(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-provider-resolution-request.v1",
            "enrollment_proposal_id": enrollment["proposal_id"],
            "device_platform": "android",
        },
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
        request={
            "schema": "home-center.device-management-provider-selection-confirm-request.v1",
            "proposal_id": selection["proposal_id"],
            "confirmed": True,
        },
        correlation_id="select-confirm",
    )


class ExecutionAdapter:
    def __init__(self) -> None:
        self.starts = 0
        self.cancels = 0

    def start(self, request):
        self.starts += 1
        return {
            "schema": "home-center.device-management-enrollment-adapter-start-result.v1",
            "state": "accepted",
            "provider_operation_id": "provider-operation-1",
            "one_time_artifact": {
                "kind": "qr",
                "reference": "secret://enrollment/qr-1",
                "expires_at": "2026-09-12T00:05:00Z",
                "single_use": True,
            },
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        }

    def cancel(self, *, provider_operation_id: str, job_id: str):
        self.cancels += 1
        return {
            "schema": "home-center.device-management-enrollment-adapter-cancel-result.v1",
            "state": "cancel-accepted",
            "provider_operation_id": provider_operation_id,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        }


class VerificationAdapter:
    verification_read_only = True

    def __init__(self, *, forge_authority: bool = False) -> None:
        self.calls = 0
        self.forge_authority = forge_authority

    def verify(self, request):
        self.calls += 1
        return {
            "schema": "home-center.device-management-enrollment-adapter-verify-result.v1",
            "state": "verified",
            "verification_id": request.verification_id,
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "provider_device_reference": "provider-device/android-001",
            "enrollment_completed": True,
            "post_condition_verified": True,
            "managed_state_change_authorized": self.forge_authority,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _provider_accepted(store: StateStore):
    selection = _confirmed_selection(store)
    execution = DeviceManagementEnrollmentExecutionRuntimeService(
        store,
        now=lambda: "2026-09-12T00:00:00Z",
    )
    adapter = ExecutionAdapter()
    execution.register_adapter("android-mdm-primary", adapter)
    plan = execution.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-enrollment-execution-plan-request.v1",
            "selection_proposal_id": selection["proposal_id"],
            "enrollment_mode": "qr",
            "credential_references": [
                {
                    "name": "provider-credential",
                    "reference": "secret://providers/android-mdm-primary",
                }
            ],
            "timeout_seconds": 600,
            "one_time_artifact": "qr",
        },
        correlation_id="exec-plan",
    )
    receipt = execution.start(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-enrollment-execution-start-request.v1",
            "plan_id": plan["plan_id"],
            "confirmed": True,
            "idempotency_key": "execute-once",
        },
        correlation_id="exec-start",
    )
    assert receipt["state"] == "provider-accepted"
    return execution, adapter, plan, receipt


def _verification_plan(
    service: DeviceManagementEnrollmentVerificationRuntimeService,
    execution_plan_id: str,
):
    return service.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-enrollment-verification-plan-request.v1",
            "execution_plan_id": execution_plan_id,
        },
        correlation_id="verify-plan",
    )


def _confirm(service, verification_id: str, key: str = "verify-once"):
    return service.confirm(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-enrollment-verification-confirm-request.v1",
            "verification_id": verification_id,
            "confirmed": True,
            "idempotency_key": key,
        },
        correlation_id="verify-confirm",
    )


def test_runtime_marks_managed_only_after_exact_provider_postcondition(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _execution, _execution_adapter, execution_plan, _receipt = _provider_accepted(store)
    verification = DeviceManagementEnrollmentVerificationRuntimeService(store)
    adapter = VerificationAdapter()
    verification.register_adapter("android-mdm-primary", adapter)
    plan = _verification_plan(verification, execution_plan["plan_id"])

    receipt = _confirm(verification, plan["verification_id"])

    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = snapshot.household.devices[0]
    assert device.managed is True
    assert adapter.calls == 1
    assert receipt["state"] == "managed-state-applied"
    assert receipt["post_condition_verified"] is True
    assert receipt["managed_state_change_authorized"] is True
    assert receipt["policy_application_authorized"] is False
    assert receipt["infrastructure_mutation_authorized"] is False
    assert receipt["external_publication_authorized"] is False
    store.close()


def test_exact_confirm_replay_does_not_reinvoke_provider(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _execution, _execution_adapter, execution_plan, _receipt = _provider_accepted(store)
    verification = DeviceManagementEnrollmentVerificationRuntimeService(store)
    adapter = VerificationAdapter()
    verification.register_adapter("android-mdm-primary", adapter)
    plan = _verification_plan(verification, execution_plan["plan_id"])

    first = _confirm(verification, plan["verification_id"])
    second = _confirm(verification, plan["verification_id"])

    assert second == first
    assert adapter.calls == 1
    store.close()


def test_adapter_registration_requires_explicit_read_only_contract(tmp_path: Path) -> None:
    store = _store(tmp_path)
    verification = DeviceManagementEnrollmentVerificationRuntimeService(store)

    class UnsafeAdapter:
        def verify(self, request):
            return None

    with pytest.raises(
        DeviceManagementEnrollmentVerificationRuntimeError,
        match="invalid_device_management_enrollment_verification_adapter_registration",
    ):
        verification.register_adapter("android-mdm-primary", UnsafeAdapter())
    store.close()


def test_provider_cannot_forge_managed_state_authority(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _execution, _execution_adapter, execution_plan, _receipt = _provider_accepted(store)
    verification = DeviceManagementEnrollmentVerificationRuntimeService(store)
    adapter = VerificationAdapter(forge_authority=True)
    verification.register_adapter("android-mdm-primary", adapter)
    plan = _verification_plan(verification, execution_plan["plan_id"])

    with pytest.raises(
        DeviceManagementEnrollmentVerificationRuntimeError,
        match="adapter_verification_rejected",
    ):
        _confirm(verification, plan["verification_id"])

    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    assert snapshot.household.devices[0].managed is False
    jobs = [job for job in store.jobs(100) if job["job_type"] == "household.device.management.enrollment.verify"]
    assert jobs[0]["state"] == "failed"
    store.close()


def test_household_drift_after_plan_blocks_provider_verification(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _execution, _execution_adapter, execution_plan, _receipt = _provider_accepted(store)
    verification = DeviceManagementEnrollmentVerificationRuntimeService(store)
    adapter = VerificationAdapter()
    verification.register_adapter("android-mdm-primary", adapter)
    plan = _verification_plan(verification, execution_plan["plan_id"])

    current, bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    changed = Household(
        household_id=current.household.household_id,
        members=current.household.members,
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-child",
                display_name="Renamed Phone",
                managed=False,
            ),
        ),
    )
    newer, _commit = build_household_replacement(
        current,
        changed,
        expected_resource_version=current.resource_version,
    )
    store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(newer, bindings))

    with pytest.raises(
        DeviceManagementEnrollmentVerificationRuntimeError,
        match="verification_stale",
    ):
        _confirm(verification, plan["verification_id"])
    assert adapter.calls == 0
    store.close()


def test_cancelled_execution_is_not_verifiable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    execution, _execution_adapter, execution_plan, execution_receipt = _provider_accepted(store)
    execution.cancel(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-enrollment-execution-cancel-request.v1",
            "plan_id": execution_plan["plan_id"],
            "start_job_id": execution_receipt["job_id"],
            "confirmed": True,
            "idempotency_key": "cancel-once",
        },
        correlation_id="exec-cancel",
    )
    verification = DeviceManagementEnrollmentVerificationRuntimeService(store)

    with pytest.raises(
        DeviceManagementEnrollmentVerificationRuntimeError,
        match="execution_not_verifiable",
    ):
        _verification_plan(verification, execution_plan["plan_id"])
    store.close()
