from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_execution_runtime import (
    DeviceManagementEnrollmentExecutionRuntimeService,
    _key as execution_key,
)
from home_center.device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from home_center.device_management_failed_enrollment_cleanup_execution_runtime import (
    EXECUTE_REQUEST_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError,
    DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService,
)
from home_center.device_management_failed_enrollment_cleanup_runtime import (
    PLAN_REQUEST_SCHEMA as CLEANUP_PLAN_REQUEST_SCHEMA,
    VERIFY_REQUEST_SCHEMA as CLEANUP_VERIFY_REQUEST_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupRuntimeService,
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
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore
from home_center.util import canonical_json

ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
PROVIDER = "android-mdm-primary"
NOW = "2026-09-12T00:01:00Z"
VERIFICATION_ID = "dmpverify-" + "a" * 24


def _snapshot():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id=PARENT, display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id=CHILD, display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(ManagedDevice(device_id=DEVICE, member_id=CHILD, display_name="Phone", managed=False),),
    )
    ref = HouseholdStore()
    ref.create(household)
    return ref.read("home")


def _catalog_raw():
    return {
        "schema": "home-center.device-management-provider-catalog.v1",
        "source": "local-trusted-registry",
        "providers": [
            {
                "provider_id": PROVIDER,
                "display_name": "Android MDM Primary",
                "supported_platforms": ["android"],
                "enrollment_modes": ["qr"],
                "ready": True,
            }
        ],
    }


def _store(tmp_path: Path) -> StateStore:
    store = StateStore(tmp_path / "state.db", b"q" * 32, "cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(_snapshot(), (ActorBinding(actor=ACTOR, member_id=PARENT),)),
    )
    store.set_meta(PROVIDER_CATALOG_STATE_KEY, _catalog_raw())
    return store


def _confirmed_selection(store: StateStore) -> dict[str, object]:
    enrollment_service = HouseholdDeviceEnrollmentRuntimeService(store)
    enrollment = enrollment_service.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.household-device-enrollment-plan-request.v1",
            "device_id": DEVICE,
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
            "provider_id": PROVIDER,
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


class _EnrollmentAdapter:
    def __init__(self, *, artifact_kind: str) -> None:
        self.artifact_kind = artifact_kind
        self.starts = 0

    def start(self, request):
        self.starts += 1
        artifact = None
        if self.artifact_kind != "none":
            artifact = {
                "kind": self.artifact_kind,
                "reference": "secret://enrollment/qr-1",
                "expires_at": "2026-09-12T00:05:00Z",
                "single_use": True,
            }
        return {
            "schema": "home-center.device-management-enrollment-adapter-start-result.v1",
            "state": "accepted",
            "provider_operation_id": "provider-op-1",
            "one_time_artifact": artifact,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        }

    def cancel(self, *, provider_operation_id: str, job_id: str):
        return {
            "schema": "home-center.device-management-enrollment-adapter-cancel-result.v1",
            "state": "cancel-accepted",
            "provider_operation_id": provider_operation_id,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        }


class _CleanupReadBack:
    verification_read_only = True

    def __init__(self, state: str) -> None:
        self.state = state
        self.reads = 0

    def read_back(self, request: dict[str, object]) -> dict[str, object]:
        self.reads += 1
        return {
            "schema": "home-center.device-management-failed-enrollment-cleanup-readback-result.v1",
            "plan_id": request["plan_id"],
            "provider_id": request["provider_id"],
            "provider_operation_id": request["provider_operation_id"],
            "device_id": request["device_id"],
            "member_id": request["member_id"],
            "observed_at": NOW,
            "state": self.state,
            "provider_read_performed": True,
        }


def _execution(store: StateStore, *, artifact_kind: str) -> tuple[dict[str, object], dict[str, object]]:
    selection = _confirmed_selection(store)
    service = DeviceManagementEnrollmentExecutionRuntimeService(
        store, now=lambda: "2026-09-12T00:00:00Z"
    )
    adapter = _EnrollmentAdapter(artifact_kind=artifact_kind)
    service.register_adapter(PROVIDER, adapter)
    plan = service.plan(
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
            "one_time_artifact": artifact_kind,
        },
        correlation_id="exec-plan",
    )
    receipt = service.start(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-enrollment-execution-start-request.v1",
            "plan_id": plan["plan_id"],
            "confirmed": True,
            "idempotency_key": "enrollment-start-1",
        },
        correlation_id="exec-start",
    )
    assert adapter.starts == 1
    return plan, receipt


def _rejected_verification(
    store: StateStore, *, plan: dict[str, object], receipt: dict[str, object]
) -> None:
    store.set_meta(
        verification_key(VERIFICATION_ID),
        {
            "schema": VERIFICATION_STATE_SCHEMA,
            "status": "rejected",
            "receipt": {
                "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
                "state": "rejected",
                "job_id": "job-verification-rejected",
                "plan_id": plan["plan_id"],
                "provider_id": PROVIDER,
                "provider_operation_id": receipt["provider_operation_id"],
                "device_id": DEVICE,
                "member_id": CHILD,
                "execution_generation": plan["generation"],
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


def _cleanup_plan(
    store: StateStore,
    *,
    plan: dict[str, object],
    receipt: dict[str, object],
    provider_state: str,
) -> tuple[dict[str, object], dict[str, object]]:
    _rejected_verification(store, plan=plan, receipt=receipt)
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    adapter = _CleanupReadBack(provider_state)
    service.register_adapter(PROVIDER, adapter)
    cleanup_plan = service.plan(
        actor=ACTOR,
        request={
            "schema": CLEANUP_PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "max_observed_age_seconds": 300,
        },
        correlation_id="cleanup-plan",
    )
    cleanup_receipt = service.verify(
        actor=ACTOR,
        request={
            "schema": CLEANUP_VERIFY_REQUEST_SCHEMA,
            "plan_id": cleanup_plan["plan_id"],
            "confirmed": True,
            "idempotency_key": "cleanup-verify-1",
        },
        correlation_id="cleanup-verify",
    )
    assert adapter.reads == 1
    return cleanup_plan, cleanup_receipt


def _execute_request(cleanup_plan: dict[str, object]) -> dict[str, object]:
    return {
        "schema": EXECUTE_REQUEST_SCHEMA,
        "plan_id": cleanup_plan["plan_id"],
        "confirmed": True,
        "idempotency_key": "cleanup-exec-1",
    }


def test_authorized_cleanup_removes_only_single_use_reference_and_is_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    plan, provider_receipt = _execution(store, artifact_kind="qr")
    cleanup_plan, cleanup_receipt = _cleanup_plan(
        store, plan=plan, receipt=provider_receipt, provider_state="unmanaged"
    )
    assert cleanup_receipt["transient_cleanup_authorized"] is True

    household_before = store.get_meta(HOUSEHOLD_STATE_KEY)
    execution_before = store.get_meta(execution_key(plan["plan_id"]))
    assert execution_before["receipt"]["one_time_artifact"]["reference"] == "secret://enrollment/qr-1"
    assert execution_before["plan"]["credential_references"] == [
        {"name": "provider-credential", "reference": "secret://providers/android-mdm-primary"}
    ]

    service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(store)
    request = _execute_request(cleanup_plan)
    result = service.execute(actor=ACTOR, request=request, correlation_id="cleanup-exec")

    assert result["state"] == "cleaned"
    assert result["one_time_reference_removed"] is True
    assert isinstance(result["removed_reference_sha256"], str)
    assert "secret://" not in canonical_json(result)
    assert result["provider_mutation_performed"] is False
    assert result["managed_state_changed"] is False
    assert result["policy_mutation_performed"] is False
    assert result["device_record_removed"] is False
    assert result["infrastructure_mutation_performed"] is False
    assert result["external_publication_performed"] is False

    execution_after = store.get_meta(execution_key(plan["plan_id"]))
    assert execution_after["receipt"]["one_time_artifact"] is None
    assert execution_after["plan"] == execution_before["plan"]
    assert execution_after["plan"]["credential_references"] == execution_before["plan"]["credential_references"]
    assert store.get_meta(HOUSEHOLD_STATE_KEY) == household_before

    job = store.job(result["job_id"])
    assert job["state"] == "succeeded"
    assert job["evidence"]["scope"] == "single-use-reference-only"
    assert "secret://enrollment/qr-1" not in canonical_json(job)

    replay = service.execute(actor=ACTOR, request=request, correlation_id="cleanup-exec-replay")
    assert replay == result
    assert len([item for item in store.jobs() if item["job_type"] == "household.device.management.enrollment.cleanup.execute"]) == 1
    store.close()


def test_blocked_cleanup_cannot_delete_reference(tmp_path: Path) -> None:
    store = _store(tmp_path)
    plan, provider_receipt = _execution(store, artifact_kind="qr")
    cleanup_plan, cleanup_receipt = _cleanup_plan(
        store, plan=plan, receipt=provider_receipt, provider_state="managed"
    )
    assert cleanup_receipt["transient_cleanup_authorized"] is False
    before = store.get_meta(execution_key(plan["plan_id"]))

    service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(store)
    with pytest.raises(
        DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError,
        match="cleanup_execution_not_authorized",
    ):
        service.execute(
            actor=ACTOR,
            request=_execute_request(cleanup_plan),
            correlation_id="cleanup-blocked",
        )

    assert store.get_meta(execution_key(plan["plan_id"])) == before
    assert not [item for item in store.jobs() if item["job_type"] == "household.device.management.enrollment.cleanup.execute"]
    store.close()


def test_cleanup_execution_fails_closed_on_tampered_provider_binding(tmp_path: Path) -> None:
    store = _store(tmp_path)
    plan, provider_receipt = _execution(store, artifact_kind="qr")
    cleanup_plan, cleanup_receipt = _cleanup_plan(
        store, plan=plan, receipt=provider_receipt, provider_state="absent"
    )
    assert cleanup_receipt["transient_cleanup_authorized"] is True

    key = execution_key(plan["plan_id"])
    tampered = store.get_meta(key)
    tampered["receipt"]["provider_operation_id"] = "different-provider-operation"
    store.set_meta(key, tampered)

    service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(store)
    with pytest.raises(
        DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError,
        match="cleanup_execution_binding_mismatch",
    ):
        service.execute(
            actor=ACTOR,
            request=_execute_request(cleanup_plan),
            correlation_id="cleanup-binding",
        )
    assert tampered["receipt"]["one_time_artifact"] is not None
    assert store.get_meta(key)["receipt"]["one_time_artifact"] is not None
    store.close()


def test_cleanup_execution_rejects_malformed_reference_without_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    plan, provider_receipt = _execution(store, artifact_kind="qr")
    cleanup_plan, cleanup_receipt = _cleanup_plan(
        store, plan=plan, receipt=provider_receipt, provider_state="unmanaged"
    )
    assert cleanup_receipt["transient_cleanup_authorized"] is True

    key = execution_key(plan["plan_id"])
    malformed = store.get_meta(key)
    malformed["receipt"]["one_time_artifact"]["reference"] = "plaintext-secret"
    store.set_meta(key, malformed)

    service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(store)
    with pytest.raises(
        DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError,
        match="cleanup_execution_artifact_invalid",
    ):
        service.execute(
            actor=ACTOR,
            request=_execute_request(cleanup_plan),
            correlation_id="cleanup-malformed",
        )
    assert store.get_meta(key) == malformed
    store.close()


def test_cleanup_without_one_time_artifact_is_bounded_success_with_no_false_deletion(tmp_path: Path) -> None:
    store = _store(tmp_path)
    plan, provider_receipt = _execution(store, artifact_kind="none")
    cleanup_plan, cleanup_receipt = _cleanup_plan(
        store, plan=plan, receipt=provider_receipt, provider_state="unmanaged"
    )
    assert cleanup_receipt["transient_cleanup_authorized"] is True

    service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(store)
    result = service.execute(
        actor=ACTOR,
        request=_execute_request(cleanup_plan),
        correlation_id="cleanup-no-artifact",
    )
    assert result["state"] == "cleaned"
    assert result["one_time_reference_removed"] is False
    assert result["removed_reference_sha256"] is None
    assert store.get_meta(execution_key(plan["plan_id"]))["receipt"]["one_time_artifact"] is None
    store.close()
