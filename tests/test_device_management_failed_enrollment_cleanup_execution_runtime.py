from __future__ import annotations

import json
from pathlib import Path

import pytest

from home_center.device_management_enrollment_execution_runtime import (
    START_ACTION,
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
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
    PLAN_REQUEST_SCHEMA,
    VERIFY_REQUEST_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupRuntimeService,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted, _state_from_dict
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore

NOW = "2026-09-12T10:20:00Z"
LATER = "2026-09-12T10:30:01Z"
ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
VERIFICATION_ID = "dmpverify-" + "a" * 24
EXECUTION_PLAN_ID = "dmpexec-" + "b" * 24
PROVIDER = "android.mdm"
PROVIDER_OPERATION = "provider-op-1"
TRANSIENT_REFERENCE = "artifact://single-use/very-secret-reference"


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"r" * 32, "cluster-test")


def _artifact() -> dict[str, object]:
    return {
        "kind": "qr",
        "reference": TRANSIENT_REFERENCE,
        "expires_at": "2026-09-12T10:24:00Z",
        "single_use": True,
    }


def _execution_receipt(job_id: str) -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": job_id,
        "retry_of_job_id": None,
        "plan_id": EXECUTION_PLAN_ID,
        "selection_proposal_id": "dmpsel-" + "d" * 24,
        "provider_id": PROVIDER,
        "provider_operation_id": PROVIDER_OPERATION,
        "device_id": DEVICE,
        "member_id": CHILD,
        "one_time_artifact": _artifact(),
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _rejected_verification_receipt() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
        "state": "rejected",
        "job_id": "job-verify-1",
        "plan_id": EXECUTION_PLAN_ID,
        "provider_id": PROVIDER,
        "provider_operation_id": PROVIDER_OPERATION,
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
    }


def _seed(tmp_path: Path) -> tuple[StateStore, str]:
    store = _store(tmp_path)
    household = Household(
        household_id="home",
        members=(
            FamilyMember(PARENT, "Parent", HouseholdRole.PARENT, True),
            FamilyMember(CHILD, "Child", HouseholdRole.CHILD, True),
        ),
        devices=(ManagedDevice(DEVICE, CHILD, "Phone", False),),
    )
    snapshot = build_household_snapshot(household, generation=1, previous_snapshot_id=None)
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=ACTOR, member_id=PARENT),)),
    )

    source_job, _ = store.create_action_job(
        action_id=START_ACTION,
        actor=ACTOR,
        reason="test provider acceptance",
        idempotency_key="source-job-1",
        request_hash="source-job-hash",
        preflight={"plan_id": EXECUTION_PLAN_ID},
        steps=[{"step": "provider-start", "state": "pending"}],
    )
    source_job = store.transition_action_job(
        source_job["job_id"], expected_state="preflight", new_state="running"
    )
    source_job = store.transition_action_job(
        source_job["job_id"],
        expected_state="running",
        new_state="verifying",
        result={
            "schema": "home-center.device-management-enrollment-provider-acceptance.v1",
            "state": "provider-accepted",
            "provider_operation_id": PROVIDER_OPERATION,
            "one_time_artifact": _artifact(),
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        },
    )
    source_job = store.transition_action_job(
        source_job["job_id"],
        expected_state="verifying",
        new_state="succeeded",
        evidence={"scope": "provider-command-accepted-only"},
    )
    receipt = _execution_receipt(source_job["job_id"])
    store.set_meta(
        execution_key(EXECUTION_PLAN_ID),
        {
            "schema": EXECUTION_STATE_SCHEMA,
            "status": "provider-accepted",
            "plan": {"plan_id": EXECUTION_PLAN_ID},
            "receipt": receipt,
            "cancel_receipt": None,
        },
    )
    store.set_meta(
        verification_key(VERIFICATION_ID),
        {
            "schema": VERIFICATION_STATE_SCHEMA,
            "status": "rejected",
            "execution_receipt": receipt,
            "receipt": _rejected_verification_receipt(),
        },
    )
    return store, source_job["job_id"]


class _ReadBack:
    verification_read_only = True

    def __init__(self, state: str = "unmanaged") -> None:
        self.state = state

    def read_back(self, request: dict[str, object]) -> dict[str, object]:
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


def _authorize(store: StateStore, *, provider_state: str = "unmanaged") -> dict[str, object]:
    verifier = DeviceManagementFailedEnrollmentCleanupRuntimeService(store, now=lambda: NOW)
    verifier.register_adapter(PROVIDER, _ReadBack(provider_state))
    plan = verifier.plan(
        actor=ACTOR,
        correlation_id="cleanup-plan",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "max_observed_age_seconds": 300,
        },
    )
    verifier.verify(
        actor=ACTOR,
        correlation_id="cleanup-verify",
        request={
            "schema": VERIFY_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
            "idempotency_key": "cleanup-verify-1",
        },
    )
    return plan


def _execute(
    service: DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService,
    plan_id: object,
) -> dict[str, object]:
    return service.execute(
        actor=ACTOR,
        correlation_id="cleanup-execute",
        request={
            "schema": EXECUTE_REQUEST_SCHEMA,
            "plan_id": plan_id,
            "confirmed": True,
            "idempotency_key": "cleanup-execute-1",
        },
    )


def test_authorized_cleanup_scrubs_reference_from_all_durable_copies(tmp_path: Path) -> None:
    store, source_job_id = _seed(tmp_path)
    plan = _authorize(store)
    service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(
        store, now=lambda: NOW
    )

    receipt = _execute(service, plan["plan_id"])

    assert receipt["state"] == "cleaned"
    assert receipt["artifact_kind"] == "qr"
    assert receipt["one_time_reference_removed"] is True
    assert receipt["provider_mutation_performed"] is False
    assert receipt["managed_state_changed"] is False
    assert receipt["device_record_removed"] is False

    execution = store.get_meta(execution_key(EXECUTION_PLAN_ID))
    verification = store.get_meta(verification_key(VERIFICATION_ID))
    source_job = store.job(source_job_id)
    assert execution["receipt"]["one_time_artifact"] is None
    assert verification["execution_receipt"]["one_time_artifact"] is None
    assert source_job["result"]["one_time_artifact"] is None

    snapshot, _ = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    device = next(item for item in snapshot.household.devices if item.device_id == DEVICE)
    assert device.managed is False

    durable = json.dumps(
        {
            "execution": execution,
            "verification": verification,
            "jobs": store.jobs(100),
            "audit": store.audit_events(100),
        },
        sort_keys=True,
    )
    assert TRANSIENT_REFERENCE not in durable
    store.close()


def test_cleanup_execute_is_idempotent_without_duplicate_jobs_or_audit(tmp_path: Path) -> None:
    store, _ = _seed(tmp_path)
    plan = _authorize(store)
    service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(store, now=lambda: NOW)

    first = _execute(service, plan["plan_id"])
    jobs_after_first = len(store.jobs(100))
    audit_after_first = len(store.audit_events(100))
    second = _execute(service, plan["plan_id"])

    assert second == first
    assert len(store.jobs(100)) == jobs_after_first
    assert len(store.audit_events(100)) == audit_after_first
    store.close()


def test_blocked_or_expired_cleanup_never_scrubs_reference(tmp_path: Path) -> None:
    blocked_path = tmp_path / "blocked"
    blocked_path.mkdir()
    blocked, blocked_job_id = _seed(blocked_path)
    blocked_plan = _authorize(blocked, provider_state="managed")
    blocked_service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(
        blocked, now=lambda: NOW
    )
    with pytest.raises(DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError) as exc:
        _execute(blocked_service, blocked_plan["plan_id"])
    assert exc.value.code == "device_management_cleanup_execution_not_authorized"
    assert blocked.job(blocked_job_id)["result"]["one_time_artifact"]["reference"] == TRANSIENT_REFERENCE
    blocked.close()

    expired_path = tmp_path / "expired"
    expired_path.mkdir()
    expired, expired_job_id = _seed(expired_path)
    expired_plan = _authorize(expired)
    expired_service = DeviceManagementFailedEnrollmentCleanupExecutionRuntimeService(
        expired, now=lambda: LATER
    )
    with pytest.raises(DeviceManagementFailedEnrollmentCleanupExecutionRuntimeError) as exc:
        _execute(expired_service, expired_plan["plan_id"])
    assert exc.value.code == "device_management_cleanup_authorization_expired"
    assert expired.job(expired_job_id)["result"]["one_time_artifact"]["reference"] == TRANSIENT_REFERENCE
    expired.close()
