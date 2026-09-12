from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from home_center.device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from home_center.device_management_enrollment_execution_runtime import (
    STATE_SCHEMA as ENROLLMENT_EXECUTION_STATE_SCHEMA,
    _key as enrollment_execution_key,
)
from home_center.device_management_failed_enrollment_cleanup_execution import (
    EXECUTE_REQUEST_SCHEMA,
    EXECUTOR_RESULT_SCHEMA,
    LOCAL_TRANSIENT_SCOPE,
    DeviceManagementFailedEnrollmentCleanupExecutionError,
    DeviceManagementFailedEnrollmentCleanupExecutionService,
    _execution_key,
)
from home_center.device_management_failed_enrollment_cleanup_runtime import (
    PLAN_REQUEST_SCHEMA,
    VERIFY_REQUEST_SCHEMA,
    DeviceManagementFailedEnrollmentCleanupRuntimeService,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore

NOW = "2026-09-12T10:20:00Z"
ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
VERIFICATION_ID = "dmpverify-" + "a" * 24
ENROLLMENT_PLAN_ID = "dmpexec-" + "b" * 24
REFERENCE = "secret://device-enrollment/one-time/phone-1"


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"e" * 32, "cluster-test")


def _seed_household_and_rejected_verification(store: StateStore) -> None:
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
        household, generation=1, previous_snapshot_id=None
    )
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=ACTOR, member_id=PARENT),)),
    )
    store.set_meta(
        verification_key(VERIFICATION_ID),
        {
            "schema": VERIFICATION_STATE_SCHEMA,
            "status": "rejected",
            "receipt": {
                "schema": (
                    "home-center.device-management-enrollment-post-condition-"
                    "verification-receipt.v1"
                ),
                "state": "rejected",
                "job_id": "job-verify-1",
                "plan_id": ENROLLMENT_PLAN_ID,
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


class _ReadBack:
    verification_read_only = True

    def read_back(self, request: dict[str, object]) -> dict[str, object]:
        return {
            "schema": (
                "home-center.device-management-failed-enrollment-cleanup-"
                "readback-result.v1"
            ),
            "plan_id": request["plan_id"],
            "provider_id": request["provider_id"],
            "provider_operation_id": request["provider_operation_id"],
            "device_id": request["device_id"],
            "member_id": request["member_id"],
            "observed_at": NOW,
            "state": "unmanaged",
            "provider_read_performed": True,
        }


def _authorize_cleanup(store: StateStore) -> dict[str, object]:
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(
        store, now=lambda: NOW
    )
    service.register_adapter("android.mdm", _ReadBack())
    plan = service.plan(
        actor=ACTOR,
        correlation_id="cleanup-plan",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "max_observed_age_seconds": 300,
        },
    )
    service.verify(
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


def _plan_only(store: StateStore) -> dict[str, object]:
    service = DeviceManagementFailedEnrollmentCleanupRuntimeService(
        store, now=lambda: NOW
    )
    return service.plan(
        actor=ACTOR,
        correlation_id="cleanup-plan-only",
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "verification_id": VERIFICATION_ID,
            "max_observed_age_seconds": 300,
        },
    )


def _seed_execution_source(store: StateStore, *, artifact_kind: str = "qr") -> None:
    artifact = None
    if artifact_kind != "none":
        artifact = {
            "kind": artifact_kind,
            "reference": REFERENCE,
            "expires_at": "2026-09-12T10:25:00Z",
            "single_use": True,
        }
    store.set_meta(
        enrollment_execution_key(ENROLLMENT_PLAN_ID),
        {
            "schema": ENROLLMENT_EXECUTION_STATE_SCHEMA,
            "status": "provider-accepted",
            "plan": {
                "plan_id": ENROLLMENT_PLAN_ID,
                "provider_id": "android.mdm",
                "device_id": DEVICE,
                "member_id": CHILD,
                "one_time_artifact": artifact_kind,
            },
            "receipt": {
                "schema": (
                    "home-center.device-management-enrollment-execution-receipt.v1"
                ),
                "state": "provider-accepted",
                "job_id": "job-start-1",
                "retry_of_job_id": None,
                "plan_id": ENROLLMENT_PLAN_ID,
                "selection_proposal_id": "dmpsel-" + "d" * 24,
                "provider_id": "android.mdm",
                "provider_operation_id": "provider-op-1",
                "device_id": DEVICE,
                "member_id": CHILD,
                "one_time_artifact": artifact,
                "enrollment_completed": False,
                "post_condition_verified": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
            "cancel_receipt": None,
        },
    )


class _Executor:
    mutation_scope = LOCAL_TRANSIENT_SCOPE
    provider_mutation = False
    idempotent = True

    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def delete_reference(self, **request: object) -> dict[str, object]:
        self.calls.append(dict(request))
        return {
            "schema": EXECUTOR_RESULT_SCHEMA,
            "state": "deleted",
            "reference_sha256": request["reference_sha256"],
            "provider_mutation_performed": False,
            "managed_state_changed": False,
        }


class _ProviderMutatingExecutor(_Executor):
    provider_mutation = True


class _LeakyExecutor(_Executor):
    def delete_reference(self, **request: object) -> dict[str, object]:
        self.calls.append(dict(request))
        return {
            "schema": EXECUTOR_RESULT_SCHEMA,
            "state": "deleted",
            "reference_sha256": request["reference_sha256"],
            "provider_mutation_performed": False,
            "managed_state_changed": False,
            "reference": request["reference"],
        }


def _execute_request(plan_id: object) -> dict[str, object]:
    return {
        "schema": EXECUTE_REQUEST_SCHEMA,
        "plan_id": plan_id,
        "confirmed": True,
        "idempotency_key": "cleanup-execute-1",
    }


def test_authorized_cleanup_deletes_only_transient_reference_and_is_idempotent(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_household_and_rejected_verification(store)
    plan = _authorize_cleanup(store)
    _seed_execution_source(store)
    executor = _Executor()
    service = DeviceManagementFailedEnrollmentCleanupExecutionService(
        store, now=lambda: NOW
    )
    service.register_executor("android.mdm", executor)

    receipt = service.execute(
        actor=ACTOR,
        correlation_id="cleanup-execute",
        request=_execute_request(plan["plan_id"]),
    )
    replay = service.execute(
        actor=ACTOR,
        correlation_id="cleanup-execute-replay",
        request=_execute_request(plan["plan_id"]),
    )

    assert replay == receipt
    assert len(executor.calls) == 1
    assert executor.calls[0]["reference"] == REFERENCE
    assert receipt["state"] == "succeeded"
    assert receipt["transient_reference_state"] == "deleted"
    assert receipt["reference_sha256"] == hashlib.sha256(
        REFERENCE.encode("utf-8")
    ).hexdigest()
    assert receipt["provider_mutation_performed"] is False
    assert receipt["managed_state_changed"] is False
    assert receipt["credential_value_persisted"] is False
    assert REFERENCE not in repr(receipt)

    state = store.get_meta(_execution_key(plan["plan_id"]))
    job = store.job(receipt["job_id"])
    assert REFERENCE not in repr(state)
    assert REFERENCE not in repr(job)
    store.close()


def test_cleanup_execution_requires_completed_readback_authorization(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_household_and_rejected_verification(store)
    plan = _plan_only(store)
    _seed_execution_source(store)
    service = DeviceManagementFailedEnrollmentCleanupExecutionService(
        store, now=lambda: NOW
    )
    service.register_executor("android.mdm", _Executor())

    with pytest.raises(
        DeviceManagementFailedEnrollmentCleanupExecutionError
    ) as exc:
        service.execute(
            actor=ACTOR,
            correlation_id="cleanup-not-authorized",
            request=_execute_request(plan["plan_id"]),
        )
    assert exc.value.code == "device_management_cleanup_execution_not_authorized"
    store.close()


def test_no_artifact_cleanup_succeeds_without_executor(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _seed_household_and_rejected_verification(store)
    plan = _authorize_cleanup(store)
    _seed_execution_source(store, artifact_kind="none")
    service = DeviceManagementFailedEnrollmentCleanupExecutionService(
        store, now=lambda: NOW
    )

    receipt = service.execute(
        actor=ACTOR,
        correlation_id="cleanup-no-artifact",
        request=_execute_request(plan["plan_id"]),
    )

    assert receipt["state"] == "succeeded"
    assert receipt["artifact_kind"] == "none"
    assert receipt["reference_sha256"] is None
    assert receipt["transient_reference_state"] == "absent"
    assert receipt["provider_mutation_performed"] is False
    store.close()


def test_executor_registration_rejects_provider_mutation_capability(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    service = DeviceManagementFailedEnrollmentCleanupExecutionService(store)

    with pytest.raises(
        DeviceManagementFailedEnrollmentCleanupExecutionError
    ) as exc:
        service.register_executor("android.mdm", _ProviderMutatingExecutor())
    assert (
        exc.value.code
        == "invalid_device_management_cleanup_executor_registration"
    )
    store.close()


def test_executor_result_is_closed_and_never_persists_reference_on_failure(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    _seed_household_and_rejected_verification(store)
    plan = _authorize_cleanup(store)
    _seed_execution_source(store)
    service = DeviceManagementFailedEnrollmentCleanupExecutionService(
        store, now=lambda: NOW
    )
    service.register_executor("android.mdm", _LeakyExecutor())

    with pytest.raises(
        DeviceManagementFailedEnrollmentCleanupExecutionError
    ) as exc:
        service.execute(
            actor=ACTOR,
            correlation_id="cleanup-leaky-result",
            request=_execute_request(plan["plan_id"]),
        )
    assert exc.value.code == "device_management_cleanup_executor_result_rejected"
    assert store.get_meta(_execution_key(plan["plan_id"])) is None
    assert REFERENCE not in repr(store.jobs(limit=20))
    store.close()
