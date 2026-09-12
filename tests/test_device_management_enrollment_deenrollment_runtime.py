from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_deenrollment import (
    DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
)
from home_center.device_management_enrollment_deenrollment_runtime import (
    DEENROLLMENT_ACTION,
    DEENROLLMENT_RUNTIME_REQUEST_SCHEMA,
    DeviceManagementEnrollmentDeenrollmentRuntimeError,
    DeviceManagementEnrollmentDeenrollmentRuntimeService,
    _hash,
)
from home_center.device_management_enrollment_verification import (
    VERIFICATION_RESULT_SCHEMA,
    build_verification_request,
    evaluate_verification_result,
    verification_result_from_dict,
)
from home_center.device_management_enrollment_verification_runtime import (
    VERIFY_ACTION,
    VERIFY_KEY_PREFIX,
    VERIFY_STATE_SCHEMA,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_runtime import (
    ActorBinding,
    HOUSEHOLD_STATE_KEY,
    _persisted,
)
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore


ACTOR = "local-admin:admin"
MEMBER_ID = "member-parent"
DEVICE_MEMBER_ID = "member-child"
DEVICE_ID = "device-phone"
PLAN_ID = "dmpexec-" + "a" * 24
PROVIDER_ID = "provider-mdm"
PROVIDER_OPERATION_ID = "provider-enroll-op-1"
NOW = "2026-09-12T05:20:00Z"


class DeenrollmentAdapter:
    def __init__(self) -> None:
        self.calls = 0
        self.requests = []

    def de_enroll(self, request):
        self.calls += 1
        self.requests.append(request)
        return {
            "schema": DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
            "state": "accepted",
            "cleanup_operation_id": "provider-cleanup-op-1",
            "post_cleanup_verified": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
        }


def _execution_receipt() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": "job-enrollment-1",
        "retry_of_job_id": None,
        "plan_id": PLAN_ID,
        "selection_proposal_id": "dmpsel-" + "b" * 24,
        "provider_id": PROVIDER_ID,
        "provider_operation_id": PROVIDER_OPERATION_ID,
        "device_id": DEVICE_ID,
        "member_id": DEVICE_MEMBER_ID,
        "one_time_artifact": None,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _store(tmp_path: Path) -> tuple[StateStore, str]:
    store = StateStore(tmp_path / "state.sqlite3", b"k" * 32, "test-cluster")
    household = Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id=MEMBER_ID,
                display_name="Parent",
                role=HouseholdRole.PARENT,
            ),
            FamilyMember(
                member_id=DEVICE_MEMBER_ID,
                display_name="Child",
                role=HouseholdRole.CHILD,
            ),
        ),
        devices=(
            ManagedDevice(
                device_id=DEVICE_ID,
                member_id=DEVICE_MEMBER_ID,
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
        _persisted(
            snapshot,
            (ActorBinding(actor=ACTOR, member_id=MEMBER_ID),),
        ),
    )

    request = build_verification_request(
        execution_receipt=_execution_receipt(),
        snapshot=snapshot,
    )
    provider_result = verification_result_from_dict(
        {
            "schema": VERIFICATION_RESULT_SCHEMA,
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "certificate_present": True,
            "profile_present": False,
            "agent_present": True,
            "management_active": False,
            "observed_at": "2026-09-12T05:15:00Z",
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        },
        request=request,
    )
    evidence = evaluate_verification_result(
        request=request,
        result=provider_result,
    )
    assert evidence.verified is False

    job, created = store.create_action_job(
        action_id=VERIFY_ACTION,
        actor=ACTOR,
        reason="persist failed verification evidence",
        idempotency_key="verify-negative-0001",
        request_hash="f" * 64,
        preflight={"verification_id": evidence.verification_id},
        steps=[{"step": "provider-readback", "state": "pending"}],
    )
    assert created
    running = store.transition_action_job(
        job["job_id"],
        expected_state="preflight",
        new_state="running",
    )
    verifying = store.transition_action_job(
        running["job_id"],
        expected_state="running",
        new_state="verifying",
    )
    succeeded = store.transition_action_job(
        verifying["job_id"],
        expected_state="verifying",
        new_state="succeeded",
        evidence=evidence.to_dict(),
    )
    store.set_meta(
        VERIFY_KEY_PREFIX + evidence.verification_id,
        {
            "schema": VERIFY_STATE_SCHEMA,
            "status": "complete",
            "job_id": succeeded["job_id"],
            "request": request.to_dict(),
            "evidence": evidence.to_dict(),
            "receipt": {
                "schema": "home-center.device-management-enrollment-verification-runtime-receipt.v1",
                "state": "post-condition-not-verified",
                "job_id": succeeded["job_id"],
                "verification_id": evidence.verification_id,
            },
        },
    )
    return store, evidence.verification_id


def _request(verification_id: str) -> dict[str, object]:
    return {
        "schema": DEENROLLMENT_RUNTIME_REQUEST_SCHEMA,
        "verification_id": verification_id,
        "confirmed": True,
        "idempotency_key": "de-enroll-request-0001",
    }


def _service(store: StateStore) -> DeviceManagementEnrollmentDeenrollmentRuntimeService:
    return DeviceManagementEnrollmentDeenrollmentRuntimeService(
        store,
        now=lambda: NOW,
    )


def _preflight(service, verification_id: str) -> dict[str, object]:
    _evidence, cleanup, plan, confirmation = service._fresh_preflight(
        actor=ACTOR,
        verification_id=verification_id,
        idempotency_key="de-enroll-request-0001",
    )
    return {
        "schema": "home-center.device-management-enrollment-deenrollment-preflight.v1",
        "verification_id": verification_id,
        "confirmed": True,
        "cleanup_plan": cleanup.to_dict(),
        "de_enrollment_plan": plan.to_dict(),
        "confirmation": confirmation.to_dict(),
        "provider_mutation_authorized": True,
        "credential_value_access_authorized": False,
        "retry_planning_allowed": False,
        "retry_execution_authorized": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _durable_job(service, verification_id: str):
    request = _request(verification_id)
    job, created = service.store.create_action_job(
        action_id=DEENROLLMENT_ACTION,
        actor=ACTOR,
        reason="explicit cleanup of residual provider enrollment state",
        idempotency_key=request["idempotency_key"],
        request_hash=_hash(
            {
                "verification_id": verification_id,
                "confirmed": True,
                "idempotency_key": request["idempotency_key"],
            }
        ),
        preflight=_preflight(service, verification_id),
        steps=[
            {"step": "revalidate-negative-evidence", "state": "succeeded"},
            {"step": "provider-de-enroll", "state": "pending"},
            {"step": "persist-provider-acceptance", "state": "pending"},
        ],
    )
    assert created
    return request, job


def test_deenrollment_runtime_persists_provider_acceptance_and_replays_without_second_call(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        service = _service(store)
        adapter = DeenrollmentAdapter()
        service.register_adapter(PROVIDER_ID, adapter)

        receipt = service.de_enroll(
            actor=ACTOR,
            request=_request(verification_id),
            correlation_id="de-enroll-first",
        )
        assert receipt["state"] == "provider-cleanup-accepted"
        assert receipt["post_cleanup_verified"] is False
        assert receipt["retry_planning_allowed"] is False
        assert receipt["retry_execution_authorized"] is False
        assert receipt["managed_state_change_authorized"] is False
        assert adapter.calls == 1

        replay = service.de_enroll(
            actor=ACTOR,
            request=_request(verification_id),
            correlation_id="de-enroll-replay",
        )
        assert replay == receipt
        assert adapter.calls == 1

        job = store.job(receipt["job_id"])
        assert job["state"] == "succeeded"
        assert job["evidence"]["provider_cleanup_command_accepted"] is True
        assert job["evidence"]["post_cleanup_verified"] is False
        assert isinstance(job["evidence"]["audit_event_id"], str)
    finally:
        store.close()


def test_missing_adapter_stays_preflight_and_can_resume_after_registration(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        service = _service(store)
        with pytest.raises(
            DeviceManagementEnrollmentDeenrollmentRuntimeError,
            match="adapter_unavailable",
        ):
            service.de_enroll(
                actor=ACTOR,
                request=_request(verification_id),
                correlation_id="de-enroll-no-adapter",
            )
        jobs = [job for job in store.jobs() if job["job_type"] == DEENROLLMENT_ACTION]
        assert len(jobs) == 1
        assert jobs[0]["state"] == "preflight"

        adapter = DeenrollmentAdapter()
        service.register_adapter(PROVIDER_ID, adapter)
        receipt = service.de_enroll(
            actor=ACTOR,
            request=_request(verification_id),
            correlation_id="de-enroll-adapter-restored",
        )
        assert receipt["state"] == "provider-cleanup-accepted"
        assert adapter.calls == 1
    finally:
        store.close()


def test_running_recovery_is_ambiguous_and_never_reinvokes_provider(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        service = _service(store)
        adapter = DeenrollmentAdapter()
        service.register_adapter(PROVIDER_ID, adapter)
        request, job = _durable_job(service, verification_id)
        store.transition_action_job(
            job["job_id"],
            expected_state="preflight",
            new_state="running",
            result={
                "schema": "home-center.device-management-enrollment-deenrollment-dispatch.v1",
                "provider_acceptance_unknown": True,
            },
        )

        with pytest.raises(
            DeviceManagementEnrollmentDeenrollmentRuntimeError,
            match="provider_acceptance_unknown",
        ):
            service.de_enroll(
                actor=ACTOR,
                request=request,
                correlation_id="de-enroll-recover-running",
            )
        assert adapter.calls == 0
        failed = store.job(job["job_id"])
        assert failed["state"] == "failed"
        assert failed["result"]["provider_acceptance_unknown"] is True
    finally:
        store.close()


def test_verifying_recovery_finalizes_persisted_acceptance_without_provider_replay(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        service = _service(store)
        adapter = DeenrollmentAdapter()
        service.register_adapter(PROVIDER_ID, adapter)
        request, job = _durable_job(service, verification_id)
        running = store.transition_action_job(
            job["job_id"],
            expected_state="preflight",
            new_state="running",
        )
        verifying = store.transition_action_job(
            running["job_id"],
            expected_state="running",
            new_state="verifying",
            result={
                "schema": DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
                "state": "accepted",
                "cleanup_operation_id": "provider-cleanup-op-recovered",
                "post_cleanup_verified": False,
                "retry_planning_allowed": False,
                "retry_execution_authorized": False,
                "managed_state_change_authorized": False,
            },
        )
        assert verifying["state"] == "verifying"

        receipt = service.de_enroll(
            actor=ACTOR,
            request=request,
            correlation_id="de-enroll-recover-verifying",
        )
        assert receipt["cleanup_operation_id"] == "provider-cleanup-op-recovered"
        assert receipt["post_cleanup_verified"] is False
        assert adapter.calls == 0
        done = store.job(job["job_id"])
        assert done["state"] == "succeeded"
        assert done["evidence"]["recovered_after_restart"] is True
    finally:
        store.close()
