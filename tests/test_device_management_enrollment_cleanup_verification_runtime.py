from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_cleanup_verification_runtime import (
    CLEANUP_VERIFY_ACTION,
    CLEANUP_VERIFY_REQUEST_SCHEMA,
    DeviceManagementEnrollmentCleanupVerificationRuntimeError,
    DeviceManagementEnrollmentCleanupVerificationRuntimeService,
)
from home_center.device_management_enrollment_deenrollment import (
    DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
)
from home_center.device_management_enrollment_deenrollment_runtime import (
    DEENROLLMENT_RUNTIME_REQUEST_SCHEMA,
    DeviceManagementEnrollmentDeenrollmentRuntimeService,
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
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore


ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
DEVICE = "device-phone"
PROVIDER = "provider-mdm"
PLAN_ID = "dmpexec-" + "a" * 24
PROVIDER_OPERATION = "provider-enroll-op-1"


class CleanupCommandAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def de_enroll(self, request):
        self.calls += 1
        return {
            "schema": DEENROLLMENT_ADAPTER_RESULT_SCHEMA,
            "state": "accepted",
            "cleanup_operation_id": "provider-cleanup-op-1",
            "post_cleanup_verified": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
        }


class ReadbackAdapter:
    def __init__(
        self,
        *,
        flags: tuple[bool, bool, bool, bool] = (False, False, False, False),
        observed_at: str = "2099-01-01T00:00:00Z",
    ) -> None:
        self.flags = flags
        self.observed_at = observed_at
        self.calls = 0

    def verify(self, request):
        self.calls += 1
        certificate, profile, agent, active = self.flags
        return {
            "schema": VERIFICATION_RESULT_SCHEMA,
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "certificate_present": certificate,
            "profile_present": profile,
            "agent_present": agent,
            "management_active": active,
            "observed_at": self.observed_at,
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        }


class CrashReadbackAdapter(ReadbackAdapter):
    def verify(self, request):
        self.calls += 1
        raise SystemExit("simulated process crash during read-only provider call")


class CrashAfterPersistService(DeviceManagementEnrollmentCleanupVerificationRuntimeService):
    def _finalize(self, **kwargs):
        raise SystemExit("simulated process crash after durable provider observation")


def _execution_receipt() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": "job-enrollment-1",
        "retry_of_job_id": None,
        "plan_id": PLAN_ID,
        "selection_proposal_id": "dmpsel-" + "b" * 24,
        "provider_id": PROVIDER,
        "provider_operation_id": PROVIDER_OPERATION,
        "device_id": DEVICE,
        "member_id": CHILD,
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
            FamilyMember(member_id=PARENT, display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id=CHILD, display_name="Child", role=HouseholdRole.CHILD),
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

    request = build_verification_request(
        execution_receipt=_execution_receipt(),
        snapshot=snapshot,
    )
    result = verification_result_from_dict(
        {
            "schema": VERIFICATION_RESULT_SCHEMA,
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "certificate_present": True,
            "profile_present": False,
            "agent_present": True,
            "management_active": False,
            "observed_at": "2026-09-12T05:00:00Z",
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        },
        request=request,
    )
    evidence = evaluate_verification_result(request=request, result=result)
    verify_job, created = store.create_action_job(
        action_id=VERIFY_ACTION,
        actor=ACTOR,
        reason="persist negative enrollment verification",
        idempotency_key="verify-negative-0001",
        request_hash="a" * 64,
        preflight={"verification_id": evidence.verification_id},
        steps=[{"step": "provider-readback", "state": "pending"}],
    )
    assert created
    running = store.transition_action_job(
        verify_job["job_id"],
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
            "receipt": {"verification_id": evidence.verification_id},
        },
    )
    return store, evidence.verification_id


def _deenroll(store: StateStore, verification_id: str) -> dict[str, object]:
    service = DeviceManagementEnrollmentDeenrollmentRuntimeService(
        store,
        now=lambda: "2026-09-12T05:05:00Z",
    )
    adapter = CleanupCommandAdapter()
    service.register_adapter(PROVIDER, adapter)
    receipt = service.de_enroll(
        actor=ACTOR,
        request={
            "schema": DEENROLLMENT_RUNTIME_REQUEST_SCHEMA,
            "verification_id": verification_id,
            "confirmed": True,
            "idempotency_key": "de-enroll-request-0001",
        },
        correlation_id="de-enroll-for-cleanup-verification",
    )
    assert adapter.calls == 1
    return receipt


def _request(de_enrollment_id: str, key: str = "cleanup-verify-0001") -> dict[str, object]:
    return {
        "schema": CLEANUP_VERIFY_REQUEST_SCHEMA,
        "de_enrollment_id": de_enrollment_id,
        "idempotency_key": key,
    }


def test_post_cleanup_readback_allows_only_retry_planning_when_provider_state_is_absent(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        de_receipt = _deenroll(store, verification_id)
        service = DeviceManagementEnrollmentCleanupVerificationRuntimeService(store)
        adapter = ReadbackAdapter(flags=(False, False, False, False))
        service.register_adapter(PROVIDER, adapter)

        receipt = service.verify_cleanup(
            actor=ACTOR,
            request=_request(de_receipt["de_enrollment_id"]),
            correlation_id="cleanup-verify-empty",
        )
        assert receipt["state"] == "post-cleanup-assessed"
        assert receipt["residual_provider_state"] is False
        assert receipt["retry_planning_allowed"] is True
        assert receipt["retry_execution_authorized"] is False
        assert receipt["provider_mutation_authorized"] is False
        assert receipt["managed_state_change_authorized"] is False
        assert adapter.calls == 1

        replay = service.verify_cleanup(
            actor=ACTOR,
            request=_request(de_receipt["de_enrollment_id"]),
            correlation_id="cleanup-verify-empty-replay",
        )
        assert replay == receipt
        assert adapter.calls == 1
    finally:
        store.close()


def test_fully_residual_state_is_valid_assessment_but_retry_planning_stays_denied(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        de_receipt = _deenroll(store, verification_id)
        service = DeviceManagementEnrollmentCleanupVerificationRuntimeService(store)
        adapter = ReadbackAdapter(flags=(True, True, True, True))
        service.register_adapter(PROVIDER, adapter)

        receipt = service.verify_cleanup(
            actor=ACTOR,
            request=_request(de_receipt["de_enrollment_id"], "cleanup-verify-residual"),
            correlation_id="cleanup-verify-residual",
        )
        assert receipt["residual_provider_state"] is True
        assert receipt["retry_planning_allowed"] is False
        assert receipt["retry_execution_authorized"] is False
        assert receipt["reason"] == "residual-provider-state"
    finally:
        store.close()


def test_running_read_only_job_can_recover_by_repeating_exact_provider_readback(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        de_receipt = _deenroll(store, verification_id)
        request = _request(de_receipt["de_enrollment_id"], "cleanup-verify-crash-running")

        crashing = DeviceManagementEnrollmentCleanupVerificationRuntimeService(store)
        crash_adapter = CrashReadbackAdapter()
        crashing.register_adapter(PROVIDER, crash_adapter)
        with pytest.raises(SystemExit):
            crashing.verify_cleanup(
                actor=ACTOR,
                request=request,
                correlation_id="cleanup-verify-crash-running",
            )
        jobs = [job for job in store.jobs() if job["job_type"] == CLEANUP_VERIFY_ACTION]
        assert jobs[0]["state"] == "running"
        assert crash_adapter.calls == 1

        recovered = DeviceManagementEnrollmentCleanupVerificationRuntimeService(store)
        adapter = ReadbackAdapter()
        recovered.register_adapter(PROVIDER, adapter)
        receipt = recovered.verify_cleanup(
            actor=ACTOR,
            request=request,
            correlation_id="cleanup-verify-recover-running",
        )
        assert receipt["retry_planning_allowed"] is True
        assert adapter.calls == 1
    finally:
        store.close()


def test_verifying_job_recovers_from_persisted_observation_without_provider_replay(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        de_receipt = _deenroll(store, verification_id)
        request = _request(de_receipt["de_enrollment_id"], "cleanup-verify-crash-verifying")

        crashing = CrashAfterPersistService(store)
        first_adapter = ReadbackAdapter()
        crashing.register_adapter(PROVIDER, first_adapter)
        with pytest.raises(SystemExit):
            crashing.verify_cleanup(
                actor=ACTOR,
                request=request,
                correlation_id="cleanup-verify-crash-verifying",
            )
        jobs = [job for job in store.jobs() if job["job_type"] == CLEANUP_VERIFY_ACTION]
        assert jobs[0]["state"] == "verifying"
        assert first_adapter.calls == 1

        recovered = DeviceManagementEnrollmentCleanupVerificationRuntimeService(store)
        second_adapter = ReadbackAdapter(flags=(True, True, True, True))
        recovered.register_adapter(PROVIDER, second_adapter)
        receipt = recovered.verify_cleanup(
            actor=ACTOR,
            request=request,
            correlation_id="cleanup-verify-recover-verifying",
        )
        assert receipt["retry_planning_allowed"] is True
        assert second_adapter.calls == 0
        done = store.job(jobs[0]["job_id"])
        assert done["state"] == "succeeded"
        assert done["evidence"]["recovered_after_restart"] is True
    finally:
        store.close()


def test_readback_timestamp_must_be_after_durable_deenrollment_acceptance(tmp_path):
    store, verification_id = _store(tmp_path)
    try:
        de_receipt = _deenroll(store, verification_id)
        service = DeviceManagementEnrollmentCleanupVerificationRuntimeService(store)
        adapter = ReadbackAdapter(observed_at="2020-01-01T00:00:00Z")
        service.register_adapter(PROVIDER, adapter)

        with pytest.raises(
            DeviceManagementEnrollmentCleanupVerificationRuntimeError,
            match="readback_not_after_deenrollment",
        ):
            service.verify_cleanup(
                actor=ACTOR,
                request=_request(de_receipt["de_enrollment_id"], "cleanup-verify-old-readback"),
                correlation_id="cleanup-verify-old-readback",
            )
        assert adapter.calls == 1
        jobs = [job for job in store.jobs() if job["job_type"] == CLEANUP_VERIFY_ACTION]
        assert jobs[0]["state"] == "failed"
        assert jobs[0]["result"]["retry_planning_allowed"] is False
    finally:
        store.close()
