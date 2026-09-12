from pathlib import Path

import pytest

from home_center.device_management_enrollment_managed_state_runtime import (
    COMMIT_ACTION,
    COMMIT_REQUEST_SCHEMA,
    DeviceManagementEnrollmentManagedStateRuntimeError,
    DeviceManagementEnrollmentManagedStateRuntimeService,
)
from home_center.device_management_enrollment_verification import (
    EXECUTION_RECEIPT_SCHEMA,
    DeviceManagementEnrollmentVerificationError,
    build_verification_request,
    evaluate_verification_result,
    verification_result_from_dict,
)
from home_center.device_management_enrollment_verification_persistence import (
    verification_evidence_from_dict,
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
    _state_from_dict,
)
from home_center.household_store import (
    build_household_replacement,
    build_household_snapshot,
)
from home_center.store import StateStore


ACTOR = "local-admin:admin"
PLAN_ID = "dmpexec-" + "a" * 24
PROVIDER_ID = "provider-test"
PROVIDER_OPERATION_ID = "provider-op-1"
DEVICE_ID = "device-1"
MEMBER_ID = "member-parent"


def _store(tmp_path: Path) -> StateStore:
    store = StateStore(tmp_path / "state.sqlite3", b"k" * 32, "test-cluster")
    household = Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id=MEMBER_ID,
                display_name="Parent",
                role=HouseholdRole.PARENT,
            ),
        ),
        devices=(
            ManagedDevice(
                device_id=DEVICE_ID,
                member_id=MEMBER_ID,
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
    return store


def _verification_evidence(store: StateStore, *, complete: bool, suffix: str):
    raw = store.get_meta(HOUSEHOLD_STATE_KEY)
    snapshot, _bindings = _state_from_dict(raw)
    execution_receipt = {
        "schema": EXECUTION_RECEIPT_SCHEMA,
        "state": "provider-accepted",
        "job_id": "execution-job-" + suffix,
        "retry_of_job_id": None,
        "plan_id": PLAN_ID,
        "selection_proposal_id": "dmpsel-" + "b" * 24,
        "provider_id": PROVIDER_ID,
        "provider_operation_id": PROVIDER_OPERATION_ID,
        "device_id": DEVICE_ID,
        "member_id": MEMBER_ID,
        "one_time_artifact": None,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    request = build_verification_request(
        execution_receipt=execution_receipt,
        snapshot=snapshot,
    )
    result = verification_result_from_dict(
        {
            "schema": "home-center.device-management-enrollment-verification-result.v1",
            "provider_operation_id": PROVIDER_OPERATION_ID,
            "device_id": DEVICE_ID,
            "certificate_present": complete,
            "profile_present": complete,
            "agent_present": complete,
            "management_active": complete,
            "observed_at": "2026-09-12T04:30:00Z",
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        },
        request=request,
    )
    evidence = evaluate_verification_result(request=request, result=result)

    job, created = store.create_action_job(
        action_id=VERIFY_ACTION,
        actor=ACTOR,
        reason="test post-condition verification",
        idempotency_key="verify-seed-" + suffix,
        request_hash=("a" if complete else "b") * 64,
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
    done = store.transition_action_job(
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
            "job_id": done["job_id"],
            "request": request.to_dict(),
            "evidence": evidence.to_dict(),
            "receipt": {"verification_id": evidence.verification_id},
        },
    )
    return evidence


def _request(evidence, key: str = "managed-commit-key-1") -> dict[str, object]:
    return {
        "schema": COMMIT_REQUEST_SCHEMA,
        "verification_id": evidence.verification_id,
        "idempotency_key": key,
    }


def test_managed_state_commit_is_atomic_audited_and_idempotent(tmp_path):
    store = _store(tmp_path)
    try:
        evidence = _verification_evidence(store, complete=True, suffix="positive")
        service = DeviceManagementEnrollmentManagedStateRuntimeService(store)

        receipt = service.commit(
            actor=ACTOR,
            request=_request(evidence),
            correlation_id="test-managed-commit",
        )

        assert receipt["state"] == "managed-state-committed"
        assert receipt["post_condition_verified"] is True
        assert receipt["managed_state_change_committed"] is True
        assert receipt["provider_mutation_authorized"] is False
        assert receipt["policy_application_authorized"] is False
        assert receipt["infrastructure_mutation_authorized"] is False
        assert receipt["external_publication_authorized"] is False

        current, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
        device = next(item for item in current.household.devices if item.device_id == DEVICE_ID)
        assert device.managed is True
        assert current.generation == 2
        assert current.resource_version == receipt["resource_version"]
        assert current.snapshot_id == receipt["snapshot_id"]

        job = store.job(receipt["job_id"])
        assert job["job_type"] == COMMIT_ACTION
        assert job["state"] == "succeeded"
        assert job["result"] == receipt
        assert job["evidence"]["audit_event_id"] == receipt["audit_event_id"]

        events = store.audit_events(100)
        event = next(item for item in events if item["event_id"] == receipt["audit_event_id"])
        assert event["action"] == COMMIT_ACTION
        assert event["target"] == DEVICE_ID
        assert event["details"]["scope"] == "local-household-managed-state-only"
        store.verify_audit_chain()

        replay = service.commit(
            actor=ACTOR,
            request=_request(evidence),
            correlation_id="test-managed-commit-replay",
        )
        assert replay == receipt
        current_after_replay, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
        assert current_after_replay.generation == 2
    finally:
        store.close()


def test_managed_state_commit_rejects_negative_verification_without_mutation(tmp_path):
    store = _store(tmp_path)
    try:
        evidence = _verification_evidence(store, complete=False, suffix="negative")
        service = DeviceManagementEnrollmentManagedStateRuntimeService(store)

        with pytest.raises(DeviceManagementEnrollmentManagedStateRuntimeError) as raised:
            service.commit(
                actor=ACTOR,
                request=_request(evidence, "managed-commit-key-2"),
                correlation_id="test-managed-negative",
            )
        assert raised.value.code == "device_management_enrollment_post_condition_not_verified"

        current, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
        assert current.generation == 1
        assert current.household.devices[0].managed is False
        failed = next(job for job in store.jobs(20) if job["job_type"] == COMMIT_ACTION)
        assert failed["state"] == "failed"
    finally:
        store.close()


def test_managed_state_commit_rejects_stale_household_without_mutation(tmp_path):
    store = _store(tmp_path)
    try:
        evidence = _verification_evidence(store, complete=True, suffix="stale")
        raw = store.get_meta(HOUSEHOLD_STATE_KEY)
        current, bindings = _state_from_dict(raw)
        changed = Household(
            household_id=current.household_id,
            members=current.household.members,
            devices=(
                ManagedDevice(
                    device_id=DEVICE_ID,
                    member_id=MEMBER_ID,
                    display_name="Renamed Phone",
                    managed=False,
                ),
            ),
        )
        replacement, _commit = build_household_replacement(
            current,
            changed,
            expected_resource_version=current.resource_version,
        )
        store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(replacement, bindings))

        service = DeviceManagementEnrollmentManagedStateRuntimeService(store)
        with pytest.raises(DeviceManagementEnrollmentManagedStateRuntimeError) as raised:
            service.commit(
                actor=ACTOR,
                request=_request(evidence, "managed-commit-key-3"),
                correlation_id="test-managed-stale",
            )
        assert raised.value.code == "device_management_enrollment_verification_stale"

        after, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
        assert after.generation == 2
        assert after.household.devices[0].display_name == "Renamed Phone"
        assert after.household.devices[0].managed is False
    finally:
        store.close()


def test_managed_state_commit_resumes_verifying_job_after_restart(tmp_path):
    store = _store(tmp_path)
    try:
        evidence = _verification_evidence(store, complete=True, suffix="restart")
        request = _request(evidence, "managed-commit-key-4")
        first = DeviceManagementEnrollmentManagedStateRuntimeService(store)

        def simulated_crash(**_kwargs):
            raise RuntimeError("simulated process crash before atomic commit")

        first._atomic_commit = simulated_crash  # type: ignore[method-assign]
        with pytest.raises(RuntimeError):
            first.commit(
                actor=ACTOR,
                request=request,
                correlation_id="test-managed-crash",
            )

        interrupted = next(job for job in store.jobs(20) if job["job_type"] == COMMIT_ACTION)
        assert interrupted["state"] == "verifying"
        before, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
        assert before.generation == 1
        assert before.household.devices[0].managed is False

        restarted = DeviceManagementEnrollmentManagedStateRuntimeService(store)
        receipt = restarted.commit(
            actor=ACTOR,
            request=request,
            correlation_id="test-managed-recover",
        )
        assert receipt["job_id"] == interrupted["job_id"]
        assert receipt["managed_state_change_committed"] is True
        after, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
        assert after.generation == 2
        assert after.household.devices[0].managed is True
        store.verify_audit_chain()
    finally:
        store.close()


def test_persisted_verification_evidence_rejects_authority_tampering(tmp_path):
    store = _store(tmp_path)
    try:
        evidence = _verification_evidence(store, complete=False, suffix="tamper")
        raw = evidence.to_dict()
        raw["managed_state_change_authorized"] = True
        with pytest.raises(DeviceManagementEnrollmentVerificationError) as raised:
            verification_evidence_from_dict(raw)
        assert raised.value.code == "device_management_enrollment_verification_evidence_invalid"
    finally:
        store.close()
