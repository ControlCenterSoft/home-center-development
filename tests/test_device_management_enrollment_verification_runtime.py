from pathlib import Path

from home_center.device_management_enrollment_execution_runtime import (
    KEY_PREFIX as EXECUTION_KEY_PREFIX,
    RECEIPT_SCHEMA as EXECUTION_RECEIPT_SCHEMA,
    START_ACTION,
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
)
from home_center.device_management_enrollment_verification_runtime import (
    VERIFY_ACTION,
    VERIFY_REQUEST_SCHEMA,
    DeviceManagementEnrollmentVerificationRuntimeService,
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
PLAN_ID = "dmpexec-" + "a" * 24
PROVIDER_ID = "provider-test"
PROVIDER_OPERATION_ID = "provider-op-1"
DEVICE_ID = "device-1"
MEMBER_ID = "member-parent"


class VerificationAdapter:
    def __init__(self, *, complete: bool = True) -> None:
        self.complete = complete
        self.calls = 0

    def verify(self, request):
        self.calls += 1
        return {
            "schema": "home-center.device-management-enrollment-verification-result.v1",
            "provider_operation_id": request.provider_operation_id,
            "device_id": request.device_id,
            "certificate_present": self.complete,
            "profile_present": self.complete,
            "agent_present": self.complete,
            "management_active": self.complete,
            "observed_at": "2026-09-12T04:30:00Z",
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        }


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
    job, created = store.create_action_job(
        action_id=START_ACTION,
        actor=ACTOR,
        reason="test provider acceptance",
        idempotency_key="execution-key-1",
        request_hash="a" * 64,
        preflight={"plan_id": PLAN_ID},
        steps=[{"step": "provider-start", "state": "pending"}],
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
    )
    receipt = {
        "schema": EXECUTION_RECEIPT_SCHEMA,
        "state": "provider-accepted",
        "job_id": succeeded["job_id"],
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
    store.set_meta(
        EXECUTION_KEY_PREFIX + PLAN_ID,
        {
            "schema": EXECUTION_STATE_SCHEMA,
            "status": "provider-accepted",
            "receipt": receipt,
        },
    )
    return store


def test_verification_runtime_persists_positive_evidence_without_mutating_household(tmp_path):
    store = _store(tmp_path)
    try:
        service = DeviceManagementEnrollmentVerificationRuntimeService(store)
        adapter = VerificationAdapter(complete=True)
        service.register_adapter(PROVIDER_ID, adapter)

        receipt = service.verify(
            actor=ACTOR,
            request={
                "schema": VERIFY_REQUEST_SCHEMA,
                "plan_id": PLAN_ID,
                "idempotency_key": "verify-key-1",
            },
            correlation_id="test-verify-positive",
        )

        assert receipt["state"] == "post-condition-verified"
        assert receipt["post_condition_verified"] is True
        assert receipt["managed_state_change_authorized"] is True
        assert receipt["provider_mutation_authorized"] is False
        assert receipt["policy_application_authorized"] is False
        assert adapter.calls == 1

        persisted = service.receipt(receipt["job_id"])
        assert persisted == receipt
        evidence = service.evidence(receipt["verification_id"])
        assert evidence["verified"] is True

        raw_household = store.get_meta(HOUSEHOLD_STATE_KEY)
        device = raw_household["snapshot"]["household"]["devices"][0]
        assert device["managed"] is False

        replay = service.verify(
            actor=ACTOR,
            request={
                "schema": VERIFY_REQUEST_SCHEMA,
                "plan_id": PLAN_ID,
                "idempotency_key": "verify-key-1",
            },
            correlation_id="test-verify-positive-replay",
        )
        assert replay == receipt
        assert adapter.calls == 1
        assert store.job(receipt["job_id"])["job_type"] == VERIFY_ACTION
    finally:
        store.close()


def test_verification_runtime_persists_negative_evidence_fail_closed(tmp_path):
    store = _store(tmp_path)
    try:
        service = DeviceManagementEnrollmentVerificationRuntimeService(store)
        adapter = VerificationAdapter(complete=False)
        service.register_adapter(PROVIDER_ID, adapter)

        receipt = service.verify(
            actor=ACTOR,
            request={
                "schema": VERIFY_REQUEST_SCHEMA,
                "plan_id": PLAN_ID,
                "idempotency_key": "verify-key-2",
            },
            correlation_id="test-verify-negative",
        )

        assert receipt["state"] == "post-condition-not-verified"
        assert receipt["post_condition_verified"] is False
        assert receipt["managed_state_change_authorized"] is False
        evidence = service.evidence(receipt["verification_id"])
        assert evidence["verified"] is False
        assert set(evidence["failure_reasons"]) == {
            "certificate-missing",
            "profile-missing",
            "agent-missing",
            "management-inactive",
        }
        assert store.get_meta(HOUSEHOLD_STATE_KEY)["snapshot"]["household"]["devices"][0]["managed"] is False
    finally:
        store.close()
