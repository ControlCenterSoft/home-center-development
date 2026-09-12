from __future__ import annotations

from pathlib import Path

from home_center.device_management_enrollment_execution_runtime import RETRY_ACTION, START_ACTION
from home_center.device_management_enrollment_execution_runtime_safe import (
    SafeDeviceManagementEnrollmentExecutionRuntimeService,
)
from home_center.store import StateStore


PLAN_ID = "dmpexec-0123456789abcdef01234567"
STATE_KEY = f"cozy.household.device-enrollment-execution.{PLAN_ID}"


def _store(path: Path) -> StateStore:
    return StateStore(path, b"r" * 32, "cluster-recovery-test")


def test_execution_envelope_and_job_evidence_survive_restart(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    before = _store(path)
    envelope = {
        "schema": "home-center.device-management-enrollment-execution-state.v1",
        "status": "provider-accepted",
        "plan": {"plan_id": PLAN_ID},
        "receipt": {
            "schema": "home-center.device-management-enrollment-execution-receipt.v1",
            "state": "provider-accepted",
            "job_id": "placeholder-until-job-created",
            "plan_id": PLAN_ID,
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        },
        "cancel_receipt": None,
    }
    before.set_meta(STATE_KEY, envelope)
    job, created = before.create_action_job(
        action_id=START_ACTION,
        actor="local-admin:admin",
        reason="recovery persistence test",
        idempotency_key="restart-idempotency-key",
        request_hash="a" * 64,
        preflight={
            "schema": "home-center.device-management-enrollment-execution-preflight.v1",
            "plan_id": PLAN_ID,
            "provider_id": "android-mdm-primary",
            "provider_execution_authorized": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        },
        steps=[{"step": "provider-start", "state": "pending"}],
    )
    assert created is True
    running = before.transition_action_job(job["job_id"], expected_state="preflight", new_state="running")
    verifying = before.transition_action_job(
        running["job_id"],
        expected_state="running",
        new_state="verifying",
        result={
            "state": "provider-accepted",
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        },
    )
    done = before.transition_action_job(
        verifying["job_id"],
        expected_state="verifying",
        new_state="succeeded",
        evidence={
            "scope": "provider-command-accepted-only",
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
            "next_required_boundary": "post-condition-verification",
        },
    )
    envelope["receipt"]["job_id"] = done["job_id"]
    before.set_meta(STATE_KEY, envelope)
    before.close()

    after = _store(path)
    assert after.get_meta(STATE_KEY) == envelope
    recovered = after.job(done["job_id"])
    assert recovered is not None
    assert recovered["state"] == "succeeded"
    assert recovered["idempotency_key"] == "restart-idempotency-key"
    assert recovered["preflight"]["provider_execution_authorized"] is False
    assert recovered["evidence"]["scope"] == "provider-command-accepted-only"
    assert recovered["evidence"]["enrollment_completed"] is False
    assert recovered["evidence"]["post_condition_verified"] is False
    assert recovered["evidence"]["managed_state_change_authorized"] is False
    after.close()


def test_action_job_idempotency_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    first = _store(path)
    job, created = first.create_action_job(
        action_id=START_ACTION,
        actor="local-admin:admin",
        reason="idempotency restart test",
        idempotency_key="durable-key",
        request_hash="b" * 64,
        preflight={"plan_id": PLAN_ID},
        steps=[],
    )
    assert created is True
    first.close()

    second = _store(path)
    replay, replay_created = second.create_action_job(
        action_id=START_ACTION,
        actor="local-admin:admin",
        reason="idempotency restart test",
        idempotency_key="durable-key",
        request_hash="b" * 64,
        preflight={"plan_id": PLAN_ID},
        steps=[],
    )
    assert replay_created is False
    assert replay["job_id"] == job["job_id"]
    second.close()


def test_attempt_order_is_deterministic_when_created_at_collides(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    store = _store(path)
    first, _ = store.create_action_job(
        action_id=START_ACTION,
        actor="local-admin:admin",
        reason="first provider attempt",
        idempotency_key="attempt-1",
        request_hash="c" * 64,
        preflight={"plan_id": PLAN_ID},
        steps=[],
    )
    first_running = store.transition_action_job(first["job_id"], expected_state="preflight", new_state="running")
    store.transition_action_job(
        first_running["job_id"],
        expected_state="running",
        new_state="failed",
        result={"retry_safe": True},
    )
    second, _ = store.create_action_job(
        action_id=RETRY_ACTION,
        actor="local-admin:admin",
        reason="second provider attempt",
        idempotency_key="attempt-2",
        request_hash="d" * 64,
        preflight={"plan_id": PLAN_ID, "retry_of_job_id": first["job_id"]},
        steps=[],
    )
    second_running = store.transition_action_job(second["job_id"], expected_state="preflight", new_state="running")
    store.transition_action_job(
        second_running["job_id"],
        expected_state="running",
        new_state="failed",
        result={"retry_safe": False},
    )

    # utc_now() is second-resolution. Force the collision so a safety decision can
    # never depend on SQLite's unspecified ordering for equal timestamps.
    with store._lock, store._connection:
        store._connection.execute(
            "UPDATE jobs SET created_at=? WHERE job_id IN (?,?)",
            ("2026-09-12T00:00:00Z", first["job_id"], second["job_id"]),
        )

    service = SafeDeviceManagementEnrollmentExecutionRuntimeService(store)
    attempts = service._jobs_for_plan(PLAN_ID, {START_ACTION, RETRY_ACTION})
    assert [item["job_id"] for item in attempts[:2]] == [second["job_id"], first["job_id"]]
    assert attempts[0]["result"]["retry_safe"] is False
    assert attempts[1]["result"]["retry_safe"] is True
    store.close()


def test_execution_state_survives_backup_restore(tmp_path: Path) -> None:
    source_path = tmp_path / "state.db"
    backup_path = tmp_path / "backup" / "state.db"
    source = _store(source_path)
    envelope = {
        "schema": "home-center.device-management-enrollment-execution-state.v1",
        "status": "planned",
        "plan": {"plan_id": PLAN_ID},
        "receipt": None,
        "cancel_receipt": None,
    }
    source.set_meta(STATE_KEY, envelope)
    job, created = source.create_action_job(
        action_id=START_ACTION,
        actor="local-admin:admin",
        reason="backup recovery test",
        idempotency_key="backup-idempotency-key",
        request_hash="e" * 64,
        preflight={
            "plan_id": PLAN_ID,
            "provider_execution_authorized": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        },
        steps=[{"step": "provider-start", "state": "pending"}],
    )
    assert created is True
    source.backup_to(backup_path)
    source.close()

    restored = _store(backup_path)
    assert restored.integrity_check() is True
    assert restored.get_meta(STATE_KEY) == envelope
    recovered = restored.job(job["job_id"])
    assert recovered is not None
    assert recovered["state"] == "preflight"
    assert recovered["idempotency_key"] == "backup-idempotency-key"
    assert recovered["preflight"]["provider_execution_authorized"] is False
    assert recovered["preflight"]["post_condition_verified"] is False
    assert recovered["preflight"]["managed_state_change_authorized"] is False
    restored.close()
