from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

from home_center.device_management_enrollment_execution_runtime import START_ACTION
from home_center.store import StateStore


ROOT = Path(__file__).resolve().parents[1]
PLAN_ID = "dmpexec-0123456789abcdef01234567"
STATE_KEY = f"cozy.household.device-enrollment-execution.{PLAN_ID}"


def _store(path: Path) -> StateStore:
    return StateStore(path, b"q" * 32, "cluster-release-057-qualification")


def test_release_057_deployment_path_preserves_state_and_has_rollback() -> None:
    installer = (ROOT / "deploy/scripts/install-node.sh").read_text(encoding="utf-8")
    rollback = (ROOT / "deploy/scripts/rollback-node.sh").read_text(encoding="utf-8")

    # Upgrade must snapshot the configured SQLite state before switching the
    # release symlink and must restore that state when service activation fails.
    assert "raw.get('state_db')" in installer
    assert "src.backup(dst)" in installer
    assert '"$BACKUP/state.sqlite3"' in installer
    assert "restore_state=$(cat \"$BACKUP/state-db.path\")" in installer
    assert "ln -sfn \"$previous\" /opt/home-center/.current.rollback" in installer
    assert "SERVICE_START_FAILED" in installer
    assert "SERVICE_READINESS_FAILED" in installer
    assert "CURRENT_SWITCH_VERIFICATION_FAILED" in installer

    # The standalone rollback path must restore both release identity and state,
    # not merely repoint a symlink.
    assert "state.sqlite3" in rollback
    assert "previous.release" in rollback
    assert "systemctl start home-center.service" in rollback


def test_release_057_auto_update_remains_stable_only_and_checksum_gated() -> None:
    updater = (ROOT / "deploy/scripts/home-center-auto-update.sh").read_text(encoding="utf-8")
    assert "home-center-stable/releases?per_page=30" in updater
    assert "home-center-stable/releases/download/" in updater
    assert "home-center-development/releases" not in updater
    assert ".tar.gz.sha256" in updater
    assert "sha256sum" in updater
    assert "./deploy/rollback-node.sh" in updater


def test_release_057_intermediate_execution_jobs_survive_restart_without_state_loss(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    before = _store(path)
    envelope = {
        "schema": "home-center.device-management-enrollment-execution-state.v1",
        "status": "planned",
        "plan": {"plan_id": PLAN_ID},
        "receipt": None,
        "cancel_receipt": None,
    }
    before.set_meta(STATE_KEY, envelope)

    preflight, created = before.create_action_job(
        action_id=START_ACTION,
        actor="local-admin:admin",
        reason="release 0.57 restart qualification",
        idempotency_key="restart-qualification-key",
        request_hash="c" * 64,
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
    running = before.transition_action_job(
        preflight["job_id"], expected_state="preflight", new_state="running"
    )
    verifying = before.transition_action_job(
        running["job_id"],
        expected_state="running",
        new_state="verifying",
        result={
            "schema": "home-center.device-management-enrollment-provider-acceptance.v1",
            "state": "provider-accepted",
            "provider_operation_id": "provider-op-restart-1",
            "one_time_artifact": None,
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        },
    )
    before.close()

    after = _store(path)
    assert after.get_meta(STATE_KEY) == envelope
    recovered = after.job(verifying["job_id"])
    assert recovered is not None
    assert recovered["state"] == "verifying"
    assert recovered["idempotency_key"] == "restart-qualification-key"
    assert recovered["result"]["state"] == "provider-accepted"
    assert recovered["result"]["post_condition_verified"] is False
    assert recovered["result"]["managed_state_change_authorized"] is False
    after.close()


def test_release_057_durable_execution_state_survives_sqlite_backup_and_restore(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    backup_path = tmp_path / "state.backup.sqlite3"
    store = _store(path)
    envelope = {
        "schema": "home-center.device-management-enrollment-execution-state.v1",
        "status": "planned",
        "plan": {"plan_id": PLAN_ID},
        "receipt": None,
        "cancel_receipt": None,
    }
    store.set_meta(STATE_KEY, envelope)
    job, created = store.create_action_job(
        action_id=START_ACTION,
        actor="local-admin:admin",
        reason="release 0.57 backup recovery qualification",
        idempotency_key="backup-recovery-qualification-key",
        request_hash="d" * 64,
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
    running = store.transition_action_job(job["job_id"], expected_state="preflight", new_state="running")
    verifying = store.transition_action_job(
        running["job_id"],
        expected_state="running",
        new_state="verifying",
        result={
            "schema": "home-center.device-management-enrollment-provider-acceptance.v1",
            "state": "provider-accepted",
            "provider_operation_id": "provider-op-backup-1",
            "one_time_artifact": None,
            "enrollment_completed": False,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
        },
    )

    # Exercise the same SQLite online-backup primitive used by install-node.sh.
    source = sqlite3.connect(path)
    destination = sqlite3.connect(backup_path)
    try:
        source.backup(destination)
    finally:
        destination.close()
        source.close()

    # Prove restore is not accidentally reading the live database: mutate state
    # after the recovery point, then replace it with the qualified backup.
    store.set_meta(STATE_KEY, {"schema": "qualification-drift", "status": "mutated-after-backup"})
    store.close()
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists():
            sidecar.unlink()
    shutil.copy2(backup_path, path)

    recovered_store = _store(path)
    assert recovered_store.get_meta(STATE_KEY) == envelope
    recovered_job = recovered_store.job(verifying["job_id"])
    assert recovered_job is not None
    assert recovered_job["state"] == "verifying"
    assert recovered_job["idempotency_key"] == "backup-recovery-qualification-key"
    assert recovered_job["result"]["state"] == "provider-accepted"
    assert recovered_job["result"]["enrollment_completed"] is False
    assert recovered_job["result"]["post_condition_verified"] is False
    assert recovered_job["result"]["managed_state_change_authorized"] is False
    recovered_store.close()


def test_release_057_recovery_never_auto_reinvokes_ambiguous_running_provider_command() -> None:
    recovery = (
        ROOT / "product/control-plane/src/home_center/device_management_enrollment_execution_recovery.py"
    ).read_text(encoding="utf-8")

    # Safe automatic continuation is deliberately limited to states where the
    # provider was definitely not called (preflight) or acceptance evidence is
    # already durable (verifying). There must be no running-state resume branch.
    assert 'latest.get("state") == "preflight"' in recovery
    assert 'latest.get("state") == "verifying"' in recovery
    assert 'latest.get("state") == "running"' not in recovery
    assert '"provider_reinvoked": False' in recovery
    assert "finalized-durable-provider-acceptance" in recovery
