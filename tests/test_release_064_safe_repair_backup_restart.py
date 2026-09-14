from __future__ import annotations

from pathlib import Path

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from home_center.safe_auto_repair_job import (
    RepairExecutionOutcome,
    RepairJobState,
    build_safe_repair_job,
    record_safe_repair_execution,
    start_safe_repair_job,
)
from home_center.safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from home_center.store import StateStore


def _recommendation_and_admission():
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=7,
        evidence_sha256="a" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=RepairRisk.LOW,
        recovery_proven=True,
        post_condition_verifiable=True,
    )
    policy = SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256="b" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )
    recommendation = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    admission = evaluate_safe_auto_repair_admission(
        reviewed=recommendation,
        current_candidate=candidate,
        current_policy=policy,
    )
    return recommendation, admission


def _repositories(store: StateStore):
    return (
        SQLiteSafeAutoRepairHistoryRepository(store._connection, store._lock),  # noqa: SLF001
        SQLiteSafeAutoRepairJobRepository(store._connection, store._lock),  # noqa: SLF001
    )


def _assert_restored(
    path: Path,
    *,
    audit_key: bytes,
    recommendation_id: str,
    running_job_id: str,
    verifying_job_id: str,
    raw_running_key: str,
    raw_verifying_key: str,
) -> None:
    store = StateStore(path, audit_key, "cluster-test")
    try:
        history, jobs = _repositories(store)
        stored_history = history.get(recommendation_id)
        assert stored_history is not None
        assert stored_history["recommendation"]["recommendation_id"] == recommendation_id

        running = jobs.get(running_job_id)
        verifying = jobs.get(verifying_job_id)
        assert running is not None and running.state is RepairJobState.RUNNING
        assert verifying is not None and verifying.state is RepairJobState.VERIFYING
        assert running.to_dict()["automatic_retry_authorized"] is False
        assert verifying.effect_receipt_sha256 == "c" * 64
        assert verifying.post_condition_verified is False

        durable_text = "\n".join(
            str(value)
            for row in store._connection.execute(  # noqa: SLF001
                "SELECT recommendation_json FROM safe_auto_repair_recommendations"
            ).fetchall()
            for value in row
        )
        durable_text += "\n" + "\n".join(
            str(value)
            for row in store._connection.execute(  # noqa: SLF001
                "SELECT idempotency_key_sha256,job_json FROM safe_auto_repair_jobs"
            ).fetchall()
            for value in row
        )
        assert raw_running_key not in durable_text
        assert raw_verifying_key not in durable_text
        assert store.integrity_check() is True
    finally:
        store.close()


def test_safe_repair_history_and_uncertain_jobs_survive_restart_and_backup_restore(
    tmp_path: Path,
) -> None:
    audit_key = b"safe-repair-064-backup-key".ljust(32, b"-")
    source_path = tmp_path / "source" / "state.db"
    backup_path = tmp_path / "backup" / "state.db"

    store = StateStore(source_path, audit_key, "cluster-test")
    history, jobs = _repositories(store)
    recommendation, admission = _recommendation_and_admission()
    assert history.append(recommendation, recorded_at_epoch=100) is True

    raw_running_key = "repair-running-0640"
    running_base = build_safe_repair_job(
        admission=admission,
        idempotency_key=raw_running_key,
        created_at_epoch=110,
    )
    assert jobs.create(running_base) is True
    running = start_safe_repair_job(running_base, updated_at_epoch=120)
    jobs.save(
        running,
        expected_state=RepairJobState.ADMITTED,
        expected_updated_at_epoch=running_base.updated_at_epoch,
    )

    raw_verifying_key = "repair-verifying-0640"
    verifying_base = build_safe_repair_job(
        admission=admission,
        idempotency_key=raw_verifying_key,
        created_at_epoch=130,
    )
    assert jobs.create(verifying_base) is True
    second_running = start_safe_repair_job(verifying_base, updated_at_epoch=140)
    jobs.save(
        second_running,
        expected_state=RepairJobState.ADMITTED,
        expected_updated_at_epoch=verifying_base.updated_at_epoch,
    )
    verifying = record_safe_repair_execution(
        second_running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=150,
    )
    jobs.save(
        verifying,
        expected_state=RepairJobState.RUNNING,
        expected_updated_at_epoch=second_running.updated_at_epoch,
    )

    store.backup_to(backup_path)
    store.close()

    for path in (source_path, backup_path):
        _assert_restored(
            path,
            audit_key=audit_key,
            recommendation_id=recommendation.recommendation_id,
            running_job_id=running.job_id,
            verifying_job_id=verifying.job_id,
            raw_running_key=raw_running_key,
            raw_verifying_key=raw_verifying_key,
        )
