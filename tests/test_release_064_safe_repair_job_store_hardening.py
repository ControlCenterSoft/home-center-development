from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_job import (
    RepairExecutionOutcome,
    RepairJobState,
    build_safe_repair_job,
    record_safe_repair_execution,
    start_safe_repair_job,
    verify_safe_repair_post_condition,
)
from home_center.safe_auto_repair_job_store import (
    SQLiteSafeAutoRepairJobRepository,
    SafeAutoRepairJobStoreError,
)


def _job():
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=1,
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
    return build_safe_repair_job(
        admission=admission,
        idempotency_key="job-store-hardening-0640",
        created_at_epoch=100,
    )


def _repo() -> SQLiteSafeAutoRepairJobRepository:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteSafeAutoRepairJobRepository.schema_sql())
    return SQLiteSafeAutoRepairJobRepository(connection)


def test_save_requires_exact_state_and_timestamp() -> None:
    repo = _repo()
    job = _job()
    assert repo.create(job) is True
    running = start_safe_repair_job(job, updated_at_epoch=110)
    assert repo.save(
        running,
        expected_state=RepairJobState.ADMITTED,
        expected_updated_at_epoch=100,
    ) == running

    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_stale"):
        repo.save(
            verifying,
            expected_state=RepairJobState.RUNNING,
            expected_updated_at_epoch=109,
        )


def test_save_rejects_non_monotonic_timestamp_before_write() -> None:
    repo = _repo()
    job = _job()
    repo.create(job)
    running = start_safe_repair_job(job, updated_at_epoch=110)
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_non_monotonic"):
        repo.save(
            running,
            expected_state=RepairJobState.ADMITTED,
            expected_updated_at_epoch=120,
        )
    assert repo.get(job.job_id) == job


def test_save_rejects_direct_admitted_to_succeeded() -> None:
    repo = _repo()
    job = _job()
    repo.create(job)
    running = start_safe_repair_job(job, updated_at_epoch=110)
    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    succeeded = verify_safe_repair_post_condition(
        verifying,
        evidence_sha256="d" * 64,
        verified=True,
        updated_at_epoch=130,
    )
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_transition_invalid"):
        repo.save(
            succeeded,
            expected_state=RepairJobState.ADMITTED,
            expected_updated_at_epoch=100,
        )


def test_save_rejects_verifying_to_running_and_terminal_transition() -> None:
    repo = _repo()
    job = _job()
    repo.create(job)
    running = start_safe_repair_job(job, updated_at_epoch=110)
    repo.save(running, expected_state=RepairJobState.ADMITTED, expected_updated_at_epoch=100)
    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    repo.save(verifying, expected_state=RepairJobState.RUNNING, expected_updated_at_epoch=110)

    later_running = replace(running, updated_at_epoch=130)
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_transition_invalid"):
        repo.save(
            later_running,
            expected_state=RepairJobState.VERIFYING,
            expected_updated_at_epoch=120,
        )

    succeeded = verify_safe_repair_post_condition(
        verifying,
        evidence_sha256="d" * 64,
        verified=True,
        updated_at_epoch=130,
    )
    repo.save(succeeded, expected_state=RepairJobState.VERIFYING, expected_updated_at_epoch=120)
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_transition_invalid"):
        repo.save(
            replace(running, updated_at_epoch=140),
            expected_state=RepairJobState.SUCCEEDED,
            expected_updated_at_epoch=130,
        )


def test_save_rejects_created_at_identity_drift() -> None:
    repo = _repo()
    job = _job()
    repo.create(job)
    running = start_safe_repair_job(job, updated_at_epoch=110)
    tampered = replace(running, created_at_epoch=99)
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_identity_conflict"):
        repo.save(
            tampered,
            expected_state=RepairJobState.ADMITTED,
            expected_updated_at_epoch=100,
        )
