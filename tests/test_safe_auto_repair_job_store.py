from __future__ import annotations

import json
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
)
from home_center.safe_auto_repair_job_store import (
    SQLiteSafeAutoRepairJobRepository,
    SafeAutoRepairJobStoreError,
)


def admission(*, generation: int = 1):
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=generation,
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
    reviewed = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    return evaluate_safe_auto_repair_admission(
        reviewed=reviewed,
        current_candidate=candidate,
        current_policy=policy,
    )


def repository(connection: sqlite3.Connection | None = None) -> SQLiteSafeAutoRepairJobRepository:
    connection = connection or sqlite3.connect(":memory:")
    connection.executescript(SQLiteSafeAutoRepairJobRepository.schema_sql())
    return SQLiteSafeAutoRepairJobRepository(connection)


def test_create_and_exact_replay_are_idempotent_without_raw_key_persistence() -> None:
    repo = repository()
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-101", created_at_epoch=100
    )
    assert repo.create(job) is True
    assert repo.create(job) is False
    stored = repo.get(job.job_id)
    assert stored == job
    encoded = json.dumps(stored.to_dict(), sort_keys=True)
    assert "repair-request-101" not in encoded
    assert stored.to_dict()["raw_idempotency_key_persisted"] is False


def test_same_job_identity_with_different_payload_fails_closed() -> None:
    repo = repository()
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-102", created_at_epoch=100
    )
    repo.create(job)
    tampered = replace(job, state=RepairJobState.RUNNING, updated_at_epoch=110)
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_identity_conflict"):
        repo.create(tampered)


def test_compare_and_set_persists_only_exact_current_transition() -> None:
    repo = repository()
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-103", created_at_epoch=100
    )
    repo.create(job)
    running = start_safe_repair_job(job, updated_at_epoch=110)
    assert repo.compare_and_set(
        expected_state=RepairJobState.ADMITTED,
        expected_updated_at_epoch=100,
        updated=running,
    ) == running

    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_stale"):
        repo.compare_and_set(
            expected_state=RepairJobState.ADMITTED,
            expected_updated_at_epoch=100,
            updated=running,
        )

    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    assert repo.compare_and_set(
        expected_state=RepairJobState.RUNNING,
        expected_updated_at_epoch=110,
        updated=verifying,
    ) == verifying


def test_restart_reopens_exact_durable_job_without_execution_replay_authority(tmp_path) -> None:
    path = tmp_path / "repair.sqlite3"
    first_connection = sqlite3.connect(path)
    first_connection.executescript(SQLiteSafeAutoRepairJobRepository.schema_sql())
    first = SQLiteSafeAutoRepairJobRepository(first_connection)
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-104", created_at_epoch=100
    )
    first.create(job)
    running = start_safe_repair_job(job, updated_at_epoch=110)
    first.compare_and_set(
        expected_state=RepairJobState.ADMITTED,
        expected_updated_at_epoch=100,
        updated=running,
    )
    first_connection.close()

    second_connection = sqlite3.connect(path)
    second = SQLiteSafeAutoRepairJobRepository(second_connection)
    restored = second.get(job.job_id)
    assert restored == running
    assert restored is not None
    payload = restored.to_dict()
    assert payload["automatic_retry_authorized"] is False
    assert payload["execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False
    second_connection.close()


def test_recent_query_is_bounded_and_ordered() -> None:
    repo = repository()
    first = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-105", created_at_epoch=100
    )
    second = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-106", created_at_epoch=200
    )
    repo.create(first)
    repo.create(second)
    recent = repo.recent_for_recommendation(recommendation_id=first.recommendation_id)
    assert [item.job_id for item in recent] == [second.job_id, first.job_id]
    with pytest.raises(SafeAutoRepairJobStoreError, match="safe_repair_job_store_limit_invalid"):
        repo.recent_for_recommendation(recommendation_id=first.recommendation_id, limit=201)


def test_repository_does_not_self_migrate() -> None:
    connection = sqlite3.connect(":memory:")
    repo = SQLiteSafeAutoRepairJobRepository(connection)
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-107", created_at_epoch=100
    )
    with pytest.raises(sqlite3.OperationalError):
        repo.create(job)
