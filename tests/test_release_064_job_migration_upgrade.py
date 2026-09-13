from __future__ import annotations

import json
import sqlite3
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
    RepairJobState,
    build_safe_repair_job,
    start_safe_repair_job,
)
from home_center.safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from home_center.store import MIGRATIONS, StateStore


LEGACY_V5_VERSIONS = (1, 2, 3, 4, 5)


def _candidate() -> RepairCandidate:
    return RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=7,
        evidence_sha256="a" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=RepairRisk.LOW,
        recovery_proven=True,
        post_condition_verifiable=True,
    )


def _policy() -> SafeRepairPolicy:
    return SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256="b" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )


def _create_v5_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        for version, sql in MIGRATIONS[:5]:
            assert version in LEGACY_V5_VERSIONS
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, f"2026-09-13T15:4{version}:00Z"),
            )
        marker = json.dumps(
            {"stable": "0.63.0", "history_migration": 5},
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "INSERT INTO cluster_meta(key,value_json,updated_at) VALUES (?,?,?)",
            ("pre_job_migration_marker", marker, "2026-09-13T15:49:00Z"),
        )
        recommendation = evaluate_safe_auto_repair(
            candidate=_candidate(),
            policy=_policy(),
        )
        history = SQLiteSafeAutoRepairHistoryRepository(connection)
        assert history.append(recommendation, recorded_at_epoch=1_000) is True
        connection.commit()
    finally:
        connection.close()


def _versions(store: StateStore) -> list[int]:
    return [
        int(row[0])
        for row in store._connection.execute(  # noqa: SLF001 - release migration evidence
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]


def test_current_statestore_upgrades_v5_to_job_migration_without_state_loss(tmp_path: Path) -> None:
    path = tmp_path / "upgrade" / "state.db"
    _create_v5_database(path)

    store = StateStore(path, b"j" * 32, "cluster-job-upgrade")
    try:
        assert [version for version, _ in MIGRATIONS] == [1, 2, 3, 4, 5, 6]
        assert _versions(store) == [1, 2, 3, 4, 5, 6]
        assert store.get_meta("pre_job_migration_marker") == {
            "stable": "0.63.0",
            "history_migration": 5,
        }
        assert store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM safe_auto_repair_recommendations LIMIT 1"
        ).fetchone() is not None
        assert store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_jobs'"
        ).fetchone() is not None
        assert store.integrity_check() is True
    finally:
        store.close()


def test_job_migration_survives_cas_restart_and_backup_without_retry_authority(
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "source" / "state.db"
    backup_path = tmp_path / "backup" / "state.db"
    _create_v5_database(source_path)

    store = StateStore(source_path, b"k" * 32, "cluster-job-backup")
    reviewed = evaluate_safe_auto_repair(candidate=_candidate(), policy=_policy())
    admission = evaluate_safe_auto_repair_admission(
        reviewed=reviewed,
        current_candidate=_candidate(),
        current_policy=_policy(),
    )
    job = build_safe_repair_job(
        admission=admission,
        idempotency_key="repair-request-v6-001",
        created_at_epoch=2_000,
    )
    jobs = SQLiteSafeAutoRepairJobRepository(
        store._connection,  # noqa: SLF001 - canonical shared StateStore connection
        store._lock,  # noqa: SLF001 - canonical shared StateStore lock
    )
    assert jobs.create(job) is True
    running = start_safe_repair_job(job, updated_at_epoch=2_010)
    assert jobs.compare_and_set(
        expected_state=RepairJobState.ADMITTED,
        expected_updated_at_epoch=2_000,
        updated=running,
    ) == running
    store.backup_to(backup_path)
    store.close()

    for path in (source_path, backup_path):
        reopened = StateStore(path, b"k" * 32, "cluster-job-backup")
        try:
            restored = SQLiteSafeAutoRepairJobRepository(
                reopened._connection,  # noqa: SLF001
                reopened._lock,  # noqa: SLF001
            ).get(job.job_id)
            assert restored == running
            assert restored is not None
            payload = restored.to_dict()
            assert payload["raw_idempotency_key_persisted"] is False
            assert payload["automatic_retry_authorized"] is False
            assert payload["execution_authorized"] is False
            assert payload["provider_execution_authorized"] is False
            assert payload["infrastructure_mutation_authorized"] is False
            assert payload["external_publication_authorized"] is False
            assert _versions(reopened) == [1, 2, 3, 4, 5, 6]
            assert reopened.integrity_check() is True
        finally:
            reopened.close()
