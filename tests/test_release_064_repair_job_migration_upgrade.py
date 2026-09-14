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
from home_center.safe_auto_repair_job import build_safe_repair_job
from home_center.safe_auto_repair_job_migration import (
    SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL,
    SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION,
    normalized_job_migration_sql,
)
from home_center.safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from home_center.store import MIGRATIONS, StateStore


LEGACY_V5_VERSIONS = (1, 2, 3, 4, 5)


def _normalize(sql: str) -> str:
    return "\n".join(line.rstrip() for line in sql.strip().splitlines()) + "\n"


def _create_legacy_v5_database(path: Path, *, marker: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        for version, sql in MIGRATIONS[:5]:
            assert version in LEGACY_V5_VERSIONS
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, f"2026-09-14T07:5{version}:00Z"),
            )
        connection.execute(
            "INSERT INTO cluster_meta(key,value_json,updated_at) VALUES (?,?,?)",
            (
                "pre_job_migration_marker",
                json.dumps(marker, sort_keys=True, separators=(",", ":")),
                "2026-09-14T07:59:00Z",
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _admission():
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=8,
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


def _migration_versions(store: StateStore) -> list[int]:
    return [
        int(row[0])
        for row in store._connection.execute(  # noqa: SLF001 - release migration evidence
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]


def test_job_migration_is_canonical_migration_six_and_matches_repository_schema() -> None:
    versions = [version for version, _ in MIGRATIONS]
    assert versions == [1, 2, 3, 4, 5, 6]
    assert versions == sorted(set(versions))
    assert SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION == 6
    installed = [sql for version, sql in MIGRATIONS if version == SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION]
    assert len(installed) == 1
    assert _normalize(installed[0]) == normalized_job_migration_sql()
    assert normalized_job_migration_sql() == _normalize(SQLiteSafeAutoRepairJobRepository.schema_sql())


def test_job_migration_is_idempotent_and_bounded() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL)
        connection.executescript(SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL)
        columns = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(safe_auto_repair_jobs)").fetchall()
        }
        assert columns == {
            "job_id": "TEXT",
            "admission_id": "TEXT",
            "recommendation_id": "TEXT",
            "recommendation_sha256": "TEXT",
            "idempotency_key_sha256": "TEXT",
            "state": "TEXT",
            "job_json": "TEXT",
            "created_at_epoch": "INTEGER",
            "updated_at_epoch": "INTEGER",
        }
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(safe_auto_repair_jobs)").fetchall()
        }
        assert "idx_safe_auto_repair_jobs_recommendation" in indexes
    finally:
        connection.close()


def test_current_statestore_upgrades_v5_and_job_survives_restart_and_backup(tmp_path: Path) -> None:
    source_path = tmp_path / "source" / "state.db"
    backup_path = tmp_path / "backup" / "state.db"
    marker = {"stable": "0.63.0", "history_migration": 5, "preserved": True}
    _create_legacy_v5_database(source_path, marker=marker)

    upgraded = StateStore(source_path, b"z" * 32, "cluster-job-migration")
    try:
        assert upgraded.get_meta("pre_job_migration_marker") == marker
        assert _migration_versions(upgraded) == [1, 2, 3, 4, 5, 6]
        repository = SQLiteSafeAutoRepairJobRepository(
            upgraded._connection,  # noqa: SLF001 - canonical shared StateStore connection
            upgraded._lock,  # noqa: SLF001 - canonical shared StateStore lock
        )
        job = build_safe_repair_job(
            admission=_admission(),
            idempotency_key="repair-migration-6-proof",
            created_at_epoch=1_000,
        )
        assert repository.create(job) is True
        upgraded.backup_to(backup_path)
        assert upgraded.integrity_check() is True
    finally:
        upgraded.close()

    for path in (source_path, backup_path):
        reopened = StateStore(path, b"z" * 32, "cluster-job-migration")
        try:
            assert reopened.get_meta("pre_job_migration_marker") == marker
            assert _migration_versions(reopened) == [1, 2, 3, 4, 5, 6]
            repository = SQLiteSafeAutoRepairJobRepository(
                reopened._connection,  # noqa: SLF001
                reopened._lock,  # noqa: SLF001
            )
            restored = repository.get(job.job_id)
            assert restored == job
            assert restored is not None
            payload = restored.to_dict()
            assert payload["raw_idempotency_key_persisted"] is False
            assert payload["automatic_retry_authorized"] is False
            assert payload["execution_authorized"] is False
            assert payload["provider_execution_authorized"] is False
            assert payload["infrastructure_mutation_authorized"] is False
            assert payload["external_publication_authorized"] is False
            assert reopened.integrity_check() is True
        finally:
            reopened.close()
