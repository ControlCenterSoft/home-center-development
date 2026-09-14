from __future__ import annotations

import sqlite3

from home_center.safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from home_center.safe_auto_repair_job_migration import (
    SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL,
    SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION,
)
from home_center.safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from home_center.safe_auto_repair_migration import (
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL,
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION,
    normalized_migration_sql,
)
from home_center.store import MIGRATIONS


def _normalize(sql: str) -> str:
    return "\n".join(line.rstrip() for line in sql.strip().splitlines()) + "\n"


def test_safe_repair_migrations_are_installed_once_in_canonical_order() -> None:
    versions = [version for version, _ in MIGRATIONS]
    assert versions == [1, 2, 3, 4, 5, 6]
    assert versions == sorted(set(versions))
    assert SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION == 5
    assert SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION == 6

    installed_history = [
        sql for version, sql in MIGRATIONS if version == SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION
    ]
    installed_jobs = [
        sql for version, sql in MIGRATIONS if version == SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION
    ]
    assert len(installed_history) == 1
    assert len(installed_jobs) == 1
    assert _normalize(installed_history[0]) == normalized_migration_sql()
    assert _normalize(installed_jobs[0]) == _normalize(SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL)


def test_installed_migrations_match_repository_schemas_exactly() -> None:
    assert normalized_migration_sql() == _normalize(SQLiteSafeAutoRepairHistoryRepository.schema_sql())
    assert _normalize(SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL) == _normalize(
        SQLiteSafeAutoRepairJobRepository.schema_sql()
    )


def test_prepared_migrations_are_idempotent_and_create_bounded_schema() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL)
        connection.executescript(SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL)
        connection.executescript(SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL)
        connection.executescript(SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL)

        history_columns = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(safe_auto_repair_recommendations)").fetchall()
        }
        assert history_columns == {
            "recommendation_id": "TEXT",
            "household_id": "TEXT",
            "resource_id": "TEXT",
            "resource_generation": "INTEGER",
            "evidence_sha256": "TEXT",
            "policy_id": "TEXT",
            "policy_sha256": "TEXT",
            "eligible_for_auto_repair": "INTEGER",
            "recommendation_json": "TEXT",
            "recorded_at_epoch": "INTEGER",
        }
        job_columns = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(safe_auto_repair_jobs)").fetchall()
        }
        assert job_columns == {
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
        history_indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(safe_auto_repair_recommendations)").fetchall()
        }
        job_indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(safe_auto_repair_jobs)").fetchall()
        }
        assert "idx_safe_auto_repair_history_household_resource" in history_indexes
        assert "idx_safe_auto_repair_jobs_recommendation" in job_indexes
    finally:
        connection.close()
