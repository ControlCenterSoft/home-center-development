from __future__ import annotations

import sqlite3

from home_center.safe_auto_repair_job_migration import (
    SAFE_AUTO_REPAIR_JOB_MIGRATION_SQL,
    SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION,
    normalized_migration_sql,
)
from home_center.safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from home_center.store import MIGRATIONS


def _normalize(sql: str) -> str:
    return "\n".join(line.rstrip() for line in sql.strip().splitlines()) + "\n"


def test_repair_job_migration_is_unique_immediate_successor_of_history_migration() -> None:
    versions = [version for version, _ in MIGRATIONS]
    assert versions == [1, 2, 3, 4, 5]
    assert SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION == max(versions) + 1
    assert SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION == 6


def test_prepared_repair_job_migration_matches_repository_schema_exactly() -> None:
    assert normalized_migration_sql() == _normalize(SQLiteSafeAutoRepairJobRepository.schema_sql())


def test_prepared_repair_job_migration_is_idempotent_and_bounded() -> None:
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
        sql_lower = normalized_migration_sql().lower()
        for forbidden in (
            "raw_idempotency_key",
            "credential",
            "password",
            "token_value",
            "provider_payload",
            "command",
            "execution_authorized",
            "external_publication_authorized",
        ):
            assert forbidden not in sql_lower
    finally:
        connection.close()
