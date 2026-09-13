from __future__ import annotations

import sqlite3

from home_center.safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from home_center.safe_auto_repair_migration import (
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL,
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION,
    normalized_migration_sql,
)
from home_center.store import MIGRATIONS


def _normalize(sql: str) -> str:
    return "\n".join(line.rstrip() for line in sql.strip().splitlines()) + "\n"


def test_history_migration_is_installed_once_as_canonical_migration_five() -> None:
    versions = [version for version, _ in MIGRATIONS]
    assert versions == [1, 2, 3, 4, 5]
    assert versions == sorted(set(versions))
    assert SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION == 5
    installed = [sql for version, sql in MIGRATIONS if version == SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION]
    assert len(installed) == 1
    assert _normalize(installed[0]) == normalized_migration_sql()


def test_installed_migration_matches_repository_schema_exactly() -> None:
    assert normalized_migration_sql() == _normalize(SQLiteSafeAutoRepairHistoryRepository.schema_sql())


def test_prepared_migration_is_idempotent_and_creates_bounded_schema() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL)
        connection.executescript(SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL)
        columns = {
            row[1]: row[2]
            for row in connection.execute("PRAGMA table_info(safe_auto_repair_recommendations)").fetchall()
        }
        assert columns == {
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
        indexes = {
            row[1]
            for row in connection.execute("PRAGMA index_list(safe_auto_repair_recommendations)").fetchall()
        }
        assert "idx_safe_auto_repair_history_household_resource" in indexes
    finally:
        connection.close()
