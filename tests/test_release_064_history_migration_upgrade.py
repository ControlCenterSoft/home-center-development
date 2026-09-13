from __future__ import annotations

import sqlite3
from pathlib import Path

from home_center.safe_auto_repair_migration import (
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL,
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION,
)
from home_center.store import MIGRATIONS, StateStore


def _apply_history_migration(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL)
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION, "2026-09-13T09:50:00Z"),
        )
        connection.commit()
    finally:
        connection.close()


def test_history_migration_preserves_canonical_v4_state(tmp_path: Path) -> None:
    path = tmp_path / "upgrade" / "state.db"
    store = StateStore(path, b"x" * 32, "cluster-test")
    try:
        assert [version for version, _ in MIGRATIONS] == [1, 2, 3, 4]
        store.set_meta("pre_064_marker", {"preserved": True, "generation": 7})
    finally:
        store.close()

    _apply_history_migration(path)

    reopened = StateStore(path, b"x" * 32, "cluster-test")
    try:
        assert reopened.get_meta("pre_064_marker") == {"preserved": True, "generation": 7}
        versions = [
            int(row[0])
            for row in reopened._connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert versions == [1, 2, 3, 4, 5]
        assert reopened._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_recommendations'"
        ).fetchone() is not None
        assert reopened.integrity_check() is True
    finally:
        reopened.close()


def test_v4_store_reopens_database_with_additive_v5_history_schema(tmp_path: Path) -> None:
    path = tmp_path / "compat" / "state.db"
    store = StateStore(path, b"y" * 32, "cluster-compat")
    try:
        store.set_meta("compat_marker", {"stable": "0.63.0"})
    finally:
        store.close()

    _apply_history_migration(path)

    compatibility_store = StateStore(path, b"y" * 32, "cluster-compat")
    try:
        assert compatibility_store.get_meta("compat_marker") == {"stable": "0.63.0"}
        versions = {
            int(row[0])
            for row in compatibility_store._connection.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
        }
        assert versions == {1, 2, 3, 4, 5}
        assert compatibility_store._connection.execute(
            "SELECT COUNT(*) FROM safe_auto_repair_recommendations"
        ).fetchone()[0] == 0
        assert compatibility_store.integrity_check() is True
    finally:
        compatibility_store.close()
