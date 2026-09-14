from __future__ import annotations

import sqlite3
from pathlib import Path

from home_center.safe_auto_repair_job_migration import (
    SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION,
    apply_safe_auto_repair_job_migration,
)
from home_center.store import MIGRATIONS, StateStore


def _versions(store: StateStore) -> list[int]:
    return [
        int(row[0])
        for row in store._connection.execute(  # noqa: SLF001
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]


def _create_legacy_v5_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        for version, sql in MIGRATIONS[:5]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, f"2026-09-14T10:0{version}:00Z"),
            )
        connection.execute(
            "INSERT INTO cluster_meta(key,value_json,updated_at) VALUES (?,?,?)",
            ("pre_v6_marker", '{"preserved":true}', "2026-09-14T10:10:00Z"),
        )
        connection.commit()
    finally:
        connection.close()


def test_job_migration_is_canonical_v6_on_fresh_statestore(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "fresh" / "state.db", b"k" * 32, "cluster-test")
    try:
        assert SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION == 6
        assert _versions(store) == [1, 2, 3, 4, 5, 6]
        assert store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_jobs'"
        ).fetchone() is not None
        assert store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_recommendations'"
        ).fetchone() is not None

        apply_safe_auto_repair_job_migration(store)
        assert _versions(store) == [1, 2, 3, 4, 5, 6]
    finally:
        store.close()


def test_current_statestore_upgrades_existing_v5_to_v6_without_losing_state(tmp_path: Path) -> None:
    path = tmp_path / "upgrade" / "state.db"
    _create_legacy_v5_database(path)

    store = StateStore(path, b"m" * 32, "cluster-test")
    try:
        assert _versions(store) == [1, 2, 3, 4, 5, 6]
        assert store.get_meta("pre_v6_marker") == {"preserved": True}
        assert store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_jobs'"
        ).fetchone() is not None
        assert store.integrity_check() is True
    finally:
        store.close()
