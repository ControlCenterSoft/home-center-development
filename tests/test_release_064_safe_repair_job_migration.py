from __future__ import annotations

from home_center.safe_auto_repair_job_migration import (
    SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION,
    apply_safe_auto_repair_job_migration,
)
from home_center.store import StateStore


def test_job_migration_is_additive_after_canonical_history_v5(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"k" * 32, "cluster-test")
    try:
        before = [
            int(row[0])
            for row in store._connection.execute(  # noqa: SLF001
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert before == [1, 2, 3, 4, 5]

        apply_safe_auto_repair_job_migration(store)
        after = [
            int(row[0])
            for row in store._connection.execute(  # noqa: SLF001
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert after == [1, 2, 3, 4, 5, SAFE_AUTO_REPAIR_JOB_MIGRATION_VERSION]
        assert store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_jobs'"
        ).fetchone() is not None
        assert store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_recommendations'"
        ).fetchone() is not None

        apply_safe_auto_repair_job_migration(store)
        repeated = [
            int(row[0])
            for row in store._connection.execute(  # noqa: SLF001
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert repeated == after
    finally:
        store.close()
