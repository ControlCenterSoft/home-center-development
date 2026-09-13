from __future__ import annotations

import sqlite3
from pathlib import Path

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from home_center.safe_auto_repair_migration import (
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_SQL,
    SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION,
    normalized_migration_sql,
)
from home_center.store import MIGRATIONS, StateStore
from home_center.util import canonical_json, utc_now


def _recommendation():
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=7,
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
    return evaluate_safe_auto_repair(candidate=candidate, policy=policy)


def _versions(store: StateStore) -> list[int]:
    return [
        int(row[0])
        for row in store._connection.execute(  # noqa: SLF001 - release migration qualification
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]


def test_history_schema_is_canonical_state_store_migration_5() -> None:
    assert [version for version, _ in MIGRATIONS] == [1, 2, 3, 4, 5]
    assert SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION == 5
    assert MIGRATIONS[4][0] == SAFE_AUTO_REPAIR_HISTORY_MIGRATION_VERSION
    assert "\n".join(line.rstrip() for line in MIGRATIONS[4][1].strip().splitlines()) + "\n" == normalized_migration_sql()
    assert normalized_migration_sql() == (
        "\n".join(
            line.rstrip()
            for line in SQLiteSafeAutoRepairHistoryRepository.schema_sql().strip().splitlines()
        )
        + "\n"
    )


def test_fresh_state_store_installs_history_schema_and_repository_uses_it(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "fresh" / "state.db", b"h" * 32, "cluster-test")
    try:
        assert _versions(store) == [1, 2, 3, 4, 5]
        repository = SQLiteSafeAutoRepairHistoryRepository(
            store._connection,  # noqa: SLF001
            store._lock,  # noqa: SLF001
        )
        recommendation = _recommendation()
        assert repository.append(recommendation, recorded_at_epoch=1_000) is True
        stored = repository.get(recommendation.recommendation_id)
        assert stored is not None
        assert stored["recommendation"] == recommendation.to_dict()
        assert stored["recorded_at_epoch"] == 1_000
        assert store.integrity_check() is True
    finally:
        store.close()


def test_upgrade_from_canonical_v4_preserves_existing_state_and_applies_only_history_migration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "upgrade" / "state.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        for version, sql in MIGRATIONS[:4]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, utc_now()),
            )
        connection.execute(
            "INSERT INTO cluster_meta(key, value_json, updated_at) VALUES (?, ?, ?)",
            ("pre_history_marker", canonical_json({"preserved": True}), utc_now()),
        )
        connection.commit()
    finally:
        connection.close()

    store = StateStore(path, b"h" * 32, "cluster-test")
    try:
        assert store.get_meta("pre_history_marker") == {"preserved": True}
        assert _versions(store) == [1, 2, 3, 4, 5]
        table = store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_recommendations'"
        ).fetchone()
        assert table is not None
        index = store._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='index' AND name='idx_safe_auto_repair_history_household_resource'"
        ).fetchone()
        assert index is not None
        assert store.integrity_check() is True
        assert store.verify_audit_chain() == "0" * 64
    finally:
        store.close()


def test_history_state_survives_backup_and_restart(tmp_path: Path) -> None:
    live_path = tmp_path / "live" / "state.db"
    backup_path = tmp_path / "backup" / "state.db"
    store = StateStore(live_path, b"h" * 32, "cluster-test")
    recommendation = _recommendation()
    try:
        repository = SQLiteSafeAutoRepairHistoryRepository(
            store._connection,  # noqa: SLF001
            store._lock,  # noqa: SLF001
        )
        repository.append(recommendation, recorded_at_epoch=2_000)
        store.backup_to(backup_path)
    finally:
        store.close()

    restored = StateStore(backup_path, b"h" * 32, "cluster-test")
    try:
        assert _versions(restored) == [1, 2, 3, 4, 5]
        repository = SQLiteSafeAutoRepairHistoryRepository(
            restored._connection,  # noqa: SLF001
            restored._lock,  # noqa: SLF001
        )
        stored = repository.get(recommendation.recommendation_id)
        assert stored is not None
        assert stored["recommendation"] == recommendation.to_dict()
        assert stored["recorded_at_epoch"] == 2_000
        assert restored.integrity_check() is True
    finally:
        restored.close()
