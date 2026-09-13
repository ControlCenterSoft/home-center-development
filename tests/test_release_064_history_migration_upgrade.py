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
from home_center.safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from home_center.store import MIGRATIONS, StateStore


LEGACY_V4_VERSIONS = (1, 2, 3, 4)


def _create_legacy_v4_database(path: Path, *, marker: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        for version, sql in MIGRATIONS[:4]:
            assert version in LEGACY_V4_VERSIONS
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, f"2026-09-13T09:4{version}:00Z"),
            )
        connection.execute(
            "INSERT INTO cluster_meta(key,value_json,updated_at) VALUES (?,?,?)",
            (
                "pre_064_marker",
                json.dumps(marker, sort_keys=True, separators=(",", ":")),
                "2026-09-13T09:49:00Z",
            ),
        )
        connection.commit()
    finally:
        connection.close()


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


def _migration_versions(store: StateStore) -> list[int]:
    return [
        int(row[0])
        for row in store._connection.execute(  # noqa: SLF001 - release migration evidence
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    ]


def test_current_statestore_automatically_upgrades_v4_and_preserves_existing_state(tmp_path: Path) -> None:
    path = tmp_path / "upgrade" / "state.db"
    marker = {"preserved": True, "generation": 7, "stable": "0.63.0"}
    _create_legacy_v4_database(path, marker=marker)

    upgraded = StateStore(path, b"x" * 32, "cluster-test")
    try:
        assert [version for version, _ in MIGRATIONS] == [1, 2, 3, 4, 5, 6]
        assert upgraded.get_meta("pre_064_marker") == marker
        assert _migration_versions(upgraded) == [1, 2, 3, 4, 5, 6]
        assert upgraded._connection.execute(  # noqa: SLF001
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='safe_auto_repair_recommendations'"
        ).fetchone() is not None
        assert upgraded.integrity_check() is True
    finally:
        upgraded.close()


def test_v5_history_survives_restart_and_sqlite_backup_restore(tmp_path: Path) -> None:
    source_path = tmp_path / "source" / "state.db"
    backup_path = tmp_path / "backup" / "state.db"
    marker = {"preserved": True, "stable": "0.63.0"}
    _create_legacy_v4_database(source_path, marker=marker)

    upgraded = StateStore(source_path, b"y" * 32, "cluster-backup")
    recommendation = _recommendation()
    repository = SQLiteSafeAutoRepairHistoryRepository(
        upgraded._connection,  # noqa: SLF001 - canonical shared StateStore connection
        upgraded._lock,  # noqa: SLF001 - canonical shared StateStore lock
    )
    assert repository.append(recommendation, recorded_at_epoch=1_000) is True
    upgraded.backup_to(backup_path)
    upgraded.close()

    for path in (source_path, backup_path):
        reopened = StateStore(path, b"y" * 32, "cluster-backup")
        try:
            assert reopened.get_meta("pre_064_marker") == marker
            assert _migration_versions(reopened) == [1, 2, 3, 4, 5, 6]
            history = SQLiteSafeAutoRepairHistoryRepository(
                reopened._connection,  # noqa: SLF001
                reopened._lock,  # noqa: SLF001
            )
            stored = history.get(recommendation.recommendation_id)
            assert stored is not None
            assert stored["recorded_at_epoch"] == 1_000
            assert stored["recommendation"] == recommendation.to_dict()
            assert stored["recommendation"]["execution_authorized"] is False
            assert stored["recommendation"]["provider_execution_authorized"] is False
            assert stored["recommendation"]["infrastructure_mutation_authorized"] is False
            assert stored["recommendation"]["external_publication_authorized"] is False
            assert reopened.integrity_check() is True
        finally:
            reopened.close()
