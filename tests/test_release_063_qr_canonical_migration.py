from __future__ import annotations

import sqlite3
from pathlib import Path

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from home_center.store import MIGRATIONS, StateStore
from home_center.util import canonical_json, utc_now


def _snapshot():
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
            FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
        ),
        devices=(),
    )
    household_store = HouseholdStore()
    household_store.create(household)
    return household_store.read("home-main")


def test_qr_runtime_schema_is_canonical_migration_4_and_matches_adapter_contract() -> None:
    assert [version for version, _ in MIGRATIONS] == [1, 2, 3, 4]
    assert MIGRATIONS[3][1].strip() == SQLiteQrOnboardingRuntimeRepository.schema_sql().strip()


def test_fresh_state_store_installs_qr_schema_without_repository_self_migration(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "fresh" / "state.db", b"m" * 32, "cluster-test")
    try:
        versions = [
            int(row[0])
            for row in store._connection.execute(  # noqa: SLF001 - release migration qualification
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert versions == [1, 2, 3, 4]
        tables = {
            row[0]
            for row in store._connection.execute(  # noqa: SLF001
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert {"qr_onboarding_runtime", "qr_onboarding_runtime_operations"} <= tables

        repository = SQLiteQrOnboardingRuntimeRepository(
            store._connection,  # noqa: SLF001
            store._lock,  # noqa: SLF001
        )
        runtime = QrOnboardingRuntimeService(repository)
        result = runtime.issue(
            snapshot=_snapshot(),
            issuer_member_id="parent-1",
            target_member_id="guest-1",
            subject=OnboardingSubject.GUEST,
            created_at_epoch=1_000,
            expires_at_epoch=2_000,
            guest_scope=(GuestScope.INTERNET_GUEST,),
            onboarding_code="M" * 32,
        )
        persisted = repository.get(result.record.invitation.invitation_id, now_epoch=1_100)
        assert persisted is not None
        assert persisted.runtime_record_id == result.record.runtime_record_id
    finally:
        store.close()


def test_upgrade_from_canonical_v3_preserves_existing_state_and_applies_only_qr_migration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "upgrade" / "state.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        for version, sql in MIGRATIONS[:3]:
            connection.executescript(sql)
            connection.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, utc_now()),
            )
        connection.execute(
            "INSERT INTO cluster_meta(key, value_json, updated_at) VALUES (?, ?, ?)",
            ("pre_qr_marker", canonical_json({"preserved": True}), utc_now()),
        )
        connection.commit()
    finally:
        connection.close()

    store = StateStore(path, b"m" * 32, "cluster-test")
    try:
        assert store.get_meta("pre_qr_marker") == {"preserved": True}
        versions = [
            int(row[0])
            for row in store._connection.execute(  # noqa: SLF001
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        ]
        assert versions == [1, 2, 3, 4]
        for table in ("qr_onboarding_runtime", "qr_onboarding_runtime_operations"):
            assert store._connection.execute(  # noqa: SLF001
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone() is not None
        assert store.integrity_check() is True
        assert store.verify_audit_chain() == "0" * 64
    finally:
        store.close()
