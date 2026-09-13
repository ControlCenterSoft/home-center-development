from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, InvitationState, OnboardingSubject
from home_center.qr_onboarding_runtime import (
    QrOnboardingRuntimeError,
    QrOnboardingRuntimeService,
    SQLiteQrOnboardingRuntimeRepository,
)
from home_center.store import StateStore


def _snapshot():
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
            FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
        ),
    )
    store = HouseholdStore()
    store.create(household)
    return store.read("home-main")


def _runtime_on_state_store(store: StateStore) -> QrOnboardingRuntimeService:
    with store._lock, store._connection:  # noqa: SLF001 - release qualification of shared SQLite state
        store._connection.executescript(  # noqa: SLF001
            SQLiteQrOnboardingRuntimeRepository.schema_sql()
        )
    repository = SQLiteQrOnboardingRuntimeRepository(
        store._connection,  # noqa: SLF001
        store._lock,  # noqa: SLF001
    )
    return QrOnboardingRuntimeService(repository)


def _assert_terminal_state_survives(
    path: Path,
    *,
    snapshot,
    consumed_invitation_id: str,
    consumed_code: str,
    revoked_invitation_id: str,
    revoked_code: str,
) -> None:
    connection = sqlite3.connect(path)
    try:
        repository = SQLiteQrOnboardingRuntimeRepository(connection)
        service = QrOnboardingRuntimeService(repository)

        consumed = repository.get(consumed_invitation_id, now_epoch=2_500)
        revoked = repository.get(revoked_invitation_id, now_epoch=2_500)
        assert consumed is not None
        assert revoked is not None
        assert consumed.state is InvitationState.CONSUMED
        assert consumed.version == 2
        assert consumed.consumed_at_epoch == 1_200
        assert revoked.state is InvitationState.REVOKED
        assert revoked.version == 2
        assert revoked.revoked_at_epoch == 2_200

        with pytest.raises(QrOnboardingRuntimeError, match="qr_invitation_consumed"):
            service.plan_redemption(
                snapshot=snapshot,
                invitation_id=consumed_invitation_id,
                onboarding_code=consumed_code,
                now_epoch=2_500,
            )
        with pytest.raises(QrOnboardingRuntimeError, match="qr_invitation_revoked"):
            service.plan_redemption(
                snapshot=snapshot,
                invitation_id=revoked_invitation_id,
                onboarding_code=revoked_code,
                now_epoch=2_500,
            )

        durable_text = "\n".join(
            str(value)
            for row in connection.execute(
                "SELECT invitation_json, token_sha256 FROM qr_onboarding_runtime ORDER BY invitation_id"
            ).fetchall()
            for value in row
        )
        durable_text += "\n" + "\n".join(
            str(value)
            for row in connection.execute(
                "SELECT request_sha256, receipt_json FROM qr_onboarding_runtime_operations ORDER BY created_at_epoch"
            ).fetchall()
            for value in row
        )
        assert consumed_code not in durable_text
        assert revoked_code not in durable_text
    finally:
        connection.close()


def test_qr_consumed_and_revoked_state_survives_restart_and_backup_restore(tmp_path: Path) -> None:
    snapshot = _snapshot()
    source_path = tmp_path / "source" / "state.db"
    backup_path = tmp_path / "backup" / "state.db"
    store = StateStore(source_path, b"q" * 32, "cluster-test")
    runtime = _runtime_on_state_store(store)

    consumed_code = "R" * 32
    consumed_issue = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code=consumed_code,
    )
    consumed_plan = runtime.plan_redemption(
        snapshot=snapshot,
        invitation_id=consumed_issue.record.invitation.invitation_id,
        onboarding_code=consumed_code,
        now_epoch=1_100,
    )
    consumed_record, _ = runtime.consume(
        snapshot=snapshot,
        plan=consumed_plan,
        onboarding_code=consumed_code,
        actor="redemption-session-1",
        idempotency_key="consume-key-0630",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    assert consumed_record.state is InvitationState.CONSUMED

    revoked_code = "S" * 32
    revoked_issue = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=2_000,
        expires_at_epoch=2_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code=revoked_code,
    )
    revoked_record, _ = runtime.revoke(
        snapshot=snapshot,
        invitation_id=revoked_issue.record.invitation.invitation_id,
        actor_member_id="parent-1",
        idempotency_key="revoke-key-0630",
        expected_version=1,
        now_epoch=2_200,
    )
    assert revoked_record.state is InvitationState.REVOKED

    store.backup_to(backup_path)
    store.close()

    for path in (source_path, backup_path):
        _assert_terminal_state_survives(
            path,
            snapshot=snapshot,
            consumed_invitation_id=consumed_issue.record.invitation.invitation_id,
            consumed_code=consumed_code,
            revoked_invitation_id=revoked_issue.record.invitation.invitation_id,
            revoked_code=revoked_code,
        )
