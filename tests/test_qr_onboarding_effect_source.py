from __future__ import annotations

import json
import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_handoff import QrOnboardingEffectKind
from home_center.qr_onboarding_effect_source import (
    QrOnboardingEffectSourceError,
    QrOnboardingEffectSourceService,
)
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository


def _snapshot():
    households = HouseholdStore()
    households.create(
        Household(
            household_id="home-main",
            members=(
                FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
                FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
            ),
            devices=(ManagedDevice("tablet-1", "guest-1", "Guest tablet", managed=False),),
        )
    )
    return households.read("home-main")


def _open(path):
    connection = sqlite3.connect(path)
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    return connection, SQLiteQrOnboardingRuntimeRepository(connection)


def _consume_guest(repository, snapshot):
    runtime = QrOnboardingRuntimeService(repository)
    issued = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        created_at_epoch=1000,
        expires_at_epoch=1600,
        onboarding_code="G" * 32,
    )
    plan = runtime.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="G" * 32,
        now_epoch=1100,
    )
    runtime.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="G" * 32,
        actor="redemption-session",
        idempotency_key="guest-terminal-consume-1",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return issued.record.invitation.invitation_id


def test_terminal_guest_transition_recovers_exact_handoff_after_process_restart(tmp_path) -> None:
    snapshot = _snapshot()
    path = tmp_path / "qr.db"
    connection, repository = _open(path)
    invitation_id = _consume_guest(repository, snapshot)
    connection.close()

    connection2, repository2 = _open(path)
    try:
        handoff = QrOnboardingEffectSourceService(repository2).recover(
            snapshot=snapshot,
            invitation_id=invitation_id,
            now_epoch=1300,
        )
        assert handoff.effect_kind is QrOnboardingEffectKind.GUEST_ACCESS_GRANT
        assert handoff.target_member_id == "guest-1"
        assert handoff.device_id is None
        assert [scope.value for scope in handoff.guest_scope] == ["internet.guest"]
        assert handoff.required_job_type == "typed-guest-access-change-job"
        assert handoff.effect_execution_authorized is False
        assert handoff.account_creation_authorized is False
        assert handoff.device_registration_authorized is False
        assert handoff.managed_state_change_authorized is False
        assert handoff.provider_execution_authorized is False
        assert handoff.infrastructure_mutation_authorized is False
        assert handoff.external_publication_authorized is False
    finally:
        connection2.close()


def test_terminal_device_revoke_recovers_exact_revocation_handoff(tmp_path) -> None:
    snapshot = _snapshot()
    connection, repository = _open(tmp_path / "qr.db")
    runtime = QrOnboardingRuntimeService(repository)
    issued = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.DEVICE,
        device_id="tablet-1",
        created_at_epoch=1000,
        expires_at_epoch=1600,
        onboarding_code="D" * 32,
    )
    runtime.revoke(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        actor_member_id="parent-1",
        idempotency_key="device-terminal-revoke-1",
        expected_version=1,
        now_epoch=1150,
    )
    try:
        handoff = QrOnboardingEffectSourceService(repository).recover(
            snapshot=snapshot,
            invitation_id=issued.record.invitation.invitation_id,
            now_epoch=1200,
        )
        assert handoff.effect_kind is QrOnboardingEffectKind.ACCESS_REVOCATION
        assert handoff.device_id == "tablet-1"
        assert handoff.required_job_type == "typed-access-revocation-change-job"
    finally:
        connection.close()


def test_active_invitation_cannot_become_effect_handoff(tmp_path) -> None:
    snapshot = _snapshot()
    connection, repository = _open(tmp_path / "qr.db")
    runtime = QrOnboardingRuntimeService(repository)
    issued = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        created_at_epoch=1000,
        expires_at_epoch=1600,
        onboarding_code="A" * 32,
    )
    try:
        with pytest.raises(QrOnboardingEffectSourceError, match="qr_effect_source_invitation_not_terminal"):
            QrOnboardingEffectSourceService(repository).recover(
                snapshot=snapshot,
                invitation_id=issued.record.invitation.invitation_id,
                now_epoch=1100,
            )
    finally:
        connection.close()


def test_tampered_terminal_receipt_is_rejected_fail_closed(tmp_path) -> None:
    snapshot = _snapshot()
    connection, repository = _open(tmp_path / "qr.db")
    invitation_id = _consume_guest(repository, snapshot)
    row = connection.execute(
        "SELECT operation_key_sha256, receipt_json FROM qr_onboarding_runtime_operations LIMIT 1"
    ).fetchone()
    value = json.loads(row[1])
    value["external_publication_authorized"] = True
    connection.execute(
        "UPDATE qr_onboarding_runtime_operations SET receipt_json=? WHERE operation_key_sha256=?",
        (json.dumps(value, sort_keys=True, separators=(",", ":")), row[0]),
    )
    connection.commit()
    try:
        with pytest.raises(QrOnboardingEffectSourceError, match="qr_effect_source_receipt_storage_rejected"):
            QrOnboardingEffectSourceService(repository).recover(
                snapshot=snapshot,
                invitation_id=invitation_id,
                now_epoch=1300,
            )
    finally:
        connection.close()
