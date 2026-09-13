from __future__ import annotations

import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, InvitationState, OnboardingSubject
from home_center.qr_onboarding_runtime import (
    QrOnboardingRuntimeError,
    QrOnboardingRuntimeService,
    SQLiteQrOnboardingRuntimeRepository,
)


def _household(*, guest_enabled: bool = True) -> Household:
    return Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
            FamilyMember("guest-1", "Guest", HouseholdRole.GUEST, enabled=guest_enabled),
            FamilyMember("child-1", "Child", HouseholdRole.CHILD),
        ),
        devices=(ManagedDevice("tablet-1", "child-1", "Tablet", managed=False),),
    )


def _snapshot():
    store = HouseholdStore()
    store.create(_household())
    return store, store.read("home-main")


def _service():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    repository = SQLiteQrOnboardingRuntimeRepository(connection)
    return connection, repository, QrOnboardingRuntimeService(repository)


def test_issue_persists_digest_only_and_binds_exact_household_state() -> None:
    _, snapshot = _snapshot()
    connection, repository, service = _service()
    result = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="A" * 32,
    )

    assert result.record.state is InvitationState.ACTIVE
    assert result.record.household_snapshot_id == snapshot.snapshot_id
    assert result.record.household_resource_version == snapshot.resource_version
    assert result.record.household_generation == snapshot.generation
    assert result.record.target_member_id == "guest-1"
    assert result.payload.onboarding_code == "A" * 32
    assert "onboarding_code" not in result.record.to_dict()
    assert "onboarding_code" not in result.receipt.to_dict()
    assert result.receipt.to_dict()["onboarding_effect_verified"] is False
    assert result.receipt.to_dict()["account_creation_authorized"] is False

    row = connection.execute(
        "SELECT invitation_json, token_sha256 FROM qr_onboarding_runtime WHERE invitation_id=?",
        (result.record.invitation.invitation_id,),
    ).fetchone()
    assert "A" * 32 not in row[0]
    assert row[1] == result.record.invitation.token_sha256
    assert repository.get(result.record.invitation.invitation_id, now_epoch=1_100) == result.record


def test_guest_issue_is_bounded_to_enabled_guest_and_internet_scope() -> None:
    _, snapshot = _snapshot()
    _, _, service = _service()
    with pytest.raises(QrOnboardingRuntimeError, match="qr_runtime_guest_member_required"):
        service.issue(
            snapshot=snapshot,
            issuer_member_id="parent-1",
            target_member_id="child-1",
            subject=OnboardingSubject.GUEST,
            created_at_epoch=1_000,
            expires_at_epoch=1_600,
            guest_scope=(GuestScope.INTERNET_GUEST,),
            onboarding_code="B" * 32,
        )
    with pytest.raises(QrOnboardingRuntimeError, match="qr_runtime_guest_scope_not_bounded"):
        service.issue(
            snapshot=snapshot,
            issuer_member_id="parent-1",
            target_member_id="guest-1",
            subject=OnboardingSubject.GUEST,
            created_at_epoch=1_000,
            expires_at_epoch=1_600,
            guest_scope=(GuestScope.HOME_STATUS_READ,),
            onboarding_code="C" * 32,
        )


def test_device_issue_requires_existing_unmanaged_device_binding() -> None:
    _, snapshot = _snapshot()
    _, _, service = _service()
    result = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="child-1",
        subject=OnboardingSubject.DEVICE,
        device_id="tablet-1",
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        onboarding_code="D" * 32,
    )
    assert result.record.target_member_id == "child-1"
    assert result.receipt.to_dict()["device_registration_authorized"] is False
    assert result.receipt.to_dict()["managed_state_change_authorized"] is False

    with pytest.raises(QrOnboardingRuntimeError, match="qr_runtime_device_not_registered"):
        service.issue(
            snapshot=snapshot,
            issuer_member_id="parent-1",
            target_member_id="child-1",
            subject=OnboardingSubject.DEVICE,
            device_id="unknown-device",
            created_at_epoch=1_000,
            expires_at_epoch=1_600,
            onboarding_code="E" * 32,
        )


def test_consume_is_confirmation_gated_atomic_and_idempotent() -> None:
    _, snapshot = _snapshot()
    _, repository, service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="F" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="F" * 32,
        now_epoch=1_100,
    )
    with pytest.raises(QrOnboardingRuntimeError, match="qr_runtime_confirmation_required"):
        service.consume(
            snapshot=snapshot,
            plan=plan,
            onboarding_code="F" * 32,
            actor="redemption-session-1",
            idempotency_key="consume-key-0001",
            confirmed=False,
            expected_version=1,
            now_epoch=1_200,
        )

    first_record, first_receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="F" * 32,
        actor="redemption-session-1",
        idempotency_key="consume-key-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    assert first_record.state is InvitationState.CONSUMED
    assert first_record.version == 2
    assert first_record.consumed_at_epoch == 1_200
    assert first_receipt.next_required_boundary == "typed-guest-access-change-job"
    assert first_receipt.to_dict()["onboarding_effect_verified"] is False

    replay_record, replay_receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="F" * 32,
        actor="redemption-session-1",
        idempotency_key="consume-key-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    assert replay_record == first_record
    assert replay_receipt == first_receipt
    assert repository.get(issued.record.invitation.invitation_id, now_epoch=1_300).version == 2


def test_wrong_code_expiry_and_reuse_fail_closed() -> None:
    _, snapshot = _snapshot()
    _, _, service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="G" * 32,
    )
    with pytest.raises(QrOnboardingRuntimeError, match="qr_onboarding_code_mismatch"):
        service.plan_redemption(
            snapshot=snapshot,
            invitation_id=issued.record.invitation.invitation_id,
            onboarding_code="H" * 32,
            now_epoch=1_100,
        )
    with pytest.raises(QrOnboardingRuntimeError, match="qr_invitation_expired"):
        service.plan_redemption(
            snapshot=snapshot,
            invitation_id=issued.record.invitation.invitation_id,
            onboarding_code="G" * 32,
            now_epoch=1_600,
        )


def test_household_drift_blocks_redemption_before_consume() -> None:
    store, snapshot = _snapshot()
    _, _, service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="I" * 32,
    )
    store.replace(_household(guest_enabled=False), expected_resource_version=snapshot.resource_version)
    changed = store.read("home-main")
    with pytest.raises(QrOnboardingRuntimeError, match="qr_runtime_household_state_stale"):
        service.plan_redemption(
            snapshot=changed,
            invitation_id=issued.record.invitation.invitation_id,
            onboarding_code="I" * 32,
            now_epoch=1_100,
        )


def test_revoke_requires_parent_and_prevents_later_redemption() -> None:
    _, snapshot = _snapshot()
    _, _, service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="J" * 32,
    )
    with pytest.raises(QrOnboardingRuntimeError, match="qr_runtime_parent_required"):
        service.revoke(
            snapshot=snapshot,
            invitation_id=issued.record.invitation.invitation_id,
            actor_member_id="child-1",
            idempotency_key="revoke-key-0001",
            expected_version=1,
            now_epoch=1_100,
        )
    record, receipt = service.revoke(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        actor_member_id="parent-1",
        idempotency_key="revoke-key-0001",
        expected_version=1,
        now_epoch=1_100,
    )
    assert record.state is InvitationState.REVOKED
    assert record.revoked_at_epoch == 1_100
    assert receipt.next_required_boundary == "typed-access-revocation-change-job"
    with pytest.raises(QrOnboardingRuntimeError, match="qr_invitation_revoked"):
        service.plan_redemption(
            snapshot=snapshot,
            invitation_id=issued.record.invitation.invitation_id,
            onboarding_code="J" * 32,
            now_epoch=1_200,
        )
