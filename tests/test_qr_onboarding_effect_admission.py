from __future__ import annotations

import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import (
    QrOnboardingEffectAdmissionError,
    QrOnboardingEffectAdmissionService,
)
from home_center.qr_onboarding_effect_handoff import build_qr_onboarding_effect_handoff
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from home_center.store import StateStore


def _household_store() -> HouseholdStore:
    store = HouseholdStore()
    store.create(
        Household(
            household_id="home-main",
            members=(
                FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
                FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
                FamilyMember("child-1", "Child", HouseholdRole.CHILD),
            ),
            devices=(ManagedDevice("tablet-1", "child-1", "Tablet", managed=False),),
        )
    )
    return store


def _qr_service() -> QrOnboardingRuntimeService:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    return QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))


def _guest_handoff(snapshot):
    service = _qr_service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1000,
        expires_at_epoch=1600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="A" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="A" * 32,
        now_epoch=1100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="A" * 32,
        actor="redemption-session",
        idempotency_key="consume-admission-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def _device_handoff(snapshot):
    service = _qr_service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="child-1",
        subject=OnboardingSubject.DEVICE,
        device_id="tablet-1",
        created_at_epoch=1000,
        expires_at_epoch=1600,
        onboarding_code="B" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="B" * 32,
        now_epoch=1100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="B" * 32,
        actor="redemption-session",
        idempotency_key="consume-admission-0002",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def test_admission_persists_typed_job_without_execution_or_success(tmp_path) -> None:
    household_store = _household_store()
    snapshot = household_store.read("home-main")
    handoff = _guest_handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"a" * 32, "cluster-test")
    try:
        service = QrOnboardingEffectAdmissionService(store)
        receipt = service.admit(
            actor="parent-session",
            correlation_id="corr-admission-1",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="qr-effect-admit-0001",
        )
        assert receipt.required_job_type == "typed-guest-access-change-job"
        assert receipt.state == "preflight"
        payload = receipt.to_dict()
        assert payload["execution_authorized"] is False
        assert payload["post_condition_verified"] is False
        assert payload["effect_success_claimed"] is False
        job = store.job(receipt.job_id)
        assert job is not None
        assert job["job_type"] == "typed-guest-access-change-job"
        assert job["state"] == "preflight"
        assert job["result"] is None
        assert job["evidence"] is None
        assert job["steps"][1:] == [
            {"state": "pending", "step": "typed-effect-execute"},
            {"state": "pending", "step": "authoritative-readback"},
            {"state": "pending", "step": "post-condition-verify"},
        ]
        events = store.audit_events()
        assert any(event["action"] == "household.qr-onboarding.effect.admit" for event in events)
        store.verify_audit_chain()
    finally:
        store.close()


def test_admission_replay_returns_same_job_without_duplicate(tmp_path) -> None:
    household_store = _household_store()
    snapshot = household_store.read("home-main")
    handoff = _guest_handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"b" * 32, "cluster-test")
    try:
        service = QrOnboardingEffectAdmissionService(store)
        first = service.admit(
            actor="parent-session",
            correlation_id="corr-admission-2",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="qr-effect-admit-0002",
        )
        second = service.admit(
            actor="parent-session",
            correlation_id="corr-admission-3",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="qr-effect-admit-0002",
        )
        assert second.job_id == first.job_id
        assert len([job for job in store.jobs() if job["job_type"] == handoff.required_job_type]) == 1
    finally:
        store.close()


def test_admission_rejects_stale_household_before_job_creation(tmp_path) -> None:
    household_store = _household_store()
    original = household_store.read("home-main")
    handoff = _guest_handoff(original)
    replacement = Household(
        household_id="home-main",
        members=original.household.members,
        devices=original.household.devices,
    )
    household_store.replace(replacement, expected_resource_version=original.resource_version)
    current = household_store.read("home-main")
    store = StateStore(tmp_path / "state.db", b"c" * 32, "cluster-test")
    try:
        service = QrOnboardingEffectAdmissionService(store)
        with pytest.raises(QrOnboardingEffectAdmissionError, match="qr_effect_admission_household_state_stale"):
            service.admit(
                actor="parent-session",
                correlation_id="corr-admission-4",
                handoff=handoff,
                current_snapshot=current,
                idempotency_key="qr-effect-admit-0003",
            )
        assert store.jobs() == []
    finally:
        store.close()


def test_admission_same_idempotency_key_is_scoped_by_typed_effect(tmp_path) -> None:
    household_store = _household_store()
    snapshot = household_store.read("home-main")
    guest = _guest_handoff(snapshot)
    device = _device_handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"d" * 32, "cluster-test")
    try:
        service = QrOnboardingEffectAdmissionService(store)
        service.admit(
            actor="parent-session",
            correlation_id="corr-admission-5",
            handoff=guest,
            current_snapshot=snapshot,
            idempotency_key="qr-effect-admit-shared",
        )
        other = service.admit(
            actor="parent-session",
            correlation_id="corr-admission-6",
            handoff=device,
            current_snapshot=snapshot,
            idempotency_key="qr-effect-admit-shared",
        )
        assert other.required_job_type == "typed-device-binding-change-job"
        assert len(store.jobs()) == 2
    finally:
        store.close()
