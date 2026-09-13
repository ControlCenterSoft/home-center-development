from __future__ import annotations

import json
import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import QrOnboardingEffectAdmissionService
from home_center.qr_onboarding_effect_execution import (
    QrOnboardingEffectExecutionError,
    QrOnboardingEffectExecutionService,
)
from home_center.qr_onboarding_effect_handoff import build_qr_onboarding_effect_handoff
from home_center.qr_onboarding_effect_product_state import (
    KEY_PREFIX,
    QrOnboardingLocalProductStateAdapter,
    register_local_qr_effect_adapters,
)
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from home_center.store import StateStore
from home_center.util import canonical_json


def _snapshot():
    households = HouseholdStore()
    households.create(
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
    return households.read("home-main")


def _runtime() -> QrOnboardingRuntimeService:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    return QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))


def _guest_handoff(snapshot, code: str = "G" * 32):
    service = _runtime()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1000,
        expires_at_epoch=1600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code=code,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code=code,
        now_epoch=1100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code=code,
        actor="redemption-session",
        idempotency_key="consume-local-product-state",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def _device_handoff(snapshot, code: str = "H" * 32):
    service = _runtime()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="child-1",
        subject=OnboardingSubject.DEVICE,
        device_id="tablet-1",
        created_at_epoch=1000,
        expires_at_epoch=1600,
        onboarding_code=code,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code=code,
        now_epoch=1100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code=code,
        actor="redemption-session",
        idempotency_key="consume-local-device-state",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def _revoked_guest_handoff(snapshot, code: str = "J" * 32):
    service = _runtime()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1000,
        expires_at_epoch=1600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code=code,
    )
    record, receipt = service.revoke(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        actor_member_id="parent-1",
        idempotency_key="revoke-local-guest-state",
        expected_version=1,
        now_epoch=1100,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def _execute(store: StateStore, snapshot, handoff, idempotency_key: str):
    admission = QrOnboardingEffectAdmissionService(store).admit(
        actor="parent-session",
        correlation_id=f"corr-{idempotency_key}",
        handoff=handoff,
        current_snapshot=snapshot,
        idempotency_key=idempotency_key,
    )
    service = QrOnboardingEffectExecutionService(store)
    register_local_qr_effect_adapters(service, store.path)
    job = service.execute_and_verify(
        actor="parent-session",
        correlation_id=f"corr-exec-{idempotency_key}",
        admission=admission,
        handoff=handoff,
        current_snapshot=snapshot,
    )
    return admission, job


def _effect_state(store: StateStore, handoff_id: str) -> dict[str, object]:
    key = f"{KEY_PREFIX}{handoff_id}"
    matches = [item for item in store.desired_state() if item["resource_key"] == key]
    assert len(matches) == 1
    return matches[0]


def test_guest_effect_succeeds_only_after_durable_authoritative_product_state_readback(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _guest_handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"g" * 32, "cluster-test")
    try:
        admission, job = _execute(store, snapshot, handoff, "guest-effect-local-1")
        assert job["state"] == "succeeded"
        assert job["evidence"]["post_condition_verified"] is True
        state = _effect_state(store, handoff.handoff_id)
        assert state["generation"] == 1
        assert state["value"]["state"] == "active"
        assert state["value"]["subject"] == "guest"
        assert state["value"]["guest_scope"] == ["internet.guest"]
        assert state["value"]["device_id"] is None
        assert state["value"]["handoff_id"] == handoff.handoff_id
        assert state["value"]["provider_execution_authorized"] is False
        assert state["value"]["infrastructure_mutation_authorized"] is False
        assert state["value"]["external_publication_authorized"] is False
        assert admission.job_id == job["job_id"]
        store.verify_audit_chain()
        backup = tmp_path / "backup.db"
        store.backup_to(backup)
    finally:
        store.close()

    restored = StateStore(backup, b"g" * 32, "cluster-test")
    try:
        restored_state = _effect_state(restored, handoff.handoff_id)
        assert restored_state["value"]["state"] == "active"
        assert restored.job(admission.job_id)["state"] == "succeeded"
        restored.verify_audit_chain()
    finally:
        restored.close()


def test_device_binding_effect_is_exact_local_product_state_without_managed_or_provider_mutation(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _device_handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"h" * 32, "cluster-test")
    try:
        _, job = _execute(store, snapshot, handoff, "device-effect-local-1")
        assert job["state"] == "succeeded"
        state = _effect_state(store, handoff.handoff_id)["value"]
        assert state["state"] == "active"
        assert state["subject"] == "device"
        assert state["device_id"] == "tablet-1"
        assert state["guest_scope"] == []
        assert snapshot.household.devices[0].managed is False
        assert state["provider_execution_authorized"] is False
    finally:
        store.close()


def test_revoked_invitation_writes_only_exact_handoff_revocation_tombstone(tmp_path) -> None:
    snapshot = _snapshot()
    active_handoff = _guest_handoff(snapshot, "K" * 32)
    revoked_handoff = _revoked_guest_handoff(snapshot, "L" * 32)
    store = StateStore(tmp_path / "state.db", b"i" * 32, "cluster-test")
    try:
        _execute(store, snapshot, active_handoff, "guest-active-local-1")
        _execute(store, snapshot, revoked_handoff, "guest-revoked-local-1")
        active = _effect_state(store, active_handoff.handoff_id)["value"]
        revoked = _effect_state(store, revoked_handoff.handoff_id)["value"]
        assert active["state"] == "active"
        assert revoked["state"] == "revoked"
        assert active["resource_key"] != revoked["resource_key"]
        assert active["request_id"] != revoked["request_id"]
    finally:
        store.close()


class _TamperingAdapter:
    def __init__(self, delegate: QrOnboardingLocalProductStateAdapter, path) -> None:
        self.delegate = delegate
        self.path = path

    def execute(self, request):
        receipt = self.delegate.execute(request)
        key = f"{KEY_PREFIX}{request.handoff_id}"
        connection = sqlite3.connect(self.path)
        try:
            row = connection.execute(
                "SELECT value_json FROM desired_state WHERE resource_key=?", (key,)
            ).fetchone()
            value = json.loads(row[0])
            value["state"] = "tampered-after-command"
            connection.execute(
                "UPDATE desired_state SET value_json=? WHERE resource_key=?",
                (canonical_json(value), key),
            )
            connection.commit()
        finally:
            connection.close()
        return receipt

    def observe(self, request):
        return self.delegate.observe(request)


def test_post_command_state_drift_fails_job_instead_of_inventing_success(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _guest_handoff(snapshot, "M" * 32)
    store = StateStore(tmp_path / "state.db", b"j" * 32, "cluster-test")
    try:
        admission = QrOnboardingEffectAdmissionService(store).admit(
            actor="parent-session",
            correlation_id="corr-tamper-admit",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="guest-effect-tamper-1",
        )
        service = QrOnboardingEffectExecutionService(store)
        delegate = QrOnboardingLocalProductStateAdapter(store.path)
        service.register(handoff.required_job_type, _TamperingAdapter(delegate, store.path))
        with pytest.raises(QrOnboardingEffectExecutionError, match="qr_effect_post_condition_not_verified"):
            service.execute_and_verify(
                actor="parent-session",
                correlation_id="corr-tamper-exec",
                admission=admission,
                handoff=handoff,
                current_snapshot=snapshot,
            )
        job = store.job(admission.job_id)
        assert job["state"] == "failed"
        assert job["evidence"]["post_condition_verified"] is False
        assert job["evidence"]["effect_success_claimed"] is False
    finally:
        store.close()
