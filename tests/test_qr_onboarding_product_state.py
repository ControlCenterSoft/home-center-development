from __future__ import annotations

import sqlite3

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import QrOnboardingEffectAdmissionService
from home_center.qr_onboarding_effect_execution import QrOnboardingEffectExecutionService
from home_center.qr_onboarding_effect_handoff import build_qr_onboarding_effect_handoff
from home_center.qr_onboarding_product_state import (
    QrOnboardingProductStateAdapter,
    QR_PRODUCT_STATE_SCHEMA,
)
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from home_center.store import StateStore


def _snapshot():
    households = HouseholdStore()
    households.create(
        Household(
            household_id="home-main",
            members=(
                FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
                FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
            ),
            devices=(
                ManagedDevice("tablet-1", "guest-1", "Guest tablet", managed=False),
            ),
        )
    )
    return households.read("home-main")


def _handoff(snapshot, *, subject: OnboardingSubject, revoke: bool = False):
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    runtime = QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))
    kwargs = {
        "snapshot": snapshot,
        "issuer_member_id": "parent-1",
        "target_member_id": "guest-1",
        "subject": subject,
        "created_at_epoch": 1000,
        "expires_at_epoch": 1600,
        "onboarding_code": "P" * 32,
    }
    if subject is OnboardingSubject.GUEST:
        kwargs["guest_scope"] = (GuestScope.INTERNET_GUEST,)
    else:
        kwargs["device_id"] = "tablet-1"
    issued = runtime.issue(**kwargs)
    if revoke:
        record, receipt = runtime.revoke(
            snapshot=snapshot,
            invitation_id=issued.record.invitation.invitation_id,
            actor_member_id="parent-1",
            idempotency_key="revoke-product-effect-1",
            expected_version=1,
            now_epoch=1100,
        )
    else:
        plan = runtime.plan_redemption(
            snapshot=snapshot,
            invitation_id=issued.record.invitation.invitation_id,
            onboarding_code="P" * 32,
            now_epoch=1100,
        )
        record, receipt = runtime.consume(
            snapshot=snapshot,
            plan=plan,
            onboarding_code="P" * 32,
            actor="redemption-session",
            idempotency_key=f"consume-{subject.value}-product-effect-1",
            confirmed=True,
            expected_version=1,
            now_epoch=1200,
        )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def _execute(store: StateStore, snapshot, handoff):
    admission = QrOnboardingEffectAdmissionService(store).admit(
        actor="parent-session",
        correlation_id="corr-product-state-admission",
        handoff=handoff,
        current_snapshot=snapshot,
        idempotency_key=f"admit-{handoff.handoff_id}",
    )
    adapter = QrOnboardingProductStateAdapter(store)
    service = QrOnboardingEffectExecutionService(store)
    service.register(handoff.required_job_type, adapter)
    job = service.execute_and_verify(
        actor="parent-session",
        correlation_id="corr-product-state-execute",
        admission=admission,
        handoff=handoff,
        current_snapshot=snapshot,
    )
    return adapter, job


def test_guest_access_effect_is_durable_bounded_product_state(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot, subject=OnboardingSubject.GUEST)
    path = tmp_path / "state.db"
    store = StateStore(path, b"g" * 32, "cluster-test")
    expected_state = None
    try:
        adapter, job = _execute(store, snapshot, handoff)
        state = adapter.state(handoff.handoff_id)
        assert job["state"] == "succeeded"
        assert job["evidence"]["post_condition_verified"] is True
        assert state is not None
        assert state["schema"] == QR_PRODUCT_STATE_SCHEMA
        assert state["effect"] == "guest-access"
        assert state["state"] == "effective"
        assert state["guest_scope"] == ["internet.guest"]
        assert state["target_member_id"] == "guest-1"
        assert state["device_id"] is None
        assert state["account_creation_authorized"] is False
        assert state["provider_execution_authorized"] is False
        assert state["infrastructure_mutation_authorized"] is False
        assert state["external_publication_authorized"] is False
        expected_state = state
        store.verify_audit_chain()
    finally:
        store.close()

    reopened = StateStore(path, b"g" * 32, "cluster-test")
    try:
        persisted = QrOnboardingProductStateAdapter(reopened).state(handoff.handoff_id)
        assert persisted == expected_state
        reopened.verify_audit_chain()
    finally:
        reopened.close()


def test_device_binding_effect_requires_exact_registered_device_identity(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot, subject=OnboardingSubject.DEVICE)
    store = StateStore(tmp_path / "state.db", b"d" * 32, "cluster-test")
    try:
        adapter, job = _execute(store, snapshot, handoff)
        state = adapter.state(handoff.handoff_id)
        assert job["state"] == "succeeded"
        assert state is not None
        assert state["effect"] == "device-binding"
        assert state["state"] == "effective"
        assert state["device_id"] == "tablet-1"
        assert state["target_member_id"] == "guest-1"
        assert state["managed_state_change_authorized"] is False
        assert snapshot.household.devices[0].managed is False
    finally:
        store.close()


def test_revoke_effect_persists_fail_closed_product_state_tombstone(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot, subject=OnboardingSubject.GUEST, revoke=True)
    store = StateStore(tmp_path / "state.db", b"r" * 32, "cluster-test")
    try:
        adapter, job = _execute(store, snapshot, handoff)
        state = adapter.state(handoff.handoff_id)
        assert job["state"] == "succeeded"
        assert state is not None
        assert state["effect"] == "access-revocation"
        assert state["state"] == "revoked"
        assert state["provider_execution_authorized"] is False
        assert state["infrastructure_mutation_authorized"] is False
        assert state["external_publication_authorized"] is False
    finally:
        store.close()
