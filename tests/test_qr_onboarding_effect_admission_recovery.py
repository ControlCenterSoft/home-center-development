from __future__ import annotations

import json
import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import (
    QrOnboardingEffectAdmissionError,
    QrOnboardingEffectAdmissionService,
)
from home_center.qr_onboarding_effect_handoff import build_qr_onboarding_effect_handoff
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
            devices=(),
        )
    )
    return households.read("home-main")


def _handoff(snapshot):
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    service = QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1000,
        expires_at_epoch=1600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="D" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="D" * 32,
        now_epoch=1100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="D" * 32,
        actor="redemption-session",
        idempotency_key="consume-recoverable-admission",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def test_restart_recovers_exact_admission_and_closed_handoff_without_new_job(tmp_path) -> None:
    path = tmp_path / "state.db"
    audit_key = b"r" * 32
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    first = StateStore(path, audit_key, "cluster-test")
    try:
        admission = QrOnboardingEffectAdmissionService(first).admit(
            actor="parent-session",
            correlation_id="corr-admission-recovery-1",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="effect-admission-recovery-1",
        )
        job_count = len(first.jobs())
        audit_count = len(first.audit_events())
    finally:
        first.close()

    reopened = StateStore(path, audit_key, "cluster-test")
    try:
        recovered_admission, recovered_handoff = QrOnboardingEffectAdmissionService(reopened).recover(admission.job_id)
        assert recovered_admission.to_dict() == admission.to_dict()
        assert recovered_handoff.to_dict() == handoff.to_dict()
        assert len(reopened.jobs()) == job_count
        assert len(reopened.audit_events()) == audit_count
        job = reopened.job(admission.job_id)
        assert job is not None
        assert job["state"] == "preflight"
        assert job["result"] is None
        assert job["evidence"] is None
        assert job["preflight"]["handoff"] == handoff.to_dict()
        store_handoff = job["preflight"]["handoff"]
        assert store_handoff["effect_execution_authorized"] is False
        assert store_handoff["provider_execution_authorized"] is False
        assert store_handoff["infrastructure_mutation_authorized"] is False
        assert store_handoff["external_publication_authorized"] is False
        reopened.verify_audit_chain()
    finally:
        reopened.close()


def test_recovery_rejects_tampered_persisted_handoff_fail_closed(tmp_path) -> None:
    path = tmp_path / "state.db"
    audit_key = b"s" * 32
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(path, audit_key, "cluster-test")
    try:
        admission = QrOnboardingEffectAdmissionService(store).admit(
            actor="parent-session",
            correlation_id="corr-admission-recovery-2",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="effect-admission-recovery-2",
        )
    finally:
        store.close()

    connection = sqlite3.connect(path)
    try:
        raw = connection.execute("SELECT preflight_json FROM jobs WHERE job_id = ?", (admission.job_id,)).fetchone()[0]
        preflight = json.loads(raw)
        preflight["handoff"]["target_member_id"] = "attacker-substitution"
        connection.execute(
            "UPDATE jobs SET preflight_json = ? WHERE job_id = ?",
            (json.dumps(preflight, sort_keys=True, separators=(",", ":")), admission.job_id),
        )
        connection.commit()
    finally:
        connection.close()

    reopened = StateStore(path, audit_key, "cluster-test")
    try:
        with pytest.raises(QrOnboardingEffectAdmissionError, match="qr_effect_admission_recovery_handoff_rejected"):
            QrOnboardingEffectAdmissionService(reopened).recover(admission.job_id)
        assert len(reopened.jobs()) == 1
    finally:
        reopened.close()
