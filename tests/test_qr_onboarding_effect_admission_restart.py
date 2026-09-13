from __future__ import annotations

import sqlite3

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import QrOnboardingEffectAdmissionService
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
    qr = QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))
    code = "R" * 32
    issued = qr.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code=code,
    )
    plan = qr.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code=code,
        now_epoch=1_100,
    )
    record, receipt = qr.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code=code,
        actor="redemption-session-restart",
        idempotency_key="consume-restart-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def test_effect_admission_replay_survives_store_reopen_without_duplicate_or_success(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    path = tmp_path / "state.db"
    key = b"r" * 32

    first_store = StateStore(path, key, "cluster-test")
    try:
        first = QrOnboardingEffectAdmissionService(first_store).admit(
            actor="parent-session",
            correlation_id="corr-restart-first",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="qr-effect-restart-0001",
        )
        first_job = first_store.job(first.job_id)
        assert first_job is not None
        assert first_job["state"] == "preflight"
        assert first_job["result"] is None
        assert first_job["evidence"] is None
        first_store.verify_audit_chain()
    finally:
        first_store.close()

    reopened = StateStore(path, key, "cluster-test")
    try:
        replay = QrOnboardingEffectAdmissionService(reopened).admit(
            actor="parent-session",
            correlation_id="corr-restart-replay",
            handoff=handoff,
            current_snapshot=snapshot,
            idempotency_key="qr-effect-restart-0001",
        )
        assert replay.job_id == first.job_id
        jobs = [job for job in reopened.jobs() if job["job_type"] == handoff.required_job_type]
        assert len(jobs) == 1
        assert jobs[0]["state"] == "preflight"
        assert jobs[0]["result"] is None
        assert jobs[0]["evidence"] is None
        assert replay.execution_authorized is False
        assert replay.post_condition_verified is False
        assert replay.effect_success_claimed is False
        assert replay.provider_execution_authorized is False
        assert replay.infrastructure_mutation_authorized is False
        assert replay.external_publication_authorized is False
        reopened.verify_audit_chain()
    finally:
        reopened.close()
