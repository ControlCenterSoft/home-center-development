from __future__ import annotations

import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore, build_household_snapshot
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import QrOnboardingEffectAdmissionService
from home_center.qr_onboarding_effect_execution import (
    QrOnboardingEffectExecutionError,
    QrOnboardingEffectExecutionService,
)
from home_center.qr_onboarding_effect_handoff import build_qr_onboarding_effect_handoff
from home_center.qr_onboarding_effect_worker import (
    QrOnboardingEffectWorkerError,
    QrOnboardingEffectWorkerService,
)
from home_center.qr_onboarding_product_state import QrOnboardingProductStateAdapter, SUPPORTED_JOB_TYPES
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
    runtime = QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))
    issued = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1000,
        expires_at_epoch=1600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="W" * 32,
    )
    plan = runtime.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="W" * 32,
        now_epoch=1100,
    )
    record, receipt = runtime.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="W" * 32,
        actor="redemption-session",
        idempotency_key="consume-worker-effect-1",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def _persist_household(store: StateStore, snapshot) -> None:
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor="parent-session", member_id="parent-1"),)),
    )


def _admit(store: StateStore, snapshot, handoff):
    return QrOnboardingEffectAdmissionService(store).admit(
        actor="parent-session",
        correlation_id="corr-worker-admit",
        handoff=handoff,
        current_snapshot=snapshot,
        idempotency_key="worker-effect-admission-1",
    )


def _worker(store: StateStore) -> QrOnboardingEffectWorkerService:
    execution = QrOnboardingEffectExecutionService(store)
    adapter = QrOnboardingProductStateAdapter(store)
    for job_type in SUPPORTED_JOB_TYPES:
        execution.register(job_type, adapter)
    return QrOnboardingEffectWorkerService(store, execution)


def test_worker_recovers_preflight_after_restart_and_executes_once(tmp_path) -> None:
    path = tmp_path / "state.db"
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    first = StateStore(path, b"w" * 32, "cluster-test")
    _persist_household(first, snapshot)
    admission = _admit(first, snapshot, handoff)
    first.close()

    reopened = StateStore(path, b"w" * 32, "cluster-test")
    try:
        worker = _worker(reopened)
        succeeded = worker.run(
            actor="parent-session",
            correlation_id="corr-worker-run-1",
            job_id=admission.job_id,
        )
        assert succeeded["state"] == "succeeded"
        assert succeeded["evidence"]["post_condition_verified"] is True
        assert succeeded["evidence"]["effect_success_claimed"] is False

        replay = worker.run(
            actor="parent-session",
            correlation_id="corr-worker-run-2",
            job_id=admission.job_id,
        )
        assert replay == succeeded
        reopened.verify_audit_chain()
    finally:
        reopened.close()


def test_worker_revalidates_current_household_before_effect_mutation(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"x" * 32, "cluster-test")
    try:
        _persist_household(store, snapshot)
        admission = _admit(store, snapshot, handoff)
        newer = build_household_snapshot(
            snapshot.household,
            generation=snapshot.generation + 1,
            previous_snapshot_id=snapshot.snapshot_id,
        )
        _persist_household(store, newer)

        with pytest.raises(QrOnboardingEffectExecutionError, match="qr_effect_execution_household_state_stale"):
            _worker(store).run(
                actor="parent-session",
                correlation_id="corr-worker-stale",
                job_id=admission.job_id,
            )
        assert store.job(admission.job_id)["state"] == "preflight"
    finally:
        store.close()


def test_worker_never_reinvokes_running_uncertain_job(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"y" * 32, "cluster-test")
    try:
        _persist_household(store, snapshot)
        admission = _admit(store, snapshot, handoff)
        store.transition_action_job(
            admission.job_id,
            expected_state="preflight",
            new_state="running",
            steps=[
                {"step": "handoff-revalidate", "state": "succeeded"},
                {"step": "typed-effect-execute", "state": "running"},
                {"step": "authoritative-readback", "state": "pending"},
                {"step": "post-condition-verify", "state": "pending"},
            ],
        )
        with pytest.raises(QrOnboardingEffectWorkerError, match="qr_effect_worker_outcome_uncertain"):
            _worker(store).run(
                actor="parent-session",
                correlation_id="corr-worker-uncertain",
                job_id=admission.job_id,
            )
        assert store.job(admission.job_id)["state"] == "running"
    finally:
        store.close()
