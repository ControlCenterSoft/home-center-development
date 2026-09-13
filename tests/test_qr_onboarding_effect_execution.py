from __future__ import annotations

import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import QrOnboardingEffectAdmissionService
from home_center.qr_onboarding_effect_execution import (
    QrOnboardingEffectExecutionError,
    QrOnboardingEffectExecutionReceipt,
    QrOnboardingEffectExecutionService,
    QrOnboardingEffectObservation,
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
        onboarding_code="C" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="C" * 32,
        now_epoch=1100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="C" * 32,
        actor="redemption-session",
        idempotency_key="consume-effect-execution-1",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def _admit(store, snapshot, handoff):
    return QrOnboardingEffectAdmissionService(store).admit(
        actor="parent-session",
        correlation_id="corr-effect-admission",
        handoff=handoff,
        current_snapshot=snapshot,
        idempotency_key="effect-admission-1",
    )


class _Adapter:
    def __init__(self, *, verified: bool = True, execute_error: Exception | None = None) -> None:
        self.verified = verified
        self.execute_error = execute_error
        self.execute_calls = 0
        self.observe_calls = 0
        self.crash_on_first_observe = False

    def execute(self, request):
        self.execute_calls += 1
        if self.execute_error is not None:
            raise self.execute_error
        return QrOnboardingEffectExecutionReceipt(
            request_id=request.request_id,
            operation_id="effect-operation-1",
            accepted=True,
        )

    def observe(self, request):
        self.observe_calls += 1
        if self.crash_on_first_observe and self.observe_calls == 1:
            raise SystemExit("simulated process loss after durable receipt")
        return QrOnboardingEffectObservation(
            request_id=request.request_id,
            operation_id="effect-operation-1",
            observed_post_condition=request.expected_post_condition,
            post_condition_verified=self.verified,
            evidence_sha256="a" * 64,
        )


def test_effect_job_succeeds_only_after_authoritative_positive_readback(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"a" * 32, "cluster-test")
    try:
        admission = _admit(store, snapshot, handoff)
        adapter = _Adapter(verified=True)
        service = QrOnboardingEffectExecutionService(store)
        service.register(handoff.required_job_type, adapter)
        job = service.execute_and_verify(
            actor="parent-session",
            correlation_id="corr-effect-execute-1",
            admission=admission,
            handoff=handoff,
            current_snapshot=snapshot,
        )
        assert adapter.execute_calls == 1
        assert adapter.observe_calls == 1
        assert job["state"] == "succeeded"
        assert job["result"]["accepted"] is True
        assert job["result"]["post_condition_verified"] is False
        assert job["result"]["effect_success_claimed"] is False
        assert job["evidence"]["post_condition_verified"] is True
        assert job["evidence"]["effect_success_claimed"] is False
        assert job["steps"][-1] == {"state": "succeeded", "step": "post-condition-verify"}
        store.verify_audit_chain()
    finally:
        store.close()


def test_missing_adapter_fails_closed_without_starting_job(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"b" * 32, "cluster-test")
    try:
        admission = _admit(store, snapshot, handoff)
        service = QrOnboardingEffectExecutionService(store)
        with pytest.raises(QrOnboardingEffectExecutionError, match="qr_effect_adapter_unavailable"):
            service.execute_and_verify(
                actor="parent-session",
                correlation_id="corr-effect-execute-2",
                admission=admission,
                handoff=handoff,
                current_snapshot=snapshot,
            )
        assert store.job(admission.job_id)["state"] == "preflight"
    finally:
        store.close()


def test_ambiguous_execution_failure_is_terminal_and_never_auto_retried(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"c" * 32, "cluster-test")
    try:
        admission = _admit(store, snapshot, handoff)
        adapter = _Adapter(execute_error=TimeoutError("ambiguous transport loss"))
        service = QrOnboardingEffectExecutionService(store)
        service.register(handoff.required_job_type, adapter)
        with pytest.raises(QrOnboardingEffectExecutionError, match="qr_effect_execution_outcome_uncertain"):
            service.execute_and_verify(
                actor="parent-session",
                correlation_id="corr-effect-execute-3",
                admission=admission,
                handoff=handoff,
                current_snapshot=snapshot,
            )
        failed = store.job(admission.job_id)
        assert failed["state"] == "failed"
        assert failed["evidence"]["outcome_uncertain"] is True
        assert failed["evidence"]["automatic_retry_authorized"] is False
        with pytest.raises(QrOnboardingEffectExecutionError, match="qr_effect_execution_job_not_preflight"):
            service.execute_and_verify(
                actor="parent-session",
                correlation_id="corr-effect-execute-4",
                admission=admission,
                handoff=handoff,
                current_snapshot=snapshot,
            )
        assert adapter.execute_calls == 1
    finally:
        store.close()


def test_negative_readback_cannot_be_presented_as_success(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"d" * 32, "cluster-test")
    try:
        admission = _admit(store, snapshot, handoff)
        adapter = _Adapter(verified=False)
        service = QrOnboardingEffectExecutionService(store)
        service.register(handoff.required_job_type, adapter)
        with pytest.raises(QrOnboardingEffectExecutionError, match="qr_effect_post_condition_not_verified"):
            service.execute_and_verify(
                actor="parent-session",
                correlation_id="corr-effect-execute-5",
                admission=admission,
                handoff=handoff,
                current_snapshot=snapshot,
            )
        failed = store.job(admission.job_id)
        assert failed["state"] == "failed"
        assert failed["evidence"]["post_condition_verified"] is False
        assert failed["evidence"]["effect_success_claimed"] is False
    finally:
        store.close()


def test_restart_reconciliation_repeats_readback_but_never_execution(tmp_path) -> None:
    snapshot = _snapshot()
    handoff = _handoff(snapshot)
    store = StateStore(tmp_path / "state.db", b"e" * 32, "cluster-test")
    try:
        admission = _admit(store, snapshot, handoff)
        adapter = _Adapter(verified=True)
        adapter.crash_on_first_observe = True
        service = QrOnboardingEffectExecutionService(store)
        service.register(handoff.required_job_type, adapter)
        with pytest.raises(SystemExit, match="simulated process loss"):
            service.execute_and_verify(
                actor="parent-session",
                correlation_id="corr-effect-execute-6",
                admission=admission,
                handoff=handoff,
                current_snapshot=snapshot,
            )
        assert store.job(admission.job_id)["state"] == "verifying"
        assert adapter.execute_calls == 1
        job = service.reconcile_verifying(
            actor="parent-session",
            correlation_id="corr-effect-reconcile-1",
            admission=admission,
            handoff=handoff,
            current_snapshot=snapshot,
        )
        assert job["state"] == "succeeded"
        assert adapter.execute_calls == 1
        assert adapter.observe_calls == 2
    finally:
        store.close()
