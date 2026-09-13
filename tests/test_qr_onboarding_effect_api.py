from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_admission import QrOnboardingEffectAdmissionService
from home_center.qr_onboarding_effect_api import (
    ADMIT_REQUEST_SCHEMA,
    RUN_REQUEST_SCHEMA,
    QrOnboardingEffectApiError,
    QrOnboardingEffectApiService,
    parse_effect_admit_request,
    parse_effect_run_request,
)
from home_center.qr_onboarding_effect_execution import QrOnboardingEffectExecutionService
from home_center.qr_onboarding_effect_source import QrOnboardingEffectSourceService
from home_center.qr_onboarding_effect_worker import QrOnboardingEffectWorkerService
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


def _services(store: StateStore):
    repository = SQLiteQrOnboardingRuntimeRepository(store._connection, store._lock)  # noqa: SLF001
    qr = QrOnboardingRuntimeService(repository)
    source = QrOnboardingEffectSourceService(repository)
    admissions = QrOnboardingEffectAdmissionService(store)
    execution = QrOnboardingEffectExecutionService(store)
    adapter = QrOnboardingProductStateAdapter(store)
    for job_type in SUPPORTED_JOB_TYPES:
        execution.register(job_type, adapter)
    worker = QrOnboardingEffectWorkerService(store, execution)
    return qr, QrOnboardingEffectApiService(source, admissions, worker)


def _persist_household(store: StateStore, snapshot) -> None:
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor="parent-session", member_id="parent-1"),)),
    )


def _consume_guest(qr: QrOnboardingRuntimeService, snapshot) -> str:
    issued = qr.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        created_at_epoch=1000,
        expires_at_epoch=1600,
        onboarding_code="E" * 32,
    )
    plan = qr.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="E" * 32,
        now_epoch=1100,
    )
    qr.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="E" * 32,
        actor="redemption-session",
        idempotency_key="effect-api-consume-1",
        confirmed=True,
        expected_version=1,
        now_epoch=1200,
    )
    return issued.record.invitation.invitation_id


def test_effect_api_admits_then_runs_only_verified_terminal_qr_effect(tmp_path) -> None:
    snapshot = _snapshot()
    store = StateStore(tmp_path / "state.db", b"e" * 32, "cluster-test")
    try:
        _persist_household(store, snapshot)
        qr, api = _services(store)
        invitation_id = _consume_guest(qr, snapshot)

        admitted = api.admit(
            snapshot=snapshot,
            actor="parent-session",
            correlation_id="corr-effect-api-admit",
            now_epoch=1250,
            body={
                "schema": ADMIT_REQUEST_SCHEMA,
                "invitation_id": invitation_id,
                "idempotency_key": "effect-api-admit-1",
                "confirmed": True,
            },
        )
        admitted_dict = admitted.to_dict()
        assert admitted_dict["state"] == "preflight"
        assert admitted_dict["execution_authorized"] is False
        assert admitted_dict["post_condition_verified"] is False
        assert admitted_dict["provider_execution_authorized"] is False
        assert admitted_dict["infrastructure_mutation_authorized"] is False
        assert admitted_dict["external_publication_authorized"] is False

        completed = api.run(
            actor="parent-session",
            correlation_id="corr-effect-api-run",
            body={"schema": RUN_REQUEST_SCHEMA, "job_id": admitted.job_id, "confirmed": True},
        )
        completed_dict = completed.to_dict()
        assert completed_dict["state"] == "succeeded"
        assert completed_dict["onboarding_effect_verified"] is True
        assert completed_dict["post_condition_verified"] is True
        assert completed_dict["provider_execution_authorized"] is False
        assert completed_dict["infrastructure_mutation_authorized"] is False
        assert completed_dict["external_publication_authorized"] is False

        replay = api.run(
            actor="parent-session",
            correlation_id="corr-effect-api-replay",
            body={"schema": RUN_REQUEST_SCHEMA, "job_id": admitted.job_id, "confirmed": True},
        )
        assert replay == completed
        store.verify_audit_chain()
    finally:
        store.close()


def test_effect_api_requires_separate_explicit_confirmation() -> None:
    with pytest.raises(QrOnboardingEffectApiError, match="qr_effect_api_confirmation_required"):
        parse_effect_admit_request(
            {
                "schema": ADMIT_REQUEST_SCHEMA,
                "invitation_id": "hcqri-" + "a" * 24,
                "idempotency_key": "effect-api-admit-2",
                "confirmed": False,
            }
        )
    with pytest.raises(QrOnboardingEffectApiError, match="qr_effect_api_confirmation_required"):
        parse_effect_run_request(
            {"schema": RUN_REQUEST_SCHEMA, "job_id": "hcjob-example", "confirmed": False}
        )


def test_effect_api_rejects_unknown_fields_and_active_invitation(tmp_path) -> None:
    with pytest.raises(QrOnboardingEffectApiError, match="qr_effect_api_admit_request_rejected"):
        parse_effect_admit_request(
            {
                "schema": ADMIT_REQUEST_SCHEMA,
                "invitation_id": "hcqri-" + "b" * 24,
                "idempotency_key": "effect-api-admit-3",
                "confirmed": True,
                "unexpected": True,
            }
        )

    snapshot = _snapshot()
    store = StateStore(tmp_path / "state.db", b"f" * 32, "cluster-test")
    try:
        _persist_household(store, snapshot)
        qr, api = _services(store)
        issued = qr.issue(
            snapshot=snapshot,
            issuer_member_id="parent-1",
            target_member_id="guest-1",
            subject=OnboardingSubject.GUEST,
            guest_scope=(GuestScope.INTERNET_GUEST,),
            created_at_epoch=1000,
            expires_at_epoch=1600,
            onboarding_code="A" * 32,
        )
        with pytest.raises(QrOnboardingEffectApiError, match="qr_effect_source_invitation_not_terminal"):
            api.admit(
                snapshot=snapshot,
                actor="parent-session",
                correlation_id="corr-effect-active",
                now_epoch=1100,
                body={
                    "schema": ADMIT_REQUEST_SCHEMA,
                    "invitation_id": issued.record.invitation.invitation_id,
                    "idempotency_key": "effect-api-admit-4",
                    "confirmed": True,
                },
            )
    finally:
        store.close()
