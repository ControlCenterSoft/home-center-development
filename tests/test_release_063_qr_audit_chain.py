from __future__ import annotations

import json
from pathlib import Path

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_audit import qr_onboarding_audit_details
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from home_center.store import StateStore


def _snapshot():
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
            FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
        ),
        devices=(),
    )
    household_store = HouseholdStore()
    household_store.create(household)
    return household_store.read("home-main")


def _runtime(store: StateStore) -> QrOnboardingRuntimeService:
    with store._lock, store._connection:  # noqa: SLF001 - release qualification of shared SQLite boundary
        store._connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())  # noqa: SLF001
    return QrOnboardingRuntimeService(
        SQLiteQrOnboardingRuntimeRepository(
            store._connection,  # noqa: SLF001
            store._lock,  # noqa: SLF001
        )
    )


def _audit_receipt(store: StateStore, *, actor: str, receipt, correlation_id: str) -> None:
    store.audit(
        actor=actor,
        action=f"qr-onboarding.{receipt.operation.value}",
        target=receipt.invitation_id,
        outcome="accepted",
        correlation_id=correlation_id,
        details=qr_onboarding_audit_details(receipt).to_dict(),
    )


def test_qr_issue_consume_revoke_receipts_persist_as_bounded_hash_chained_audit(tmp_path: Path) -> None:
    snapshot = _snapshot()
    state_path = tmp_path / "state" / "home-center.db"
    store = StateStore(state_path, b"a" * 32, "cluster-test")
    runtime = _runtime(store)

    consumed_code = "C" * 32
    consumed_issue = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=2_700,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code=consumed_code,
    )
    _audit_receipt(
        store,
        actor="parent-1",
        receipt=consumed_issue.receipt,
        correlation_id="qr-issue-consumed-063",
    )
    plan = runtime.plan_redemption(
        snapshot=snapshot,
        invitation_id=consumed_issue.record.invitation.invitation_id,
        onboarding_code=consumed_code,
        now_epoch=1_100,
    )
    _, consumed_receipt = runtime.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code=consumed_code,
        actor="redemption-session-1",
        idempotency_key="consume-audit-key-0630",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    _audit_receipt(
        store,
        actor="redemption-session-1",
        receipt=consumed_receipt,
        correlation_id="qr-consume-063",
    )

    revoked_code = "D" * 32
    revoked_issue = runtime.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=2_000,
        expires_at_epoch=3_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code=revoked_code,
    )
    _audit_receipt(
        store,
        actor="parent-1",
        receipt=revoked_issue.receipt,
        correlation_id="qr-issue-revoked-063",
    )
    _, revoked_receipt = runtime.revoke(
        snapshot=snapshot,
        invitation_id=revoked_issue.record.invitation.invitation_id,
        actor_member_id="parent-1",
        idempotency_key="revoke-audit-key-0630",
        expected_version=1,
        now_epoch=2_200,
    )
    _audit_receipt(
        store,
        actor="parent-1",
        receipt=revoked_receipt,
        correlation_id="qr-revoke-063",
    )

    chain_head = store.verify_audit_chain()
    assert chain_head != "0" * 64

    events = list(reversed(store.audit_events(limit=10)))
    qr_events = [event for event in events if event["action"].startswith("qr-onboarding.")]
    assert [event["action"] for event in qr_events] == [
        "qr-onboarding.issue",
        "qr-onboarding.consume",
        "qr-onboarding.issue",
        "qr-onboarding.revoke",
    ]
    assert all(event["outcome"] == "accepted" for event in qr_events)
    assert all(event["previous_hash"] != event["entry_hash"] for event in qr_events)
    assert all(event["details"]["raw_onboarding_code_included"] is False for event in qr_events)
    assert all(event["details"]["qr_payload_included"] is False for event in qr_events)
    assert all(event["details"]["account_creation_authorized"] is False for event in qr_events)
    assert all(event["details"]["device_registration_authorized"] is False for event in qr_events)
    assert all(event["details"]["provider_execution_authorized"] is False for event in qr_events)
    assert all(event["details"]["infrastructure_mutation_authorized"] is False for event in qr_events)
    assert all(event["details"]["external_publication_authorized"] is False for event in qr_events)

    encoded_audit = json.dumps(qr_events, sort_keys=True)
    assert consumed_code not in encoded_audit
    assert revoked_code not in encoded_audit

    store.close()

    reopened = StateStore(state_path, b"a" * 32, "cluster-test")
    try:
        assert reopened.verify_audit_chain() == chain_head
        reopened_encoded = json.dumps(reopened.audit_events(limit=10), sort_keys=True)
        assert consumed_code not in reopened_encoded
        assert revoked_code not in reopened_encoded
    finally:
        reopened.close()
