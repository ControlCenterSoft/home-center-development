from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from home_center.qr_onboarding import InvitationState
from home_center.qr_onboarding_runtime import QrOnboardingOperationReceipt, RuntimeOperation
from home_center.qr_onboarding_state_audit import (
    QrOnboardingAuditedRuntimeService,
    QrOnboardingStateAuditError,
)
from home_center.store import StateStore
from home_center.util import canonical_json


def _receipt(operation: RuntimeOperation) -> QrOnboardingOperationReceipt:
    if operation is RuntimeOperation.ISSUE:
        before = None
        after = InvitationState.ACTIVE
        version = 1
        next_boundary = "explicit-qr-presentation-and-redemption"
    elif operation is RuntimeOperation.CONSUME:
        before = InvitationState.ACTIVE
        after = InvitationState.CONSUMED
        version = 2
        next_boundary = "typed-guest-access-change-job"
    else:
        before = InvitationState.ACTIVE
        after = InvitationState.REVOKED
        version = 2
        next_boundary = "typed-access-revocation-change-job"
    material = {
        "operation": operation.value,
        "runtime_record_id": "hcqrr-test",
        "invitation_id": "hcqri-test",
        "household_id": "home-test",
        "household_snapshot_id": "snapshot-test",
        "household_resource_version": "resource-test",
        "household_generation": 7,
        "target_member_id": "member-guest",
        "before_state": before.value if before else None,
        "after_state": after.value,
        "record_version": version,
        "occurred_at_epoch": 1_800_000_000,
        "invitation_evidence_sha256": "a" * 64,
        "next_required_boundary": next_boundary,
    }
    receipt_id = "hcqro-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
    return QrOnboardingOperationReceipt(
        receipt_id=receipt_id,
        operation=operation,
        runtime_record_id="hcqrr-test",
        invitation_id="hcqri-test",
        household_id="home-test",
        household_snapshot_id="snapshot-test",
        household_resource_version="resource-test",
        household_generation=7,
        target_member_id="member-guest",
        before_state=before,
        after_state=after,
        record_version=version,
        occurred_at_epoch=1_800_000_000,
        invitation_evidence_sha256="a" * 64,
        next_required_boundary=next_boundary,
    )


class _Runtime:
    def __init__(self) -> None:
        self.fail = False

    def issue(self, **kwargs):
        if self.fail:
            raise RuntimeError("delegate-failed")
        return SimpleNamespace(receipt=_receipt(RuntimeOperation.ISSUE))

    def consume(self, **kwargs):
        if self.fail:
            raise RuntimeError("delegate-failed")
        return object(), _receipt(RuntimeOperation.CONSUME)

    def revoke(self, **kwargs):
        if self.fail:
            raise RuntimeError("delegate-failed")
        return object(), _receipt(RuntimeOperation.REVOKE)


def _service(tmp_path):
    store = StateStore(tmp_path / "state.db", b"q" * 32, "cluster-test")
    runtime = _Runtime()
    return store, runtime, QrOnboardingAuditedRuntimeService(runtime, store)


def test_issue_consume_revoke_append_receipt_only_audit(tmp_path) -> None:
    store, _, service = _service(tmp_path)
    try:
        service.issue(
            correlation_id="qr.issue.1",
            issuer_member_id="member-parent",
            onboarding_code="raw-secret-code",
        )
        service.consume(
            correlation_id="qr.consume.1",
            actor="member-guest",
            onboarding_code="raw-secret-code",
        )
        service.revoke(
            correlation_id="qr.revoke.1",
            actor_member_id="member-parent",
        )
        events = list(reversed(store.audit_events(limit=10)))
        assert [event["action"] for event in events[-3:]] == [
            "qr.onboarding.issue",
            "qr.onboarding.consume",
            "qr.onboarding.revoke",
        ]
        assert [event["correlation_id"] for event in events[-3:]] == [
            "qr.issue.1",
            "qr.consume.1",
            "qr.revoke.1",
        ]
        for event in events[-3:]:
            details = event["details"]
            assert details["raw_onboarding_code_included"] is False
            assert details["qr_payload_included"] is False
            assert details["account_creation_authorized"] is False
            assert details["device_registration_authorized"] is False
            assert details["managed_state_change_authorized"] is False
            assert details["provider_execution_authorized"] is False
            assert details["infrastructure_mutation_authorized"] is False
            assert details["external_publication_authorized"] is False
            assert "raw-secret-code" not in canonical_json(event)
        store.verify_audit_chain()
    finally:
        store.close()


def test_delegate_failure_never_creates_false_success_audit(tmp_path) -> None:
    store, runtime, service = _service(tmp_path)
    try:
        baseline = len(store.audit_events(limit=10))
        runtime.fail = True
        with pytest.raises(RuntimeError, match="delegate-failed"):
            service.consume(
                correlation_id="qr.consume.failure",
                actor="member-guest",
                onboarding_code="raw-secret-code",
            )
        assert len(store.audit_events(limit=10)) == baseline
    finally:
        store.close()


def test_invalid_correlation_id_fails_before_runtime_or_audit(tmp_path) -> None:
    store, runtime, service = _service(tmp_path)
    try:
        with pytest.raises(QrOnboardingStateAuditError, match="qr_audit_correlation_id_invalid"):
            service.issue(
                correlation_id="bad\ncorrelation",
                issuer_member_id="member-parent",
                onboarding_code="raw-secret-code",
            )
        assert runtime.fail is False
        assert store.audit_events(limit=10) == []
    finally:
        store.close()
