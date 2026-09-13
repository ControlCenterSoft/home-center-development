from __future__ import annotations

import copy
import json
import sqlite3
from pathlib import Path

import jsonschema
import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_handoff import (
    QrOnboardingEffectHandoffError,
    QrOnboardingEffectKind,
    build_qr_onboarding_effect_handoff,
    qr_onboarding_effect_handoff_from_dict,
)
from home_center.qr_onboarding_effect_verification import (
    QrOnboardingEffectVerificationError,
    QrOnboardingPostCondition,
    build_qr_onboarding_effect_verification_request,
    qr_onboarding_effect_verification_request_from_dict,
    validate_verification_request_against_handoff,
)
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository

ROOT = Path(__file__).resolve().parents[1]


def _snapshot():
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
    return store.read("home-main")


def _service() -> QrOnboardingRuntimeService:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    return QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))


def _consumed_guest():
    snapshot = _snapshot()
    service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="A" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="A" * 32,
        now_epoch=1_100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="A" * 32,
        actor="redemption-session-1",
        idempotency_key="consume-handoff-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    return record, receipt


def _consumed_device():
    snapshot = _snapshot()
    service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="child-1",
        subject=OnboardingSubject.DEVICE,
        device_id="tablet-1",
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        onboarding_code="B" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="B" * 32,
        now_epoch=1_100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="B" * 32,
        actor="redemption-session-2",
        idempotency_key="consume-handoff-0002",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    return record, receipt


def _revoked_guest():
    snapshot = _snapshot()
    service = _service()
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="C" * 32,
    )
    return service.revoke(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        actor_member_id="parent-1",
        idempotency_key="revoke-handoff-0001",
        expected_version=1,
        now_epoch=1_100,
    )


def test_consumed_guest_handoff_requires_separate_change_job_and_never_claims_effect_success() -> None:
    record, receipt = _consumed_guest()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    assert handoff.effect_kind is QrOnboardingEffectKind.GUEST_ACCESS_GRANT
    assert handoff.required_job_type == "typed-guest-access-change-job"
    assert handoff.guest_scope == (GuestScope.INTERNET_GUEST,)
    assert handoff.device_id is None
    payload = handoff.to_dict()
    assert payload["explicit_change_job_required"] is True
    assert payload["post_condition_verification_required"] is True
    assert payload["effect_execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert qr_onboarding_effect_handoff_from_dict(payload) == handoff


def test_consumed_device_handoff_is_exact_device_binding_without_registration_or_managed_authority() -> None:
    record, receipt = _consumed_device()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    assert handoff.effect_kind is QrOnboardingEffectKind.DEVICE_BINDING
    assert handoff.required_job_type == "typed-device-binding-change-job"
    assert handoff.device_id == "tablet-1"
    assert handoff.guest_scope == ()
    payload = handoff.to_dict()
    assert payload["device_registration_authorized"] is False
    assert payload["managed_state_change_authorized"] is False


def test_revocation_handoff_never_relabels_invitation_transition_as_product_state_success() -> None:
    record, receipt = _revoked_guest()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    assert handoff.effect_kind is QrOnboardingEffectKind.ACCESS_REVOCATION
    assert handoff.required_job_type == "typed-access-revocation-change-job"
    assert handoff.to_dict()["effect_execution_authorized"] is False


def test_handoff_rejects_cross_record_or_stale_receipt_binding() -> None:
    record, receipt = _consumed_guest()
    forged = copy.copy(record)
    object.__setattr__(forged, "version", record.version + 1)
    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_binding_mismatch"):
        build_qr_onboarding_effect_handoff(receipt=receipt, record=forged)


def test_handoff_transport_rejects_authority_escalation_and_boundary_relabeling() -> None:
    record, receipt = _consumed_guest()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    escalated = handoff.to_dict()
    escalated["effect_execution_authorized"] = True
    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_rejected"):
        qr_onboarding_effect_handoff_from_dict(escalated)

    relabeled = handoff.to_dict()
    relabeled["required_job_type"] = "typed-device-binding-change-job"
    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_rejected"):
        qr_onboarding_effect_handoff_from_dict(relabeled)


def test_verification_request_is_exact_job_bound_and_remains_explicitly_unverified() -> None:
    record, receipt = _consumed_guest()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    request = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-qr-effect-0001",
    )
    assert request.expected_post_condition is QrOnboardingPostCondition.GUEST_ACCESS_EFFECTIVE
    payload = request.to_dict()
    assert payload["authoritative_readback_required"] is True
    assert payload["post_condition_verified"] is False
    assert payload["effect_success_claimed"] is False
    assert payload["provider_execution_authorized"] is False
    assert qr_onboarding_effect_verification_request_from_dict(payload) == request
    validate_verification_request_against_handoff(request, handoff)


def test_verification_request_rejects_premature_success_claim() -> None:
    record, receipt = _consumed_device()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    request = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-qr-effect-0002",
    )
    forged = request.to_dict()
    forged["post_condition_verified"] = True
    with pytest.raises(QrOnboardingEffectVerificationError, match="qr_effect_verification_request_rejected"):
        qr_onboarding_effect_verification_request_from_dict(forged)


def test_handoff_and_verification_contracts_accept_exact_outputs() -> None:
    record, receipt = _consumed_device()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    request = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-qr-effect-0003",
    )
    handoff_schema = json.loads(
        (ROOT / "contracts/household/qr-onboarding-effect-handoff.v1.schema.json").read_text(encoding="utf-8")
    )
    verification_schema = json.loads(
        (ROOT / "contracts/household/qr-onboarding-effect-verification-request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(handoff_schema).validate(handoff.to_dict())
    jsonschema.Draft202012Validator(verification_schema).validate(request.to_dict())
