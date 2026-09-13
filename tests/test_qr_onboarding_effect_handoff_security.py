from __future__ import annotations

import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import HouseholdStore
from home_center.qr_onboarding import GuestScope, OnboardingSubject
from home_center.qr_onboarding_effect_handoff import (
    QrOnboardingEffectHandoffError,
    build_qr_onboarding_effect_handoff,
    qr_onboarding_effect_handoff_from_dict,
)
from home_center.qr_onboarding_effect_verification import (
    QrOnboardingEffectVerificationError,
    build_qr_onboarding_effect_verification_request,
    qr_onboarding_effect_verification_request_from_dict,
)
from home_center.qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository


def _guest_handoff():
    household_store = HouseholdStore()
    household_store.create(
        Household(
            household_id="home-main",
            members=(
                FamilyMember("parent-1", "Parent", HouseholdRole.PARENT),
                FamilyMember("guest-1", "Guest", HouseholdRole.GUEST),
            ),
            devices=(),
        )
    )
    snapshot = household_store.read("home-main")
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    service = QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="guest-1",
        subject=OnboardingSubject.GUEST,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
        onboarding_code="S" * 32,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code="S" * 32,
        now_epoch=1_100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code="S" * 32,
        actor="redemption-session-security",
        idempotency_key="consume-security-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    return build_qr_onboarding_effect_handoff(receipt=receipt, record=record)


def test_transport_cannot_broaden_guest_scope_after_valid_consume() -> None:
    payload = _guest_handoff().to_dict()
    payload["guest_scope"] = ["home.status.read"]
    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_rejected"):
        qr_onboarding_effect_handoff_from_dict(payload)


def test_transport_rejects_duplicate_guest_scope_and_non_string_digest_with_bounded_error() -> None:
    payload = _guest_handoff().to_dict()
    payload["guest_scope"] = ["internet.guest", "internet.guest"]
    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_rejected"):
        qr_onboarding_effect_handoff_from_dict(payload)

    payload = _guest_handoff().to_dict()
    payload["source_receipt_sha256"] = 7
    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_rejected"):
        qr_onboarding_effect_handoff_from_dict(payload)


def test_verification_transport_cannot_invent_device_identity_or_success() -> None:
    handoff = _guest_handoff()
    request = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-qr-security-0001",
    )
    payload = request.to_dict()
    payload["device_id"] = "invented-device"
    with pytest.raises(QrOnboardingEffectVerificationError, match="qr_effect_verification_request_rejected"):
        qr_onboarding_effect_verification_request_from_dict(payload)

    payload = request.to_dict()
    payload["effect_success_claimed"] = True
    with pytest.raises(QrOnboardingEffectVerificationError, match="qr_effect_verification_request_rejected"):
        qr_onboarding_effect_verification_request_from_dict(payload)
