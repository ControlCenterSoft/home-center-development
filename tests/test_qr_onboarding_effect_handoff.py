from __future__ import annotations

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


def _service():
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteQrOnboardingRuntimeRepository.schema_sql())
    return QrOnboardingRuntimeService(SQLiteQrOnboardingRuntimeRepository(connection))


def _guest_consumed(*, code: str = "A" * 32, key: str = "consume-key-0001"):
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
        onboarding_code=code,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code=code,
        now_epoch=1_100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code=code,
        actor="redemption-session-1",
        idempotency_key=key,
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )
    return snapshot, service, record, receipt


def _schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_guest_consume_builds_closed_non_authorizing_handoff_and_verification_request() -> None:
    _, _, record, receipt = _guest_consumed()
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)

    assert handoff.effect_kind is QrOnboardingEffectKind.GUEST_ACCESS_GRANT
    assert handoff.required_job_type == "typed-guest-access-change-job"
    assert handoff.guest_scope == (GuestScope.INTERNET_GUEST,)
    assert handoff.device_id is None
    assert handoff.effect_execution_authorized is False
    assert handoff.provider_execution_authorized is False
    assert handoff.infrastructure_mutation_authorized is False
    assert handoff.external_publication_authorized is False
    jsonschema.Draft202012Validator(_schema("qr-onboarding-effect-handoff.v1.schema.json")).validate(handoff.to_dict())
    assert qr_onboarding_effect_handoff_from_dict(handoff.to_dict()) == handoff

    verification = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-guest-access-0001",
    )
    assert verification.expected_post_condition is QrOnboardingPostCondition.GUEST_ACCESS_EFFECTIVE
    assert verification.post_condition_verified is False
    assert verification.effect_success_claimed is False
    jsonschema.Draft202012Validator(
        _schema("qr-onboarding-effect-verification-request.v1.schema.json")
    ).validate(verification.to_dict())
    assert qr_onboarding_effect_verification_request_from_dict(verification.to_dict()) == verification
    validate_verification_request_against_handoff(verification, handoff)


def test_device_consume_requires_typed_device_binding_job_and_readback() -> None:
    snapshot = _snapshot()
    service = _service()
    code = "B" * 32
    issued = service.issue(
        snapshot=snapshot,
        issuer_member_id="parent-1",
        target_member_id="child-1",
        subject=OnboardingSubject.DEVICE,
        device_id="tablet-1",
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        onboarding_code=code,
    )
    plan = service.plan_redemption(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        onboarding_code=code,
        now_epoch=1_100,
    )
    record, receipt = service.consume(
        snapshot=snapshot,
        plan=plan,
        onboarding_code=code,
        actor="redemption-session-2",
        idempotency_key="consume-key-device-0001",
        confirmed=True,
        expected_version=1,
        now_epoch=1_200,
    )

    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    assert handoff.effect_kind is QrOnboardingEffectKind.DEVICE_BINDING
    assert handoff.required_job_type == "typed-device-binding-change-job"
    assert handoff.device_id == "tablet-1"
    assert handoff.guest_scope == ()

    verification = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-device-binding-0001",
    )
    assert verification.expected_post_condition is QrOnboardingPostCondition.DEVICE_BINDING_EFFECTIVE
    assert verification.authoritative_readback_required is True
    assert verification.post_condition_verified is False


def test_revoke_handoff_never_claims_revocation_effect_success() -> None:
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
    record, receipt = service.revoke(
        snapshot=snapshot,
        invitation_id=issued.record.invitation.invitation_id,
        actor_member_id="parent-1",
        idempotency_key="revoke-key-0001",
        expected_version=1,
        now_epoch=1_100,
    )

    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)
    assert handoff.effect_kind is QrOnboardingEffectKind.ACCESS_REVOCATION
    assert handoff.required_job_type == "typed-access-revocation-change-job"
    assert handoff.effect_execution_authorized is False

    verification = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-access-revoke-0001",
    )
    assert verification.expected_post_condition is QrOnboardingPostCondition.ACCESS_REVOKED
    assert verification.effect_success_claimed is False


def test_handoff_rejects_receipt_record_binding_mismatch() -> None:
    _, _, first_record, first_receipt = _guest_consumed(code="D" * 32, key="consume-key-0002")
    _, _, second_record, _ = _guest_consumed(code="E" * 32, key="consume-key-0003")

    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_binding_mismatch"):
        build_qr_onboarding_effect_handoff(receipt=first_receipt, record=second_record)
    assert first_record != second_record


def test_transport_tampering_cannot_grant_execution_or_claim_success() -> None:
    _, _, record, receipt = _guest_consumed(code="F" * 32, key="consume-key-0004")
    handoff = build_qr_onboarding_effect_handoff(receipt=receipt, record=record)

    tampered_handoff = handoff.to_dict()
    tampered_handoff["effect_execution_authorized"] = True
    with pytest.raises(QrOnboardingEffectHandoffError, match="qr_effect_handoff_rejected"):
        qr_onboarding_effect_handoff_from_dict(tampered_handoff)

    verification = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id="job-guest-access-0002",
    )
    tampered_verification = verification.to_dict()
    tampered_verification["post_condition_verified"] = True
    tampered_verification["effect_success_claimed"] = True
    with pytest.raises(QrOnboardingEffectVerificationError, match="qr_effect_verification_request_rejected"):
        qr_onboarding_effect_verification_request_from_dict(tampered_verification)


def test_verification_request_is_bound_to_exact_handoff() -> None:
    _, _, first_record, first_receipt = _guest_consumed(code="G" * 32, key="consume-key-0005")
    _, _, second_record, second_receipt = _guest_consumed(code="H" * 32, key="consume-key-0006")
    first = build_qr_onboarding_effect_handoff(receipt=first_receipt, record=first_record)
    second = build_qr_onboarding_effect_handoff(receipt=second_receipt, record=second_record)
    verification = build_qr_onboarding_effect_verification_request(
        handoff=first,
        effect_job_id="job-guest-access-0003",
    )

    with pytest.raises(QrOnboardingEffectVerificationError, match="qr_effect_verification_handoff_mismatch"):
        validate_verification_request_against_handoff(verification, second)
