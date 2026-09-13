from __future__ import annotations

import copy
import secrets

import pytest

from home_center.household import HouseholdRole
from home_center.qr_onboarding import (
    GuestScope,
    OnboardingSubject,
    build_qr_onboarding_invitation,
    build_qr_payload,
    plan_qr_redemption,
)
from home_center.qr_onboarding_validation import (
    QrOnboardingEvidenceError,
    invitation_from_dict,
    payload_from_dict,
    redemption_plan_from_dict,
)


def _fixture():
    code = secrets.token_urlsafe(24)
    invitation = build_qr_onboarding_invitation(
        household_id="household-1",
        issuer_member_id="parent-1",
        issuer_role=HouseholdRole.PARENT,
        subject=OnboardingSubject.GUEST,
        onboarding_code=code,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
    )
    payload = build_qr_payload(invitation=invitation, onboarding_code=code)
    plan = plan_qr_redemption(invitation=invitation, onboarding_code=code, now_epoch=1_200)
    return invitation, payload, plan


def test_round_trip_reconstruction_is_exact() -> None:
    invitation, payload, plan = _fixture()
    rebuilt = invitation_from_dict(invitation.to_dict())
    assert rebuilt == invitation
    assert payload_from_dict(payload.to_dict(), invitation=rebuilt) == payload
    assert redemption_plan_from_dict(plan.to_dict(), invitation=rebuilt) == plan


def test_unknown_invitation_field_is_rejected() -> None:
    invitation, _, _ = _fixture()
    raw = invitation.to_dict()
    raw["unexpected"] = True
    with pytest.raises(QrOnboardingEvidenceError, match="qr_invitation_evidence_rejected"):
        invitation_from_dict(raw)


def test_authority_tampering_is_rejected() -> None:
    invitation, _, plan = _fixture()
    raw = invitation.to_dict()
    raw["device_binding_authorized"] = True
    with pytest.raises(QrOnboardingEvidenceError, match="qr_invitation_evidence_rejected"):
        invitation_from_dict(raw)

    plan_raw = plan.to_dict()
    plan_raw["execution_authorized"] = True
    with pytest.raises(QrOnboardingEvidenceError, match="qr_redemption_plan_rejected"):
        redemption_plan_from_dict(plan_raw, invitation=invitation)


def test_payload_cannot_be_rebound_to_another_invitation() -> None:
    invitation, payload, _ = _fixture()
    other_code = secrets.token_urlsafe(24)
    other = build_qr_onboarding_invitation(
        household_id="household-1",
        issuer_member_id="parent-1",
        issuer_role=HouseholdRole.PARENT,
        subject=OnboardingSubject.GUEST,
        onboarding_code=other_code,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        guest_scope=(GuestScope.INTERNET_GUEST,),
    )
    with pytest.raises(QrOnboardingEvidenceError, match="qr_payload_rejected"):
        payload_from_dict(payload.to_dict(), invitation=other)


def test_plan_identity_and_expiry_binding_are_fail_closed() -> None:
    invitation, _, plan = _fixture()
    raw = copy.deepcopy(plan.to_dict())
    raw["plan_id"] = "hcqrp-" + "0" * 24
    with pytest.raises(QrOnboardingEvidenceError, match="qr_redemption_plan_rejected"):
        redemption_plan_from_dict(raw, invitation=invitation)

    raw = plan.to_dict()
    raw["presented_at_epoch"] = invitation.expires_at_epoch
    with pytest.raises(QrOnboardingEvidenceError, match="qr_redemption_plan_rejected"):
        redemption_plan_from_dict(raw, invitation=invitation)
