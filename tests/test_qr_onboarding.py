from __future__ import annotations

import secrets

import pytest

from home_center.household import HouseholdRole
from home_center.qr_onboarding import (
    GuestScope,
    InvitationState,
    OnboardingSubject,
    QrOnboardingError,
    build_qr_onboarding_invitation,
    build_qr_payload,
    invitation_state,
    plan_qr_redemption,
)


def _code() -> str:
    return secrets.token_urlsafe(24)


def _guest_invitation(*, code: str, created: int = 1_000, expires: int = 1_600):
    return build_qr_onboarding_invitation(
        household_id="household-1",
        issuer_member_id="parent-1",
        issuer_role=HouseholdRole.PARENT,
        subject=OnboardingSubject.GUEST,
        onboarding_code=code,
        created_at_epoch=created,
        expires_at_epoch=expires,
        guest_scope=(GuestScope.INTERNET_GUEST,),
    )


def test_qr_payload_is_short_lived_single_use_and_not_admin_credential() -> None:
    code = _code()
    invitation = _guest_invitation(code=code)
    payload = build_qr_payload(invitation=invitation, onboarding_code=code).to_dict()
    durable = invitation.to_dict()

    assert payload["single_use"] is True
    assert payload["credential_class"] == "ephemeral-onboarding-code"
    assert payload["administrative_credential_included"] is False
    assert payload["long_lived_credential_included"] is False
    assert "onboarding_code" not in durable
    assert durable["max_uses"] == 1
    assert durable["revocation_supported"] is True


def test_only_parent_can_issue_invitation() -> None:
    with pytest.raises(QrOnboardingError, match="qr_issuer_parent_required"):
        build_qr_onboarding_invitation(
            household_id="household-1",
            issuer_member_id="guest-1",
            issuer_role=HouseholdRole.GUEST,
            subject=OnboardingSubject.GUEST,
            onboarding_code=_code(),
            created_at_epoch=1_000,
            expires_at_epoch=1_600,
            guest_scope=(GuestScope.INTERNET_GUEST,),
        )


def test_ttl_is_bounded() -> None:
    code = _code()
    with pytest.raises(QrOnboardingError, match="qr_ttl_invalid"):
        _guest_invitation(code=code, created=1_000, expires=1_059)
    with pytest.raises(QrOnboardingError, match="qr_ttl_invalid"):
        _guest_invitation(code=code, created=1_000, expires=2_801)


def test_revoked_consumed_and_expired_invitations_fail_closed() -> None:
    code = _code()
    invitation = _guest_invitation(code=code)

    assert invitation_state(invitation, now_epoch=1_200, revoked=False, consumed=False) is InvitationState.ACTIVE
    assert invitation_state(invitation, now_epoch=1_200, revoked=True, consumed=False) is InvitationState.REVOKED
    assert invitation_state(invitation, now_epoch=1_200, revoked=False, consumed=True) is InvitationState.CONSUMED
    assert invitation_state(invitation, now_epoch=1_600, revoked=False, consumed=False) is InvitationState.EXPIRED

    for kwargs, code_name in (
        ({"revoked": True}, "qr_invitation_revoked"),
        ({"consumed": True}, "qr_invitation_consumed"),
    ):
        with pytest.raises(QrOnboardingError, match=code_name):
            plan_qr_redemption(invitation=invitation, onboarding_code=code, now_epoch=1_200, **kwargs)

    with pytest.raises(QrOnboardingError, match="qr_invitation_expired"):
        plan_qr_redemption(invitation=invitation, onboarding_code=code, now_epoch=1_600)


def test_code_mismatch_never_produces_plan() -> None:
    invitation = _guest_invitation(code=_code())
    with pytest.raises(QrOnboardingError, match="qr_onboarding_code_mismatch"):
        plan_qr_redemption(invitation=invitation, onboarding_code=_code(), now_epoch=1_200)


def test_guest_redemption_plan_requires_separate_confirmation() -> None:
    code = _code()
    invitation = _guest_invitation(code=code)
    plan = plan_qr_redemption(invitation=invitation, onboarding_code=code, now_epoch=1_200).to_dict()

    assert plan["subject"] == "guest"
    assert plan["guest_scope"] == ["internet.guest"]
    assert plan["explicit_confirmation_required"] is True
    assert plan["account_creation_authorized"] is False
    assert plan["device_binding_authorized"] is False
    assert plan["execution_authorized"] is False
    assert plan["infrastructure_mutation_authorized"] is False
    assert plan["external_publication_authorized"] is False


def test_device_invitation_is_bound_to_one_device_and_has_no_guest_scope() -> None:
    code = _code()
    invitation = build_qr_onboarding_invitation(
        household_id="household-1",
        issuer_member_id="parent-1",
        issuer_role=HouseholdRole.PARENT,
        subject=OnboardingSubject.DEVICE,
        onboarding_code=code,
        created_at_epoch=1_000,
        expires_at_epoch=1_600,
        device_id="device-42",
    )
    plan = plan_qr_redemption(invitation=invitation, onboarding_code=code, now_epoch=1_200).to_dict()

    assert plan["subject"] == "device"
    assert plan["device_id"] == "device-42"
    assert plan["guest_scope"] == []
    assert plan["device_binding_authorized"] is False


def test_guest_and_device_bindings_cannot_be_mixed() -> None:
    with pytest.raises(QrOnboardingError, match="qr_guest_binding_invalid"):
        build_qr_onboarding_invitation(
            household_id="household-1",
            issuer_member_id="parent-1",
            issuer_role=HouseholdRole.PARENT,
            subject=OnboardingSubject.GUEST,
            onboarding_code=_code(),
            created_at_epoch=1_000,
            expires_at_epoch=1_600,
            device_id="device-42",
            guest_scope=(GuestScope.INTERNET_GUEST,),
        )

    with pytest.raises(QrOnboardingError, match="qr_device_scope_invalid"):
        build_qr_onboarding_invitation(
            household_id="household-1",
            issuer_member_id="parent-1",
            issuer_role=HouseholdRole.PARENT,
            subject=OnboardingSubject.DEVICE,
            onboarding_code=_code(),
            created_at_epoch=1_000,
            expires_at_epoch=1_600,
            device_id="device-42",
            guest_scope=(GuestScope.HOME_STATUS_READ,),
        )
