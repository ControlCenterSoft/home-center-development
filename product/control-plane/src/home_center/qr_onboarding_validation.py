"""Strict transport/storage reconstruction for Home Center 0.63 QR onboarding."""
from __future__ import annotations

from .household import HouseholdRole
from .qr_onboarding import (
    GuestScope,
    OnboardingSubject,
    QR_INVITATION_SCHEMA,
    QR_PAYLOAD_SCHEMA,
    QR_REDEMPTION_PLAN_SCHEMA,
    QrOnboardingError,
    QrOnboardingInvitation,
    QrOnboardingPayload,
    QrOnboardingRedemptionPlan,
    _digest,
    hash_onboarding_code,
)


class QrOnboardingEvidenceError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _exact(value: object, keys: set[str], schema: str, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys or value.get("schema") != schema:
        raise QrOnboardingEvidenceError(code)
    return value


def invitation_from_dict(value: object) -> QrOnboardingInvitation:
    raw = _exact(
        value,
        {
            "schema", "invitation_id", "household_id", "issuer_member_id", "issuer_role", "subject",
            "device_id", "guest_scope", "token_sha256", "created_at_epoch", "expires_at_epoch",
            "single_use", "max_uses", "revocation_supported", "administrative_credential_included",
            "long_lived_credential_included", "account_creation_authorized", "device_binding_authorized",
            "execution_authorized", "infrastructure_mutation_authorized", "external_publication_authorized",
        },
        QR_INVITATION_SCHEMA,
        "qr_invitation_evidence_rejected",
    )
    if (
        raw.get("issuer_role") != "parent"
        or raw.get("single_use") is not True
        or raw.get("max_uses") != 1
        or raw.get("revocation_supported") is not True
    ):
        raise QrOnboardingEvidenceError("qr_invitation_evidence_rejected")
    for key in (
        "administrative_credential_included", "long_lived_credential_included",
        "account_creation_authorized", "device_binding_authorized", "execution_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    ):
        if raw.get(key) is not False:
            raise QrOnboardingEvidenceError("qr_invitation_evidence_rejected")
    scope = raw.get("guest_scope")
    if not isinstance(scope, list):
        raise QrOnboardingEvidenceError("qr_invitation_evidence_rejected")
    try:
        result = QrOnboardingInvitation(
            invitation_id=raw["invitation_id"],
            household_id=raw["household_id"],
            issuer_member_id=raw["issuer_member_id"],
            issuer_role=HouseholdRole.PARENT,
            subject=OnboardingSubject(raw["subject"]),
            device_id=raw["device_id"],
            guest_scope=tuple(GuestScope(item) for item in scope),
            token_sha256=raw["token_sha256"],
            created_at_epoch=raw["created_at_epoch"],
            expires_at_epoch=raw["expires_at_epoch"],
        )
    except (KeyError, TypeError, ValueError, QrOnboardingError) as exc:
        raise QrOnboardingEvidenceError("qr_invitation_evidence_rejected") from exc
    if result.to_dict() != raw:
        raise QrOnboardingEvidenceError("qr_invitation_evidence_rejected")
    return result


def payload_from_dict(value: object, *, invitation: QrOnboardingInvitation) -> QrOnboardingPayload:
    raw = _exact(
        value,
        {
            "schema", "invitation_id", "household_id", "onboarding_code", "expires_at_epoch",
            "single_use", "credential_class", "administrative_credential_included",
            "long_lived_credential_included",
        },
        QR_PAYLOAD_SCHEMA,
        "qr_payload_rejected",
    )
    if not isinstance(invitation, QrOnboardingInvitation):
        raise QrOnboardingEvidenceError("qr_payload_rejected")
    if (
        raw.get("single_use") is not True
        or raw.get("credential_class") != "ephemeral-onboarding-code"
        or raw.get("administrative_credential_included") is not False
        or raw.get("long_lived_credential_included") is not False
        or raw.get("invitation_id") != invitation.invitation_id
        or raw.get("household_id") != invitation.household_id
        or raw.get("expires_at_epoch") != invitation.expires_at_epoch
    ):
        raise QrOnboardingEvidenceError("qr_payload_rejected")
    try:
        if hash_onboarding_code(raw["onboarding_code"]) != invitation.token_sha256:
            raise QrOnboardingEvidenceError("qr_payload_rejected")
        result = QrOnboardingPayload(
            invitation_id=raw["invitation_id"],
            household_id=raw["household_id"],
            onboarding_code=raw["onboarding_code"],
            expires_at_epoch=raw["expires_at_epoch"],
        )
    except (KeyError, TypeError, ValueError, QrOnboardingError) as exc:
        raise QrOnboardingEvidenceError("qr_payload_rejected") from exc
    if result.to_dict() != raw:
        raise QrOnboardingEvidenceError("qr_payload_rejected")
    return result


def redemption_plan_from_dict(
    value: object,
    *,
    invitation: QrOnboardingInvitation,
) -> QrOnboardingRedemptionPlan:
    raw = _exact(
        value,
        {
            "schema", "plan_id", "invitation_id", "household_id", "subject", "device_id",
            "guest_scope", "presented_at_epoch", "explicit_confirmation_required",
            "account_creation_authorized", "device_binding_authorized", "execution_authorized",
            "infrastructure_mutation_authorized", "external_publication_authorized",
        },
        QR_REDEMPTION_PLAN_SCHEMA,
        "qr_redemption_plan_rejected",
    )
    if not isinstance(invitation, QrOnboardingInvitation):
        raise QrOnboardingEvidenceError("qr_redemption_plan_rejected")
    if raw.get("explicit_confirmation_required") is not True:
        raise QrOnboardingEvidenceError("qr_redemption_plan_rejected")
    for key in (
        "account_creation_authorized", "device_binding_authorized", "execution_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    ):
        if raw.get(key) is not False:
            raise QrOnboardingEvidenceError("qr_redemption_plan_rejected")
    scope = raw.get("guest_scope")
    if not isinstance(scope, list):
        raise QrOnboardingEvidenceError("qr_redemption_plan_rejected")
    try:
        subject = OnboardingSubject(raw["subject"])
        scopes = tuple(GuestScope(item) for item in scope)
        presented = raw["presented_at_epoch"]
        if type(presented) is not int or presented < invitation.created_at_epoch or presented >= invitation.expires_at_epoch:
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise QrOnboardingEvidenceError("qr_redemption_plan_rejected") from exc
    if (
        raw.get("invitation_id") != invitation.invitation_id
        or raw.get("household_id") != invitation.household_id
        or subject is not invitation.subject
        or raw.get("device_id") != invitation.device_id
        or scopes != invitation.guest_scope
    ):
        raise QrOnboardingEvidenceError("qr_redemption_plan_rejected")
    material = {
        "invitation_id": invitation.invitation_id,
        "household_id": invitation.household_id,
        "subject": invitation.subject.value,
        "device_id": invitation.device_id,
        "guest_scope": [scope.value for scope in invitation.guest_scope],
        "presented_at_epoch": presented,
    }
    expected_plan_id = "hcqrp-" + _digest(material)[:24]
    if raw.get("plan_id") != expected_plan_id:
        raise QrOnboardingEvidenceError("qr_redemption_plan_rejected")
    result = QrOnboardingRedemptionPlan(
        plan_id=expected_plan_id,
        invitation_id=invitation.invitation_id,
        household_id=invitation.household_id,
        subject=invitation.subject,
        device_id=invitation.device_id,
        guest_scope=invitation.guest_scope,
        presented_at_epoch=presented,
    )
    if result.to_dict() != raw:
        raise QrOnboardingEvidenceError("qr_redemption_plan_rejected")
    return result
