"""Home Center 0.63 bounded QR guest/device onboarding foundation.

The module is intentionally side-effect free. It creates and validates short-lived,
single-use onboarding invitations and returns a confirmation plan. It never creates
an account, binds a device, mutates infrastructure, or embeds an administrative
credential into a QR payload.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .home_services import _identifier
from .household import HouseholdRole
from .util import canonical_json

QR_INVITATION_SCHEMA = "home-center.qr-onboarding-invitation.v1"
QR_PAYLOAD_SCHEMA = "home-center.qr-onboarding-payload.v1"
QR_REDEMPTION_PLAN_SCHEMA = "home-center.qr-onboarding-redemption-plan.v1"

_CODE = re.compile(r"[A-Za-z0-9_-]{22,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MIN_TTL_SECONDS = 60
_MAX_TTL_SECONDS = 1800


class QrOnboardingError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class OnboardingSubject(StrEnum):
    GUEST = "guest"
    DEVICE = "device"


class GuestScope(StrEnum):
    INTERNET_GUEST = "internet.guest"
    HOME_STATUS_READ = "home.status.read"


class InvitationState(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _code(value: object) -> str:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise QrOnboardingError("qr_onboarding_code_invalid")
    return value


def hash_onboarding_code(code: object) -> str:
    """Return the durable digest; the raw short-lived code must not be persisted."""
    normalized = _code(code)
    return hashlib.sha256(normalized.encode("ascii")).hexdigest()


def _epoch(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        raise QrOnboardingError(code)
    return value


def _scope(values: object) -> tuple[GuestScope, ...]:
    if not isinstance(values, (tuple, list)):
        raise QrOnboardingError("qr_guest_scope_invalid")
    try:
        result = tuple(sorted({GuestScope(item) for item in values}, key=lambda item: item.value))
    except (TypeError, ValueError) as exc:
        raise QrOnboardingError("qr_guest_scope_invalid") from exc
    if len(result) != len(values) or len(result) > len(GuestScope):
        raise QrOnboardingError("qr_guest_scope_invalid")
    return result


@dataclass(frozen=True, slots=True)
class QrOnboardingInvitation:
    invitation_id: str
    household_id: str
    issuer_member_id: str
    issuer_role: HouseholdRole
    subject: OnboardingSubject
    device_id: str | None
    guest_scope: tuple[GuestScope, ...]
    token_sha256: str
    created_at_epoch: int
    expires_at_epoch: int
    schema: str = field(default=QR_INVITATION_SCHEMA, init=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "household_id", _identifier(self.household_id, "qr_household_id_invalid"))
            object.__setattr__(
                self,
                "issuer_member_id",
                _identifier(self.issuer_member_id, "qr_issuer_member_id_invalid"),
            )
        except (TypeError, ValueError) as exc:
            raise QrOnboardingError(str(exc)) from exc
        if self.issuer_role is not HouseholdRole.PARENT:
            raise QrOnboardingError("qr_issuer_parent_required")
        if not isinstance(self.subject, OnboardingSubject):
            raise QrOnboardingError("qr_subject_invalid")
        object.__setattr__(self, "guest_scope", _scope(self.guest_scope))
        if not isinstance(self.token_sha256, str) or not _SHA256.fullmatch(self.token_sha256):
            raise QrOnboardingError("qr_token_digest_invalid")
        created = _epoch(self.created_at_epoch, "qr_created_at_invalid")
        expires = _epoch(self.expires_at_epoch, "qr_expires_at_invalid")
        ttl = expires - created
        if not _MIN_TTL_SECONDS <= ttl <= _MAX_TTL_SECONDS:
            raise QrOnboardingError("qr_ttl_invalid")

        if self.subject is OnboardingSubject.GUEST:
            if self.device_id is not None or not self.guest_scope:
                raise QrOnboardingError("qr_guest_binding_invalid")
        else:
            if self.guest_scope:
                raise QrOnboardingError("qr_device_scope_invalid")
            try:
                device_id = _identifier(self.device_id, "qr_device_id_invalid")
            except (TypeError, ValueError) as exc:
                raise QrOnboardingError("qr_device_id_invalid") from exc
            object.__setattr__(self, "device_id", device_id)

        expected = "hcqri-" + _digest(self.identity_material())[:24]
        if self.invitation_id != expected:
            raise QrOnboardingError("qr_invitation_identity_invalid")

    def identity_material(self) -> dict[str, object]:
        return {
            "household_id": self.household_id,
            "issuer_member_id": self.issuer_member_id,
            "issuer_role": self.issuer_role.value,
            "subject": self.subject.value,
            "device_id": self.device_id,
            "guest_scope": [scope.value for scope in self.guest_scope],
            "token_sha256": self.token_sha256,
            "created_at_epoch": self.created_at_epoch,
            "expires_at_epoch": self.expires_at_epoch,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "invitation_id": self.invitation_id,
            **self.identity_material(),
            "single_use": True,
            "max_uses": 1,
            "revocation_supported": True,
            "administrative_credential_included": False,
            "long_lived_credential_included": False,
            "account_creation_authorized": False,
            "device_binding_authorized": False,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QrOnboardingPayload:
    invitation_id: str
    household_id: str
    onboarding_code: str
    expires_at_epoch: int
    schema: str = field(default=QR_PAYLOAD_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.invitation_id, str) or not self.invitation_id.startswith("hcqri-"):
            raise QrOnboardingError("qr_payload_invitation_invalid")
        try:
            object.__setattr__(self, "household_id", _identifier(self.household_id, "qr_household_id_invalid"))
        except (TypeError, ValueError) as exc:
            raise QrOnboardingError("qr_household_id_invalid") from exc
        object.__setattr__(self, "onboarding_code", _code(self.onboarding_code))
        _epoch(self.expires_at_epoch, "qr_expires_at_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "invitation_id": self.invitation_id,
            "household_id": self.household_id,
            "onboarding_code": self.onboarding_code,
            "expires_at_epoch": self.expires_at_epoch,
            "single_use": True,
            "credential_class": "ephemeral-onboarding-code",
            "administrative_credential_included": False,
            "long_lived_credential_included": False,
        }


@dataclass(frozen=True, slots=True)
class QrOnboardingRedemptionPlan:
    plan_id: str
    invitation_id: str
    household_id: str
    subject: OnboardingSubject
    device_id: str | None
    guest_scope: tuple[GuestScope, ...]
    presented_at_epoch: int
    schema: str = field(default=QR_REDEMPTION_PLAN_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "invitation_id": self.invitation_id,
            "household_id": self.household_id,
            "subject": self.subject.value,
            "device_id": self.device_id,
            "guest_scope": [scope.value for scope in self.guest_scope],
            "presented_at_epoch": self.presented_at_epoch,
            "explicit_confirmation_required": True,
            "account_creation_authorized": False,
            "device_binding_authorized": False,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_qr_onboarding_invitation(
    *,
    household_id: str,
    issuer_member_id: str,
    issuer_role: HouseholdRole,
    subject: OnboardingSubject,
    onboarding_code: str,
    created_at_epoch: int,
    expires_at_epoch: int,
    device_id: str | None = None,
    guest_scope: tuple[GuestScope, ...] = (),
) -> QrOnboardingInvitation:
    token_sha256 = hash_onboarding_code(onboarding_code)
    material = {
        "household_id": household_id,
        "issuer_member_id": issuer_member_id,
        "issuer_role": issuer_role.value if isinstance(issuer_role, HouseholdRole) else issuer_role,
        "subject": subject.value if isinstance(subject, OnboardingSubject) else subject,
        "device_id": device_id,
        "guest_scope": [item.value if isinstance(item, GuestScope) else item for item in guest_scope],
        "token_sha256": token_sha256,
        "created_at_epoch": created_at_epoch,
        "expires_at_epoch": expires_at_epoch,
    }
    invitation_id = "hcqri-" + _digest(material)[:24]
    return QrOnboardingInvitation(
        invitation_id=invitation_id,
        household_id=household_id,
        issuer_member_id=issuer_member_id,
        issuer_role=issuer_role,
        subject=subject,
        device_id=device_id,
        guest_scope=guest_scope,
        token_sha256=token_sha256,
        created_at_epoch=created_at_epoch,
        expires_at_epoch=expires_at_epoch,
    )


def build_qr_payload(*, invitation: QrOnboardingInvitation, onboarding_code: str) -> QrOnboardingPayload:
    if not isinstance(invitation, QrOnboardingInvitation):
        raise TypeError("qr_invitation_invalid")
    if hash_onboarding_code(onboarding_code) != invitation.token_sha256:
        raise QrOnboardingError("qr_onboarding_code_mismatch")
    return QrOnboardingPayload(
        invitation_id=invitation.invitation_id,
        household_id=invitation.household_id,
        onboarding_code=onboarding_code,
        expires_at_epoch=invitation.expires_at_epoch,
    )


def invitation_state(
    invitation: QrOnboardingInvitation,
    *,
    now_epoch: int,
    revoked: bool,
    consumed: bool,
) -> InvitationState:
    if not isinstance(invitation, QrOnboardingInvitation):
        raise TypeError("qr_invitation_invalid")
    now = _epoch(now_epoch, "qr_now_invalid")
    if type(revoked) is not bool or type(consumed) is not bool:
        raise QrOnboardingError("qr_invitation_state_invalid")
    if revoked:
        return InvitationState.REVOKED
    if consumed:
        return InvitationState.CONSUMED
    if now >= invitation.expires_at_epoch:
        return InvitationState.EXPIRED
    return InvitationState.ACTIVE


def plan_qr_redemption(
    *,
    invitation: QrOnboardingInvitation,
    onboarding_code: str,
    now_epoch: int,
    revoked: bool = False,
    consumed: bool = False,
) -> QrOnboardingRedemptionPlan:
    state = invitation_state(invitation, now_epoch=now_epoch, revoked=revoked, consumed=consumed)
    if state is not InvitationState.ACTIVE:
        raise QrOnboardingError(f"qr_invitation_{state.value}")
    if hash_onboarding_code(onboarding_code) != invitation.token_sha256:
        raise QrOnboardingError("qr_onboarding_code_mismatch")
    material = {
        "invitation_id": invitation.invitation_id,
        "household_id": invitation.household_id,
        "subject": invitation.subject.value,
        "device_id": invitation.device_id,
        "guest_scope": [scope.value for scope in invitation.guest_scope],
        "presented_at_epoch": now_epoch,
    }
    return QrOnboardingRedemptionPlan(
        plan_id="hcqrp-" + _digest(material)[:24],
        invitation_id=invitation.invitation_id,
        household_id=invitation.household_id,
        subject=invitation.subject,
        device_id=invitation.device_id,
        guest_scope=invitation.guest_scope,
        presented_at_epoch=now_epoch,
    )
