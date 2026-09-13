"""Post-condition verification request contract for Home Center 0.63 QR effects.

A consumed/revoked invitation is only evidence that the one-time QR token changed
state. It is not evidence that the requested guest/device effect happened. This
module prepares an exact, non-authorizing verification request that a later typed
Change/Job implementation can fulfill using authoritative product-state readback.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .qr_onboarding import OnboardingSubject
from .qr_onboarding_effect_handoff import QrOnboardingEffectHandoff, QrOnboardingEffectKind
from .util import canonical_json

QR_EFFECT_VERIFICATION_REQUEST_SCHEMA = "home-center.qr-onboarding-effect-verification-request.v1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REQUEST_ID = re.compile(r"hcqev-[0-9a-f]{24}\Z")
_HANDOFF_ID = re.compile(r"hcqeh-[0-9a-f]{24}\Z")
_SNAPSHOT_ID = re.compile(r"hsnap-[0-9a-f]{24}\Z")
_RESOURCE_VERSION = re.compile(r"hrv-[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class QrOnboardingEffectVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QrOnboardingPostCondition(StrEnum):
    GUEST_ACCESS_EFFECTIVE = "guest-access-effective"
    DEVICE_BINDING_EFFECTIVE = "device-binding-effective"
    ACCESS_REVOKED = "access-revoked"


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectVerificationRequest:
    request_id: str
    handoff_id: str
    handoff_sha256: str
    effect_job_id: str
    required_job_type: str
    effect_kind: QrOnboardingEffectKind
    household_id: str
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    target_member_id: str
    subject: OnboardingSubject
    device_id: str | None
    expected_post_condition: QrOnboardingPostCondition
    schema: str = field(default=QR_EFFECT_VERIFICATION_REQUEST_SCHEMA, init=False)
    authoritative_readback_required: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    effect_success_claimed: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "handoff_id": self.handoff_id,
            "handoff_sha256": self.handoff_sha256,
            "effect_job_id": self.effect_job_id,
            "required_job_type": self.required_job_type,
            "effect_kind": self.effect_kind.value,
            "household_id": self.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "subject": self.subject.value,
            "device_id": self.device_id,
            "expected_post_condition": self.expected_post_condition.value,
            "authoritative_readback_required": True,
            "post_condition_verified": False,
            "effect_success_claimed": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _string(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise QrOnboardingEffectVerificationError(code)
    return value


def _expected_post_condition(effect_kind: QrOnboardingEffectKind) -> QrOnboardingPostCondition:
    if effect_kind is QrOnboardingEffectKind.GUEST_ACCESS_GRANT:
        return QrOnboardingPostCondition.GUEST_ACCESS_EFFECTIVE
    if effect_kind is QrOnboardingEffectKind.DEVICE_BINDING:
        return QrOnboardingPostCondition.DEVICE_BINDING_EFFECTIVE
    if effect_kind is QrOnboardingEffectKind.ACCESS_REVOCATION:
        return QrOnboardingPostCondition.ACCESS_REVOKED
    raise QrOnboardingEffectVerificationError("qr_effect_verification_effect_kind_invalid")


def _expected_job_type(effect_kind: QrOnboardingEffectKind) -> str:
    if effect_kind is QrOnboardingEffectKind.GUEST_ACCESS_GRANT:
        return "typed-guest-access-change-job"
    if effect_kind is QrOnboardingEffectKind.DEVICE_BINDING:
        return "typed-device-binding-change-job"
    if effect_kind is QrOnboardingEffectKind.ACCESS_REVOCATION:
        return "typed-access-revocation-change-job"
    raise QrOnboardingEffectVerificationError("qr_effect_verification_effect_kind_invalid")


def _handoff_digest(handoff: QrOnboardingEffectHandoff) -> str:
    return hashlib.sha256(canonical_json(handoff.to_dict()).encode("utf-8")).hexdigest()


def _validate_subject_shape(subject: OnboardingSubject, device_id: str | None) -> None:
    if subject is OnboardingSubject.GUEST:
        if device_id is not None:
            raise QrOnboardingEffectVerificationError("qr_effect_verification_subject_shape_invalid")
        return
    if subject is OnboardingSubject.DEVICE:
        if device_id is None:
            raise QrOnboardingEffectVerificationError("qr_effect_verification_subject_shape_invalid")
        return
    raise QrOnboardingEffectVerificationError("qr_effect_verification_subject_shape_invalid")


def build_qr_onboarding_effect_verification_request(
    *,
    handoff: QrOnboardingEffectHandoff,
    effect_job_id: str,
) -> QrOnboardingEffectVerificationRequest:
    """Create verification work only after a concrete typed effect Job exists."""

    if not isinstance(handoff, QrOnboardingEffectHandoff):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_handoff_invalid")
    normalized_job_id = _string(effect_job_id, _IDENTIFIER, "qr_effect_verification_job_id_invalid")
    expected_post_condition = _expected_post_condition(handoff.effect_kind)
    if handoff.required_job_type != _expected_job_type(handoff.effect_kind):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_job_type_mismatch")
    _validate_subject_shape(handoff.subject, handoff.device_id)
    handoff_sha256 = _handoff_digest(handoff)
    material = {
        "handoff_id": handoff.handoff_id,
        "handoff_sha256": handoff_sha256,
        "effect_job_id": normalized_job_id,
        "required_job_type": handoff.required_job_type,
        "effect_kind": handoff.effect_kind.value,
        "household_id": handoff.household_id,
        "household_snapshot_id": handoff.household_snapshot_id,
        "household_resource_version": handoff.household_resource_version,
        "household_generation": handoff.household_generation,
        "target_member_id": handoff.target_member_id,
        "subject": handoff.subject.value,
        "device_id": handoff.device_id,
        "expected_post_condition": expected_post_condition.value,
    }
    request_id = "hcqev-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
    return QrOnboardingEffectVerificationRequest(
        request_id=request_id,
        handoff_id=handoff.handoff_id,
        handoff_sha256=handoff_sha256,
        effect_job_id=normalized_job_id,
        required_job_type=handoff.required_job_type,
        effect_kind=handoff.effect_kind,
        household_id=handoff.household_id,
        household_snapshot_id=handoff.household_snapshot_id,
        household_resource_version=handoff.household_resource_version,
        household_generation=handoff.household_generation,
        target_member_id=handoff.target_member_id,
        subject=handoff.subject,
        device_id=handoff.device_id,
        expected_post_condition=expected_post_condition,
    )


def qr_onboarding_effect_verification_request_from_dict(
    value: object,
) -> QrOnboardingEffectVerificationRequest:
    """Reject transport/storage tampering and any premature success claim."""

    expected = {
        "schema",
        "request_id",
        "handoff_id",
        "handoff_sha256",
        "effect_job_id",
        "required_job_type",
        "effect_kind",
        "household_id",
        "household_snapshot_id",
        "household_resource_version",
        "household_generation",
        "target_member_id",
        "subject",
        "device_id",
        "expected_post_condition",
        "authoritative_readback_required",
        "post_condition_verified",
        "effect_success_claimed",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")
    if value.get("schema") != QR_EFFECT_VERIFICATION_REQUEST_SCHEMA:
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")
    if value.get("authoritative_readback_required") is not True:
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")
    for key in (
        "post_condition_verified",
        "effect_success_claimed",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        if value.get(key) is not False:
            raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")

    try:
        effect_kind = QrOnboardingEffectKind(value["effect_kind"])
        subject = OnboardingSubject(value["subject"])
        expected_post_condition = QrOnboardingPostCondition(value["expected_post_condition"])
        generation = value["household_generation"]
        if type(generation) is not int or generation < 1:
            raise ValueError("generation")
        device_id_raw = value["device_id"]
        device_id = None if device_id_raw is None else _string(
            device_id_raw, _IDENTIFIER, "qr_effect_verification_device_id_invalid"
        )
        request = QrOnboardingEffectVerificationRequest(
            request_id=_string(value["request_id"], _REQUEST_ID, "qr_effect_verification_request_id_invalid"),
            handoff_id=_string(value["handoff_id"], _HANDOFF_ID, "qr_effect_verification_handoff_id_invalid"),
            handoff_sha256=_string(value["handoff_sha256"], _SHA256, "qr_effect_verification_digest_invalid"),
            effect_job_id=_string(value["effect_job_id"], _IDENTIFIER, "qr_effect_verification_job_id_invalid"),
            required_job_type=_string(
                value["required_job_type"], _IDENTIFIER, "qr_effect_verification_job_type_invalid"
            ),
            effect_kind=effect_kind,
            household_id=_string(value["household_id"], _IDENTIFIER, "qr_effect_verification_household_id_invalid"),
            household_snapshot_id=_string(
                value["household_snapshot_id"], _SNAPSHOT_ID, "qr_effect_verification_snapshot_id_invalid"
            ),
            household_resource_version=_string(
                value["household_resource_version"],
                _RESOURCE_VERSION,
                "qr_effect_verification_resource_version_invalid",
            ),
            household_generation=generation,
            target_member_id=_string(
                value["target_member_id"], _IDENTIFIER, "qr_effect_verification_target_member_invalid"
            ),
            subject=subject,
            device_id=device_id,
            expected_post_condition=expected_post_condition,
        )
        _validate_subject_shape(subject, device_id)
    except (KeyError, TypeError, ValueError, QrOnboardingEffectVerificationError) as exc:
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected") from exc

    if request.expected_post_condition is not _expected_post_condition(request.effect_kind):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")
    if request.required_job_type != _expected_job_type(request.effect_kind):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")
    if request.effect_kind is QrOnboardingEffectKind.GUEST_ACCESS_GRANT and request.subject is not OnboardingSubject.GUEST:
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")
    if request.effect_kind is QrOnboardingEffectKind.DEVICE_BINDING and request.subject is not OnboardingSubject.DEVICE:
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")

    material = {
        "handoff_id": request.handoff_id,
        "handoff_sha256": request.handoff_sha256,
        "effect_job_id": request.effect_job_id,
        "required_job_type": request.required_job_type,
        "effect_kind": request.effect_kind.value,
        "household_id": request.household_id,
        "household_snapshot_id": request.household_snapshot_id,
        "household_resource_version": request.household_resource_version,
        "household_generation": request.household_generation,
        "target_member_id": request.target_member_id,
        "subject": request.subject.value,
        "device_id": request.device_id,
        "expected_post_condition": request.expected_post_condition.value,
    }
    expected_id = "hcqev-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
    if request.request_id != expected_id or request.to_dict() != value:
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_rejected")
    return request


def validate_verification_request_against_handoff(
    request: QrOnboardingEffectVerificationRequest,
    handoff: QrOnboardingEffectHandoff,
) -> None:
    """Re-bind stored verification work to its exact immutable handoff."""

    if not isinstance(request, QrOnboardingEffectVerificationRequest):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_request_invalid")
    if not isinstance(handoff, QrOnboardingEffectHandoff):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_handoff_invalid")
    if request.handoff_id != handoff.handoff_id or request.handoff_sha256 != _handoff_digest(handoff):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_handoff_mismatch")
    if (
        request.required_job_type != handoff.required_job_type
        or request.effect_kind is not handoff.effect_kind
        or request.household_id != handoff.household_id
        or request.household_snapshot_id != handoff.household_snapshot_id
        or request.household_resource_version != handoff.household_resource_version
        or request.household_generation != handoff.household_generation
        or request.target_member_id != handoff.target_member_id
        or request.subject is not handoff.subject
        or request.device_id != handoff.device_id
    ):
        raise QrOnboardingEffectVerificationError("qr_effect_verification_handoff_mismatch")
