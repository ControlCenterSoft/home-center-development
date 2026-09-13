"""Authoritative read-back verification for Home Center 0.63 QR effects.

A QR invitation consume/revoke receipt and a durable effect Job are not success.
This module accepts a bounded read-only observation, re-binds it to the exact
handoff and verification request, enforces freshness, and emits a positive
verification receipt only when the requested post-condition is actually
observed.  It never authorizes another effect, provider call, infrastructure
mutation or external publication.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .qr_onboarding import GuestScope, OnboardingSubject
from .qr_onboarding_effect_handoff import QrOnboardingEffectHandoff, QrOnboardingEffectKind
from .qr_onboarding_effect_verification import (
    QrOnboardingEffectVerificationRequest,
    QrOnboardingPostCondition,
    validate_verification_request_against_handoff,
)
from .util import canonical_json

QR_EFFECT_OBSERVATION_SCHEMA = "home-center.qr-onboarding-effect-observation.v1"
QR_EFFECT_VERIFICATION_RECEIPT_SCHEMA = "home-center.qr-onboarding-effect-verification-receipt.v1"
MAX_OBSERVATION_FRESHNESS_SECONDS = 300

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OBSERVATION_ID = re.compile(r"hcqeo-[0-9a-f]{24}\Z")
_RECEIPT_ID = re.compile(r"hcqvr-[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class QrOnboardingEffectPostConditionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QrOnboardingEffectObservationState(StrEnum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not-satisfied"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectObservation:
    observation_id: str
    request_id: str
    request_sha256: str
    handoff_id: str
    handoff_sha256: str
    effect_job_id: str
    effect_kind: QrOnboardingEffectKind
    household_id: str
    target_member_id: str
    subject: OnboardingSubject
    device_id: str | None
    guest_scope: tuple[GuestScope, ...]
    expected_post_condition: QrOnboardingPostCondition
    observed_post_condition: QrOnboardingPostCondition
    state: QrOnboardingEffectObservationState
    source_id: str
    observed_at_epoch: int
    valid_until_epoch: int
    evidence_sha256: str
    schema: str = field(default=QR_EFFECT_OBSERVATION_SCHEMA, init=False)
    read_only: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    effect_success_claimed: bool = field(default=False, init=False)
    effect_execution_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def evidence_material(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "handoff_id": self.handoff_id,
            "handoff_sha256": self.handoff_sha256,
            "effect_job_id": self.effect_job_id,
            "effect_kind": self.effect_kind.value,
            "household_id": self.household_id,
            "target_member_id": self.target_member_id,
            "subject": self.subject.value,
            "device_id": self.device_id,
            "guest_scope": [scope.value for scope in self.guest_scope],
            "expected_post_condition": self.expected_post_condition.value,
            "observed_post_condition": self.observed_post_condition.value,
            "state": self.state.value,
            "source_id": self.source_id,
            "observed_at_epoch": self.observed_at_epoch,
            "valid_until_epoch": self.valid_until_epoch,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "observation_id": self.observation_id,
            **self.evidence_material(),
            "evidence_sha256": self.evidence_sha256,
            "read_only": True,
            "post_condition_verified": False,
            "effect_success_claimed": False,
            "effect_execution_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectVerificationReceipt:
    receipt_id: str
    request_id: str
    request_sha256: str
    handoff_id: str
    handoff_sha256: str
    effect_job_id: str
    effect_kind: QrOnboardingEffectKind
    household_id: str
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    target_member_id: str
    subject: OnboardingSubject
    device_id: str | None
    guest_scope: tuple[GuestScope, ...]
    expected_post_condition: QrOnboardingPostCondition
    observed_post_condition: QrOnboardingPostCondition
    observation_id: str
    observation_evidence_sha256: str
    verified_at_epoch: int
    schema: str = field(default=QR_EFFECT_VERIFICATION_RECEIPT_SCHEMA, init=False)
    state: str = field(default="verified", init=False)
    authoritative_readback_verified: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=True, init=False)
    effect_success_claimed: bool = field(default=True, init=False)
    effect_execution_authorized: bool = field(default=False, init=False)
    durable_state_change_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def identity_material(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "handoff_id": self.handoff_id,
            "handoff_sha256": self.handoff_sha256,
            "effect_job_id": self.effect_job_id,
            "effect_kind": self.effect_kind.value,
            "household_id": self.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "subject": self.subject.value,
            "device_id": self.device_id,
            "guest_scope": [scope.value for scope in self.guest_scope],
            "expected_post_condition": self.expected_post_condition.value,
            "observed_post_condition": self.observed_post_condition.value,
            "observation_id": self.observation_id,
            "observation_evidence_sha256": self.observation_evidence_sha256,
            "verified_at_epoch": self.verified_at_epoch,
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            **self.identity_material(),
            "state": "verified",
            "authoritative_readback_verified": True,
            "post_condition_verified": True,
            "effect_success_claimed": True,
            "effect_execution_authorized": False,
            "durable_state_change_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _string(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise QrOnboardingEffectPostConditionError(code)
    return value


def _epoch(value: object, code: str) -> int:
    if type(value) is not int or value < 0:
        raise QrOnboardingEffectPostConditionError(code)
    return value


def _request_digest(request: QrOnboardingEffectVerificationRequest) -> str:
    return _digest(request.to_dict())


def _handoff_digest(handoff: QrOnboardingEffectHandoff) -> str:
    return _digest(handoff.to_dict())


def _validate_subject_shape(
    *, subject: OnboardingSubject, device_id: str | None, guest_scope: tuple[GuestScope, ...]
) -> None:
    if subject is OnboardingSubject.GUEST:
        if device_id is not None or guest_scope != (GuestScope.INTERNET_GUEST,):
            raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_subject_shape_invalid")
        return
    if subject is OnboardingSubject.DEVICE:
        if device_id is None or guest_scope:
            raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_subject_shape_invalid")
        return
    raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_subject_shape_invalid")


def build_qr_onboarding_effect_observation(
    *,
    request: QrOnboardingEffectVerificationRequest,
    handoff: QrOnboardingEffectHandoff,
    observed_post_condition: QrOnboardingPostCondition,
    state: QrOnboardingEffectObservationState,
    source_id: str,
    observed_at_epoch: int,
    valid_until_epoch: int,
) -> QrOnboardingEffectObservation:
    """Build bounded read-only evidence returned by an authoritative reader."""

    if not isinstance(request, QrOnboardingEffectVerificationRequest):
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_request_invalid")
    if not isinstance(handoff, QrOnboardingEffectHandoff):
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_handoff_invalid")
    try:
        validate_verification_request_against_handoff(request, handoff)
    except Exception as exc:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_binding_mismatch") from exc
    if not isinstance(observed_post_condition, QrOnboardingPostCondition) or not isinstance(
        state, QrOnboardingEffectObservationState
    ):
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_observation_invalid")
    normalized_source = _string(source_id, _IDENTIFIER, "qr_effect_post_condition_source_invalid")
    observed = _epoch(observed_at_epoch, "qr_effect_post_condition_observed_at_invalid")
    valid_until = _epoch(valid_until_epoch, "qr_effect_post_condition_valid_until_invalid")
    if valid_until < observed or valid_until - observed > MAX_OBSERVATION_FRESHNESS_SECONDS:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_freshness_window_invalid")
    _validate_subject_shape(subject=handoff.subject, device_id=handoff.device_id, guest_scope=handoff.guest_scope)

    request_sha256 = _request_digest(request)
    handoff_sha256 = _handoff_digest(handoff)
    material = {
        "request_id": request.request_id,
        "request_sha256": request_sha256,
        "handoff_id": handoff.handoff_id,
        "handoff_sha256": handoff_sha256,
        "effect_job_id": request.effect_job_id,
        "effect_kind": request.effect_kind.value,
        "household_id": request.household_id,
        "target_member_id": request.target_member_id,
        "subject": request.subject.value,
        "device_id": request.device_id,
        "guest_scope": [scope.value for scope in handoff.guest_scope],
        "expected_post_condition": request.expected_post_condition.value,
        "observed_post_condition": observed_post_condition.value,
        "state": state.value,
        "source_id": normalized_source,
        "observed_at_epoch": observed,
        "valid_until_epoch": valid_until,
    }
    evidence_sha256 = _digest(material)
    observation_id = "hcqeo-" + evidence_sha256[:24]
    return QrOnboardingEffectObservation(
        observation_id=observation_id,
        request_id=request.request_id,
        request_sha256=request_sha256,
        handoff_id=handoff.handoff_id,
        handoff_sha256=handoff_sha256,
        effect_job_id=request.effect_job_id,
        effect_kind=request.effect_kind,
        household_id=request.household_id,
        target_member_id=request.target_member_id,
        subject=request.subject,
        device_id=request.device_id,
        guest_scope=handoff.guest_scope,
        expected_post_condition=request.expected_post_condition,
        observed_post_condition=observed_post_condition,
        state=state,
        source_id=normalized_source,
        observed_at_epoch=observed,
        valid_until_epoch=valid_until,
        evidence_sha256=evidence_sha256,
    )


def qr_onboarding_effect_observation_from_dict(value: object) -> QrOnboardingEffectObservation:
    expected = {
        "schema", "observation_id", "request_id", "request_sha256", "handoff_id", "handoff_sha256",
        "effect_job_id", "effect_kind", "household_id", "target_member_id", "subject", "device_id",
        "guest_scope", "expected_post_condition", "observed_post_condition", "state", "source_id",
        "observed_at_epoch", "valid_until_epoch", "evidence_sha256", "read_only", "post_condition_verified",
        "effect_success_claimed", "effect_execution_authorized", "provider_execution_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != QR_EFFECT_OBSERVATION_SCHEMA:
        raise QrOnboardingEffectPostConditionError("qr_effect_observation_rejected")
    if value.get("read_only") is not True:
        raise QrOnboardingEffectPostConditionError("qr_effect_observation_rejected")
    for key in (
        "post_condition_verified", "effect_success_claimed", "effect_execution_authorized",
        "provider_execution_authorized", "infrastructure_mutation_authorized", "external_publication_authorized",
    ):
        if value.get(key) is not False:
            raise QrOnboardingEffectPostConditionError("qr_effect_observation_rejected")
    try:
        effect_kind = QrOnboardingEffectKind(value["effect_kind"])
        subject = OnboardingSubject(value["subject"])
        expected_condition = QrOnboardingPostCondition(value["expected_post_condition"])
        observed_condition = QrOnboardingPostCondition(value["observed_post_condition"])
        state = QrOnboardingEffectObservationState(value["state"])
        guest_scope_raw = value["guest_scope"]
        if not isinstance(guest_scope_raw, list):
            raise ValueError("guest_scope")
        guest_scope = tuple(sorted((GuestScope(item) for item in guest_scope_raw), key=lambda item: item.value))
        if len(guest_scope) != len(set(guest_scope)):
            raise ValueError("guest_scope_duplicate")
        device_raw = value["device_id"]
        device_id = None if device_raw is None else _string(
            device_raw, _IDENTIFIER, "qr_effect_observation_device_invalid"
        )
        observed_at = _epoch(value["observed_at_epoch"], "qr_effect_observation_observed_at_invalid")
        valid_until = _epoch(value["valid_until_epoch"], "qr_effect_observation_valid_until_invalid")
        if valid_until < observed_at or valid_until - observed_at > MAX_OBSERVATION_FRESHNESS_SECONDS:
            raise ValueError("freshness")
        observation = QrOnboardingEffectObservation(
            observation_id=_string(value["observation_id"], _OBSERVATION_ID, "qr_effect_observation_id_invalid"),
            request_id=_string(value["request_id"], _IDENTIFIER, "qr_effect_observation_request_invalid"),
            request_sha256=_string(value["request_sha256"], _SHA256, "qr_effect_observation_digest_invalid"),
            handoff_id=_string(value["handoff_id"], _IDENTIFIER, "qr_effect_observation_handoff_invalid"),
            handoff_sha256=_string(value["handoff_sha256"], _SHA256, "qr_effect_observation_digest_invalid"),
            effect_job_id=_string(value["effect_job_id"], _IDENTIFIER, "qr_effect_observation_job_invalid"),
            effect_kind=effect_kind,
            household_id=_string(value["household_id"], _IDENTIFIER, "qr_effect_observation_household_invalid"),
            target_member_id=_string(value["target_member_id"], _IDENTIFIER, "qr_effect_observation_member_invalid"),
            subject=subject,
            device_id=device_id,
            guest_scope=guest_scope,
            expected_post_condition=expected_condition,
            observed_post_condition=observed_condition,
            state=state,
            source_id=_string(value["source_id"], _IDENTIFIER, "qr_effect_observation_source_invalid"),
            observed_at_epoch=observed_at,
            valid_until_epoch=valid_until,
            evidence_sha256=_string(value["evidence_sha256"], _SHA256, "qr_effect_observation_digest_invalid"),
        )
        _validate_subject_shape(subject=subject, device_id=device_id, guest_scope=guest_scope)
    except (KeyError, TypeError, ValueError, QrOnboardingEffectPostConditionError) as exc:
        raise QrOnboardingEffectPostConditionError("qr_effect_observation_rejected") from exc
    expected_digest = _digest(observation.evidence_material())
    if observation.evidence_sha256 != expected_digest or observation.observation_id != "hcqeo-" + expected_digest[:24]:
        raise QrOnboardingEffectPostConditionError("qr_effect_observation_rejected")
    if observation.to_dict() != value:
        raise QrOnboardingEffectPostConditionError("qr_effect_observation_rejected")
    return observation


def verify_qr_onboarding_effect_post_condition(
    *,
    request: QrOnboardingEffectVerificationRequest,
    handoff: QrOnboardingEffectHandoff,
    observation: QrOnboardingEffectObservation,
    now_epoch: int,
) -> QrOnboardingEffectVerificationReceipt:
    """Return success evidence only after exact, fresh authoritative read-back."""

    if not isinstance(request, QrOnboardingEffectVerificationRequest) or not isinstance(
        handoff, QrOnboardingEffectHandoff
    ) or not isinstance(observation, QrOnboardingEffectObservation):
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_input_invalid")
    try:
        validate_verification_request_against_handoff(request, handoff)
    except Exception as exc:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_binding_mismatch") from exc
    current = _epoch(now_epoch, "qr_effect_post_condition_now_invalid")
    request_sha256 = _request_digest(request)
    handoff_sha256 = _handoff_digest(handoff)
    exact = (
        observation.request_id == request.request_id
        and observation.request_sha256 == request_sha256
        and observation.handoff_id == handoff.handoff_id
        and observation.handoff_sha256 == handoff_sha256
        and observation.effect_job_id == request.effect_job_id
        and observation.effect_kind is request.effect_kind
        and observation.household_id == request.household_id
        and observation.target_member_id == request.target_member_id
        and observation.subject is request.subject
        and observation.device_id == request.device_id
        and observation.guest_scope == handoff.guest_scope
        and observation.expected_post_condition is request.expected_post_condition
    )
    if not exact:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_binding_mismatch")
    if observation.evidence_sha256 != _digest(observation.evidence_material()):
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_evidence_invalid")
    if current < observation.observed_at_epoch:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_observation_from_future")
    if current > observation.valid_until_epoch:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_observation_stale")
    if observation.state is QrOnboardingEffectObservationState.UNKNOWN:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_unknown")
    if observation.state is not QrOnboardingEffectObservationState.SATISFIED:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_not_satisfied")
    if observation.observed_post_condition is not request.expected_post_condition:
        raise QrOnboardingEffectPostConditionError("qr_effect_post_condition_mismatch")

    material = {
        "request_id": request.request_id,
        "request_sha256": request_sha256,
        "handoff_id": handoff.handoff_id,
        "handoff_sha256": handoff_sha256,
        "effect_job_id": request.effect_job_id,
        "effect_kind": request.effect_kind.value,
        "household_id": request.household_id,
        "household_snapshot_id": request.household_snapshot_id,
        "household_resource_version": request.household_resource_version,
        "household_generation": request.household_generation,
        "target_member_id": request.target_member_id,
        "subject": request.subject.value,
        "device_id": request.device_id,
        "guest_scope": [scope.value for scope in handoff.guest_scope],
        "expected_post_condition": request.expected_post_condition.value,
        "observed_post_condition": observation.observed_post_condition.value,
        "observation_id": observation.observation_id,
        "observation_evidence_sha256": observation.evidence_sha256,
        "verified_at_epoch": current,
    }
    receipt_id = "hcqvr-" + _digest(material)[:24]
    return QrOnboardingEffectVerificationReceipt(
        receipt_id=receipt_id,
        request_id=request.request_id,
        request_sha256=request_sha256,
        handoff_id=handoff.handoff_id,
        handoff_sha256=handoff_sha256,
        effect_job_id=request.effect_job_id,
        effect_kind=request.effect_kind,
        household_id=request.household_id,
        household_snapshot_id=request.household_snapshot_id,
        household_resource_version=request.household_resource_version,
        household_generation=request.household_generation,
        target_member_id=request.target_member_id,
        subject=request.subject,
        device_id=request.device_id,
        guest_scope=handoff.guest_scope,
        expected_post_condition=request.expected_post_condition,
        observed_post_condition=observation.observed_post_condition,
        observation_id=observation.observation_id,
        observation_evidence_sha256=observation.evidence_sha256,
        verified_at_epoch=current,
    )


def qr_onboarding_effect_verification_receipt_from_dict(
    value: object,
) -> QrOnboardingEffectVerificationReceipt:
    expected = {
        "schema", "receipt_id", "request_id", "request_sha256", "handoff_id", "handoff_sha256",
        "effect_job_id", "effect_kind", "household_id", "household_snapshot_id",
        "household_resource_version", "household_generation", "target_member_id", "subject", "device_id",
        "guest_scope", "expected_post_condition", "observed_post_condition", "observation_id",
        "observation_evidence_sha256", "verified_at_epoch", "state", "authoritative_readback_verified",
        "post_condition_verified", "effect_success_claimed", "effect_execution_authorized",
        "durable_state_change_authorized", "provider_execution_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != QR_EFFECT_VERIFICATION_RECEIPT_SCHEMA:
        raise QrOnboardingEffectPostConditionError("qr_effect_verification_receipt_rejected")
    if (
        value.get("state") != "verified"
        or value.get("authoritative_readback_verified") is not True
        or value.get("post_condition_verified") is not True
        or value.get("effect_success_claimed") is not True
    ):
        raise QrOnboardingEffectPostConditionError("qr_effect_verification_receipt_rejected")
    for key in (
        "effect_execution_authorized", "durable_state_change_authorized", "provider_execution_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    ):
        if value.get(key) is not False:
            raise QrOnboardingEffectPostConditionError("qr_effect_verification_receipt_rejected")
    try:
        effect_kind = QrOnboardingEffectKind(value["effect_kind"])
        subject = OnboardingSubject(value["subject"])
        expected_condition = QrOnboardingPostCondition(value["expected_post_condition"])
        observed_condition = QrOnboardingPostCondition(value["observed_post_condition"])
        generation = value["household_generation"]
        if type(generation) is not int or generation < 1:
            raise ValueError("generation")
        guest_scope_raw = value["guest_scope"]
        if not isinstance(guest_scope_raw, list):
            raise ValueError("guest_scope")
        guest_scope = tuple(sorted((GuestScope(item) for item in guest_scope_raw), key=lambda item: item.value))
        if len(guest_scope) != len(set(guest_scope)):
            raise ValueError("guest_scope_duplicate")
        device_raw = value["device_id"]
        device_id = None if device_raw is None else _string(
            device_raw, _IDENTIFIER, "qr_effect_verification_receipt_device_invalid"
        )
        receipt = QrOnboardingEffectVerificationReceipt(
            receipt_id=_string(value["receipt_id"], _RECEIPT_ID, "qr_effect_verification_receipt_id_invalid"),
            request_id=_string(value["request_id"], _IDENTIFIER, "qr_effect_verification_receipt_request_invalid"),
            request_sha256=_string(value["request_sha256"], _SHA256, "qr_effect_verification_receipt_digest_invalid"),
            handoff_id=_string(value["handoff_id"], _IDENTIFIER, "qr_effect_verification_receipt_handoff_invalid"),
            handoff_sha256=_string(value["handoff_sha256"], _SHA256, "qr_effect_verification_receipt_digest_invalid"),
            effect_job_id=_string(value["effect_job_id"], _IDENTIFIER, "qr_effect_verification_receipt_job_invalid"),
            effect_kind=effect_kind,
            household_id=_string(value["household_id"], _IDENTIFIER, "qr_effect_verification_receipt_household_invalid"),
            household_snapshot_id=_string(
                value["household_snapshot_id"], _IDENTIFIER, "qr_effect_verification_receipt_snapshot_invalid"
            ),
            household_resource_version=_string(
                value["household_resource_version"], _IDENTIFIER, "qr_effect_verification_receipt_resource_version_invalid"
            ),
            household_generation=generation,
            target_member_id=_string(
                value["target_member_id"], _IDENTIFIER, "qr_effect_verification_receipt_member_invalid"
            ),
            subject=subject,
            device_id=device_id,
            guest_scope=guest_scope,
            expected_post_condition=expected_condition,
            observed_post_condition=observed_condition,
            observation_id=_string(value["observation_id"], _OBSERVATION_ID, "qr_effect_verification_receipt_observation_invalid"),
            observation_evidence_sha256=_string(
                value["observation_evidence_sha256"], _SHA256, "qr_effect_verification_receipt_digest_invalid"
            ),
            verified_at_epoch=_epoch(value["verified_at_epoch"], "qr_effect_verification_receipt_time_invalid"),
        )
        _validate_subject_shape(subject=subject, device_id=device_id, guest_scope=guest_scope)
    except (KeyError, TypeError, ValueError, QrOnboardingEffectPostConditionError) as exc:
        raise QrOnboardingEffectPostConditionError("qr_effect_verification_receipt_rejected") from exc
    if receipt.expected_post_condition is not receipt.observed_post_condition:
        raise QrOnboardingEffectPostConditionError("qr_effect_verification_receipt_rejected")
    expected_id = "hcqvr-" + _digest(receipt.identity_material())[:24]
    if receipt.receipt_id != expected_id or receipt.to_dict() != value:
        raise QrOnboardingEffectPostConditionError("qr_effect_verification_receipt_rejected")
    return receipt
