"""Exact-bound QR onboarding effect handoff for Home Center 0.63.

This module connects a *verified invitation-state transition* to the next typed
Change/Job boundary without granting that boundary execution authority.  It is
intentionally runner-free source preparation: the handoff is deterministic,
closed and privacy-minimized, but it never creates a Job, mutates Household
state, calls a provider or reports onboarding success.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from .home_services import HomeServiceCatalogError, _identifier
from .qr_onboarding import GuestScope, InvitationState, OnboardingSubject
from .qr_onboarding_runtime import (
    QrOnboardingOperationReceipt,
    QrOnboardingRuntimeError,
    QrOnboardingRuntimeRecord,
    RuntimeOperation,
)
from .util import canonical_json

QR_EFFECT_HANDOFF_SCHEMA = "home-center.qr-onboarding-effect-handoff.v1"


class QrOnboardingEffectHandoffError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QrOnboardingEffectKind(StrEnum):
    GUEST_ACCESS_GRANT = "guest-access-grant"
    DEVICE_BINDING = "device-binding"
    ACCESS_REVOCATION = "access-revocation"


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectHandoff:
    handoff_id: str
    effect_kind: QrOnboardingEffectKind
    source_operation: RuntimeOperation
    source_receipt_id: str
    source_receipt_sha256: str
    runtime_record_id: str
    invitation_id: str
    invitation_evidence_sha256: str
    household_id: str
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    target_member_id: str
    subject: OnboardingSubject
    device_id: str | None
    guest_scope: tuple[GuestScope, ...]
    source_record_version: int
    required_job_type: str
    schema: str = field(default=QR_EFFECT_HANDOFF_SCHEMA, init=False)
    explicit_change_job_required: bool = field(default=True, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    effect_execution_authorized: bool = field(default=False, init=False)
    account_creation_authorized: bool = field(default=False, init=False)
    device_registration_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "handoff_id": self.handoff_id,
            "effect_kind": self.effect_kind.value,
            "source_operation": self.source_operation.value,
            "source_receipt_id": self.source_receipt_id,
            "source_receipt_sha256": self.source_receipt_sha256,
            "runtime_record_id": self.runtime_record_id,
            "invitation_id": self.invitation_id,
            "invitation_evidence_sha256": self.invitation_evidence_sha256,
            "household_id": self.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "subject": self.subject.value,
            "device_id": self.device_id,
            "guest_scope": [scope.value for scope in self.guest_scope],
            "source_record_version": self.source_record_version,
            "required_job_type": self.required_job_type,
            "explicit_change_job_required": True,
            "post_condition_verification_required": True,
            "effect_execution_authorized": False,
            "account_creation_authorized": False,
            "device_registration_authorized": False,
            "managed_state_change_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _identifier_value(value: object, code: str) -> str:
    try:
        return _identifier(value, code)
    except (HomeServiceCatalogError, TypeError, ValueError) as exc:
        raise QrOnboardingEffectHandoffError(code) from exc


def _receipt_digest(receipt: QrOnboardingOperationReceipt) -> str:
    return hashlib.sha256(canonical_json(receipt.to_dict()).encode("utf-8")).hexdigest()


def _expected_boundary(
    operation: RuntimeOperation,
    subject: OnboardingSubject,
) -> tuple[QrOnboardingEffectKind, str]:
    if operation is RuntimeOperation.CONSUME:
        if subject is OnboardingSubject.GUEST:
            return QrOnboardingEffectKind.GUEST_ACCESS_GRANT, "typed-guest-access-change-job"
        if subject is OnboardingSubject.DEVICE:
            return QrOnboardingEffectKind.DEVICE_BINDING, "typed-device-binding-change-job"
    if operation is RuntimeOperation.REVOKE:
        return QrOnboardingEffectKind.ACCESS_REVOCATION, "typed-access-revocation-change-job"
    raise QrOnboardingEffectHandoffError("qr_effect_handoff_operation_not_effectful")


def build_qr_onboarding_effect_handoff(
    *,
    receipt: QrOnboardingOperationReceipt,
    record: QrOnboardingRuntimeRecord,
) -> QrOnboardingEffectHandoff:
    """Bind a terminal invitation receipt to the next typed effect boundary.

    The current durable record must be the exact record described by the receipt.
    This prevents a consumed/revoked receipt from being replayed against another
    Household snapshot, target, invitation or later record version.
    """

    if not isinstance(receipt, QrOnboardingOperationReceipt):
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_receipt_invalid")
    if not isinstance(record, QrOnboardingRuntimeRecord):
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_record_invalid")

    invitation = record.invitation
    exact = (
        receipt.runtime_record_id == record.runtime_record_id
        and receipt.invitation_id == invitation.invitation_id
        and receipt.household_id == invitation.household_id
        and receipt.household_snapshot_id == record.household_snapshot_id
        and receipt.household_resource_version == record.household_resource_version
        and receipt.household_generation == record.household_generation
        and receipt.target_member_id == record.target_member_id
        and receipt.invitation_evidence_sha256 == record.invitation_evidence_sha256
        and receipt.record_version == record.version
        and receipt.after_state is record.state
    )
    if not exact:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_binding_mismatch")

    if receipt.operation is RuntimeOperation.CONSUME:
        if receipt.before_state is not InvitationState.ACTIVE or record.state is not InvitationState.CONSUMED:
            raise QrOnboardingEffectHandoffError("qr_effect_handoff_consume_state_invalid")
    elif receipt.operation is RuntimeOperation.REVOKE:
        if receipt.before_state is not InvitationState.ACTIVE or record.state is not InvitationState.REVOKED:
            raise QrOnboardingEffectHandoffError("qr_effect_handoff_revoke_state_invalid")
    else:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_operation_not_effectful")

    effect_kind, required_job_type = _expected_boundary(receipt.operation, invitation.subject)
    if receipt.next_required_boundary != required_job_type:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_boundary_mismatch")

    source_receipt_sha256 = _receipt_digest(receipt)
    material = {
        "effect_kind": effect_kind.value,
        "source_operation": receipt.operation.value,
        "source_receipt_id": receipt.receipt_id,
        "source_receipt_sha256": source_receipt_sha256,
        "runtime_record_id": record.runtime_record_id,
        "invitation_id": invitation.invitation_id,
        "invitation_evidence_sha256": record.invitation_evidence_sha256,
        "household_id": invitation.household_id,
        "household_snapshot_id": record.household_snapshot_id,
        "household_resource_version": record.household_resource_version,
        "household_generation": record.household_generation,
        "target_member_id": record.target_member_id,
        "subject": invitation.subject.value,
        "device_id": invitation.device_id,
        "guest_scope": [scope.value for scope in invitation.guest_scope],
        "source_record_version": record.version,
        "required_job_type": required_job_type,
    }
    handoff_id = "hcqeh-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
    return QrOnboardingEffectHandoff(
        handoff_id=handoff_id,
        effect_kind=effect_kind,
        source_operation=receipt.operation,
        source_receipt_id=receipt.receipt_id,
        source_receipt_sha256=source_receipt_sha256,
        runtime_record_id=record.runtime_record_id,
        invitation_id=invitation.invitation_id,
        invitation_evidence_sha256=record.invitation_evidence_sha256,
        household_id=invitation.household_id,
        household_snapshot_id=record.household_snapshot_id,
        household_resource_version=record.household_resource_version,
        household_generation=record.household_generation,
        target_member_id=record.target_member_id,
        subject=invitation.subject,
        device_id=invitation.device_id,
        guest_scope=invitation.guest_scope,
        source_record_version=record.version,
        required_job_type=required_job_type,
    )


def qr_onboarding_effect_handoff_from_dict(value: object) -> QrOnboardingEffectHandoff:
    """Strictly reconstruct a handoff received across a storage/transport seam."""

    expected = {
        "schema",
        "handoff_id",
        "effect_kind",
        "source_operation",
        "source_receipt_id",
        "source_receipt_sha256",
        "runtime_record_id",
        "invitation_id",
        "invitation_evidence_sha256",
        "household_id",
        "household_snapshot_id",
        "household_resource_version",
        "household_generation",
        "target_member_id",
        "subject",
        "device_id",
        "guest_scope",
        "source_record_version",
        "required_job_type",
        "explicit_change_job_required",
        "post_condition_verification_required",
        "effect_execution_authorized",
        "account_creation_authorized",
        "device_registration_authorized",
        "managed_state_change_authorized",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != QR_EFFECT_HANDOFF_SCHEMA:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")
    if value.get("explicit_change_job_required") is not True or value.get("post_condition_verification_required") is not True:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")
    for key in (
        "effect_execution_authorized",
        "account_creation_authorized",
        "device_registration_authorized",
        "managed_state_change_authorized",
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        if value.get(key) is not False:
            raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")

    try:
        effect_kind = QrOnboardingEffectKind(value["effect_kind"])
        source_operation = RuntimeOperation(value["source_operation"])
        subject = OnboardingSubject(value["subject"])
        guest_scope_raw = value["guest_scope"]
        if not isinstance(guest_scope_raw, list):
            raise ValueError("guest_scope")
        guest_scope = tuple(sorted((GuestScope(item) for item in guest_scope_raw), key=lambda item: item.value))
        if len(guest_scope) != len(guest_scope_raw):
            raise ValueError("guest_scope")
        household_generation = value["household_generation"]
        source_record_version = value["source_record_version"]
        if type(household_generation) is not int or household_generation < 1:
            raise ValueError("generation")
        if type(source_record_version) is not int or source_record_version < 1:
            raise ValueError("version")
        device_id_raw = value["device_id"]
        device_id = None if device_id_raw is None else _identifier_value(device_id_raw, "qr_effect_device_id_invalid")
        handoff = QrOnboardingEffectHandoff(
            handoff_id=_identifier_value(value["handoff_id"], "qr_effect_handoff_id_invalid"),
            effect_kind=effect_kind,
            source_operation=source_operation,
            source_receipt_id=_identifier_value(value["source_receipt_id"], "qr_effect_receipt_id_invalid"),
            source_receipt_sha256=value["source_receipt_sha256"],
            runtime_record_id=_identifier_value(value["runtime_record_id"], "qr_effect_runtime_record_id_invalid"),
            invitation_id=_identifier_value(value["invitation_id"], "qr_effect_invitation_id_invalid"),
            invitation_evidence_sha256=value["invitation_evidence_sha256"],
            household_id=_identifier_value(value["household_id"], "qr_effect_household_id_invalid"),
            household_snapshot_id=_identifier_value(value["household_snapshot_id"], "qr_effect_household_snapshot_id_invalid"),
            household_resource_version=_identifier_value(value["household_resource_version"], "qr_effect_household_resource_version_invalid"),
            household_generation=household_generation,
            target_member_id=_identifier_value(value["target_member_id"], "qr_effect_target_member_id_invalid"),
            subject=subject,
            device_id=device_id,
            guest_scope=guest_scope,
            source_record_version=source_record_version,
            required_job_type=value["required_job_type"],
        )
    except (KeyError, TypeError, ValueError, QrOnboardingRuntimeError, QrOnboardingEffectHandoffError) as exc:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected") from exc

    if len(handoff.source_receipt_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in handoff.source_receipt_sha256):
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")
    if len(handoff.invitation_evidence_sha256) != 64 or any(
        ch not in "0123456789abcdef" for ch in handoff.invitation_evidence_sha256
    ):
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")

    expected_kind, expected_job = _expected_boundary(handoff.source_operation, handoff.subject)
    if handoff.effect_kind is not expected_kind or handoff.required_job_type != expected_job:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")
    if handoff.subject is OnboardingSubject.GUEST:
        if handoff.device_id is not None or not handoff.guest_scope:
            raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")
    elif handoff.device_id is None or handoff.guest_scope:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")

    material = {
        "effect_kind": handoff.effect_kind.value,
        "source_operation": handoff.source_operation.value,
        "source_receipt_id": handoff.source_receipt_id,
        "source_receipt_sha256": handoff.source_receipt_sha256,
        "runtime_record_id": handoff.runtime_record_id,
        "invitation_id": handoff.invitation_id,
        "invitation_evidence_sha256": handoff.invitation_evidence_sha256,
        "household_id": handoff.household_id,
        "household_snapshot_id": handoff.household_snapshot_id,
        "household_resource_version": handoff.household_resource_version,
        "household_generation": handoff.household_generation,
        "target_member_id": handoff.target_member_id,
        "subject": handoff.subject.value,
        "device_id": handoff.device_id,
        "guest_scope": [scope.value for scope in handoff.guest_scope],
        "source_record_version": handoff.source_record_version,
        "required_job_type": handoff.required_job_type,
    }
    expected_id = "hcqeh-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
    if handoff.handoff_id != expected_id or handoff.to_dict() != value:
        raise QrOnboardingEffectHandoffError("qr_effect_handoff_rejected")
    return handoff
