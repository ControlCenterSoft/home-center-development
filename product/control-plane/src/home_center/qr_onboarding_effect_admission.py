"""Durable non-executing QR effect Job admission for Home Center 0.63.

This boundary converts an exact verified QR effect handoff into a durable typed
Job only after revalidating the current Household snapshot. Admission itself does
not execute the effect and never claims post-condition success.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .household import HouseholdRole
from .household_store import HouseholdSnapshot
from .qr_onboarding import OnboardingSubject
from .qr_onboarding_effect_handoff import QrOnboardingEffectHandoff, QrOnboardingEffectKind
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

QR_EFFECT_ADMISSION_SCHEMA = "home-center.qr-onboarding-effect-admission.v1"
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class QrOnboardingEffectAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectAdmission:
    job_id: str
    handoff_id: str
    required_job_type: str
    household_id: str
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    target_member_id: str
    device_id: str | None
    state: str = field(default="preflight", init=False)
    schema: str = field(default=QR_EFFECT_ADMISSION_SCHEMA, init=False)
    execution_authorized: bool = field(default=False, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    effect_success_claimed: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "handoff_id": self.handoff_id,
            "required_job_type": self.required_job_type,
            "household_id": self.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "device_id": self.device_id,
            "state": "preflight",
            "execution_authorized": False,
            "post_condition_verified": False,
            "effect_success_claimed": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _handoff_sha256(handoff: QrOnboardingEffectHandoff) -> str:
    return hashlib.sha256(canonical_json(handoff.to_dict()).encode("utf-8")).hexdigest()


def _revalidate_snapshot(handoff: QrOnboardingEffectHandoff, snapshot: HouseholdSnapshot) -> None:
    if not isinstance(handoff, QrOnboardingEffectHandoff):
        raise QrOnboardingEffectAdmissionError("qr_effect_admission_handoff_invalid")
    if not isinstance(snapshot, HouseholdSnapshot):
        raise QrOnboardingEffectAdmissionError("qr_effect_admission_snapshot_invalid")
    if (
        snapshot.household_id != handoff.household_id
        or snapshot.snapshot_id != handoff.household_snapshot_id
        or snapshot.resource_version != handoff.household_resource_version
        or snapshot.generation != handoff.household_generation
    ):
        raise QrOnboardingEffectAdmissionError("qr_effect_admission_household_state_stale")

    try:
        member = snapshot.household.member(handoff.target_member_id)
    except Exception as exc:
        raise QrOnboardingEffectAdmissionError("qr_effect_admission_target_member_missing") from exc
    if not member.enabled:
        raise QrOnboardingEffectAdmissionError("qr_effect_admission_target_member_disabled")

    if handoff.effect_kind is QrOnboardingEffectKind.GUEST_ACCESS_GRANT:
        if handoff.subject is not OnboardingSubject.GUEST or member.role is not HouseholdRole.GUEST:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_guest_target_mismatch")
        if handoff.device_id is not None or not handoff.guest_scope:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_guest_scope_invalid")
    elif handoff.effect_kind is QrOnboardingEffectKind.DEVICE_BINDING:
        if handoff.subject is not OnboardingSubject.DEVICE or not isinstance(handoff.device_id, str):
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_device_target_invalid")
        device = next((item for item in snapshot.household.devices if item.device_id == handoff.device_id), None)
        if device is None or device.member_id != handoff.target_member_id:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_device_binding_stale")
    elif handoff.effect_kind is QrOnboardingEffectKind.ACCESS_REVOCATION:
        if handoff.subject is OnboardingSubject.DEVICE:
            if not isinstance(handoff.device_id, str):
                raise QrOnboardingEffectAdmissionError("qr_effect_admission_device_target_invalid")
            device = next((item for item in snapshot.household.devices if item.device_id == handoff.device_id), None)
            if device is None or device.member_id != handoff.target_member_id:
                raise QrOnboardingEffectAdmissionError("qr_effect_admission_device_binding_stale")
    else:
        raise QrOnboardingEffectAdmissionError("qr_effect_admission_effect_kind_invalid")


class QrOnboardingEffectAdmissionService:
    def __init__(self, store: StateStore) -> None:
        self.store = store

    def admit(
        self,
        *,
        actor: str,
        correlation_id: str,
        handoff: QrOnboardingEffectHandoff,
        current_snapshot: HouseholdSnapshot,
        idempotency_key: str,
    ) -> QrOnboardingEffectAdmission:
        if not isinstance(actor, str) or not actor or not isinstance(correlation_id, str) or not correlation_id:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_actor_or_correlation_invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_idempotency_key_invalid")
        _revalidate_snapshot(handoff, current_snapshot)
        handoff_sha256 = _handoff_sha256(handoff)
        request_hash = hashlib.sha256(
            canonical_json(
                {
                    "handoff_id": handoff.handoff_id,
                    "handoff_sha256": handoff_sha256,
                    "required_job_type": handoff.required_job_type,
                    "household_snapshot_id": current_snapshot.snapshot_id,
                    "household_resource_version": current_snapshot.resource_version,
                    "household_generation": current_snapshot.generation,
                }
            ).encode("utf-8")
        ).hexdigest()
        preflight = {
            "schema": "home-center.qr-onboarding-effect-admission-preflight.v1",
            "handoff_id": handoff.handoff_id,
            "handoff_sha256": handoff_sha256,
            "effect_kind": handoff.effect_kind.value,
            "required_job_type": handoff.required_job_type,
            "household_id": handoff.household_id,
            "household_snapshot_id": current_snapshot.snapshot_id,
            "household_resource_version": current_snapshot.resource_version,
            "household_generation": current_snapshot.generation,
            "target_member_id": handoff.target_member_id,
            "device_id": handoff.device_id,
            "execution_authorized": False,
            "post_condition_verification_required": True,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
        try:
            job, _created = self.store.create_action_job(
                action_id=handoff.required_job_type,
                actor=actor,
                reason="explicit QR onboarding effect handoff admission",
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                preflight=preflight,
                steps=[
                    {"step": "handoff-revalidate", "state": "succeeded"},
                    {"step": "typed-effect-execute", "state": "pending"},
                    {"step": "authoritative-readback", "state": "pending"},
                    {"step": "post-condition-verify", "state": "pending"},
                ],
            )
        except IdempotencyConflict as exc:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_idempotency_conflict") from exc

        if job.get("state") != "preflight" or job.get("job_type") != handoff.required_job_type:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_job_state_invalid")
        persisted = job.get("preflight")
        if not isinstance(persisted, dict) or persisted != preflight:
            raise QrOnboardingEffectAdmissionError("qr_effect_admission_persistence_mismatch")

        receipt = QrOnboardingEffectAdmission(
            job_id=job["job_id"],
            handoff_id=handoff.handoff_id,
            required_job_type=handoff.required_job_type,
            household_id=handoff.household_id,
            household_snapshot_id=current_snapshot.snapshot_id,
            household_resource_version=current_snapshot.resource_version,
            household_generation=current_snapshot.generation,
            target_member_id=handoff.target_member_id,
            device_id=handoff.device_id,
        )
        self.store.audit(
            actor=actor,
            action="household.qr-onboarding.effect.admit",
            target=handoff.target_member_id,
            outcome="admitted",
            correlation_id=correlation_id,
            details={
                "job_id": receipt.job_id,
                "handoff_id": handoff.handoff_id,
                "required_job_type": handoff.required_job_type,
                "execution_authorized": False,
                "post_condition_verified": False,
                "effect_success_claimed": False,
                "provider_execution_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )
        return receipt
