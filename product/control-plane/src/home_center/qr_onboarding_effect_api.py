"""Authenticated transport-neutral QR effect apply boundary for Home Center 0.63.

The client supplies only an invitation identity, an explicit confirmation and an
idempotency key. Effect kind, target, scope and Job type are always reconstructed
from durable server-side QR state. The boundary admits one typed durable Job and
hands it to the restart-safe worker; it never accepts client-selected execution
or provider/infrastructure authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .household_store import HouseholdSnapshot
from .qr_onboarding_effect_admission import (
    QrOnboardingEffectAdmissionError,
    QrOnboardingEffectAdmissionService,
)
from .qr_onboarding_effect_execution import QrOnboardingEffectExecutionError
from .qr_onboarding_effect_source import QrOnboardingEffectSourceError, QrOnboardingEffectSourceService
from .qr_onboarding_effect_worker import QrOnboardingEffectWorkerError, QrOnboardingEffectWorkerService

QR_EFFECT_APPLY_REQUEST_SCHEMA = "home-center.qr-onboarding-effect-apply-request.v1"
QR_EFFECT_APPLY_RESULT_SCHEMA = "home-center.qr-onboarding-effect-apply-result.v1"
_INVITATION_ID = re.compile(r"hcqri-[0-9a-f]{24}\Z")
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9._:-]{8,128}\Z")


class QrOnboardingEffectApiError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectApplyRequest:
    invitation_id: str
    idempotency_key: str
    confirmed: bool = True


def parse_qr_effect_apply_request(value: object) -> QrOnboardingEffectApplyRequest:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "invitation_id", "confirmed", "idempotency_key"}
        or value.get("schema") != QR_EFFECT_APPLY_REQUEST_SCHEMA
    ):
        raise QrOnboardingEffectApiError("qr_effect_api_request_rejected")
    invitation_id = value.get("invitation_id")
    if not isinstance(invitation_id, str) or _INVITATION_ID.fullmatch(invitation_id) is None:
        raise QrOnboardingEffectApiError("qr_effect_api_invitation_id_invalid")
    if value.get("confirmed") is not True:
        raise QrOnboardingEffectApiError("qr_effect_api_confirmation_required")
    idempotency_key = value.get("idempotency_key")
    if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
        raise QrOnboardingEffectApiError("qr_effect_api_idempotency_key_invalid")
    return QrOnboardingEffectApplyRequest(
        invitation_id=invitation_id,
        idempotency_key=idempotency_key,
    )


class QrOnboardingEffectApiService:
    """Resolve durable QR evidence, admit a typed Job and run the safe worker."""

    def __init__(
        self,
        source: QrOnboardingEffectSourceService,
        admission: QrOnboardingEffectAdmissionService,
        worker: QrOnboardingEffectWorkerService,
    ) -> None:
        if not isinstance(source, QrOnboardingEffectSourceService):
            raise QrOnboardingEffectApiError("qr_effect_api_source_invalid")
        if not isinstance(admission, QrOnboardingEffectAdmissionService):
            raise QrOnboardingEffectApiError("qr_effect_api_admission_invalid")
        if not isinstance(worker, QrOnboardingEffectWorkerService):
            raise QrOnboardingEffectApiError("qr_effect_api_worker_invalid")
        if admission.store is not worker.store:
            raise QrOnboardingEffectApiError("qr_effect_api_store_mismatch")
        self.source = source
        self.admission = admission
        self.worker = worker

    def apply(
        self,
        *,
        snapshot: HouseholdSnapshot,
        actor: str,
        correlation_id: str,
        body: object,
        now_epoch: int,
    ) -> dict[str, object]:
        request = parse_qr_effect_apply_request(body)
        if not isinstance(actor, str) or not actor or not isinstance(correlation_id, str) or not correlation_id:
            raise QrOnboardingEffectApiError("qr_effect_api_actor_or_correlation_invalid")
        if type(now_epoch) is not int or now_epoch < 0:
            raise QrOnboardingEffectApiError("qr_effect_api_server_time_invalid")
        try:
            handoff = self.source.recover(
                snapshot=snapshot,
                invitation_id=request.invitation_id,
                now_epoch=now_epoch,
            )
            admission = self.admission.admit(
                actor=actor,
                correlation_id=correlation_id,
                handoff=handoff,
                current_snapshot=snapshot,
                idempotency_key=request.idempotency_key,
            )
            job = self.worker.run(
                actor=actor,
                correlation_id=correlation_id,
                job_id=admission.job_id,
            )
        except (
            QrOnboardingEffectSourceError,
            QrOnboardingEffectAdmissionError,
            QrOnboardingEffectWorkerError,
            QrOnboardingEffectExecutionError,
        ) as exc:
            raise QrOnboardingEffectApiError(getattr(exc, "code", str(exc))) from exc

        evidence = job.get("evidence")
        verified = isinstance(evidence, dict) and evidence.get("post_condition_verified") is True
        state = job.get("state")
        if state != "succeeded" or not verified:
            raise QrOnboardingEffectApiError("qr_effect_api_verified_completion_missing")
        return {
            "schema": QR_EFFECT_APPLY_RESULT_SCHEMA,
            "job_id": admission.job_id,
            "required_job_type": admission.required_job_type,
            "state": "succeeded",
            "post_condition_verified": True,
            "effect_success_claimed": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
