"""Transport-neutral explicit QR effect admission/run boundary for Home Center 0.63.

The invitation consume/revoke transition and the resulting product effect are separate
operations. This API therefore requires a second explicit confirmation, reconstructs
the effect handoff from authoritative durable terminal QR state, admits one durable
typed Job, and runs only that Job through the restart-safe worker. It never accepts a
client-supplied effect handoff and never grants generic provider, infrastructure or
external-publication authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .household_store import HouseholdSnapshot
from .qr_onboarding_effect_admission import (
    QrOnboardingEffectAdmissionError,
    QrOnboardingEffectAdmissionService,
)
from .qr_onboarding_effect_execution import QrOnboardingEffectExecutionError
from .qr_onboarding_effect_source import (
    QrOnboardingEffectSourceError,
    QrOnboardingEffectSourceService,
)
from .qr_onboarding_effect_worker import (
    QrOnboardingEffectWorkerError,
    QrOnboardingEffectWorkerService,
)

ADMIT_REQUEST_SCHEMA = "home-center.qr-onboarding-effect-api-admit-request.v1"
ADMIT_RESULT_SCHEMA = "home-center.qr-onboarding-effect-api-admit-result.v1"
RUN_REQUEST_SCHEMA = "home-center.qr-onboarding-effect-api-run-request.v1"
RUN_RESULT_SCHEMA = "home-center.qr-onboarding-effect-api-run-result.v1"

_INVITATION_ID = re.compile(r"hcqri-[0-9a-f]{24}\Z")
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9._:-]{8,128}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class QrOnboardingEffectApiError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _exact_object(value: object, keys: set[str], schema: str, code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys or value.get("schema") != schema:
        raise QrOnboardingEffectApiError(code)
    return value


def _confirmed(value: object) -> None:
    if value is not True:
        raise QrOnboardingEffectApiError("qr_effect_api_confirmation_required")


def _server_epoch(value: object) -> int:
    if type(value) is not int or value < 0:
        raise QrOnboardingEffectApiError("qr_effect_api_server_time_invalid")
    return value


@dataclass(frozen=True, slots=True)
class EffectAdmitRequest:
    invitation_id: str
    idempotency_key: str
    confirmed: bool = field(default=True, init=False)


@dataclass(frozen=True, slots=True)
class EffectRunRequest:
    job_id: str
    confirmed: bool = field(default=True, init=False)


@dataclass(frozen=True, slots=True)
class EffectAdmitResult:
    job_id: str
    handoff_id: str
    required_job_type: str
    schema: str = field(default=ADMIT_RESULT_SCHEMA, init=False)
    state: str = field(default="preflight", init=False)
    execution_authorized: bool = field(default=False, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "handoff_id": self.handoff_id,
            "required_job_type": self.required_job_type,
            "state": self.state,
            "execution_authorized": False,
            "post_condition_verified": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class EffectRunResult:
    job_id: str
    required_job_type: str
    schema: str = field(default=RUN_RESULT_SCHEMA, init=False)
    state: str = field(default="succeeded", init=False)
    onboarding_effect_verified: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=True, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "required_job_type": self.required_job_type,
            "state": self.state,
            "onboarding_effect_verified": True,
            "post_condition_verified": True,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def parse_effect_admit_request(value: object) -> EffectAdmitRequest:
    raw = _exact_object(
        value,
        {"schema", "invitation_id", "idempotency_key", "confirmed"},
        ADMIT_REQUEST_SCHEMA,
        "qr_effect_api_admit_request_rejected",
    )
    invitation_id = raw["invitation_id"]
    if not isinstance(invitation_id, str) or _INVITATION_ID.fullmatch(invitation_id) is None:
        raise QrOnboardingEffectApiError("qr_effect_api_invitation_id_invalid")
    idempotency_key = raw["idempotency_key"]
    if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
        raise QrOnboardingEffectApiError("qr_effect_api_idempotency_key_invalid")
    _confirmed(raw["confirmed"])
    return EffectAdmitRequest(invitation_id=invitation_id, idempotency_key=idempotency_key)


def parse_effect_run_request(value: object) -> EffectRunRequest:
    raw = _exact_object(
        value,
        {"schema", "job_id", "confirmed"},
        RUN_REQUEST_SCHEMA,
        "qr_effect_api_run_request_rejected",
    )
    job_id = raw["job_id"]
    if not isinstance(job_id, str) or _JOB_ID.fullmatch(job_id) is None:
        raise QrOnboardingEffectApiError("qr_effect_api_job_id_invalid")
    _confirmed(raw["confirmed"])
    return EffectRunRequest(job_id=job_id)


class QrOnboardingEffectApiService:
    """Explicitly admit and run an effect sourced only from authoritative terminal QR state."""

    def __init__(
        self,
        source: QrOnboardingEffectSourceService,
        admissions: QrOnboardingEffectAdmissionService,
        worker: QrOnboardingEffectWorkerService,
    ) -> None:
        if not isinstance(source, QrOnboardingEffectSourceService):
            raise QrOnboardingEffectApiError("qr_effect_api_source_invalid")
        if not isinstance(admissions, QrOnboardingEffectAdmissionService):
            raise QrOnboardingEffectApiError("qr_effect_api_admission_invalid")
        if not isinstance(worker, QrOnboardingEffectWorkerService):
            raise QrOnboardingEffectApiError("qr_effect_api_worker_invalid")
        self.source = source
        self.admissions = admissions
        self.worker = worker

    def admit(
        self,
        *,
        snapshot: HouseholdSnapshot,
        actor: str,
        correlation_id: str,
        body: object,
        now_epoch: int,
    ) -> EffectAdmitResult:
        request = parse_effect_admit_request(body)
        now = _server_epoch(now_epoch)
        try:
            handoff = self.source.recover(
                snapshot=snapshot,
                invitation_id=request.invitation_id,
                now_epoch=now,
            )
            admission = self.admissions.admit(
                actor=actor,
                correlation_id=correlation_id,
                handoff=handoff,
                current_snapshot=snapshot,
                idempotency_key=request.idempotency_key,
            )
        except (QrOnboardingEffectSourceError, QrOnboardingEffectAdmissionError) as exc:
            raise QrOnboardingEffectApiError(exc.code) from exc
        return EffectAdmitResult(
            job_id=admission.job_id,
            handoff_id=admission.handoff_id,
            required_job_type=admission.required_job_type,
        )

    def run(
        self,
        *,
        actor: str,
        correlation_id: str,
        body: object,
    ) -> EffectRunResult:
        request = parse_effect_run_request(body)
        try:
            job = self.worker.run(
                actor=actor,
                correlation_id=correlation_id,
                job_id=request.job_id,
            )
        except (QrOnboardingEffectWorkerError, QrOnboardingEffectExecutionError) as exc:
            code = getattr(exc, "code", str(exc))
            raise QrOnboardingEffectApiError(code) from exc
        evidence = job.get("evidence")
        required_job_type = job.get("job_type")
        if (
            job.get("state") != "succeeded"
            or not isinstance(required_job_type, str)
            or _JOB_ID.fullmatch(required_job_type) is None
            or not isinstance(evidence, dict)
            or evidence.get("post_condition_verified") is not True
        ):
            raise QrOnboardingEffectApiError("qr_effect_api_verified_result_invalid")
        return EffectRunResult(job_id=request.job_id, required_job_type=required_job_type)


__all__ = [
    "ADMIT_REQUEST_SCHEMA",
    "ADMIT_RESULT_SCHEMA",
    "RUN_REQUEST_SCHEMA",
    "RUN_RESULT_SCHEMA",
    "EffectAdmitRequest",
    "EffectAdmitResult",
    "EffectRunRequest",
    "EffectRunResult",
    "QrOnboardingEffectApiError",
    "QrOnboardingEffectApiService",
    "parse_effect_admit_request",
    "parse_effect_run_request",
]
