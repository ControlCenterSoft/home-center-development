"""Fail-closed typed QR onboarding effect execution for Home Center 0.63.

This boundary starts only from an already durable QR effect admission Job. It may
invoke one explicitly registered typed effect adapter exactly once, but success is
not declared from command acceptance. The Job reaches ``succeeded`` only after an
authoritative read-back proves the exact expected post-condition.

No generic provider, infrastructure or external-publication authority is granted.
An interrupted/ambiguous execution is never automatically repeated.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Protocol

from .household_store import HouseholdSnapshot
from .qr_onboarding_effect_admission import QrOnboardingEffectAdmission
from .qr_onboarding_effect_handoff import QrOnboardingEffectHandoff
from .qr_onboarding_effect_verification import (
    QrOnboardingPostCondition,
    build_qr_onboarding_effect_verification_request,
    validate_verification_request_against_handoff,
)
from .store import StateStore
from .util import canonical_json

EXECUTION_REQUEST_SCHEMA = "home-center.qr-onboarding-effect-execution-request.v1"
EXECUTION_RECEIPT_SCHEMA = "home-center.qr-onboarding-effect-execution-receipt.v1"
OBSERVATION_SCHEMA = "home-center.qr-onboarding-effect-observation.v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class QrOnboardingEffectExecutionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectExecutionRequest:
    request_id: str
    job_id: str
    handoff_id: str
    handoff_sha256: str
    required_job_type: str
    household_id: str
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    target_member_id: str
    device_id: str | None
    expected_post_condition: QrOnboardingPostCondition
    schema: str = field(default=EXECUTION_REQUEST_SCHEMA, init=False)
    typed_effect_execution_authorized: bool = field(default=True, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "job_id": self.job_id,
            "handoff_id": self.handoff_id,
            "handoff_sha256": self.handoff_sha256,
            "required_job_type": self.required_job_type,
            "household_id": self.household_id,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "target_member_id": self.target_member_id,
            "device_id": self.device_id,
            "expected_post_condition": self.expected_post_condition.value,
            "typed_effect_execution_authorized": True,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectExecutionReceipt:
    request_id: str
    operation_id: str
    accepted: bool
    schema: str = field(default=EXECUTION_RECEIPT_SCHEMA, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    effect_success_claimed: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "operation_id": self.operation_id,
            "accepted": self.accepted,
            "post_condition_verified": False,
            "effect_success_claimed": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class QrOnboardingEffectObservation:
    request_id: str
    operation_id: str
    observed_post_condition: QrOnboardingPostCondition
    post_condition_verified: bool
    evidence_sha256: str
    schema: str = field(default=OBSERVATION_SCHEMA, init=False)
    effect_success_claimed: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "operation_id": self.operation_id,
            "observed_post_condition": self.observed_post_condition.value,
            "post_condition_verified": self.post_condition_verified,
            "evidence_sha256": self.evidence_sha256,
            "effect_success_claimed": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


class QrOnboardingEffectAdapter(Protocol):
    """Deliberately registered typed product-effect adapter."""

    def execute(self, request: QrOnboardingEffectExecutionRequest) -> QrOnboardingEffectExecutionReceipt: ...

    def observe(self, request: QrOnboardingEffectExecutionRequest) -> QrOnboardingEffectObservation: ...


def _handoff_sha256(handoff: QrOnboardingEffectHandoff) -> str:
    return hashlib.sha256(canonical_json(handoff.to_dict()).encode("utf-8")).hexdigest()


def _execution_request(
    admission: QrOnboardingEffectAdmission,
    handoff: QrOnboardingEffectHandoff,
) -> QrOnboardingEffectExecutionRequest:
    verification = build_qr_onboarding_effect_verification_request(
        handoff=handoff,
        effect_job_id=admission.job_id,
    )
    validate_verification_request_against_handoff(verification, handoff)
    material = {
        "job_id": admission.job_id,
        "handoff_id": handoff.handoff_id,
        "handoff_sha256": verification.handoff_sha256,
        "required_job_type": handoff.required_job_type,
        "household_id": handoff.household_id,
        "household_snapshot_id": handoff.household_snapshot_id,
        "household_resource_version": handoff.household_resource_version,
        "household_generation": handoff.household_generation,
        "target_member_id": handoff.target_member_id,
        "device_id": handoff.device_id,
        "expected_post_condition": verification.expected_post_condition.value,
    }
    request_id = "hcqex-" + hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()[:24]
    return QrOnboardingEffectExecutionRequest(
        request_id=request_id,
        job_id=admission.job_id,
        handoff_id=handoff.handoff_id,
        handoff_sha256=verification.handoff_sha256,
        required_job_type=handoff.required_job_type,
        household_id=handoff.household_id,
        household_snapshot_id=handoff.household_snapshot_id,
        household_resource_version=handoff.household_resource_version,
        household_generation=handoff.household_generation,
        target_member_id=handoff.target_member_id,
        device_id=handoff.device_id,
        expected_post_condition=verification.expected_post_condition,
    )


def _validate_binding(
    admission: QrOnboardingEffectAdmission,
    handoff: QrOnboardingEffectHandoff,
    snapshot: HouseholdSnapshot,
) -> None:
    if not isinstance(admission, QrOnboardingEffectAdmission):
        raise QrOnboardingEffectExecutionError("qr_effect_execution_admission_invalid")
    if not isinstance(handoff, QrOnboardingEffectHandoff):
        raise QrOnboardingEffectExecutionError("qr_effect_execution_handoff_invalid")
    if not isinstance(snapshot, HouseholdSnapshot):
        raise QrOnboardingEffectExecutionError("qr_effect_execution_snapshot_invalid")
    if (
        admission.handoff_id != handoff.handoff_id
        or admission.required_job_type != handoff.required_job_type
        or admission.household_id != handoff.household_id
        or admission.household_snapshot_id != handoff.household_snapshot_id
        or admission.household_resource_version != handoff.household_resource_version
        or admission.household_generation != handoff.household_generation
        or admission.target_member_id != handoff.target_member_id
        or admission.device_id != handoff.device_id
    ):
        raise QrOnboardingEffectExecutionError("qr_effect_execution_binding_mismatch")
    if (
        snapshot.household_id != handoff.household_id
        or snapshot.snapshot_id != handoff.household_snapshot_id
        or snapshot.resource_version != handoff.household_resource_version
        or snapshot.generation != handoff.household_generation
    ):
        raise QrOnboardingEffectExecutionError("qr_effect_execution_household_state_stale")


def _validate_receipt(
    request: QrOnboardingEffectExecutionRequest,
    receipt: object,
) -> QrOnboardingEffectExecutionReceipt:
    if not isinstance(receipt, QrOnboardingEffectExecutionReceipt):
        raise QrOnboardingEffectExecutionError("qr_effect_execution_receipt_invalid")
    if receipt.request_id != request.request_id or _ID.fullmatch(receipt.operation_id) is None or not receipt.accepted:
        raise QrOnboardingEffectExecutionError("qr_effect_execution_receipt_invalid")
    return receipt


def _validate_observation(
    request: QrOnboardingEffectExecutionRequest,
    receipt: QrOnboardingEffectExecutionReceipt,
    observation: object,
) -> QrOnboardingEffectObservation:
    if not isinstance(observation, QrOnboardingEffectObservation):
        raise QrOnboardingEffectExecutionError("qr_effect_observation_invalid")
    if (
        observation.request_id != request.request_id
        or observation.operation_id != receipt.operation_id
        or observation.observed_post_condition is not request.expected_post_condition
        or _SHA256.fullmatch(observation.evidence_sha256) is None
    ):
        raise QrOnboardingEffectExecutionError("qr_effect_observation_invalid")
    return observation


class QrOnboardingEffectExecutionService:
    """Execute one exact typed effect and require authoritative positive read-back."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._adapters: dict[str, QrOnboardingEffectAdapter] = {}

    def register(self, required_job_type: str, adapter: QrOnboardingEffectAdapter) -> None:
        if not isinstance(required_job_type, str) or _ID.fullmatch(required_job_type) is None:
            raise QrOnboardingEffectExecutionError("qr_effect_adapter_job_type_invalid")
        if required_job_type in self._adapters:
            raise QrOnboardingEffectExecutionError("qr_effect_adapter_already_registered")
        if not callable(getattr(adapter, "execute", None)) or not callable(getattr(adapter, "observe", None)):
            raise QrOnboardingEffectExecutionError("qr_effect_adapter_invalid")
        self._adapters[required_job_type] = adapter

    def execute_and_verify(
        self,
        *,
        actor: str,
        correlation_id: str,
        admission: QrOnboardingEffectAdmission,
        handoff: QrOnboardingEffectHandoff,
        current_snapshot: HouseholdSnapshot,
    ) -> dict[str, object]:
        if not isinstance(actor, str) or not actor or not isinstance(correlation_id, str) or not correlation_id:
            raise QrOnboardingEffectExecutionError("qr_effect_execution_actor_or_correlation_invalid")
        _validate_binding(admission, handoff, current_snapshot)
        request = _execution_request(admission, handoff)
        job = self.store.job(admission.job_id)
        if job is None or job.get("job_type") != handoff.required_job_type:
            raise QrOnboardingEffectExecutionError("qr_effect_execution_job_missing")
        if job.get("state") != "preflight":
            # Running means execution may already have escaped the process. Never repeat it.
            if job.get("state") == "running":
                raise QrOnboardingEffectExecutionError("qr_effect_execution_outcome_uncertain")
            raise QrOnboardingEffectExecutionError("qr_effect_execution_job_not_preflight")
        preflight = job.get("preflight")
        if not isinstance(preflight, dict) or preflight.get("handoff_id") != handoff.handoff_id:
            raise QrOnboardingEffectExecutionError("qr_effect_execution_job_binding_mismatch")
        adapter = self._adapters.get(handoff.required_job_type)
        if adapter is None:
            raise QrOnboardingEffectExecutionError("qr_effect_adapter_unavailable")

        running_steps = [
            {"step": "handoff-revalidate", "state": "succeeded"},
            {"step": "typed-effect-execute", "state": "running"},
            {"step": "authoritative-readback", "state": "pending"},
            {"step": "post-condition-verify", "state": "pending"},
        ]
        self.store.transition_action_job(
            admission.job_id,
            expected_state="preflight",
            new_state="running",
            steps=running_steps,
        )
        try:
            receipt = _validate_receipt(request, adapter.execute(request))
        except Exception as exc:
            failed_steps = [*running_steps]
            failed_steps[1] = {"step": "typed-effect-execute", "state": "failed-uncertain"}
            self.store.transition_action_job(
                admission.job_id,
                expected_state="running",
                new_state="failed",
                evidence={
                    "schema": "home-center.qr-onboarding-effect-uncertain.v1",
                    "request_id": request.request_id,
                    "handoff_id": handoff.handoff_id,
                    "outcome_uncertain": True,
                    "automatic_retry_authorized": False,
                    "post_condition_verified": False,
                    "effect_success_claimed": False,
                },
                steps=failed_steps,
            )
            self.store.audit(
                actor=actor,
                action="household.qr-onboarding.effect.execute",
                target=handoff.target_member_id,
                outcome="uncertain",
                correlation_id=correlation_id,
                details={"job_id": admission.job_id, "automatic_retry_authorized": False},
            )
            if isinstance(exc, QrOnboardingEffectExecutionError):
                raise
            raise QrOnboardingEffectExecutionError("qr_effect_execution_outcome_uncertain") from exc

        verifying_steps = [
            {"step": "handoff-revalidate", "state": "succeeded"},
            {"step": "typed-effect-execute", "state": "accepted"},
            {"step": "authoritative-readback", "state": "running"},
            {"step": "post-condition-verify", "state": "pending"},
        ]
        self.store.transition_action_job(
            admission.job_id,
            expected_state="running",
            new_state="verifying",
            result=receipt.to_dict(),
            steps=verifying_steps,
        )
        return self._verify(
            actor=actor,
            correlation_id=correlation_id,
            request=request,
            receipt=receipt,
            handoff=handoff,
            adapter=adapter,
        )

    def reconcile_verifying(
        self,
        *,
        actor: str,
        correlation_id: str,
        admission: QrOnboardingEffectAdmission,
        handoff: QrOnboardingEffectHandoff,
        current_snapshot: HouseholdSnapshot,
    ) -> dict[str, object]:
        """Resume read-back only; never repeat a typed effect execution."""
        _validate_binding(admission, handoff, current_snapshot)
        request = _execution_request(admission, handoff)
        job = self.store.job(admission.job_id)
        if job is None or job.get("state") != "verifying":
            raise QrOnboardingEffectExecutionError("qr_effect_reconciliation_job_not_verifying")
        result = job.get("result")
        if not isinstance(result, dict):
            raise QrOnboardingEffectExecutionError("qr_effect_reconciliation_receipt_missing")
        try:
            receipt = QrOnboardingEffectExecutionReceipt(
                request_id=result["request_id"],
                operation_id=result["operation_id"],
                accepted=result["accepted"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise QrOnboardingEffectExecutionError("qr_effect_reconciliation_receipt_invalid") from exc
        if receipt.to_dict() != result:
            raise QrOnboardingEffectExecutionError("qr_effect_reconciliation_receipt_invalid")
        _validate_receipt(request, receipt)
        adapter = self._adapters.get(handoff.required_job_type)
        if adapter is None:
            raise QrOnboardingEffectExecutionError("qr_effect_adapter_unavailable")
        return self._verify(
            actor=actor,
            correlation_id=correlation_id,
            request=request,
            receipt=receipt,
            handoff=handoff,
            adapter=adapter,
        )

    def _verify(
        self,
        *,
        actor: str,
        correlation_id: str,
        request: QrOnboardingEffectExecutionRequest,
        receipt: QrOnboardingEffectExecutionReceipt,
        handoff: QrOnboardingEffectHandoff,
        adapter: QrOnboardingEffectAdapter,
    ) -> dict[str, object]:
        try:
            observation = _validate_observation(request, receipt, adapter.observe(request))
        except Exception as exc:
            observation = None
            verify_error = exc
        else:
            verify_error = None

        if observation is None or not observation.post_condition_verified:
            evidence = (
                observation.to_dict()
                if observation is not None
                else {
                    "schema": "home-center.qr-onboarding-effect-observation-error.v1",
                    "request_id": request.request_id,
                    "post_condition_verified": False,
                    "effect_success_claimed": False,
                }
            )
            failed_steps = [
                {"step": "handoff-revalidate", "state": "succeeded"},
                {"step": "typed-effect-execute", "state": "accepted"},
                {"step": "authoritative-readback", "state": "failed" if observation is None else "succeeded"},
                {"step": "post-condition-verify", "state": "failed"},
            ]
            self.store.transition_action_job(
                request.job_id,
                expected_state="verifying",
                new_state="failed",
                evidence=evidence,
                steps=failed_steps,
            )
            self.store.audit(
                actor=actor,
                action="household.qr-onboarding.effect.verify",
                target=handoff.target_member_id,
                outcome="failed",
                correlation_id=correlation_id,
                details={"job_id": request.job_id, "post_condition_verified": False},
            )
            if isinstance(verify_error, QrOnboardingEffectExecutionError):
                raise verify_error
            raise QrOnboardingEffectExecutionError("qr_effect_post_condition_not_verified") from verify_error

        succeeded_steps = [
            {"step": "handoff-revalidate", "state": "succeeded"},
            {"step": "typed-effect-execute", "state": "accepted"},
            {"step": "authoritative-readback", "state": "succeeded"},
            {"step": "post-condition-verify", "state": "succeeded"},
        ]
        job = self.store.transition_action_job(
            request.job_id,
            expected_state="verifying",
            new_state="succeeded",
            evidence=observation.to_dict(),
            steps=succeeded_steps,
        )
        self.store.audit(
            actor=actor,
            action="household.qr-onboarding.effect.verify",
            target=handoff.target_member_id,
            outcome="verified",
            correlation_id=correlation_id,
            details={
                "job_id": request.job_id,
                "post_condition_verified": True,
                "evidence_sha256": observation.evidence_sha256,
            },
        )
        return job
