"""Durable post-cleanup read-back for Home Center 0.58.

Provider acceptance of a de-enrollment command is not cleanup success.  This
runtime performs a separate read-only provider observation after a durable
provider-cleanup acceptance and decides only whether a *new enrollment plan* may
be considered.  It never starts enrollment, never mutates the provider, never
sets ``managed=True`` and never applies policy.

The read-back adapter is explicitly read-only, so a ``running`` Job may safely
repeat the exact observation after restart.  A persisted ``verifying`` Job is
finalized from the stored observation without contacting the provider again.
"""
from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .device_management_enrollment_cleanup import (
    DeviceManagementEnrollmentCleanupError,
    assess_retry_after_cleanup,
    build_failed_enrollment_cleanup_plan,
)
from .device_management_enrollment_deenrollment import (
    DEENROLLMENT_RECEIPT_SCHEMA,
    DeviceManagementEnrollmentDeenrollmentError,
    build_deenrollment_plan,
)
from .device_management_enrollment_deenrollment_runtime import (
    DEENROLLMENT_ACTION,
    DEENROLLMENT_KEY_PREFIX,
    DEENROLLMENT_RUNTIME_STATE_SCHEMA,
)
from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationAdapter,
    DeviceManagementEnrollmentVerificationError,
    DeviceManagementEnrollmentVerificationRequest,
    evaluate_verification_result,
    verification_result_from_dict,
)
from .device_management_enrollment_verification_persistence import (
    verification_evidence_from_dict,
)
from .device_management_enrollment_verification_runtime import (
    VERIFY_ACTION,
    VERIFY_KEY_PREFIX,
    VERIFY_STATE_SCHEMA,
)
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json


CLEANUP_VERIFY_REQUEST_SCHEMA = (
    "home-center.device-management-enrollment-cleanup-verification-runtime-request.v1"
)
CLEANUP_VERIFY_RECEIPT_SCHEMA = (
    "home-center.device-management-enrollment-cleanup-verification-runtime-receipt.v1"
)
CLEANUP_VERIFY_ACTION = "household.device.management.enrollment.cleanup.verify"
CLEANUP_VERIFY_STATE_SCHEMA = (
    "home-center.device-management-enrollment-cleanup-verification-runtime-state.v1"
)
CLEANUP_VERIFY_KEY_PREFIX = "cozy.household.device-enrollment-cleanup-assessment."
CLEANUP_VERIFY_LATEST_PREFIX = "cozy.household.device-enrollment-cleanup-latest."
DEENROLLMENT_ID = re.compile(r"^dmpdeenroll-[0-9a-f]{24}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class DeviceManagementEnrollmentCleanupVerificationRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class DeviceManagementEnrollmentCleanupVerificationRuntimeService:
    """Read back provider state after explicit de-enrollment acceptance."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()
        self._adapters: dict[str, DeviceManagementEnrollmentVerificationAdapter] = {}

    def register_adapter(
        self,
        provider_id: str,
        adapter: DeviceManagementEnrollmentVerificationAdapter,
    ) -> None:
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or len(provider_id) > 128
            or provider_id in self._adapters
            or not callable(getattr(adapter, "verify", None))
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "invalid_device_management_enrollment_cleanup_verification_adapter_registration"
            )
        self._adapters[provider_id] = adapter

    def _adapter(self, provider_id: str) -> DeviceManagementEnrollmentVerificationAdapter:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_adapter_unavailable"
            )
        return adapter

    def _deenrollment(self, de_enrollment_id: str, *, actor: str):
        envelope = self.store.get_meta(DEENROLLMENT_KEY_PREFIX + de_enrollment_id)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != DEENROLLMENT_RUNTIME_STATE_SCHEMA
            or envelope.get("status") != "provider-cleanup-accepted"
            or envelope.get("de_enrollment_id") != de_enrollment_id
            or not isinstance(envelope.get("job_id"), str)
            or not isinstance(envelope.get("plan"), dict)
            or not isinstance(envelope.get("receipt"), dict)
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_deenrollment_receipt_not_found"
            )
        job = self.store.job(envelope["job_id"])
        receipt = envelope["receipt"]
        plan = envelope["plan"]
        evidence = job.get("evidence") if isinstance(job, dict) else None
        if (
            not isinstance(job, dict)
            or job.get("job_type") != DEENROLLMENT_ACTION
            or job.get("state") != "succeeded"
            or job.get("initiator") != actor
            or job.get("result") != receipt
            or receipt.get("schema") != DEENROLLMENT_RECEIPT_SCHEMA
            or receipt.get("state") != "provider-cleanup-accepted"
            or receipt.get("de_enrollment_id") != de_enrollment_id
            or receipt.get("cleanup_id") != plan.get("cleanup_id")
            or receipt.get("provider_id") != plan.get("provider_id")
            or receipt.get("provider_operation_id") != plan.get("provider_operation_id")
            or receipt.get("device_id") != plan.get("device_id")
            or receipt.get("post_cleanup_verified") is not False
            or receipt.get("retry_planning_allowed") is not False
            or receipt.get("retry_execution_authorized") is not False
            or receipt.get("managed_state_change_authorized") is not False
            or not isinstance(evidence, dict)
            or evidence.get("provider_cleanup_command_accepted") is not True
            or evidence.get("post_cleanup_verified") is not False
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_deenrollment_receipt_invalid"
            )
        accepted_at = job.get("updated_at")
        if (
            not isinstance(accepted_at, str)
            or RFC3339_UTC_SECONDS.fullmatch(accepted_at) is None
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_deenrollment_receipt_invalid"
            )
        return envelope, job, plan, accepted_at

    def _original_evidence(self, verification_id: str, *, actor: str):
        envelope = self.store.get_meta(VERIFY_KEY_PREFIX + verification_id)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != VERIFY_STATE_SCHEMA
            or envelope.get("status") != "complete"
            or not isinstance(envelope.get("job_id"), str)
            or not isinstance(envelope.get("evidence"), dict)
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_verification_evidence_not_found"
            )
        job = self.store.job(envelope["job_id"])
        if (
            not isinstance(job, dict)
            or job.get("job_type") != VERIFY_ACTION
            or job.get("state") != "succeeded"
            or job.get("initiator") != actor
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_actor_mismatch"
            )
        try:
            evidence = verification_evidence_from_dict(envelope["evidence"])
            cleanup = build_failed_enrollment_cleanup_plan(evidence)
        except (
            DeviceManagementEnrollmentVerificationError,
            DeviceManagementEnrollmentCleanupError,
        ) as exc:
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                getattr(exc, "code", "device_management_enrollment_verification_evidence_invalid")
            ) from exc
        if evidence.verification_id != verification_id or cleanup.action != "de-enroll-required":
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_state_invalid"
            )
        request = DeviceManagementEnrollmentVerificationRequest(
            verification_id=evidence.verification_id,
            execution_job_id=evidence.execution_job_id,
            plan_id=evidence.plan_id,
            provider_id=evidence.provider_id,
            provider_operation_id=evidence.provider_operation_id,
            household_id=evidence.household_id,
            snapshot_id=evidence.snapshot_id,
            resource_version=evidence.resource_version,
            generation=evidence.generation,
            device_id=evidence.device_id,
            member_id=evidence.member_id,
        )
        return evidence, cleanup, request

    def _persisted_material(self, de_enrollment_id: str, *, actor: str):
        envelope, de_job, plan, accepted_at = self._deenrollment(
            de_enrollment_id,
            actor=actor,
        )
        verification_id = plan.get("verification_id")
        if not isinstance(verification_id, str):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_state_invalid"
            )
        evidence, cleanup, verification_request = self._original_evidence(
            verification_id,
            actor=actor,
        )
        if (
            cleanup.cleanup_id != plan.get("cleanup_id")
            or cleanup.provider_id != plan.get("provider_id")
            or cleanup.provider_operation_id != plan.get("provider_operation_id")
            or cleanup.device_id != plan.get("device_id")
            or cleanup.member_id != plan.get("member_id")
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_state_invalid"
            )
        return envelope, de_job, plan, accepted_at, evidence, cleanup, verification_request

    def _revalidate_current(self, *, actor: str, cleanup, stored_plan: dict[str, Any]) -> None:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "household_not_configured"
            )
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        actor_member_id = next(
            (binding.member_id for binding in bindings if binding.actor == actor),
            None,
        )
        if not isinstance(actor_member_id, str) or not actor_member_id:
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "household_actor_not_bound"
            )
        try:
            fresh_plan = build_deenrollment_plan(
                cleanup,
                current=snapshot,
                actor_member_id=actor_member_id,
            )
        except DeviceManagementEnrollmentDeenrollmentError as exc:
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(exc.code) from exc
        if fresh_plan.to_dict() != stored_plan:
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_stale"
            )

    def _fail(
        self,
        job: dict[str, Any],
        *,
        code: str,
        provider_state_unknown: bool,
    ) -> None:
        state = job.get("state")
        if state not in {"preflight", "running", "verifying"}:
            return
        current = self.store.job(job["job_id"])
        if not isinstance(current, dict) or current.get("state") != state:
            return
        self.store.transition_action_job(
            job["job_id"],
            expected_state=str(state),
            new_state="failed",
            result={
                "schema": "home-center.device-management-enrollment-cleanup-verification-failure.v1",
                "state": "failed",
                "code": code,
                "provider_state_unknown": provider_state_unknown,
                "retry_planning_allowed": False,
                "retry_execution_authorized": False,
                "provider_mutation_authorized": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )

    @staticmethod
    def _receipt(*, job_id: str, de_enrollment_id: str, assessment) -> dict[str, object]:
        return {
            "schema": CLEANUP_VERIFY_RECEIPT_SCHEMA,
            "state": "post-cleanup-assessed",
            "job_id": job_id,
            "de_enrollment_id": de_enrollment_id,
            "cleanup_id": assessment.cleanup_id,
            "verification_id": assessment.verification_id,
            "assessment_id": assessment.assessment_id,
            "provider_id": assessment.provider_id,
            "provider_operation_id": assessment.provider_operation_id,
            "device_id": assessment.device_id,
            "post_cleanup_observed_at": assessment.post_cleanup_observed_at,
            "residual_provider_state": assessment.residual_provider_state,
            "retry_planning_allowed": assessment.retry_planning_allowed,
            "reason": assessment.reason,
            "retry_execution_authorized": False,
            "provider_mutation_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def _persist_complete(
        self,
        *,
        receipt: dict[str, object],
        job: dict[str, Any],
    ) -> None:
        assessment_id = receipt.get("assessment_id")
        de_enrollment_id = receipt.get("de_enrollment_id")
        if not isinstance(assessment_id, str) or not isinstance(de_enrollment_id, str):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_state_invalid"
            )
        envelope = {
            "schema": CLEANUP_VERIFY_STATE_SCHEMA,
            "status": "complete",
            "job_id": job["job_id"],
            "receipt": receipt,
            "evidence": job.get("evidence"),
        }
        self.store.set_meta(CLEANUP_VERIFY_KEY_PREFIX + assessment_id, envelope)
        self.store.set_meta(
            CLEANUP_VERIFY_LATEST_PREFIX + de_enrollment_id,
            {
                "schema": "home-center.device-management-enrollment-cleanup-verification-latest.v1",
                "de_enrollment_id": de_enrollment_id,
                "assessment_id": assessment_id,
                "job_id": job["job_id"],
            },
        )

    def _finalize(
        self,
        *,
        actor: str,
        correlation_id: str,
        job: dict[str, Any],
        de_enrollment_id: str,
        stored_plan: dict[str, Any],
        accepted_at: str,
        cleanup,
        verification_request: DeviceManagementEnrollmentVerificationRequest,
        recovered_after_restart: bool,
    ) -> dict[str, object]:
        if job.get("state") != "verifying":
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_state_invalid"
            )
        try:
            self._revalidate_current(
                actor=actor,
                cleanup=cleanup,
                stored_plan=stored_plan,
            )
            result = verification_result_from_dict(
                job.get("result"),
                request=verification_request,
            )
            if result.observed_at <= accepted_at:
                raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                    "device_management_enrollment_cleanup_readback_not_after_deenrollment"
                )
            observation = evaluate_verification_result(
                request=verification_request,
                result=result,
            )
            assessment = assess_retry_after_cleanup(cleanup, observation)
        except DeviceManagementEnrollmentCleanupVerificationRuntimeError as exc:
            self._fail(job, code=exc.code, provider_state_unknown=False)
            raise
        except (
            DeviceManagementEnrollmentVerificationError,
            DeviceManagementEnrollmentCleanupError,
        ) as exc:
            code = getattr(
                exc,
                "code",
                "device_management_enrollment_cleanup_verification_state_invalid",
            )
            self._fail(job, code=code, provider_state_unknown=False)
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(code) from exc

        receipt = self._receipt(
            job_id=job["job_id"],
            de_enrollment_id=de_enrollment_id,
            assessment=assessment,
        )
        audit_event_id = self.store.audit(
            actor=actor,
            action=CLEANUP_VERIFY_ACTION,
            target=assessment.device_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={
                "job_id": job["job_id"],
                "de_enrollment_id": de_enrollment_id,
                "cleanup_id": assessment.cleanup_id,
                "verification_id": assessment.verification_id,
                "assessment_id": assessment.assessment_id,
                "provider_id": assessment.provider_id,
                "provider_operation_id": assessment.provider_operation_id,
                "post_cleanup_observed_at": assessment.post_cleanup_observed_at,
                "residual_provider_state": assessment.residual_provider_state,
                "retry_planning_allowed": assessment.retry_planning_allowed,
                "retry_execution_authorized": False,
                "provider_mutation_authorized": False,
                "managed_state_change_authorized": False,
                "recovered_after_restart": recovered_after_restart,
                "provider_readback_reinvoked": recovered_after_restart,
            },
        )
        done = self.store.transition_action_job(
            job["job_id"],
            expected_state="verifying",
            new_state="succeeded",
            result=receipt,
            evidence={
                "schema": "home-center.device-management-enrollment-cleanup-verification-evidence.v1",
                "audit_event_id": audit_event_id,
                "de_enrollment_id": de_enrollment_id,
                "cleanup_id": assessment.cleanup_id,
                "assessment_id": assessment.assessment_id,
                "post_cleanup_observed_at": assessment.post_cleanup_observed_at,
                "residual_provider_state": assessment.residual_provider_state,
                "retry_planning_allowed": assessment.retry_planning_allowed,
                "retry_execution_authorized": False,
                "provider_mutation_authorized": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
                "recovered_after_restart": recovered_after_restart,
            },
            steps=[
                {"step": "revalidate-cleanup-acceptance", "state": "succeeded"},
                {"step": "provider-readback", "state": "succeeded"},
                {"step": "assess-retry-planning", "state": "succeeded"},
            ],
        )
        self._persist_complete(receipt=receipt, job=done)
        return receipt

    def _resume_succeeded(self, job: dict[str, Any]) -> dict[str, object]:
        result = job.get("result")
        evidence = job.get("evidence")
        if (
            not isinstance(result, dict)
            or result.get("schema") != CLEANUP_VERIFY_RECEIPT_SCHEMA
            or result.get("state") != "post-cleanup-assessed"
            or result.get("retry_execution_authorized") is not False
            or result.get("provider_mutation_authorized") is not False
            or result.get("managed_state_change_authorized") is not False
            or result.get("policy_application_authorized") is not False
            or result.get("infrastructure_mutation_authorized") is not False
            or result.get("external_publication_authorized") is not False
            or not isinstance(evidence, dict)
            or not isinstance(evidence.get("audit_event_id"), str)
            or not evidence.get("audit_event_id")
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_state_invalid"
            )
        self._persist_complete(receipt=dict(result), job=job)
        return dict(result)

    def verify_cleanup(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        if (
            not isinstance(request, dict)
            or set(request) != {"schema", "de_enrollment_id", "idempotency_key"}
            or request.get("schema") != CLEANUP_VERIFY_REQUEST_SCHEMA
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "invalid_device_management_enrollment_cleanup_verification_request"
            )
        de_enrollment_id = request.get("de_enrollment_id")
        idempotency_key = request.get("idempotency_key")
        if (
            not isinstance(de_enrollment_id, str)
            or DEENROLLMENT_ID.fullmatch(de_enrollment_id) is None
            or not isinstance(idempotency_key, str)
            or IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "invalid_device_management_enrollment_cleanup_verification_request"
            )

        with self._lock:
            (
                _de_envelope,
                _de_job,
                stored_plan,
                accepted_at,
                _original_evidence,
                cleanup,
                verification_request,
            ) = self._persisted_material(de_enrollment_id, actor=actor)
            request_hash = _hash(
                {
                    "de_enrollment_id": de_enrollment_id,
                    "idempotency_key": idempotency_key,
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=CLEANUP_VERIFY_ACTION,
                    actor=actor,
                    reason="read back provider state after de-enrollment acceptance",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.device-management-enrollment-cleanup-verification-preflight.v1",
                        "de_enrollment_id": de_enrollment_id,
                        "cleanup_id": cleanup.cleanup_id,
                        "verification_id": cleanup.verification_id,
                        "provider_id": cleanup.provider_id,
                        "provider_operation_id": cleanup.provider_operation_id,
                        "device_id": cleanup.device_id,
                        "de_enrollment_accepted_at": accepted_at,
                        "provider_readback_authorized": True,
                        "retry_planning_allowed": False,
                        "retry_execution_authorized": False,
                        "provider_mutation_authorized": False,
                        "managed_state_change_authorized": False,
                        "policy_application_authorized": False,
                        "infrastructure_mutation_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-cleanup-acceptance", "state": "pending"},
                        {"step": "provider-readback", "state": "pending"},
                        {"step": "assess-retry-planning", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                    "device_management_enrollment_cleanup_verification_idempotency_conflict"
                ) from exc

            if not created:
                if (
                    job.get("job_type") != CLEANUP_VERIFY_ACTION
                    or job.get("initiator") != actor
                    or job.get("idempotency_key") != idempotency_key
                ):
                    raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                        "device_management_enrollment_cleanup_verification_state_invalid"
                    )
                if job.get("state") == "succeeded":
                    return self._resume_succeeded(job)
                if job.get("state") == "failed":
                    raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                        "device_management_enrollment_cleanup_verification_retry_required"
                    )
                if job.get("state") == "verifying":
                    return self._finalize(
                        actor=actor,
                        correlation_id=correlation_id,
                        job=job,
                        de_enrollment_id=de_enrollment_id,
                        stored_plan=stored_plan,
                        accepted_at=accepted_at,
                        cleanup=cleanup,
                        verification_request=verification_request,
                        recovered_after_restart=True,
                    )
                if job.get("state") not in {"preflight", "running"}:
                    raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                        "device_management_enrollment_cleanup_verification_state_invalid"
                    )

            try:
                self._revalidate_current(
                    actor=actor,
                    cleanup=cleanup,
                    stored_plan=stored_plan,
                )
            except DeviceManagementEnrollmentCleanupVerificationRuntimeError as exc:
                self._fail(job, code=exc.code, provider_state_unknown=False)
                raise

            adapter = self._adapter(verification_request.provider_id)
            recovered_running = job.get("state") == "running"
            if job.get("state") == "preflight":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="preflight",
                    new_state="running",
                    steps=[
                        {"step": "revalidate-cleanup-acceptance", "state": "succeeded"},
                        {"step": "provider-readback", "state": "running"},
                        {"step": "assess-retry-planning", "state": "pending"},
                    ],
                )
            try:
                raw_result = adapter.verify(verification_request)
                result = verification_result_from_dict(
                    raw_result,
                    request=verification_request,
                )
            except TimeoutError as exc:
                self._fail(
                    job,
                    code="device_management_enrollment_cleanup_verification_provider_timeout",
                    provider_state_unknown=True,
                )
                raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                    "device_management_enrollment_cleanup_verification_provider_timeout"
                ) from exc
            except DeviceManagementEnrollmentVerificationError as exc:
                self._fail(job, code=exc.code, provider_state_unknown=True)
                raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(exc.code) from exc
            except Exception as exc:
                self._fail(
                    job,
                    code="device_management_enrollment_cleanup_verification_provider_error",
                    provider_state_unknown=True,
                )
                raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                    "device_management_enrollment_cleanup_verification_provider_error"
                ) from exc

            verifying = self.store.transition_action_job(
                job["job_id"],
                expected_state="running",
                new_state="verifying",
                result=result.to_dict(),
                steps=[
                    {"step": "revalidate-cleanup-acceptance", "state": "succeeded"},
                    {"step": "provider-readback", "state": "succeeded"},
                    {"step": "assess-retry-planning", "state": "running"},
                ],
            )
            return self._finalize(
                actor=actor,
                correlation_id=correlation_id,
                job=verifying,
                de_enrollment_id=de_enrollment_id,
                stored_plan=stored_plan,
                accepted_at=accepted_at,
                cleanup=cleanup,
                verification_request=verification_request,
                recovered_after_restart=recovered_running,
            )

    def receipt(self, job_id: str) -> dict[str, object]:
        job = self.store.job(job_id)
        if (
            not isinstance(job, dict)
            or job.get("job_type") != CLEANUP_VERIFY_ACTION
            or job.get("state") != "succeeded"
            or not isinstance(job.get("result"), dict)
            or job["result"].get("schema") != CLEANUP_VERIFY_RECEIPT_SCHEMA
        ):
            raise DeviceManagementEnrollmentCleanupVerificationRuntimeError(
                "device_management_enrollment_cleanup_verification_receipt_not_found"
            )
        return dict(job["result"])
