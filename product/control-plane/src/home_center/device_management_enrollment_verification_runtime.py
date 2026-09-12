"""Durable, fail-closed post-condition verification runtime for Home Center 0.58.

The 0.57 execution boundary proves only that a provider accepted an enrollment
command. This service performs a separate read-only provider read-back, stores a
durable Job/Audit trail, and emits exact verification evidence. It never resolves
credential values, never applies policy, never mutates provider infrastructure,
and does not itself commit ``ManagedDevice.managed=True``.
"""
from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .device_management_enrollment_execution_runtime import (
    KEY_PREFIX as EXECUTION_KEY_PREFIX,
    RETRY_ACTION,
    START_ACTION,
    STATE_SCHEMA as EXECUTION_STATE_SCHEMA,
)
from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationAdapter,
    DeviceManagementEnrollmentVerificationError,
    DeviceManagementEnrollmentVerificationEvidence,
    build_verification_request,
    evaluate_verification_result,
    verification_result_from_dict,
)
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json


VERIFY_REQUEST_SCHEMA = "home-center.device-management-enrollment-verification-runtime-request.v1"
VERIFY_RECEIPT_SCHEMA = "home-center.device-management-enrollment-verification-runtime-receipt.v1"
VERIFY_STATE_SCHEMA = "home-center.device-management-enrollment-verification-runtime-state.v1"
VERIFY_ACTION = "household.device.management.enrollment.verify"
VERIFY_KEY_PREFIX = "cozy.household.device-enrollment-verification."
PLAN_ID = re.compile(r"^dmpexec-[0-9a-f]{24}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class DeviceManagementEnrollmentVerificationRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _request_hash(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _verification_key(verification_id: object) -> str:
    if not isinstance(verification_id, str) or not verification_id.startswith("dmpverify-"):
        raise DeviceManagementEnrollmentVerificationRuntimeError(
            "device_management_enrollment_verification_id_invalid"
        )
    return VERIFY_KEY_PREFIX + verification_id


class DeviceManagementEnrollmentVerificationRuntimeService:
    """Persisted 0.58 read-back runtime without provider mutation authority."""

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
            or provider_id in self._adapters
            or not callable(getattr(adapter, "verify", None))
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_verification_adapter_registration"
            )
        self._adapters[provider_id] = adapter

    def _adapter(self, provider_id: str) -> DeviceManagementEnrollmentVerificationAdapter:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_adapter_unavailable"
            )
        return adapter

    def _snapshot(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "household_not_configured"
            )
        try:
            snapshot, _bindings = _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        return snapshot

    def _execution_receipt(
        self,
        plan_id: object,
        *,
        actor: str,
    ) -> dict[str, object]:
        if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_execution_plan_id"
            )
        envelope = self.store.get_meta(EXECUTION_KEY_PREFIX + plan_id)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != EXECUTION_STATE_SCHEMA
            or envelope.get("status") != "provider-accepted"
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_execution_not_accepted"
            )
        receipt = envelope.get("receipt")
        if not isinstance(receipt, dict) or receipt.get("plan_id") != plan_id:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_execution_receipt_invalid"
            )
        execution_job_id = receipt.get("job_id")
        execution_job = self.store.job(execution_job_id) if isinstance(execution_job_id, str) else None
        if (
            not isinstance(execution_job, dict)
            or execution_job.get("state") != "succeeded"
            or execution_job.get("job_type") not in {START_ACTION, RETRY_ACTION}
            or execution_job.get("initiator") != actor
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_actor_or_execution_mismatch"
            )
        return dict(receipt)

    def _fail_job(
        self,
        job_id: str,
        *,
        code: str,
        provider_state_unknown: bool,
    ) -> None:
        job = self.store.job(job_id)
        if not isinstance(job, dict) or job.get("state") != "running":
            return
        self.store.transition_action_job(
            job_id,
            expected_state="running",
            new_state="failed",
            result={
                "schema": "home-center.device-management-enrollment-verification-failure.v1",
                "state": "failed",
                "code": code,
                "provider_state_unknown": provider_state_unknown,
                "post_condition_verified": False,
                "managed_state_change_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )

    def verify(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        expected = {"schema", "plan_id", "idempotency_key"}
        if (
            not isinstance(request, dict)
            or set(request) != expected
            or request.get("schema") != VERIFY_REQUEST_SCHEMA
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_verification_request"
            )
        idempotency_key = request.get("idempotency_key")
        if (
            not isinstance(idempotency_key, str)
            or IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_verification_idempotency_key"
            )

        with self._lock:
            execution_receipt = self._execution_receipt(
                request.get("plan_id"),
                actor=actor,
            )
            snapshot = self._snapshot()
            try:
                verification_request = build_verification_request(
                    execution_receipt=execution_receipt,
                    snapshot=snapshot,
                )
            except DeviceManagementEnrollmentVerificationError as exc:
                raise DeviceManagementEnrollmentVerificationRuntimeError(exc.code) from exc
            adapter = self._adapter(verification_request.provider_id)
            request_material = {
                "plan_id": verification_request.plan_id,
                "execution_job_id": verification_request.execution_job_id,
                "verification_id": verification_request.verification_id,
                "provider_id": verification_request.provider_id,
                "provider_operation_id": verification_request.provider_operation_id,
                "device_id": verification_request.device_id,
                "snapshot_id": verification_request.snapshot_id,
                "resource_version": verification_request.resource_version,
                "generation": verification_request.generation,
                "idempotency_key": idempotency_key,
            }
            try:
                job, created = self.store.create_action_job(
                    action_id=VERIFY_ACTION,
                    actor=actor,
                    reason="post-condition verification after provider enrollment acceptance",
                    idempotency_key=idempotency_key,
                    request_hash=_request_hash(request_material),
                    preflight={
                        "schema": "home-center.device-management-enrollment-verification-preflight.v1",
                        "verification_id": verification_request.verification_id,
                        "execution_job_id": verification_request.execution_job_id,
                        "plan_id": verification_request.plan_id,
                        "provider_id": verification_request.provider_id,
                        "device_id": verification_request.device_id,
                        "provider_readback_authorized": True,
                        "credential_value_access_authorized": False,
                        "provider_mutation_authorized": False,
                        "managed_state_change_authorized": False,
                        "policy_application_authorized": False,
                        "infrastructure_mutation_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-execution-and-household", "state": "succeeded"},
                        {"step": "provider-readback", "state": "pending"},
                        {"step": "evaluate-post-condition", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_idempotency_conflict"
                ) from exc

            if not created:
                if (
                    job.get("state") == "succeeded"
                    and isinstance(job.get("result"), dict)
                    and job["result"].get("schema") == VERIFY_RECEIPT_SCHEMA
                ):
                    return dict(job["result"])
                if job.get("state") in {"preflight", "running", "verifying"}:
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "device_management_enrollment_verification_in_progress"
                    )
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_retry_required"
                )

            running = self.store.transition_action_job(
                job["job_id"],
                expected_state="preflight",
                new_state="running",
                steps=[
                    {"step": "revalidate-execution-and-household", "state": "succeeded"},
                    {"step": "provider-readback", "state": "running"},
                    {"step": "evaluate-post-condition", "state": "pending"},
                ],
            )
            try:
                raw_result = adapter.verify(verification_request)
                result = verification_result_from_dict(
                    raw_result,
                    request=verification_request,
                )
            except TimeoutError as exc:
                self._fail_job(
                    running["job_id"],
                    code="device_management_enrollment_verification_provider_timeout",
                    provider_state_unknown=True,
                )
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_provider_timeout"
                ) from exc
            except DeviceManagementEnrollmentVerificationError as exc:
                self._fail_job(
                    running["job_id"],
                    code=exc.code,
                    provider_state_unknown=True,
                )
                raise DeviceManagementEnrollmentVerificationRuntimeError(exc.code) from exc
            except Exception as exc:
                self._fail_job(
                    running["job_id"],
                    code="device_management_enrollment_verification_provider_error",
                    provider_state_unknown=True,
                )
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_provider_error"
                ) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result={
                    "schema": result.schema,
                    "provider_operation_id": result.provider_operation_id,
                    "device_id": result.device_id,
                    "certificate_present": result.certificate_present,
                    "profile_present": result.profile_present,
                    "agent_present": result.agent_present,
                    "management_active": result.management_active,
                    "observed_at": result.observed_at,
                    "secret_material_present": False,
                    "infrastructure_mutation_authorized": False,
                },
                steps=[
                    {"step": "revalidate-execution-and-household", "state": "succeeded"},
                    {"step": "provider-readback", "state": "succeeded"},
                    {"step": "evaluate-post-condition", "state": "running"},
                ],
            )

            try:
                fresh_execution_receipt = self._execution_receipt(
                    verification_request.plan_id,
                    actor=actor,
                )
                fresh_snapshot = self._snapshot()
                fresh_request = build_verification_request(
                    execution_receipt=fresh_execution_receipt,
                    snapshot=fresh_snapshot,
                )
            except (
                DeviceManagementEnrollmentVerificationError,
                DeviceManagementEnrollmentVerificationRuntimeError,
            ) as exc:
                self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-enrollment-verification-failure.v1",
                        "state": "failed",
                        "code": "device_management_enrollment_verification_stale",
                        "provider_state_unknown": False,
                        "post_condition_verified": False,
                        "managed_state_change_authorized": False,
                    },
                )
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_stale"
                ) from exc

            if fresh_request != verification_request:
                self.store.transition_action_job(
                    verifying["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-enrollment-verification-failure.v1",
                        "state": "failed",
                        "code": "device_management_enrollment_verification_stale",
                        "provider_state_unknown": False,
                        "post_condition_verified": False,
                        "managed_state_change_authorized": False,
                    },
                )
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_stale"
                )

            evidence = evaluate_verification_result(
                request=verification_request,
                result=result,
            )
            receipt = self._receipt(
                job_id=verifying["job_id"],
                evidence=evidence,
            )
            done = self.store.transition_action_job(
                verifying["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                result=receipt,
                evidence=evidence.to_dict(),
                steps=[
                    {"step": "revalidate-execution-and-household", "state": "succeeded"},
                    {"step": "provider-readback", "state": "succeeded"},
                    {"step": "evaluate-post-condition", "state": "succeeded"},
                ],
            )
            envelope = {
                "schema": VERIFY_STATE_SCHEMA,
                "status": "complete",
                "job_id": done["job_id"],
                "request": verification_request.to_dict(),
                "evidence": evidence.to_dict(),
                "receipt": receipt,
            }
            self.store.set_meta(
                _verification_key(verification_request.verification_id),
                envelope,
            )
            self.store.audit(
                actor=actor,
                action=VERIFY_ACTION,
                target=verification_request.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "job_id": done["job_id"],
                    "verification_id": verification_request.verification_id,
                    "provider_id": verification_request.provider_id,
                    "provider_operation_id": verification_request.provider_operation_id,
                    "post_condition_verified": evidence.verified,
                    "managed_state_change_authorized": evidence.verified,
                    "provider_mutation_authorized": False,
                    "policy_application_authorized": False,
                    "infrastructure_mutation_authorized": False,
                    "external_publication_authorized": False,
                },
            )
            return receipt

    @staticmethod
    def _receipt(
        *,
        job_id: str,
        evidence: DeviceManagementEnrollmentVerificationEvidence,
    ) -> dict[str, object]:
        return {
            "schema": VERIFY_RECEIPT_SCHEMA,
            "state": (
                "post-condition-verified"
                if evidence.verified
                else "post-condition-not-verified"
            ),
            "job_id": job_id,
            "verification_id": evidence.verification_id,
            "execution_job_id": evidence.execution_job_id,
            "plan_id": evidence.plan_id,
            "provider_id": evidence.provider_id,
            "provider_operation_id": evidence.provider_operation_id,
            "device_id": evidence.device_id,
            "member_id": evidence.member_id,
            "observed_at": evidence.observed_at,
            "post_condition_verified": evidence.verified,
            "managed_state_change_authorized": evidence.verified,
            "credential_value_access_authorized": False,
            "provider_mutation_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def receipt(self, job_id: str) -> dict[str, object]:
        job = self.store.job(job_id)
        if (
            not isinstance(job, dict)
            or job.get("job_type") != VERIFY_ACTION
            or job.get("state") != "succeeded"
            or not isinstance(job.get("result"), dict)
            or job["result"].get("schema") != VERIFY_RECEIPT_SCHEMA
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_receipt_not_found"
            )
        return dict(job["result"])

    def evidence(self, verification_id: str) -> dict[str, object]:
        envelope = self.store.get_meta(_verification_key(verification_id))
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != VERIFY_STATE_SCHEMA
            or envelope.get("status") != "complete"
            or not isinstance(envelope.get("evidence"), dict)
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_evidence_not_found"
            )
        return dict(envelope["evidence"])
