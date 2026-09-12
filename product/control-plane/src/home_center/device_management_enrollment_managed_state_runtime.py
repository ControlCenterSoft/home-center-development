"""Exact-state managed-device commit runtime for Home Center 0.58.

A positive provider read-back authorizes a *local product-state* transition only.
This boundary commits ``ManagedDevice.managed=True`` with optimistic concurrency
and atomically succeeds the durable Job and appends Audit evidence. Replaying the
same idempotent request after a restart resumes only local exact-state work; no
provider operation is invoked by this module.
"""
from __future__ import annotations

import hashlib
import re
import threading
import uuid
from typing import Any

from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationError,
    build_managed_state_replacement,
)
from .device_management_enrollment_verification_persistence import (
    verification_evidence_from_dict,
)
from .device_management_enrollment_verification_runtime import (
    VERIFY_ACTION,
    VERIFY_KEY_PREFIX,
    VERIFY_STATE_SCHEMA,
)
from .household_runtime import HOUSEHOLD_STATE_KEY, _persisted, _state_from_dict
from .state_meta_cas import compare_and_swap_meta_succeed_job_and_audit
from .store import IdempotencyConflict, StateStore
from .util import canonical_json


COMMIT_REQUEST_SCHEMA = "home-center.device-management-enrollment-managed-state-commit-request.v1"
COMMIT_RECEIPT_SCHEMA = "home-center.device-management-enrollment-managed-state-commit-receipt.v1"
COMMIT_ACTION = "household.device.management.enrollment.commit-managed-state"
VERIFICATION_ID = re.compile(r"^dmpverify-[0-9a-f]{24}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class DeviceManagementEnrollmentManagedStateRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class DeviceManagementEnrollmentManagedStateRuntimeService:
    """Durable exact-state commit boundary; no provider or policy mutation."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _verified_evidence(self, verification_id: str, *, actor: str):
        envelope = self.store.get_meta(VERIFY_KEY_PREFIX + verification_id)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != VERIFY_STATE_SCHEMA
            or envelope.get("status") != "complete"
            or not isinstance(envelope.get("job_id"), str)
            or not isinstance(envelope.get("evidence"), dict)
        ):
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_verification_evidence_not_found"
            )
        verification_job = self.store.job(envelope["job_id"])
        if (
            not isinstance(verification_job, dict)
            or verification_job.get("job_type") != VERIFY_ACTION
            or verification_job.get("state") != "succeeded"
            or verification_job.get("initiator") != actor
        ):
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_actor_or_verification_mismatch"
            )
        try:
            evidence = verification_evidence_from_dict(envelope["evidence"])
        except DeviceManagementEnrollmentVerificationError as exc:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(exc.code) from exc
        if evidence.verification_id != verification_id:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_verification_evidence_mismatch"
            )
        if not evidence.verified or not evidence.managed_state_change_authorized:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_post_condition_not_verified"
            )
        return evidence

    def _fail(self, job_id: str, *, expected_state: str, code: str) -> None:
        job = self.store.job(job_id)
        if not isinstance(job, dict) or job.get("state") != expected_state:
            return
        self.store.transition_action_job(
            job_id,
            expected_state=expected_state,
            new_state="failed",
            result={
                "schema": "home-center.device-management-enrollment-managed-state-commit-failure.v1",
                "state": "failed",
                "code": code,
                "post_condition_verified": False,
                "managed_state_change_committed": False,
                "provider_mutation_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )

    def _prepare(
        self,
        *,
        actor: str,
        verification_id: str,
    ):
        evidence = self._verified_evidence(verification_id, actor=actor)
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "household_not_configured"
            )
        try:
            current, bindings = _state_from_dict(raw)
            replacement, commit = build_managed_state_replacement(current, evidence)
        except DeviceManagementEnrollmentVerificationError as exc:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(exc.code) from exc
        except Exception as exc:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        replacement_raw = _persisted(replacement, bindings)
        return evidence, raw, replacement_raw, replacement, commit

    @staticmethod
    def _prepared_result(*, verification_id: str, commit) -> dict[str, object]:
        return {
            "schema": "home-center.device-management-enrollment-managed-state-commit-prepared.v1",
            "verification_id": verification_id,
            "commit_id": commit.commit_id,
            "previous_resource_version": commit.previous_resource_version,
            "resource_version": commit.resource_version,
            "generation": commit.generation,
            "snapshot_id": commit.snapshot_id,
            "post_condition_verified": True,
            "managed_state_change_authorized": True,
            "managed_state_change_committed": False,
            "provider_mutation_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    @staticmethod
    def _receipt(
        *,
        job_id: str,
        audit_event_id: str,
        evidence,
        replacement,
        commit,
    ) -> dict[str, object]:
        return {
            "schema": COMMIT_RECEIPT_SCHEMA,
            "state": "managed-state-committed",
            "job_id": job_id,
            "verification_id": evidence.verification_id,
            "execution_job_id": evidence.execution_job_id,
            "plan_id": evidence.plan_id,
            "household_id": replacement.household_id,
            "device_id": evidence.device_id,
            "member_id": evidence.member_id,
            "commit_id": commit.commit_id,
            "previous_resource_version": commit.previous_resource_version,
            "resource_version": commit.resource_version,
            "generation": commit.generation,
            "snapshot_id": commit.snapshot_id,
            "audit_event_id": audit_event_id,
            "post_condition_verified": True,
            "managed_state_change_authorized": True,
            "managed_state_change_committed": True,
            "provider_mutation_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
            "audit_required": True,
        }

    def _atomic_commit(
        self,
        *,
        actor: str,
        correlation_id: str,
        job_id: str,
        evidence,
        expected_raw,
        replacement_raw,
        replacement,
        commit,
    ) -> dict[str, object]:
        audit_event_id = str(uuid.uuid4())
        receipt = self._receipt(
            job_id=job_id,
            audit_event_id=audit_event_id,
            evidence=evidence,
            replacement=replacement,
            commit=commit,
        )
        terminal_steps = [
            {"step": "revalidate-verification-and-household", "state": "succeeded"},
            {"step": "compare-and-swap-household-state", "state": "succeeded"},
            {"step": "append-audit-evidence", "state": "succeeded"},
        ]
        event_id = compare_and_swap_meta_succeed_job_and_audit(
            self.store,
            key=HOUSEHOLD_STATE_KEY,
            expected=expected_raw,
            replacement=replacement_raw,
            job_id=job_id,
            expected_job_state="verifying",
            result=receipt,
            evidence={
                "schema": "home-center.device-management-enrollment-managed-state-commit-evidence.v1",
                "verification_id": evidence.verification_id,
                "commit_id": commit.commit_id,
                "previous_resource_version": commit.previous_resource_version,
                "resource_version": commit.resource_version,
                "generation": commit.generation,
                "snapshot_id": commit.snapshot_id,
                "audit_event_id": audit_event_id,
                "post_condition_verified": True,
                "managed_state_change_committed": True,
                "provider_mutation_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
            steps=terminal_steps,
            audit_actor=actor,
            audit_action=COMMIT_ACTION,
            audit_target=evidence.device_id,
            audit_outcome="accepted",
            audit_correlation_id=correlation_id,
            audit_event_id=audit_event_id,
            audit_details={
                "job_id": job_id,
                "verification_id": evidence.verification_id,
                "execution_job_id": evidence.execution_job_id,
                "plan_id": evidence.plan_id,
                "device_id": evidence.device_id,
                "commit_id": commit.commit_id,
                "previous_resource_version": commit.previous_resource_version,
                "resource_version": commit.resource_version,
                "generation": commit.generation,
                "snapshot_id": commit.snapshot_id,
                "audit_event_id": audit_event_id,
                "scope": "local-household-managed-state-only",
                "provider_mutation_authorized": False,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )
        if event_id is None:
            self._fail(
                job_id,
                expected_state="verifying",
                code="device_management_enrollment_verification_stale",
            )
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_verification_stale"
            )
        if event_id != audit_event_id:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_evidence_invalid"
            )
        persisted = self.store.job(job_id)
        if (
            not isinstance(persisted, dict)
            or persisted.get("state") != "succeeded"
            or persisted.get("result") != receipt
        ):
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_evidence_invalid"
            )
        return receipt

    def _resume(
        self,
        *,
        actor: str,
        verification_id: str,
        job: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        preflight = job.get("preflight")
        if (
            job.get("job_type") != COMMIT_ACTION
            or job.get("initiator") != actor
            or not isinstance(preflight, dict)
            or preflight.get("verification_id") != verification_id
        ):
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_state_invalid"
            )
        if job.get("state") == "succeeded":
            result = job.get("result")
            if isinstance(result, dict) and result.get("schema") == COMMIT_RECEIPT_SCHEMA:
                return dict(result)
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_state_invalid"
            )
        if job.get("state") == "failed":
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_retry_required"
            )
        if job.get("state") not in {"preflight", "running", "verifying"}:
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_state_invalid"
            )

        state = str(job["state"])
        try:
            evidence, raw, replacement_raw, replacement, commit = self._prepare(
                actor=actor,
                verification_id=verification_id,
            )
        except DeviceManagementEnrollmentManagedStateRuntimeError as exc:
            self._fail(job["job_id"], expected_state=state, code=exc.code)
            raise

        prepared = self._prepared_result(
            verification_id=verification_id,
            commit=commit,
        )
        if state == "preflight":
            job = self.store.transition_action_job(
                job["job_id"],
                expected_state="preflight",
                new_state="running",
                steps=[
                    {"step": "revalidate-verification-and-household", "state": "succeeded"},
                    {"step": "compare-and-swap-household-state", "state": "pending"},
                    {"step": "append-audit-evidence", "state": "pending"},
                ],
            )
            state = "running"

        if state == "running":
            job = self.store.transition_action_job(
                job["job_id"],
                expected_state="running",
                new_state="verifying",
                result=prepared,
                steps=[
                    {"step": "revalidate-verification-and-household", "state": "succeeded"},
                    {"step": "compare-and-swap-household-state", "state": "running"},
                    {"step": "append-audit-evidence", "state": "pending"},
                ],
            )
            state = "verifying"

        if state != "verifying" or job.get("result") != prepared:
            self._fail(
                job["job_id"],
                expected_state=state,
                code="device_management_enrollment_managed_state_commit_state_invalid",
            )
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_state_invalid"
            )

        return self._atomic_commit(
            actor=actor,
            correlation_id=correlation_id,
            job_id=job["job_id"],
            evidence=evidence,
            expected_raw=raw,
            replacement_raw=replacement_raw,
            replacement=replacement,
            commit=commit,
        )

    def commit(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        if (
            not isinstance(request, dict)
            or set(request) != {"schema", "verification_id", "idempotency_key"}
            or request.get("schema") != COMMIT_REQUEST_SCHEMA
        ):
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "invalid_device_management_enrollment_managed_state_commit_request"
            )
        verification_id = request.get("verification_id")
        idempotency_key = request.get("idempotency_key")
        if (
            not isinstance(verification_id, str)
            or VERIFICATION_ID.fullmatch(verification_id) is None
            or not isinstance(idempotency_key, str)
            or IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
        ):
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "invalid_device_management_enrollment_managed_state_commit_request"
            )

        with self._lock:
            try:
                job, _created = self.store.create_action_job(
                    action_id=COMMIT_ACTION,
                    actor=actor,
                    reason="commit verified enrollment to local household managed state",
                    idempotency_key=idempotency_key,
                    request_hash=_hash(
                        {
                            "verification_id": verification_id,
                            "idempotency_key": idempotency_key,
                        }
                    ),
                    preflight={
                        "schema": "home-center.device-management-enrollment-managed-state-commit-preflight.v1",
                        "verification_id": verification_id,
                        "verification_reference_present": True,
                        "post_condition_verified": False,
                        "managed_state_change_authorized": False,
                        "provider_mutation_authorized": False,
                        "policy_application_authorized": False,
                        "infrastructure_mutation_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-verification-and-household", "state": "pending"},
                        {"step": "compare-and-swap-household-state", "state": "pending"},
                        {"step": "append-audit-evidence", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementEnrollmentManagedStateRuntimeError(
                    "device_management_enrollment_managed_state_idempotency_conflict"
                ) from exc
            return self._resume(
                actor=actor,
                verification_id=verification_id,
                job=job,
                correlation_id=correlation_id,
            )

    def receipt(self, job_id: str) -> dict[str, object]:
        job = self.store.job(job_id)
        if (
            not isinstance(job, dict)
            or job.get("job_type") != COMMIT_ACTION
            or job.get("state") != "succeeded"
            or not isinstance(job.get("result"), dict)
            or job["result"].get("schema") != COMMIT_RECEIPT_SCHEMA
        ):
            raise DeviceManagementEnrollmentManagedStateRuntimeError(
                "device_management_enrollment_managed_state_commit_receipt_not_found"
            )
        return dict(job["result"])
