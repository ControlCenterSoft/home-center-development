"""Recovery guards for the 0.58 enrollment verification runtime."""
from __future__ import annotations

import json
import re
from typing import Any

from .device_management_enrollment_verification_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DeviceManagementEnrollmentVerificationRuntimeError,
    DeviceManagementEnrollmentVerificationRuntimeService,
)
from .household_runtime import HOUSEHOLD_STATE_KEY, _persisted, _snapshot_from_dict, _state_from_dict
from .util import canonical_json, utc_now


IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class RecoverableDeviceManagementEnrollmentVerificationRuntimeService(
    DeviceManagementEnrollmentVerificationRuntimeService
):
    """Tighten replay semantics and make the managed-state commit compare-and-set."""

    def _mark_stale_failure(
        self,
        *,
        key: str,
        envelope: dict[str, Any],
        job: dict[str, Any],
        code: str,
    ) -> None:
        refreshed = self.store.job(job["job_id"])
        if refreshed is not None and refreshed.get("state") == "verifying":
            self.store.transition_action_job(
                refreshed["job_id"],
                expected_state="verifying",
                new_state="failed",
                result={
                    "schema": "home-center.device-management-enrollment-verification-failure.v1",
                    "state": "failed",
                    "code": code,
                    "provider_post_condition_observed": True,
                    "post_condition_verified": False,
                    "managed_state_change_authorized": False,
                    "policy_application_authorized": False,
                    "infrastructure_mutation_authorized": False,
                    "external_publication_authorized": False,
                },
            )
        failed = dict(envelope)
        failed.update(status="failed", failure_code=code)
        self.store.set_meta(key, failed)

    def _prepare_apply(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: Any,
        job: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            ) from exc
        current, _bindings = self._state()
        if current != base:
            self._mark_stale_failure(
                key=key,
                envelope=envelope,
                job=job,
                code="device_management_enrollment_verification_stale",
            )
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_stale"
            )
        return super()._prepare_apply(
            actor=actor,
            correlation_id=correlation_id,
            key=key,
            envelope=envelope,
            plan=plan,
            job=job,
        )

    def _finish_apply(
        self,
        *,
        actor: str,
        correlation_id: str,
        key: str,
        envelope: dict[str, Any],
        plan: Any,
        job: dict[str, Any],
    ) -> dict[str, object]:
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
            expected = _snapshot_from_dict(envelope.get("expected_snapshot"))
        except Exception as exc:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            ) from exc
        receipt = envelope.get("receipt")
        commit = envelope.get("commit")
        if (
            not isinstance(receipt, dict)
            or receipt.get("verification_id") != plan.verification_id
            or receipt.get("snapshot_id") != expected.snapshot_id
            or receipt.get("resource_version") != expected.resource_version
            or receipt.get("managed_state_change_authorized") is not True
            or receipt.get("policy_application_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
            or not isinstance(commit, dict)
            or commit.get("snapshot_id") != expected.snapshot_id
            or commit.get("resource_version") != expected.resource_version
        ):
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )

        connection = getattr(self.store, "_connection", None)
        lock = getattr(self.store, "_lock", None)
        if connection is None or lock is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )

        stale = False
        with lock:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT value_json FROM cluster_meta WHERE key=?",
                    (HOUSEHOLD_STATE_KEY,),
                ).fetchone()
                if row is None:
                    raise DeviceManagementEnrollmentVerificationRuntimeError(
                        "household_not_configured"
                    )
                original_payload = row[0]
                current, bindings = _state_from_dict(json.loads(original_payload))
                self._actor(actor, bindings)
                if current == base:
                    next_payload = canonical_json(_persisted(expected, bindings))
                    cursor = connection.execute(
                        """UPDATE cluster_meta SET value_json=?,updated_at=?
                        WHERE key=? AND value_json=?""",
                        (next_payload, utc_now(), HOUSEHOLD_STATE_KEY, original_payload),
                    )
                    if cursor.rowcount != 1:
                        stale = True
                    else:
                        current = expected
                elif current != expected:
                    stale = True
                if stale:
                    connection.rollback()
                else:
                    connection.commit()
            except Exception:
                connection.rollback()
                raise

        if stale:
            self._mark_stale_failure(
                key=key,
                envelope=envelope,
                job=job,
                code="device_management_enrollment_verification_stale",
            )
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_stale"
            )

        completion_audit_event_id = self.store.audit(
            actor=actor,
            action="household.device.management.enrollment-verification.apply",
            target=plan.device_id,
            outcome="succeeded",
            correlation_id=correlation_id,
            details={
                "verification_id": plan.verification_id,
                "job_id": job["job_id"],
                "provider_id": plan.provider_id,
                "provider_operation_id": plan.provider_operation_id,
                "previous_snapshot_id": base.snapshot_id,
                "snapshot_id": expected.snapshot_id,
                "resource_version": expected.resource_version,
                "commit_id": commit.get("commit_id"),
                "post_condition_verified": True,
                "managed_state_change_authorized": True,
                "policy_application_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            },
        )

        refreshed = self.store.job(job["job_id"])
        if refreshed is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )
        if refreshed.get("state") == "verifying":
            self.store.transition_action_job(
                refreshed["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.device-management-enrollment-verification-evidence.v1",
                    "scope": "provider-post-condition-and-household-managed-state",
                    "verification_id": plan.verification_id,
                    "provider_operation_id": plan.provider_operation_id,
                    "snapshot_id": expected.snapshot_id,
                    "resource_version": expected.resource_version,
                    "post_condition_verified": True,
                    "managed_state_change_authorized": True,
                    "policy_application_authorized": False,
                    "infrastructure_mutation_authorized": False,
                    "external_publication_authorized": False,
                    "compare_and_set_commit": True,
                },
            )
        elif refreshed.get("state") != "succeeded":
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "device_management_enrollment_verification_state_invalid"
            )

        final = dict(envelope)
        final.update(
            status="applied",
            completion_audit_event_id=completion_audit_event_id,
            receipt=receipt,
        )
        self.store.set_meta(key, final)
        return dict(receipt)

    def confirm(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        if (
            set(request) != {"schema", "verification_id", "confirmed", "idempotency_key"}
            or request.get("schema") != CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            return super().confirm(actor=actor, request=request, correlation_id=correlation_id)
        idempotency_key = request.get("idempotency_key")
        if not isinstance(idempotency_key, str) or IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                "invalid_device_management_enrollment_verification_confirm_request"
            )

        verification_id = request.get("verification_id")
        try:
            _key, envelope, plan = self._load(verification_id)
        except DeviceManagementEnrollmentVerificationRuntimeError:
            return super().confirm(actor=actor, request=request, correlation_id=correlation_id)

        if envelope.get("status") == "failed":
            code = envelope.get("failure_code")
            raise DeviceManagementEnrollmentVerificationRuntimeError(
                code if isinstance(code, str) and code else "device_management_enrollment_verification_previous_attempt_failed"
            )
        if envelope.get("status") != "applied":
            return super().confirm(actor=actor, request=request, correlation_id=correlation_id)

        with self._lock:
            current, _bindings = self._revalidate(actor=actor, envelope=envelope, plan=plan)
            try:
                expected = _snapshot_from_dict(envelope.get("expected_snapshot"))
            except Exception as exc:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                ) from exc
            if current != expected:
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_state_mismatch"
                )
            receipt = envelope.get("receipt")
            if not isinstance(receipt, dict):
                raise DeviceManagementEnrollmentVerificationRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                )
            return dict(receipt)
