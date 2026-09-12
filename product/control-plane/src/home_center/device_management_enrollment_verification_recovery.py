"""Recovery guards for the 0.58 enrollment verification runtime."""
from __future__ import annotations

import re
from typing import Any

from .device_management_enrollment_verification_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DeviceManagementEnrollmentVerificationRuntimeError,
    DeviceManagementEnrollmentVerificationRuntimeService,
)
from .household_runtime import _snapshot_from_dict


IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class RecoverableDeviceManagementEnrollmentVerificationRuntimeService(
    DeviceManagementEnrollmentVerificationRuntimeService
):
    """Tighten replay semantics and stale-state handling around the local commit."""

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
            return super()._finish_apply(
                actor=actor,
                correlation_id=correlation_id,
                key=key,
                envelope=envelope,
                plan=plan,
                job=job,
            )
        except DeviceManagementEnrollmentVerificationRuntimeError as exc:
            if exc.code == "device_management_enrollment_verification_stale":
                self._mark_stale_failure(
                    key=key,
                    envelope=envelope,
                    job=job,
                    code=exc.code,
                )
            raise

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
