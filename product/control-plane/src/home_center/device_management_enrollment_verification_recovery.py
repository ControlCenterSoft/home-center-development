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
    """Tighten replay semantics after the managed-state commit is durable."""

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
