"""Contract-qualified registry wrapper for Home Center 0.58 verifier adapters.

The wrapper keeps the existing fail-closed verification runtime unchanged while adding
an explicit static qualification gate for any concrete provider read-back adapter.
Static qualification remains contract-only and never implies live provider acceptance.
"""
from __future__ import annotations

from typing import Any

from .device_management_enrollment_post_condition_runtime import (
    PLAN_REQUEST_SCHEMA,
    DeviceManagementEnrollmentPostConditionRuntimeError,
)
from .device_management_enrollment_post_condition_runtime_safe import (
    SafeDeviceManagementEnrollmentPostConditionRuntimeService,
)
from .device_management_verifier_qualification import (
    DeviceManagementVerifierQualificationError,
    qualify_read_back_adapter,
    validate_contract_qualification_receipt,
)


QUALIFICATION_BINDING_FIELD = "verifier_qualification"
_PLAN_REQUEST_FIELDS = frozenset(
    {"schema", "execution_plan_id", "max_observed_age_seconds", "expected_signals"}
)


class ContractQualifiedDeviceManagementEnrollmentPostConditionRuntimeService(
    SafeDeviceManagementEnrollmentPostConditionRuntimeService
):
    """Require deterministic contract evidence before registering a concrete verifier."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._adapter_qualifications: dict[str, dict[str, object]] = {}

    def register_adapter(
        self,
        provider_id: str,
        adapter: object,
        *,
        qualification_profile: object | None = None,
    ) -> dict[str, object]:
        if qualification_profile is None:
            raise DeviceManagementVerifierQualificationError(
                "device_management_enrollment_verifier_qualification_required"
            )
        receipt = qualify_read_back_adapter(
            provider_id=provider_id,
            adapter=adapter,
            profile=qualification_profile,
        )
        super().register_adapter(provider_id, adapter)
        self._adapter_qualifications[provider_id] = dict(receipt)
        return dict(receipt)

    def _validated_qualification(
        self,
        provider_id: object,
        *,
        adapter: object | None = None,
    ) -> dict[str, object]:
        if not isinstance(provider_id, str):
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verifier_qualification_required"
            )
        receipt = self._adapter_qualifications.get(provider_id)
        if receipt is None:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verifier_qualification_required"
            )
        if adapter is None:
            adapter = super()._adapter(provider_id)
        try:
            return validate_contract_qualification_receipt(
                provider_id=provider_id,
                adapter=adapter,
                receipt=receipt,
            )
        except DeviceManagementVerifierQualificationError as exc:
            raise DeviceManagementEnrollmentPostConditionRuntimeError(
                "device_management_enrollment_verifier_qualification_stale"
            ) from exc

    def _adapter(self, provider_id: object):
        adapter = super()._adapter(provider_id)
        self._validated_qualification(provider_id, adapter=adapter)
        return adapter

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        """Require qualification before persistence, then bind it to the exact plan."""
        with self._lock:
            # Preserve the base API's closed-request error precedence. Invalid input
            # is rejected by the base service before any provider/qualification lookup.
            if set(request) != _PLAN_REQUEST_FIELDS or request.get("schema") != PLAN_REQUEST_SCHEMA:
                return super().plan(
                    actor=actor,
                    request=request,
                    correlation_id=correlation_id,
                )

            # Resolve the already-durable 0.57 execution receipt only to identify the
            # provider. This is read-only and prevents creation/audit of a 0.58 plan
            # when no currently valid contract-qualified verifier is registered.
            execution_plan, _execution_envelope, _execution_receipt = self._execution(
                request.get("execution_plan_id")
            )
            self._validated_qualification(execution_plan.provider_id)

            plan = super().plan(
                actor=actor,
                request=request,
                correlation_id=correlation_id,
            )
            provider_id = plan.get("provider_id")
            # Revalidate after base planning as well so descriptor drift cannot race
            # between preflight admission and durable qualification binding.
            qualification = self._validated_qualification(provider_id)
            key, envelope, loaded_plan = self._load(plan.get("verification_id"))
            if loaded_plan != plan:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verification_state_invalid"
                )
            bound = envelope.get(QUALIFICATION_BINDING_FIELD)
            if bound is not None and bound != qualification:
                raise DeviceManagementEnrollmentPostConditionRuntimeError(
                    "device_management_enrollment_verifier_qualification_binding_mismatch"
                )
            if bound is None:
                updated = dict(envelope)
                updated[QUALIFICATION_BINDING_FIELD] = dict(qualification)
                self.store.set_meta(key, updated)
        return plan

    def confirm(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        step_up_token: object,
        correlation_id: str,
    ) -> dict[str, object]:
        """Fail before step-up consumption/provider I/O if qualification drifted since plan."""
        with self._lock:
            _key, envelope, plan = self._load(request.get("verification_id"))
            if envelope.get("status") != "applied":
                qualification = self._validated_qualification(plan.get("provider_id"))
                if envelope.get(QUALIFICATION_BINDING_FIELD) != qualification:
                    raise DeviceManagementEnrollmentPostConditionRuntimeError(
                        "device_management_enrollment_verifier_qualification_binding_mismatch"
                    )
        return super().confirm(
            actor=actor,
            request=request,
            step_up_token=step_up_token,
            correlation_id=correlation_id,
        )

    def adapter_qualification(self, provider_id: str) -> dict[str, object] | None:
        receipt = self._adapter_qualifications.get(provider_id)
        if receipt is None:
            return None
        return dict(self._validated_qualification(provider_id))
