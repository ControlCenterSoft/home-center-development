"""Contract-qualified registry wrapper for Home Center 0.58 verifier adapters.

The wrapper keeps the existing fail-closed verification runtime unchanged while adding
an explicit static qualification gate for any concrete provider read-back adapter.
Static qualification remains contract-only and never implies live provider acceptance.
"""
from __future__ import annotations

from typing import Any

from .device_management_enrollment_post_condition_runtime_safe import (
    SafeDeviceManagementEnrollmentPostConditionRuntimeService,
)
from .device_management_verifier_qualification import (
    DeviceManagementVerifierQualificationError,
    qualify_read_back_adapter,
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

    def adapter_qualification(self, provider_id: str) -> dict[str, object] | None:
        receipt = self._adapter_qualifications.get(provider_id)
        return None if receipt is None else dict(receipt)
