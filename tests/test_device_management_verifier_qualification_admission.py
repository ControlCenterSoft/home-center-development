from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from home_center.device_management_enrollment_post_condition_runtime import (
    PLAN_REQUEST_SCHEMA,
    DeviceManagementEnrollmentPostConditionRuntimeError,
)
from home_center.device_management_enrollment_post_condition_runtime_qualified import (
    ContractQualifiedDeviceManagementEnrollmentPostConditionRuntimeService,
)


PROVIDER = "android.mdm"


class AdmissionHarness(ContractQualifiedDeviceManagementEnrollmentPostConditionRuntimeService):
    """Exercise strict admission without durable state or provider I/O."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._adapter_qualifications: dict[str, dict[str, object]] = {}
        self.execution_reads = 0

    def _execution(self, execution_plan_id: object):
        self.execution_reads += 1
        return SimpleNamespace(provider_id=PROVIDER), {}, {}


def test_invalid_plan_request_keeps_base_closed_request_error_precedence() -> None:
    service = AdmissionHarness()

    with pytest.raises(
        DeviceManagementEnrollmentPostConditionRuntimeError,
        match="invalid_device_management_enrollment_verification_plan_request",
    ):
        service.plan(
            actor="local-admin:admin",
            request={"schema": PLAN_REQUEST_SCHEMA},
            correlation_id="invalid-request",
        )

    assert service.execution_reads == 0


def test_missing_qualification_fails_before_base_plan_persistence() -> None:
    service = AdmissionHarness()

    with pytest.raises(
        DeviceManagementEnrollmentPostConditionRuntimeError,
        match="device_management_enrollment_verifier_qualification_required",
    ):
        service.plan(
            actor="local-admin:admin",
            request={
                "schema": PLAN_REQUEST_SCHEMA,
                "execution_plan_id": "dmpexec-0123456789abcdef01234567",
                "max_observed_age_seconds": 300,
                "expected_signals": {
                    "certificate": "present",
                    "profile": "present",
                    "agent": "present",
                },
            },
            correlation_id="qualification-preflight",
        )

    assert service.execution_reads == 1
