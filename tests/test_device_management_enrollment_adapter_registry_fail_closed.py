from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_enrollment_execution_runtime import (
    DeviceManagementEnrollmentExecutionRuntimeError,
    DeviceManagementEnrollmentExecutionRuntimeService,
)
from home_center.store import StateStore


def test_unregistered_provider_adapter_is_fail_closed_and_creates_no_job(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db", b"x" * 32, "cluster-test")
    service = DeviceManagementEnrollmentExecutionRuntimeService(store)

    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="adapter_unavailable"):
        service._adapter("android-mdm-primary")

    assert store.jobs() == []
    store.close()


def test_adapter_registration_requires_start_and_cancel_callables(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.db", b"x" * 32, "cluster-test")
    service = DeviceManagementEnrollmentExecutionRuntimeService(store)

    class StartOnlyAdapter:
        def start(self, request):
            return None

    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="adapter_registration"):
        service.register_adapter("android-mdm-primary", StartOnlyAdapter())

    with pytest.raises(DeviceManagementEnrollmentExecutionRuntimeError, match="adapter_unavailable"):
        service._adapter("android-mdm-primary")
    assert store.jobs() == []
    store.close()
