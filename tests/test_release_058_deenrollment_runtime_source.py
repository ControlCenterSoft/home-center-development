from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_058_deenrollment_runtime_request_is_explicit_and_closed() -> None:
    schema = json.loads(
        (
            ROOT
            / "contracts/devices/device-management-enrollment-deenrollment-runtime-request.v1.schema.json"
        ).read_text(encoding="utf-8")
    )

    assert schema["additionalProperties"] is False
    assert schema["required"] == [
        "schema",
        "verification_id",
        "confirmed",
        "idempotency_key",
    ]
    assert schema["properties"]["confirmed"] == {"const": True}
    assert schema["properties"]["verification_id"]["pattern"] == "^dmpverify-[0-9a-f]{24}$"


def test_058_deenrollment_runtime_has_durable_fail_closed_recovery() -> None:
    source = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_deenrollment_runtime.py"
    ).read_text(encoding="utf-8")
    runtime = (
        ROOT / "product/control-plane/src/home_center/runtime.py"
    ).read_text(encoding="utf-8")
    api = (
        ROOT / "product/control-plane/src/home_center/api_v4.py"
    ).read_text(encoding="utf-8")

    assert "DeviceManagementEnrollmentDeenrollmentRuntimeService" in source
    assert "create_action_job" in source
    assert "provider-de-enroll" in source
    assert "provider_acceptance_unknown" in source
    assert "recovered_after_restart" in source
    assert "provider_reinvoked" in source
    assert "retry_execution_authorized\": False" in source
    assert "managed_state_change_authorized\": False" in source
    assert "policy_application_authorized\": False" in source
    assert "external_publication_authorized\": False" in source
    assert "secret://" not in source

    assert "device_management_enrollment_deenrollment" in runtime
    assert "/api/v1/household/devices/enrollment/cleanup/de-enroll" in api
    assert "_same_origin_post_allowed" in api
    assert "_blocked_for_external" in api
    assert "provider_reinvoked\": False" in api
