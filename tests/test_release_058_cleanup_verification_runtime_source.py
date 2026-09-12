from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/devices"


def _contract(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def test_post_cleanup_runtime_contracts_never_authorize_execution() -> None:
    request = _contract(
        "device-management-enrollment-cleanup-verification-runtime-request.v1.schema.json"
    )
    receipt = _contract(
        "device-management-enrollment-cleanup-verification-runtime-receipt.v1.schema.json"
    )

    assert request["additionalProperties"] is False
    assert request["required"] == ["schema", "de_enrollment_id", "idempotency_key"]
    assert receipt["additionalProperties"] is False
    assert receipt["properties"]["state"] == {"const": "post-cleanup-assessed"}
    assert receipt["properties"]["retry_planning_allowed"] == {"type": "boolean"}
    for field in (
        "retry_execution_authorized",
        "provider_mutation_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert receipt["properties"][field] == {"const": False}


def test_post_cleanup_runtime_and_api_are_read_only_and_fail_closed() -> None:
    source = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_cleanup_verification_runtime.py"
    ).read_text(encoding="utf-8")
    api = (ROOT / "product/control-plane/src/home_center/api_v5.py").read_text(
        encoding="utf-8"
    )
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(
        encoding="utf-8"
    )

    assert "DeviceManagementEnrollmentCleanupVerificationRuntimeService" in source
    assert "provider-readback" in source
    assert "assess_retry_after_cleanup" in source
    assert "readback_not_after_deenrollment" in source
    assert "retry_execution_authorized\": False" in source
    assert "provider_mutation_authorized\": False" in source
    assert "managed_state_change_authorized\": False" in source
    assert "secret://" not in source

    assert "/api/v1/household/devices/enrollment/cleanup/verify" in api
    assert "_same_origin_post_allowed" in api
    assert "_blocked_for_external" in api
    assert "RuntimeRequestHandlerV5" in server
