from __future__ import annotations

import json
import tomllib
from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/devices" / name).read_text(encoding="utf-8"))


def test_release_057_candidate_identity_is_057() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == "0.57.0"
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.57.0"
    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    assert '__version__ = "0.57.0"' in runtime_init
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert '<small id="version">0.57.0</small>' in html


def test_release_057_execution_runtime_and_safety_guard_are_required_in_artifact() -> None:
    assert {
        "home_center/device_management_enrollment_execution.py",
        "home_center/device_management_enrollment_execution_runtime.py",
        "home_center/device_management_enrollment_execution_runtime_safe.py",
        "home_center/device_management_enrollment_execution_recovery.py",
        "home_center/api_v3.py",
    } <= REQUIRED_MEMBERS


def test_release_057_api_requires_distinct_plan_start_cancel_retry_operations() -> None:
    api = (ROOT / "product/control-plane/src/home_center/api_v3.py").read_text(encoding="utf-8")
    for suffix in ("/plan", "/start", "/cancel", "/retry"):
        assert f'"/api/v1/household/devices/enrollment/execution{suffix}"' in api
    assert "_same_origin_post_allowed" in api
    assert "_require_actor" in api
    assert "max_bytes=8192" in api


def test_release_057_requests_are_closed_and_mutating_commands_require_confirmation() -> None:
    plan = _contract("device-management-enrollment-execution-plan-request.v1.schema.json")
    start = _contract("device-management-enrollment-execution-start-request.v1.schema.json")
    cancel = _contract("device-management-enrollment-execution-cancel-request.v1.schema.json")
    retry = _contract("device-management-enrollment-execution-retry-request.v1.schema.json")
    for schema in (plan, start, cancel, retry):
        assert schema["additionalProperties"] is False
    for schema in (start, cancel, retry):
        assert schema["properties"]["confirmed"] == {"const": True}
        assert "idempotency_key" in schema["required"]
    serialized = json.dumps(plan, sort_keys=True)
    assert "secret://" in serialized
    assert "password" not in serialized.lower()


def test_release_057_provider_adapter_contract_never_receives_raw_secret_authority() -> None:
    request = _contract("device-management-enrollment-adapter-start-request.v1.schema.json")
    result = _contract("device-management-enrollment-adapter-start-result.v1.schema.json")
    cancel_result = _contract("device-management-enrollment-adapter-cancel-result.v1.schema.json")
    assert request["additionalProperties"] is False
    assert result["additionalProperties"] is False
    assert cancel_result["additionalProperties"] is False
    assert request["properties"]["provider_execution_authorized"] == {"const": True}
    assert request["properties"]["credential_value_access_authorized"] == {"const": False}
    assert request["properties"]["managed_state_change_authorized"] == {"const": False}
    assert request["properties"]["policy_application_authorized"] == {"const": False}
    assert request["properties"]["infrastructure_mutation_authorized"] == {"const": False}
    assert request["properties"]["external_publication_authorized"] == {"const": False}
    assert result["properties"]["post_condition_verified"] == {"const": False}
    assert result["properties"]["managed_state_change_authorized"] == {"const": False}
    assert cancel_result["properties"]["state"] == {"const": "cancel-accepted"}
    assert cancel_result["properties"]["post_condition_verified"] == {"const": False}
    assert cancel_result["properties"]["managed_state_change_authorized"] == {"const": False}


def test_release_057_receipts_cannot_claim_enrollment_or_managed_state() -> None:
    receipt = _contract("device-management-enrollment-execution-receipt.v1.schema.json")
    cancel = _contract("device-management-enrollment-cancel-receipt.v1.schema.json")
    assert receipt["additionalProperties"] is False
    assert receipt["properties"]["state"] == {"const": "provider-accepted"}
    assert receipt["properties"]["enrollment_completed"] == {"const": False}
    assert receipt["properties"]["post_condition_verified"] == {"const": False}
    assert receipt["properties"]["managed_state_change_authorized"] == {"const": False}
    assert receipt["properties"]["policy_application_authorized"] == {"const": False}
    assert receipt["properties"]["infrastructure_mutation_authorized"] == {"const": False}
    assert receipt["properties"]["external_publication_authorized"] == {"const": False}
    assert cancel["properties"]["post_condition_verified"] == {"const": False}
    assert cancel["properties"]["managed_state_change_authorized"] == {"const": False}


def test_release_057_runtime_fails_closed_on_replay_and_ambiguous_retry() -> None:
    safe = (
        ROOT / "product/control-plane/src/home_center/device_management_enrollment_execution_runtime_safe.py"
    ).read_text(encoding="utf-8")
    assert "device_management_enrollment_execution_already_started" in safe
    assert "device_management_enrollment_execution_retry_required" in safe
    assert "device_management_enrollment_execution_retry_not_safe" in safe
    assert "latest durable attempt" in safe
    assert "device_management_enrollment_execution_cancel_retry_not_safe" in safe
    assert "device_management_enrollment_adapter_cancel_result_rejected" in safe
    assert 'receipt.get("provider_execution_authorized") is not False' in safe
    assert 'receipt.get("managed_state_change_authorized") is not False' in safe


def test_release_057_runtime_never_marks_device_managed_from_provider_acceptance() -> None:
    execution = (
        ROOT / "product/control-plane/src/home_center/device_management_enrollment_execution_runtime.py"
    ).read_text(encoding="utf-8")
    assert '"enrollment_completed":False' in execution
    assert '"post_condition_verified":False' in execution
    assert '"managed_state_change_authorized":False' in execution
    assert "managed=True" not in execution
    assert '"next_required_boundary":"post-condition-verification"' in execution


def test_release_057_notes_are_official_bounded_stable_and_preserve_verification_boundary() -> None:
    notes = (ROOT / "docs/releases/0.57.0.md").read_text(encoding="utf-8")
    assert "Status: official release." in notes
    assert "`single-node-core`" in notes
    assert "multi-node HA / automatic failover — не заявлены" in notes
    assert "concrete provider execution — не заявлен" in notes
    assert "commercial launch clearance — не заявлен" in notes
    assert "enrollment_completed = false" in notes
    assert "post_condition_verified = false" in notes
    assert "managed_state_change_authorized = false" in notes
    assert "Состояние `managed=true` допустимо только после отдельной последующей post-condition verification" in notes
