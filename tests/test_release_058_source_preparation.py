from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/devices"


def _contract(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def test_058_cleanup_contract_is_closed_and_non_authorizing() -> None:
    schema = _contract("device-management-enrollment-cleanup-plan.v1.schema.json")

    assert schema["additionalProperties"] is False
    assert schema["properties"]["action"]["enum"] == [
        "no-provider-cleanup",
        "de-enroll-required",
    ]
    for field in (
        "provider_mutation_authorized",
        "retry_planning_allowed",
        "retry_execution_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert schema["properties"][field] == {"const": False}


def test_058_retry_assessment_never_authorizes_execution() -> None:
    schema = _contract(
        "device-management-enrollment-cleanup-retry-assessment.v1.schema.json"
    )

    assert schema["additionalProperties"] is False
    assert schema["properties"]["retry_planning_allowed"]["type"] == "boolean"
    assert schema["properties"]["reason"]["enum"] == [
        "cleanup-verified-no-residual-state",
        "residual-provider-state",
    ]
    for field in (
        "retry_execution_authorized",
        "provider_mutation_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert schema["properties"][field] == {"const": False}


def test_058_deenrollment_plan_requires_confirmation_before_provider_authority() -> None:
    plan = _contract("device-management-enrollment-deenrollment-plan.v1.schema.json")
    confirmation = _contract(
        "device-management-enrollment-deenrollment-confirmation.v1.schema.json"
    )

    assert plan["additionalProperties"] is False
    assert plan["properties"]["confirmation_required"] == {"const": True}
    assert plan["properties"]["durable_job_required"] == {"const": True}
    assert plan["properties"]["audit_required"] == {"const": True}
    assert plan["properties"]["provider_mutation_authorized"] == {"const": False}
    assert confirmation["additionalProperties"] is False
    assert confirmation["properties"]["confirmed"] == {"const": True}
    assert confirmation["properties"]["provider_mutation_authorized"] == {"const": True}
    for field in (
        "credential_value_access_authorized",
        "retry_execution_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert confirmation["properties"][field] == {"const": False}


def test_058_deenrollment_adapter_acceptance_cannot_claim_cleanup_success() -> None:
    request = _contract(
        "device-management-enrollment-deenrollment-adapter-request.v1.schema.json"
    )
    result = _contract(
        "device-management-enrollment-deenrollment-adapter-result.v1.schema.json"
    )
    receipt = _contract(
        "device-management-enrollment-deenrollment-receipt.v1.schema.json"
    )

    assert request["additionalProperties"] is False
    assert request["properties"]["provider_mutation_authorized"] == {"const": True}
    assert request["properties"]["credential_value_access_authorized"] == {"const": False}
    assert result["additionalProperties"] is False
    assert result["properties"]["state"] == {"const": "accepted"}
    assert receipt["additionalProperties"] is False
    assert receipt["properties"]["state"] == {"const": "provider-cleanup-accepted"}
    for schema in (result, receipt):
        assert schema["properties"]["post_cleanup_verified"] == {"const": False}
        assert schema["properties"]["retry_planning_allowed"] == {"const": False}
        assert schema["properties"]["retry_execution_authorized"] == {"const": False}
        assert schema["properties"]["managed_state_change_authorized"] == {"const": False}


def test_058_source_contains_verification_cleanup_and_deenrollment_boundaries() -> None:
    verification = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_verification.py"
    ).read_text(encoding="utf-8")
    verification_runtime = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_verification_runtime.py"
    ).read_text(encoding="utf-8")
    cleanup = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_cleanup.py"
    ).read_text(encoding="utf-8")
    de_enrollment = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_deenrollment.py"
    ).read_text(encoding="utf-8")

    assert "build_managed_state_replacement" in verification
    assert "DeviceManagementEnrollmentVerificationRuntimeService" in verification_runtime
    assert "create_action_job" in verification_runtime
    assert "provider-readback" in verification_runtime
    assert "post-condition-verified" in verification_runtime
    assert "credential_value_access_authorized\": False" in verification_runtime
    assert "provider_mutation_authorized\": False" in verification_runtime
    assert "policy_application_authorized\": False" in verification_runtime
    assert "external_publication_authorized\": False" in verification_runtime
    assert "build_managed_state_replacement" not in verification_runtime
    assert "build_failed_enrollment_cleanup_plan" in cleanup
    assert "assess_retry_after_cleanup" in cleanup
    assert "build_deenrollment_plan" in de_enrollment
    assert "confirm_deenrollment" in de_enrollment
    assert "build_deenrollment_adapter_request" in de_enrollment
    assert "build_deenrollment_receipt" in de_enrollment
    assert "retry_execution_authorized" in cleanup
    assert "retry_execution_authorized" in de_enrollment
    assert "provider_mutation_authorized" in de_enrollment
    assert "secret://" not in cleanup
    assert "secret://" not in de_enrollment
    assert "secret://" not in verification_runtime


def test_058_notes_keep_release_status_closed_and_describe_cleanup_boundary() -> None:
    notes = (ROOT / "docs/releases/0.58.0.md").read_text(encoding="utf-8")

    assert "не Release Candidate и не Public Stable" in notes
    assert "Failed-enrollment cleanup" in notes
    assert "Явный de-enrollment boundary" in notes
    assert "Durable post-condition verification runtime" in notes
    assert "de-enroll-required" in notes
    assert "retry_planning_allowed=true" in notes
    assert "retry_execution_authorized=false" in notes
    assert "не применяет" in notes
    assert "managed=true" in notes
    assert "не запускает CI или release workflow" in notes
