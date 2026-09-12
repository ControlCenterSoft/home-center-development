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


def test_058_source_contains_verification_cleanup_and_safe_retry_boundaries() -> None:
    verification = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_verification.py"
    ).read_text(encoding="utf-8")
    cleanup = (
        ROOT
        / "product/control-plane/src/home_center/device_management_enrollment_cleanup.py"
    ).read_text(encoding="utf-8")

    assert "build_managed_state_replacement" in verification
    assert "build_failed_enrollment_cleanup_plan" in cleanup
    assert "assess_retry_after_cleanup" in cleanup
    assert "retry_execution_authorized" in cleanup
    assert "provider_mutation_authorized" in cleanup
    assert "secret://" not in cleanup


def test_058_notes_keep_release_status_closed_and_describe_cleanup_boundary() -> None:
    notes = (ROOT / "docs/releases/0.58.0.md").read_text(encoding="utf-8")

    assert "не Release Candidate и не Public Stable" in notes
    assert "Failed-enrollment cleanup" in notes
    assert "de-enroll-required" in notes
    assert "retry_planning_allowed=true" in notes
    assert "retry_execution_authorized=false" in notes
    assert "не выполняет de-enrollment provider command" in notes
    assert "не запускает CI или release workflow" in notes
