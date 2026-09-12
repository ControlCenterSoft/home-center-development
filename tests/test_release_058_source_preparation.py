from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/devices"


def _contract(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def test_058_verification_requests_are_closed_and_cannot_supply_provider_evidence() -> None:
    plan = _contract("device-management-enrollment-verification-plan-request.v1.schema.json")
    verify = _contract("device-management-enrollment-verification-request.v1.schema.json")

    assert plan["additionalProperties"] is False
    assert verify["additionalProperties"] is False
    assert set(plan["required"]) == {"schema", "execution_plan_id", "execution_job_id"}
    assert set(verify["required"]) == {"schema", "verification_id"}

    serialized = json.dumps({"plan": plan, "verify": verify}, sort_keys=True).lower()
    for forbidden in (
        "required_checks",
        "provider_observation",
        "certificate",
        "profile",
        "agent",
        "credential",
        "secret",
        "managed_state_change_authorized",
    ):
        assert forbidden not in serialized


def test_058_provider_observation_is_closed_read_only_evidence() -> None:
    schema = _contract("device-management-enrollment-provider-observation.v1.schema.json")
    assert schema["additionalProperties"] is False
    assert schema["properties"]["read_only"] == {"const": True}
    assert schema["properties"]["provider_state"]["enum"] == [
        "enrolled",
        "not-enrolled",
        "cancelled",
        "unknown",
    ]
    checks = schema["properties"]["checks"]
    assert checks["additionalProperties"] is False
    assert set(checks["required"]) == {"certificate", "profile", "agent"}


def test_058_verification_result_keeps_non_enrollment_authority_closed() -> None:
    schema = _contract("device-management-enrollment-verification-result.v1.schema.json")
    assert schema["additionalProperties"] is False
    for field in (
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert schema["properties"][field] == {"const": False}

    branches = schema["allOf"]
    verified = branches[0]["then"]["properties"]
    rejected = branches[1]["then"]["properties"]
    assert verified["enrollment_completed"] == {"const": True}
    assert verified["post_condition_verified"] == {"const": True}
    assert verified["managed_state_change_authorized"] == {"const": True}
    assert rejected["enrollment_completed"] == {"const": False}
    assert rejected["post_condition_verified"] == {"const": False}
    assert rejected["managed_state_change_authorized"] == {"const": False}


def test_058_managed_transition_contracts_keep_other_authority_closed() -> None:
    plan = _contract(
        "device-management-enrollment-managed-transition-plan.v1.schema.json"
    )
    receipt = _contract(
        "device-management-enrollment-managed-transition-receipt.v1.schema.json"
    )

    assert plan["additionalProperties"] is False
    assert receipt["additionalProperties"] is False
    assert plan["properties"]["managed_before"] == {"const": False}
    assert plan["properties"]["managed_after"] == {"const": True}
    assert plan["properties"]["post_condition_verified"] == {"const": True}
    assert receipt["properties"]["managed"] == {"const": True}
    assert receipt["properties"]["post_condition_verified"] == {"const": True}

    for schema in (plan, receipt):
        for field in (
            "policy_application_authorized",
            "provider_mutation_authorized",
            "infrastructure_mutation_authorized",
            "external_publication_authorized",
        ):
            assert schema["properties"][field] == {"const": False}


def test_058_trusted_verification_profile_contract_cannot_grant_authority() -> None:
    profile = _contract(
        "device-management-enrollment-verification-profile.v1.schema.json"
    )
    catalog = _contract(
        "device-management-enrollment-verification-profile-catalog.v1.schema.json"
    )
    assert profile["additionalProperties"] is False
    assert catalog["additionalProperties"] is False
    assert profile["properties"]["trusted"] == {"const": True}
    assert profile["properties"]["read_only"] == {"const": True}
    assert profile["properties"]["required_checks"]["items"] == {
        "enum": ["certificate", "profile", "agent"]
    }
    for field in (
        "provider_mutation_authorized",
        "credential_access_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert profile["properties"][field] == {"const": False}


def test_058_failed_enrollment_cleanup_is_plan_only_and_retry_closed() -> None:
    cleanup = _contract("device-management-enrollment-cleanup-plan.v1.schema.json")
    assert cleanup["additionalProperties"] is False
    assert cleanup["properties"]["action"]["enum"] == [
        "observe-provider-state",
        "no-provider-cleanup",
        "de-enroll-required",
    ]
    for field in (
        "provider_mutation_authorized",
        "retry_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert cleanup["properties"][field] == {"const": False}


def test_058_notes_keep_release_status_closed_and_describe_exact_cas_boundary() -> None:
    notes = (ROOT / "docs/releases/0.58.0.md").read_text(encoding="utf-8")
    assert "не Release Candidate и не Public Stable" in notes
    assert "ManagedDevice.managed: false -> true" in notes
    assert "CAS-precondition" in notes
    assert "не применяет результат к production store" in notes
    assert "trusted verification profile" in notes
    assert "retry_authorized=false" in notes
    assert "не запускает de-enrollment автоматически" in notes
    assert "policy application" in notes
    assert "external publication" in notes
