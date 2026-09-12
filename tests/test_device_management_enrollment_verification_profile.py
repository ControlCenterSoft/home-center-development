from __future__ import annotations

import json
from pathlib import Path

import pytest

from home_center.device_management_enrollment_verification_profile import (
    DeviceManagementEnrollmentVerificationProfileError,
    build_enrollment_verification_plan_from_profile,
    build_verification_profile,
    build_verification_profile_catalog,
    resolve_verification_profile,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/devices"


def _receipt(provider_id: str = "android-mdm") -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": "job-057-start",
        "retry_of_job_id": None,
        "plan_id": "dmpexec-1234567890abcdef12345678",
        "selection_proposal_id": "dmpsel-1234567890abcdef12345678",
        "provider_id": provider_id,
        "provider_operation_id": "op-123",
        "device_id": "device-1",
        "member_id": "member-1",
        "one_time_artifact": None,
        "enrollment_completed": False,
        "post_condition_verified": False,
        "managed_state_change_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _catalog():
    return build_verification_profile_catalog(
        [
            build_verification_profile(
                provider_id="android-mdm",
                required_checks=["profile", "agent"],
            ),
            build_verification_profile(
                provider_id="certificate-mdm",
                required_checks=["certificate", "profile"],
            ),
        ]
    )


def test_profile_is_deterministic_read_only_and_non_authorizing() -> None:
    first = build_verification_profile(
        provider_id="android-mdm",
        required_checks=["agent", "profile"],
    )
    second = build_verification_profile(
        provider_id="android-mdm",
        required_checks=["profile", "agent"],
    )
    assert first == second
    evidence = first.to_dict()
    assert evidence["required_checks"] == ["agent", "profile"]
    assert evidence["trusted"] is True
    assert evidence["read_only"] is True
    for name in (
        "provider_mutation_authorized",
        "credential_access_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert evidence[name] is False


def test_catalog_rejects_duplicate_provider_policy() -> None:
    profile = build_verification_profile(
        provider_id="android-mdm",
        required_checks=["profile"],
    )
    with pytest.raises(
        DeviceManagementEnrollmentVerificationProfileError,
        match="duplicate_device_management_enrollment_verification_profile",
    ):
        build_verification_profile_catalog([profile, profile])


def test_plan_uses_controller_profile_not_caller_selected_checks() -> None:
    plan = build_enrollment_verification_plan_from_profile(
        execution_receipt=_receipt(),
        household_id="household-1",
        snapshot_id="snapshot-10",
        resource_version="rv-10",
        generation=10,
        actor_member_id="member-parent",
        catalog=_catalog(),
    )
    assert plan.provider_id == "android-mdm"
    assert plan.required_checks == ("agent", "profile")
    assert plan.managed_state_change_authorized is False


def test_missing_provider_profile_fails_closed() -> None:
    with pytest.raises(
        DeviceManagementEnrollmentVerificationProfileError,
        match="device_management_enrollment_verification_profile_unavailable",
    ):
        build_enrollment_verification_plan_from_profile(
            execution_receipt=_receipt("unknown-provider"),
            household_id="household-1",
            snapshot_id="snapshot-10",
            resource_version="rv-10",
            generation=10,
            actor_member_id="member-parent",
            catalog=_catalog(),
        )


def test_resolution_is_exactly_one_profile_per_provider() -> None:
    profile = resolve_verification_profile(_catalog(), "certificate-mdm")
    assert profile.provider_id == "certificate-mdm"
    assert profile.required_checks == ("certificate", "profile")


def test_profile_contracts_are_closed_and_keep_authority_false() -> None:
    profile = json.loads(
        (CONTRACTS / "device-management-enrollment-verification-profile.v1.schema.json")
        .read_text(encoding="utf-8")
    )
    catalog = json.loads(
        (CONTRACTS / "device-management-enrollment-verification-profile-catalog.v1.schema.json")
        .read_text(encoding="utf-8")
    )
    assert profile["additionalProperties"] is False
    assert catalog["additionalProperties"] is False
    assert profile["properties"]["trusted"] == {"const": True}
    assert profile["properties"]["read_only"] == {"const": True}
    for name in (
        "provider_mutation_authorized",
        "credential_access_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert profile["properties"][name] == {"const": False}
