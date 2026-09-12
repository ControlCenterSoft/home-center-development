from __future__ import annotations

import json
from pathlib import Path

import pytest

from home_center.device_management_enrollment_cleanup import (
    DeviceManagementEnrollmentCleanupError,
    build_failed_enrollment_cleanup_plan,
)
from home_center.device_management_enrollment_verification import (
    build_enrollment_verification_plan,
    evaluate_enrollment_post_condition,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts/devices"


def _receipt() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-execution-receipt.v1",
        "state": "provider-accepted",
        "job_id": "job-057-start",
        "retry_of_job_id": None,
        "plan_id": "dmpexec-1234567890abcdef12345678",
        "selection_proposal_id": "dmpsel-1234567890abcdef12345678",
        "provider_id": "android-mdm",
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


def _plan():
    return build_enrollment_verification_plan(
        execution_receipt=_receipt(),
        household_id="household-1",
        snapshot_id="snapshot-10",
        resource_version="rv-10",
        generation=10,
        actor_member_id="member-parent",
        required_checks=["profile", "agent"],
    )


def _observation(
    *,
    provider_state: str = "enrolled",
    profile: str = "present",
    agent: str = "present",
) -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-provider-observation.v1",
        "provider_id": "android-mdm",
        "provider_operation_id": "op-123",
        "device_id": "device-1",
        "provider_state": provider_state,
        "checks": {
            "certificate": "not-applicable",
            "profile": profile,
            "agent": agent,
        },
        "observed_at": "2026-09-12T00:00:00Z",
        "read_only": True,
    }


def test_unknown_provider_state_requires_observation_not_mutation_or_retry() -> None:
    result = evaluate_enrollment_post_condition(
        _plan(), _observation(provider_state="unknown")
    )
    cleanup = build_failed_enrollment_cleanup_plan(
        result,
        actor_member_id="member-parent",
    ).to_dict()
    assert cleanup["action"] == "observe-provider-state"
    assert cleanup["explicit_confirmation_required"] is False
    assert cleanup["provider_mutation_authorized"] is False
    assert cleanup["retry_authorized"] is False
    assert cleanup["managed_state_change_authorized"] is False


def test_absent_provider_enrollment_needs_no_provider_cleanup_but_retry_stays_closed() -> None:
    result = evaluate_enrollment_post_condition(
        _plan(), _observation(provider_state="not-enrolled")
    )
    cleanup = build_failed_enrollment_cleanup_plan(
        result,
        actor_member_id="member-parent",
    ).to_dict()
    assert cleanup["action"] == "no-provider-cleanup"
    assert cleanup["explicit_confirmation_required"] is False
    assert cleanup["provider_mutation_authorized"] is False
    assert cleanup["retry_authorized"] is False


def test_incomplete_enrolled_state_requires_separately_confirmed_de_enrollment() -> None:
    result = evaluate_enrollment_post_condition(
        _plan(), _observation(profile="missing")
    )
    cleanup = build_failed_enrollment_cleanup_plan(
        result,
        actor_member_id="member-parent",
    ).to_dict()
    assert cleanup["action"] == "de-enroll-required"
    assert cleanup["explicit_confirmation_required"] is True
    assert cleanup["provider_mutation_authorized"] is False
    assert cleanup["retry_authorized"] is False
    assert cleanup["policy_application_authorized"] is False
    assert cleanup["infrastructure_mutation_authorized"] is False
    assert cleanup["external_publication_authorized"] is False


def test_successful_verification_cannot_be_reinterpreted_as_cleanup() -> None:
    result = evaluate_enrollment_post_condition(_plan(), _observation())
    with pytest.raises(
        DeviceManagementEnrollmentCleanupError,
        match="device_management_enrollment_cleanup_not_required",
    ):
        build_failed_enrollment_cleanup_plan(
            result,
            actor_member_id="member-parent",
        )


def test_cleanup_identity_is_bound_to_actor_and_exact_verification_evidence() -> None:
    result = evaluate_enrollment_post_condition(
        _plan(), _observation(profile="missing")
    )
    first = build_failed_enrollment_cleanup_plan(
        result,
        actor_member_id="member-parent",
    )
    second = build_failed_enrollment_cleanup_plan(
        result,
        actor_member_id="member-other-parent",
    )
    assert first.cleanup_id != second.cleanup_id


def test_cleanup_contract_is_closed_and_never_authorizes_retry_or_mutation() -> None:
    schema = json.loads(
        (CONTRACTS / "device-management-enrollment-cleanup-plan.v1.schema.json")
        .read_text(encoding="utf-8")
    )
    assert schema["additionalProperties"] is False
    for name in (
        "provider_mutation_authorized",
        "retry_authorized",
        "managed_state_change_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        assert schema["properties"][name] == {"const": False}
