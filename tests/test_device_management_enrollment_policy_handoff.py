from __future__ import annotations

import copy

import pytest

from home_center.device_management_enrollment_policy_handoff import (
    HANDOFF_SCHEMA,
    DeviceManagementEnrollmentPolicyHandoffError,
    build_policy_handoff,
)


def _receipt() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-managed-state-commit-receipt.v1",
        "state": "managed-state-committed",
        "job_id": "job-managed-state-1",
        "verification_id": "dmpverify-0123456789abcdef01234567",
        "execution_job_id": "job-enrollment-1",
        "plan_id": "dmpexec-0123456789abcdef01234567",
        "household_id": "home-main",
        "device_id": "device-phone",
        "member_id": "member-child",
        "commit_id": "hcommit-0123456789abcdef01234567",
        "previous_resource_version": "hrv-0123456789abcdef01234567",
        "resource_version": "hrv-1123456789abcdef01234567",
        "generation": 2,
        "snapshot_id": "hsnap-0123456789abcdef01234567",
        "audit_event_id": "123e4567-e89b-12d3-a456-426614174000",
        "post_condition_verified": True,
        "managed_state_change_authorized": True,
        "managed_state_change_committed": True,
        "provider_mutation_authorized": False,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
        "audit_required": True,
    }


def test_policy_handoff_is_deterministic_and_never_authorizes_application() -> None:
    first = build_policy_handoff(_receipt()).to_dict()
    second = build_policy_handoff(_receipt()).to_dict()

    assert first == second
    assert first["schema"] == HANDOFF_SCHEMA
    assert first["handoff_id"].startswith("dmphandoff-")
    assert first["policy_context_ready"] is True
    assert first["separate_policy_plan_required"] is True
    assert first["separate_confirmation_required"] is True
    assert first["policy_application_authorized"] is False
    assert first["policy_execution_authorized"] is False
    assert first["provider_mutation_authorized"] is False
    assert first["infrastructure_mutation_authorized"] is False
    assert first["external_publication_authorized"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("post_condition_verified", False),
        ("managed_state_change_authorized", False),
        ("managed_state_change_committed", False),
        ("provider_mutation_authorized", True),
        ("policy_application_authorized", True),
        ("infrastructure_mutation_authorized", True),
        ("external_publication_authorized", True),
        ("audit_required", False),
    ],
)
def test_policy_handoff_rejects_tampered_authority(field: str, value: object) -> None:
    receipt = _receipt()
    receipt[field] = value

    with pytest.raises(
        DeviceManagementEnrollmentPolicyHandoffError,
        match="policy_handoff_receipt_invalid",
    ):
        build_policy_handoff(receipt)


def test_policy_handoff_rejects_unknown_fields_and_stale_resource_identity() -> None:
    receipt = _receipt()
    receipt["unexpected"] = True
    with pytest.raises(DeviceManagementEnrollmentPolicyHandoffError):
        build_policy_handoff(receipt)

    stale = copy.deepcopy(_receipt())
    stale["resource_version"] = stale["previous_resource_version"]
    with pytest.raises(DeviceManagementEnrollmentPolicyHandoffError):
        build_policy_handoff(stale)
