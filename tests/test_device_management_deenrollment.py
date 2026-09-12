from __future__ import annotations

import pytest

from home_center.device_management_deenrollment import (
    DeviceManagementDeenrollmentError,
    authorize_failed_enrollment_cleanup,
    build_deenrollment_plan,
    build_failed_enrollment_cleanup_plan,
    cleanup_readback_from_dict,
    confirm_deenrollment,
    readback_from_dict,
    verify_deenrollment,
)


def _verification_receipt(*, verified: bool = True) -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
        "state": "verified" if verified else "rejected",
        "job_id": "job-enroll-1",
        "plan_id": "dmpexec-0123456789abcdef01234567",
        "provider_id": "android-mdm-primary",
        "provider_operation_id": "provider-op-1",
        "device_id": "device-phone",
        "member_id": "member-child",
        "execution_generation": 1,
        "evidence_sha256": "a" * 64,
        "enrollment_completed": verified,
        "post_condition_verified": verified,
        "managed_state_change_authorized": verified,
        "cleanup_required": not verified,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _plan():
    return build_deenrollment_plan(
        verification_receipt=_verification_receipt(),
        household_id="household-main",
        snapshot_id="snapshot-11",
        resource_version="rv-11",
        generation=11,
        actor_member_id="member-parent",
        requested_at="2026-09-12T08:10:00Z",
    )


def _readback(plan_id: str, *, state: str = "unmanaged") -> dict[str, object]:
    return {
        "schema": "home-center.device-management-deenrollment-readback-result.v1",
        "plan_id": plan_id,
        "provider_id": "android-mdm-primary",
        "provider_operation_id": "provider-op-1",
        "device_id": "device-phone",
        "member_id": "member-child",
        "observed_at": "2026-09-12T08:10:05Z",
        "state": state,
        "provider_read_performed": True,
    }


def _cleanup_readback(plan_id: str, *, state: str = "unmanaged") -> dict[str, object]:
    return {
        "schema": "home-center.device-management-failed-enrollment-cleanup-readback-result.v1",
        "plan_id": plan_id,
        "provider_id": "android-mdm-primary",
        "provider_operation_id": "provider-op-1",
        "device_id": "device-phone",
        "member_id": "member-child",
        "observed_at": "2026-09-12T08:20:05Z",
        "state": state,
        "provider_read_performed": True,
    }


def test_deenrollment_plan_requires_verified_enrollment_evidence() -> None:
    with pytest.raises(DeviceManagementDeenrollmentError, match="verification_receipt_invalid"):
        build_deenrollment_plan(
            verification_receipt=_verification_receipt(verified=False),
            household_id="household-main",
            snapshot_id="snapshot-11",
            resource_version="rv-11",
            generation=11,
            actor_member_id="member-parent",
            requested_at="2026-09-12T08:10:00Z",
        )


def test_deenrollment_plan_is_deterministic_and_authority_stays_closed() -> None:
    first = _plan()
    second = _plan()
    assert first.to_dict() == second.to_dict()
    value = first.to_dict()
    assert value["confirmation_required"] is True
    assert value["provider_mutation_authorized"] is False
    assert value["managed_state_change_authorized"] is False
    assert value["policy_mutation_authorized"] is False
    assert value["device_record_removal_authorized"] is False
    assert value["external_publication_authorized"] is False


def test_confirmation_authorizes_only_provider_mutation_and_never_automatic_retry() -> None:
    plan = _plan()
    confirmation = confirm_deenrollment(
        plan=plan,
        actor_member_id="member-parent",
        confirmed_at="2026-09-12T08:10:01Z",
    ).to_dict()
    assert confirmation["provider_mutation_authorized"] is True
    assert confirmation["managed_state_change_authorized"] is False
    assert confirmation["automatic_retry_authorized"] is False
    assert confirmation["credential_value_access_authorized"] is False


@pytest.mark.parametrize("state", ["unmanaged", "absent"])
def test_deenrollment_succeeds_only_after_fresh_readback(state: str) -> None:
    plan = _plan()
    confirmation = confirm_deenrollment(
        plan=plan,
        actor_member_id="member-parent",
        confirmed_at="2026-09-12T08:10:01Z",
    )
    receipt = verify_deenrollment(
        plan=plan,
        confirmation=confirmation,
        readback=_readback(plan.plan_id, state=state),
        now="2026-09-12T08:10:06Z",
        job_id="job-deenroll-1",
    ).to_dict()
    assert receipt["state"] == "verified"
    assert receipt["deenrollment_completed"] is True
    assert receipt["managed_state_change_authorized"] is True
    assert receipt["automatic_provider_retry_authorized"] is False


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        ("managed", "provider-still-managed"),
        ("unknown", "provider-state-unknown"),
        ("ambiguous", "provider-state-ambiguous"),
    ],
)
def test_non_terminal_readback_is_fail_closed(state: str, reason: str) -> None:
    plan = _plan()
    confirmation = confirm_deenrollment(
        plan=plan,
        actor_member_id="member-parent",
        confirmed_at="2026-09-12T08:10:01Z",
    )
    receipt = verify_deenrollment(
        plan=plan,
        confirmation=confirmation,
        readback=_readback(plan.plan_id, state=state),
        now="2026-09-12T08:10:06Z",
        job_id="job-deenroll-1",
    ).to_dict()
    assert receipt["state"] == "rejected"
    assert receipt["failure_reason"] == reason
    assert receipt["managed_state_change_authorized"] is False
    assert receipt["recovery_required"] is True


def test_readback_requires_explicit_provider_read_and_rejects_extra_fields() -> None:
    value = _readback(_plan().plan_id)
    value["provider_read_performed"] = False
    with pytest.raises(DeviceManagementDeenrollmentError, match="readback_rejected"):
        readback_from_dict(value)
    value = _readback(_plan().plan_id)
    value["secret"] = "never"
    with pytest.raises(DeviceManagementDeenrollmentError, match="readback_rejected"):
        readback_from_dict(value)


def test_binding_mismatch_never_changes_managed_state() -> None:
    plan = _plan()
    confirmation = confirm_deenrollment(
        plan=plan,
        actor_member_id="member-parent",
        confirmed_at="2026-09-12T08:10:01Z",
    )
    value = _readback(plan.plan_id)
    value["device_id"] = "other-device"
    receipt = verify_deenrollment(
        plan=plan,
        confirmation=confirmation,
        readback=value,
        now="2026-09-12T08:10:06Z",
        job_id="job-deenroll-1",
    ).to_dict()
    assert receipt["failure_reason"] == "binding-mismatch"
    assert receipt["managed_state_change_authorized"] is False


def test_cleanup_readback_requires_explicit_provider_read() -> None:
    plan = build_failed_enrollment_cleanup_plan(
        rejected_verification_receipt=_verification_receipt(verified=False),
        cleanup_generation=2,
        created_at="2026-09-12T08:20:00Z",
    )
    value = _cleanup_readback(plan.plan_id)
    value["provider_read_performed"] = False
    with pytest.raises(DeviceManagementDeenrollmentError, match="cleanup_readback_rejected"):
        cleanup_readback_from_dict(value)


def test_cleanup_plan_requires_rejected_nr1_evidence() -> None:
    plan = build_failed_enrollment_cleanup_plan(
        rejected_verification_receipt=_verification_receipt(verified=False),
        cleanup_generation=2,
        created_at="2026-09-12T08:20:00Z",
    )
    value = plan.to_dict()
    assert value["provider_read_required"] is True
    assert value["transient_cleanup_authorized"] is False
    assert value["managed_state_change_authorized"] is False
    assert value["provider_mutation_authorized"] is False


@pytest.mark.parametrize("state", ["unmanaged", "absent"])
def test_cleanup_only_authorizes_bounded_transient_cleanup_when_provider_is_not_managed(state: str) -> None:
    plan = build_failed_enrollment_cleanup_plan(
        rejected_verification_receipt=_verification_receipt(verified=False),
        cleanup_generation=2,
        created_at="2026-09-12T08:20:00Z",
    )
    receipt = authorize_failed_enrollment_cleanup(
        plan=plan,
        readback=_cleanup_readback(plan.plan_id, state=state),
        now="2026-09-12T08:20:06Z",
    ).to_dict()
    assert receipt["state"] == "authorized"
    assert receipt["transient_cleanup_authorized"] is True
    assert receipt["managed_state_change_authorized"] is False
    assert receipt["provider_mutation_authorized"] is False


def test_cleanup_escalates_to_explicit_deenrollment_if_provider_still_managed() -> None:
    plan = build_failed_enrollment_cleanup_plan(
        rejected_verification_receipt=_verification_receipt(verified=False),
        cleanup_generation=2,
        created_at="2026-09-12T08:20:00Z",
    )
    receipt = authorize_failed_enrollment_cleanup(
        plan=plan,
        readback=_cleanup_readback(plan.plan_id, state="managed"),
        now="2026-09-12T08:20:06Z",
    ).to_dict()
    assert receipt["transient_cleanup_authorized"] is False
    assert receipt["escalation_to_deenrollment_required"] is True


@pytest.mark.parametrize("state", ["unknown", "ambiguous"])
def test_cleanup_unknown_or_ambiguous_state_changes_nothing(state: str) -> None:
    plan = build_failed_enrollment_cleanup_plan(
        rejected_verification_receipt=_verification_receipt(verified=False),
        cleanup_generation=2,
        created_at="2026-09-12T08:20:00Z",
    )
    receipt = authorize_failed_enrollment_cleanup(
        plan=plan,
        readback=_cleanup_readback(plan.plan_id, state=state),
        now="2026-09-12T08:20:06Z",
    ).to_dict()
    assert receipt["state"] == "blocked"
    assert receipt["transient_cleanup_authorized"] is False
    assert receipt["escalation_to_deenrollment_required"] is False
