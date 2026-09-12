from __future__ import annotations

from http import HTTPStatus

from home_center.household_policy_http import RuntimeRequestHandlerPolicy


def test_policy_http_integrity_failures_are_unavailable() -> None:
    codes = {
        "household_policy_composition_evidence_mismatch",
        "household_policy_proposal_collision",
        "household_policy_proposal_invalid",
        "household_policy_proposal_state_invalid",
        "household_policy_confirmation_required",
        "household_policy_confirmation_evidence_mismatch",
        "household_policy_desired_state_missing_after_apply",
        "household_policy_desired_state_write_failed",
        "household_policy_history_record_invalid",
        "household_policy_history_gap",
        "household_policy_history_audit_mismatch",
        "household_policy_rollback_evidence_mismatch",
        "household_policy_rollback_write_failed",
    }
    for code in codes:
        assert RuntimeRequestHandlerPolicy._policy_status(code) == HTTPStatus.SERVICE_UNAVAILABLE


def test_policy_http_stale_and_recovery_failures_are_conflicts() -> None:
    codes = {
        "household_policy_composition_stale",
        "household_policy_confirmation_recovery_required",
        "household_policy_proposal_invalidated",
        "household_policy_desired_state_precondition_failed",
        "household_policy_rollback_precondition_failed",
    }
    for code in codes:
        assert RuntimeRequestHandlerPolicy._policy_status(code) == HTTPStatus.CONFLICT


def test_policy_http_client_error_classes_remain_explicit() -> None:
    assert (
        RuntimeRequestHandlerPolicy._policy_status("household_policy_composition_not_authorized")
        == HTTPStatus.FORBIDDEN
    )
    assert (
        RuntimeRequestHandlerPolicy._policy_status("household_policy_history_not_found")
        == HTTPStatus.NOT_FOUND
    )
    assert (
        RuntimeRequestHandlerPolicy._policy_status("invalid_household_policy_rollback_request")
        == HTTPStatus.BAD_REQUEST
    )
