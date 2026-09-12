from __future__ import annotations

import pytest

from home_center.device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationError,
    request_from_dict,
    result_from_dict,
    verify_post_condition,
)


def _binding() -> dict[str, object]:
    return {
        "plan_id": "dmpexec-0123456789abcdef01234567",
        "provider_id": "android-mdm-primary",
        "provider_operation_id": "provider-op-1",
        "device_id": "device-phone",
        "member_id": "member-child",
        "execution_generation": 1,
    }


def _request() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-post-condition-request.v1",
        **_binding(),
        "requested_at": "2026-09-12T08:00:00Z",
        "max_observed_age_seconds": 300,
        "expected_signals": {
            "certificate": "present",
            "profile": "present",
            "agent": "not-applicable",
        },
    }


def _result() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-post-condition-result.v1",
        **_binding(),
        "observed_at": "2026-09-12T08:00:02Z",
        "status": "verified",
        "signals": {
            "certificate": "present",
            "profile": "present",
            "agent": "not-applicable",
        },
        "provider_read_performed": True,
    }


def test_contract_parsers_round_trip_closed_payloads() -> None:
    request = _request()
    result = _result()
    assert request_from_dict(request).to_dict() == request
    assert result_from_dict(result).to_dict() == result


def test_verified_read_back_produces_content_addressed_managed_receipt() -> None:
    evidence, receipt = verify_post_condition(
        request=_request(),
        result=_result(),
        now="2026-09-12T08:00:03Z",
        job_id="job-verify-1",
    )
    assert evidence.verified is True
    assert evidence.failure_reason is None
    assert len(evidence.result_sha256) == 64
    value = receipt.to_dict()
    assert value["state"] == "verified"
    assert value["enrollment_completed"] is True
    assert value["post_condition_verified"] is True
    assert value["managed_state_change_authorized"] is True
    assert value["cleanup_required"] is False
    assert value["policy_application_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("plan_id", "dmpexec-aaaaaaaaaaaaaaaaaaaaaaaa"),
        ("provider_operation_id", "different-operation"),
        ("device_id", "different-device"),
        ("member_id", "different-member"),
        ("execution_generation", 2),
    ),
)
def test_exact_binding_mismatch_is_fail_closed(field: str, value: object) -> None:
    result = _result()
    result[field] = value
    evidence, receipt = verify_post_condition(
        request=_request(),
        result=result,
        now="2026-09-12T08:00:03Z",
        job_id="job-binding",
    )
    assert evidence.verified is False
    assert evidence.failure_reason == "binding-mismatch"
    assert receipt.to_dict()["managed_state_change_authorized"] is False
    assert receipt.to_dict()["cleanup_required"] is True


def test_future_observation_is_fail_closed() -> None:
    result = _result()
    result["observed_at"] = "2026-09-12T08:00:04Z"
    evidence, receipt = verify_post_condition(
        request=_request(),
        result=result,
        now="2026-09-12T08:00:03Z",
        job_id="job-future",
    )
    assert evidence.failure_reason == "future-observation"
    assert receipt.to_dict()["state"] == "rejected"


def test_stale_observation_is_fail_closed() -> None:
    request = _request()
    request["max_observed_age_seconds"] = 5
    result = _result()
    result["observed_at"] = "2026-09-12T07:59:00Z"
    evidence, receipt = verify_post_condition(
        request=request,
        result=result,
        now="2026-09-12T08:00:03Z",
        job_id="job-stale",
    )
    assert evidence.failure_reason == "stale-observation"
    assert receipt.to_dict()["enrollment_completed"] is False


@pytest.mark.parametrize(
    ("status", "failure"),
    (
        ("ambiguous", "ambiguous"),
        ("not-enrolled", "not-enrolled"),
        ("stale", "stale-observation"),
        ("not-verified", "signal-mismatch"),
    ),
)
def test_provider_negative_status_never_authorizes_managed_state(status: str, failure: str) -> None:
    result = _result()
    result["status"] = status
    evidence, receipt = verify_post_condition(
        request=_request(),
        result=result,
        now="2026-09-12T08:00:03Z",
        job_id=f"job-{status}",
    )
    assert evidence.failure_reason == failure
    assert receipt.to_dict()["managed_state_change_authorized"] is False


def test_signal_mismatch_requires_cleanup() -> None:
    result = _result()
    result["signals"] = dict(result["signals"])
    result["signals"]["profile"] = "absent"
    evidence, receipt = verify_post_condition(
        request=_request(),
        result=result,
        now="2026-09-12T08:00:03Z",
        job_id="job-signal",
    )
    assert evidence.failure_reason == "signal-mismatch"
    assert receipt.to_dict()["cleanup_required"] is True


def test_unknown_provider_signal_never_verifies() -> None:
    result = _result()
    result["signals"] = dict(result["signals"])
    result["signals"]["certificate"] = "unknown"
    evidence, _ = verify_post_condition(
        request=_request(),
        result=result,
        now="2026-09-12T08:00:03Z",
        job_id="job-unknown",
    )
    assert evidence.failure_reason == "signal-mismatch"


def test_result_requires_explicit_provider_read() -> None:
    result = _result()
    result["provider_read_performed"] = False
    with pytest.raises(DeviceManagementEnrollmentVerificationError, match="result_rejected"):
        result_from_dict(result)


def test_unknown_or_secret_fields_are_rejected() -> None:
    request = _request()
    request["credential_value"] = "secret"
    with pytest.raises(DeviceManagementEnrollmentVerificationError, match="request_rejected"):
        request_from_dict(request)


def test_invalid_or_impossible_timestamp_is_rejected() -> None:
    result = _result()
    result["observed_at"] = "2026-02-31T08:00:02Z"
    with pytest.raises(DeviceManagementEnrollmentVerificationError, match="result_rejected"):
        result_from_dict(result)


def test_evidence_digest_is_deterministic() -> None:
    first, first_receipt = verify_post_condition(
        request=_request(),
        result=_result(),
        now="2026-09-12T08:00:03Z",
        job_id="job-repeat",
    )
    second, second_receipt = verify_post_condition(
        request=_request(),
        result=_result(),
        now="2026-09-12T08:00:03Z",
        job_id="job-repeat",
    )
    assert first.to_dict() == second.to_dict()
    assert first_receipt.to_dict() == second_receipt.to_dict()
