from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DIR = ROOT / "contracts/devices"


def _schema(name: str) -> dict[str, object]:
    return json.loads((CONTRACT_DIR / name).read_text(encoding="utf-8"))


def _binding() -> dict[str, object]:
    return {
        "plan_id": "dmpexec-0123456789abcdef01234567",
        "provider_id": "provider.example",
        "provider_operation_id": "operation-123",
        "device_id": "device-1",
        "member_id": "member-1",
        "execution_generation": 1,
    }


def _validate(name: str, value: dict[str, object]) -> None:
    jsonschema.Draft202012Validator(_schema(name)).validate(value)


def _request() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-post-condition-request.v1",
        **_binding(),
        "requested_at": "2026-09-12T07:50:00Z",
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
        "observed_at": "2026-09-12T07:50:02Z",
        "status": "verified",
        "signals": {
            "certificate": "present",
            "profile": "present",
            "agent": "not-applicable",
        },
        "provider_read_performed": True,
    }


def _evidence(*, verified: bool = True) -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-post-condition-evidence.v1",
        **_binding(),
        "observed_at": "2026-09-12T07:50:02Z",
        "verified": verified,
        "failure_reason": None if verified else "signal-mismatch",
        "result_sha256": "a" * 64,
    }


def _receipt(*, verified: bool = True) -> dict[str, object]:
    return {
        "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
        "state": "verified" if verified else "rejected",
        "job_id": "job-1",
        **_binding(),
        "evidence_sha256": "b" * 64,
        "enrollment_completed": verified,
        "post_condition_verified": verified,
        "managed_state_change_authorized": verified,
        "cleanup_required": not verified,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def test_post_condition_request_accepts_exact_closed_binding() -> None:
    _validate("device-management-enrollment-post-condition-request.v1.schema.json", _request())


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("plan_id", "dmpexec-not-a-digest"),
        ("execution_generation", 0),
        ("max_observed_age_seconds", 0),
    ),
)
def test_post_condition_request_rejects_invalid_identity_or_bounds(mutation: str, value: object) -> None:
    payload = _request()
    payload[mutation] = value
    with pytest.raises(jsonschema.ValidationError):
        _validate("device-management-enrollment-post-condition-request.v1.schema.json", payload)


def test_post_condition_request_rejects_unknown_fields() -> None:
    payload = _request()
    payload["secret_value"] = "must-never-cross-contract"
    with pytest.raises(jsonschema.ValidationError):
        _validate("device-management-enrollment-post-condition-request.v1.schema.json", payload)


def test_provider_result_requires_real_provider_read() -> None:
    _validate("device-management-enrollment-post-condition-result.v1.schema.json", _result())
    payload = _result()
    payload["provider_read_performed"] = False
    with pytest.raises(jsonschema.ValidationError):
        _validate("device-management-enrollment-post-condition-result.v1.schema.json", payload)


def test_verified_evidence_requires_null_failure_reason() -> None:
    _validate("device-management-enrollment-post-condition-evidence.v1.schema.json", _evidence())
    payload = _evidence()
    payload["failure_reason"] = "signal-mismatch"
    with pytest.raises(jsonschema.ValidationError):
        _validate("device-management-enrollment-post-condition-evidence.v1.schema.json", payload)


def test_rejected_evidence_requires_bounded_failure_reason() -> None:
    _validate("device-management-enrollment-post-condition-evidence.v1.schema.json", _evidence(verified=False))
    payload = _evidence(verified=False)
    payload["failure_reason"] = None
    with pytest.raises(jsonschema.ValidationError):
        _validate("device-management-enrollment-post-condition-evidence.v1.schema.json", payload)


def test_verified_receipt_allows_managed_transition_only_after_verification() -> None:
    _validate(
        "device-management-enrollment-post-condition-verification-receipt.v1.schema.json",
        _receipt(),
    )
    payload = _receipt()
    payload["managed_state_change_authorized"] = False
    with pytest.raises(jsonschema.ValidationError):
        _validate(
            "device-management-enrollment-post-condition-verification-receipt.v1.schema.json",
            payload,
        )


def test_rejected_receipt_is_fail_closed_and_requires_cleanup() -> None:
    _validate(
        "device-management-enrollment-post-condition-verification-receipt.v1.schema.json",
        _receipt(verified=False),
    )
    payload = _receipt(verified=False)
    payload["cleanup_required"] = False
    with pytest.raises(jsonschema.ValidationError):
        _validate(
            "device-management-enrollment-post-condition-verification-receipt.v1.schema.json",
            payload,
        )


@pytest.mark.parametrize(
    "field",
    ("policy_application_authorized", "infrastructure_mutation_authorized", "external_publication_authorized"),
)
def test_verification_receipt_never_grants_unrelated_authority(field: str) -> None:
    payload = _receipt()
    payload[field] = True
    with pytest.raises(jsonschema.ValidationError):
        _validate(
            "device-management-enrollment-post-condition-verification-receipt.v1.schema.json",
            payload,
        )
