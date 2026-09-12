"""Fail-closed provider-neutral post-condition verification contracts for Home Center 0.58.

Provider command acceptance is never treated as proof that enrollment succeeded.  This
module validates an explicit provider read-back, binds it to the exact enrollment
execution identity, evaluates freshness/signals, and produces content-addressed
verification evidence plus a bounded receipt.

No secret value, policy authority, infrastructure mutation, or external publication
authority crosses this boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


REQUEST_SCHEMA = "home-center.device-management-enrollment-post-condition-request.v1"
RESULT_SCHEMA = "home-center.device-management-enrollment-post-condition-result.v1"
EVIDENCE_SCHEMA = "home-center.device-management-enrollment-post-condition-evidence.v1"
RECEIPT_SCHEMA = "home-center.device-management-enrollment-post-condition-verification-receipt.v1"

PLAN_ID = re.compile(r"^dmpexec-[0-9a-f]{24}$")
PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_SIGNALS = frozenset({"present", "absent", "not-applicable"})
OBSERVED_SIGNALS = EXPECTED_SIGNALS | {"unknown"}
RESULT_STATUSES = frozenset({"verified", "not-verified", "ambiguous", "not-enrolled", "stale"})
FAILURE_REASONS = frozenset(
    {
        "binding-mismatch",
        "future-observation",
        "stale-observation",
        "ambiguous",
        "not-enrolled",
        "signal-mismatch",
        "provider-unavailable",
    }
)
SIGNAL_NAMES = ("certificate", "profile", "agent")


class DeviceManagementEnrollmentVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class PostConditionBinding:
    plan_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    member_id: str
    execution_generation: int

    def to_dict(self) -> dict[str, object]:
        return {
            "plan_id": self.plan_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "execution_generation": self.execution_generation,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentPostConditionRequest:
    binding: PostConditionBinding
    requested_at: str
    max_observed_age_seconds: int
    expected_signals: tuple[tuple[str, str], ...]
    schema: str = field(default=REQUEST_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            **self.binding.to_dict(),
            "requested_at": self.requested_at,
            "max_observed_age_seconds": self.max_observed_age_seconds,
            "expected_signals": dict(self.expected_signals),
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentPostConditionResult:
    binding: PostConditionBinding
    observed_at: str
    status: str
    signals: tuple[tuple[str, str], ...]
    schema: str = field(default=RESULT_SCHEMA, init=False)
    provider_read_performed: bool = field(default=True, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            **self.binding.to_dict(),
            "observed_at": self.observed_at,
            "status": self.status,
            "signals": dict(self.signals),
            "provider_read_performed": True,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentPostConditionEvidence:
    binding: PostConditionBinding
    observed_at: str
    verified: bool
    failure_reason: str | None
    result_sha256: str
    schema: str = field(default=EVIDENCE_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            **self.binding.to_dict(),
            "observed_at": self.observed_at,
            "verified": self.verified,
            "failure_reason": self.failure_reason,
            "result_sha256": self.result_sha256,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationReceipt:
    job_id: str
    binding: PostConditionBinding
    evidence_sha256: str
    verified: bool
    schema: str = field(default=RECEIPT_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "verified" if self.verified else "rejected",
            "job_id": self.job_id,
            **self.binding.to_dict(),
            "evidence_sha256": self.evidence_sha256,
            "enrollment_completed": self.verified,
            "post_condition_verified": self.verified,
            "managed_state_change_authorized": self.verified,
            "cleanup_required": not self.verified,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _closed_dict(value: object, expected: set[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentVerificationError(code)
    return dict(value)


def _nonempty_string(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeviceManagementEnrollmentVerificationError(code)
    return value


def _timestamp(value: object, code: str) -> str:
    if not isinstance(value, str) or RFC3339_UTC_SECONDS.fullmatch(value) is None:
        raise DeviceManagementEnrollmentVerificationError(code)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise DeviceManagementEnrollmentVerificationError(code) from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _binding(value: dict[str, object], code: str) -> PostConditionBinding:
    plan_id = value.get("plan_id")
    provider_id = value.get("provider_id")
    operation_id = value.get("provider_operation_id")
    device_id = value.get("device_id")
    member_id = value.get("member_id")
    generation = value.get("execution_generation")
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise DeviceManagementEnrollmentVerificationError(code)
    if not isinstance(provider_id, str) or PROVIDER_ID.fullmatch(provider_id) is None:
        raise DeviceManagementEnrollmentVerificationError(code)
    if not isinstance(operation_id, str) or PROVIDER_OPERATION_ID.fullmatch(operation_id) is None:
        raise DeviceManagementEnrollmentVerificationError(code)
    if not isinstance(device_id, str) or not device_id or len(device_id) > 256:
        raise DeviceManagementEnrollmentVerificationError(code)
    if not isinstance(member_id, str) or not member_id or len(member_id) > 256:
        raise DeviceManagementEnrollmentVerificationError(code)
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise DeviceManagementEnrollmentVerificationError(code)
    return PostConditionBinding(
        plan_id=plan_id,
        provider_id=provider_id,
        provider_operation_id=operation_id,
        device_id=device_id,
        member_id=member_id,
        execution_generation=generation,
    )


def _signals(value: object, *, observed: bool, code: str) -> tuple[tuple[str, str], ...]:
    raw = _closed_dict(value, set(SIGNAL_NAMES), code)
    allowed = OBSERVED_SIGNALS if observed else EXPECTED_SIGNALS
    items: list[tuple[str, str]] = []
    for name in SIGNAL_NAMES:
        signal = raw.get(name)
        if not isinstance(signal, str) or signal not in allowed:
            raise DeviceManagementEnrollmentVerificationError(code)
        items.append((name, signal))
    return tuple(items)


def request_from_dict(value: object) -> DeviceManagementEnrollmentPostConditionRequest:
    expected = {
        "schema",
        "plan_id",
        "provider_id",
        "provider_operation_id",
        "device_id",
        "member_id",
        "execution_generation",
        "requested_at",
        "max_observed_age_seconds",
        "expected_signals",
    }
    raw = _closed_dict(value, expected, "device_management_post_condition_request_rejected")
    if raw.get("schema") != REQUEST_SCHEMA:
        raise DeviceManagementEnrollmentVerificationError("device_management_post_condition_request_rejected")
    binding = _binding(raw, "device_management_post_condition_request_rejected")
    requested_at = _timestamp(raw.get("requested_at"), "device_management_post_condition_request_rejected")
    max_age = raw.get("max_observed_age_seconds")
    if isinstance(max_age, bool) or not isinstance(max_age, int) or not 1 <= max_age <= 3600:
        raise DeviceManagementEnrollmentVerificationError("device_management_post_condition_request_rejected")
    request = DeviceManagementEnrollmentPostConditionRequest(
        binding=binding,
        requested_at=requested_at,
        max_observed_age_seconds=max_age,
        expected_signals=_signals(
            raw.get("expected_signals"),
            observed=False,
            code="device_management_post_condition_request_rejected",
        ),
    )
    if request.to_dict() != raw:
        raise DeviceManagementEnrollmentVerificationError("device_management_post_condition_request_rejected")
    return request


def result_from_dict(value: object) -> DeviceManagementEnrollmentPostConditionResult:
    expected = {
        "schema",
        "plan_id",
        "provider_id",
        "provider_operation_id",
        "device_id",
        "member_id",
        "execution_generation",
        "observed_at",
        "status",
        "signals",
        "provider_read_performed",
    }
    raw = _closed_dict(value, expected, "device_management_post_condition_result_rejected")
    status = raw.get("status")
    if (
        raw.get("schema") != RESULT_SCHEMA
        or not isinstance(status, str)
        or status not in RESULT_STATUSES
        or raw.get("provider_read_performed") is not True
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_post_condition_result_rejected")
    result = DeviceManagementEnrollmentPostConditionResult(
        binding=_binding(raw, "device_management_post_condition_result_rejected"),
        observed_at=_timestamp(raw.get("observed_at"), "device_management_post_condition_result_rejected"),
        status=status,
        signals=_signals(
            raw.get("signals"),
            observed=True,
            code="device_management_post_condition_result_rejected",
        ),
    )
    if result.to_dict() != raw:
        raise DeviceManagementEnrollmentVerificationError("device_management_post_condition_result_rejected")
    return result


def _canonical_sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _failure_reason(
    request: DeviceManagementEnrollmentPostConditionRequest,
    result: DeviceManagementEnrollmentPostConditionResult,
    *,
    now: str,
) -> str | None:
    if request.binding != result.binding:
        return "binding-mismatch"
    now_value = _timestamp_value(_timestamp(now, "device_management_post_condition_now_invalid"))
    observed = _timestamp_value(result.observed_at)
    if observed > now_value:
        return "future-observation"
    age = (now_value - observed).total_seconds()
    if age > request.max_observed_age_seconds:
        return "stale-observation"
    if result.status == "ambiguous":
        return "ambiguous"
    if result.status == "not-enrolled":
        return "not-enrolled"
    if result.status == "stale":
        return "stale-observation"
    if result.status != "verified":
        return "signal-mismatch"
    if dict(request.expected_signals) != dict(result.signals):
        return "signal-mismatch"
    return None


def verify_post_condition(
    *,
    request: object,
    result: object,
    now: str,
    job_id: str,
) -> tuple[DeviceManagementEnrollmentPostConditionEvidence, DeviceManagementEnrollmentVerificationReceipt]:
    parsed_request = request_from_dict(request)
    parsed_result = result_from_dict(result)
    job = _nonempty_string(job_id, "device_management_post_condition_job_id_invalid")
    if len(job) > 128:
        raise DeviceManagementEnrollmentVerificationError("device_management_post_condition_job_id_invalid")

    failure_reason = _failure_reason(parsed_request, parsed_result, now=now)
    verified = failure_reason is None
    result_sha = _canonical_sha256(parsed_result.to_dict())
    evidence = DeviceManagementEnrollmentPostConditionEvidence(
        binding=parsed_request.binding,
        observed_at=parsed_result.observed_at,
        verified=verified,
        failure_reason=failure_reason,
        result_sha256=result_sha,
    )
    evidence_sha = _canonical_sha256(evidence.to_dict())
    receipt = DeviceManagementEnrollmentVerificationReceipt(
        job_id=job,
        binding=parsed_request.binding,
        evidence_sha256=evidence_sha,
        verified=verified,
    )
    return evidence, receipt
