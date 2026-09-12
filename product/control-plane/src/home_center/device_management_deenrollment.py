"""Fail-closed de-enrollment and failed-enrollment cleanup contracts for Home Center 0.58.

This module extends the provider-neutral post-condition verification boundary. It never
treats provider command acceptance as proof of de-enrollment, never repeats an ambiguous
provider mutation automatically, and never allows cleanup to mutate managed state.

Concrete provider adapters, policy application, infrastructure mutation and external
publication remain outside this boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone


DEENROLLMENT_PLAN_SCHEMA = "home-center.device-management-deenrollment-plan.v1"
DEENROLLMENT_CONFIRMATION_SCHEMA = "home-center.device-management-deenrollment-confirmation.v1"
DEENROLLMENT_READBACK_SCHEMA = "home-center.device-management-deenrollment-readback-result.v1"
DEENROLLMENT_RECEIPT_SCHEMA = "home-center.device-management-deenrollment-verification-receipt.v1"
CLEANUP_PLAN_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-plan.v1"
CLEANUP_READBACK_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-readback-result.v1"
CLEANUP_RECEIPT_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-receipt.v1"
NR1_RECEIPT_SCHEMA = "home-center.device-management-enrollment-post-condition-verification-receipt.v1"

EXECUTION_PLAN_ID = re.compile(r"^dmpexec-[0-9a-f]{24}$")
DEENROLLMENT_PLAN_ID = re.compile(r"^dmdel-[0-9a-f]{24}$")
CLEANUP_PLAN_ID = re.compile(r"^dmclean-[0-9a-f]{24}$")
PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
READBACK_STATES = frozenset({"managed", "unmanaged", "absent", "unknown", "ambiguous"})
SUCCESS_READBACK_STATES = frozenset({"unmanaged", "absent"})


class DeviceManagementDeenrollmentError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class EnrollmentVerificationBinding:
    enrollment_plan_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    member_id: str
    execution_generation: int
    verification_evidence_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "enrollment_plan_id": self.enrollment_plan_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "execution_generation": self.execution_generation,
            "verification_evidence_sha256": self.verification_evidence_sha256,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementDeenrollmentPlan:
    plan_id: str
    binding: EnrollmentVerificationBinding
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    requested_at: str
    max_observed_age_seconds: int
    schema: str = field(default=DEENROLLMENT_PLAN_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            **self.binding.to_dict(),
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "requested_at": self.requested_at,
            "max_observed_age_seconds": self.max_observed_age_seconds,
            "confirmation_required": True,
            "provider_mutation_authorized": False,
            "managed_state_change_authorized": False,
            "policy_mutation_authorized": False,
            "device_record_removal_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementDeenrollmentConfirmation:
    plan_id: str
    actor_member_id: str
    confirmed_at: str
    plan_sha256: str
    schema: str = field(default=DEENROLLMENT_CONFIRMATION_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "actor_member_id": self.actor_member_id,
            "confirmed_at": self.confirmed_at,
            "plan_sha256": self.plan_sha256,
            "provider_mutation_authorized": True,
            "managed_state_change_authorized": False,
            "automatic_retry_authorized": False,
            "credential_value_access_authorized": False,
            "policy_mutation_authorized": False,
            "device_record_removal_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementDeenrollmentReadbackResult:
    plan_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    member_id: str
    observed_at: str
    state: str
    schema: str = field(default=DEENROLLMENT_READBACK_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "observed_at": self.observed_at,
            "state": self.state,
            "provider_read_performed": True,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementDeenrollmentVerificationReceipt:
    job_id: str
    plan_id: str
    readback_sha256: str
    verified: bool
    observed_state: str
    failure_reason: str | None
    schema: str = field(default=DEENROLLMENT_RECEIPT_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "verified" if self.verified else "rejected",
            "job_id": self.job_id,
            "plan_id": self.plan_id,
            "readback_sha256": self.readback_sha256,
            "observed_state": self.observed_state,
            "failure_reason": self.failure_reason,
            "deenrollment_completed": self.verified,
            "managed_state_change_authorized": self.verified,
            "recovery_required": not self.verified,
            "automatic_provider_retry_authorized": False,
            "policy_mutation_authorized": False,
            "device_record_removal_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementFailedEnrollmentCleanupPlan:
    plan_id: str
    enrollment_plan_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    member_id: str
    verification_evidence_sha256: str
    cleanup_generation: int
    created_at: str
    max_observed_age_seconds: int
    schema: str = field(default=CLEANUP_PLAN_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "enrollment_plan_id": self.enrollment_plan_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "verification_evidence_sha256": self.verification_evidence_sha256,
            "cleanup_generation": self.cleanup_generation,
            "created_at": self.created_at,
            "max_observed_age_seconds": self.max_observed_age_seconds,
            "provider_read_required": True,
            "transient_cleanup_authorized": False,
            "managed_state_change_authorized": False,
            "provider_mutation_authorized": False,
            "policy_mutation_authorized": False,
            "device_record_removal_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementFailedEnrollmentCleanupReadbackResult:
    plan_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    member_id: str
    observed_at: str
    state: str
    schema: str = field(default=CLEANUP_READBACK_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "observed_at": self.observed_at,
            "state": self.state,
            "provider_read_performed": True,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementFailedEnrollmentCleanupReceipt:
    plan_id: str
    readback_sha256: str
    provider_state: str
    cleanup_authorized: bool
    escalation_required: bool
    schema: str = field(default=CLEANUP_RECEIPT_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        state = "authorized" if self.cleanup_authorized else "blocked"
        return {
            "schema": self.schema,
            "state": state,
            "plan_id": self.plan_id,
            "readback_sha256": self.readback_sha256,
            "provider_state": self.provider_state,
            "transient_cleanup_authorized": self.cleanup_authorized,
            "escalation_to_deenrollment_required": self.escalation_required,
            "managed_state_change_authorized": False,
            "provider_mutation_authorized": False,
            "policy_mutation_authorized": False,
            "device_record_removal_authorized": False,
        }


def _closed_dict(value: object, expected: set[str], code: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementDeenrollmentError(code)
    return dict(value)


def _nonempty(value: object, code: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise DeviceManagementDeenrollmentError(code)
    return value


def _timestamp(value: object, code: str) -> str:
    if not isinstance(value, str) or RFC3339_UTC_SECONDS.fullmatch(value) is None:
        raise DeviceManagementDeenrollmentError(code)
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise DeviceManagementDeenrollmentError(code) from exc
    return value


def _timestamp_value(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _positive_int(value: object, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DeviceManagementDeenrollmentError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise DeviceManagementDeenrollmentError(code)
    return value


def _provider_id(value: object, code: str) -> str:
    if not isinstance(value, str) or PROVIDER_ID.fullmatch(value) is None:
        raise DeviceManagementDeenrollmentError(code)
    return value


def _provider_operation_id(value: object, code: str) -> str:
    if not isinstance(value, str) or PROVIDER_OPERATION_ID.fullmatch(value) is None:
        raise DeviceManagementDeenrollmentError(code)
    return value


def _canonical_sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _verified_binding(receipt: object) -> EnrollmentVerificationBinding:
    expected = {
        "schema", "state", "job_id", "plan_id", "provider_id", "provider_operation_id", "device_id",
        "member_id", "execution_generation", "evidence_sha256", "enrollment_completed",
        "post_condition_verified", "managed_state_change_authorized", "cleanup_required",
        "policy_application_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    raw = _closed_dict(receipt, expected, "device_management_deenrollment_verification_receipt_invalid")
    if (
        raw.get("schema") != NR1_RECEIPT_SCHEMA
        or raw.get("state") != "verified"
        or raw.get("enrollment_completed") is not True
        or raw.get("post_condition_verified") is not True
        or raw.get("managed_state_change_authorized") is not True
        or raw.get("cleanup_required") is not False
        or raw.get("policy_application_authorized") is not False
        or raw.get("infrastructure_mutation_authorized") is not False
        or raw.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_verification_receipt_invalid")
    plan_id = raw.get("plan_id")
    if not isinstance(plan_id, str) or EXECUTION_PLAN_ID.fullmatch(plan_id) is None:
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_verification_receipt_invalid")
    return EnrollmentVerificationBinding(
        enrollment_plan_id=plan_id,
        provider_id=_provider_id(raw.get("provider_id"), "device_management_deenrollment_verification_receipt_invalid"),
        provider_operation_id=_provider_operation_id(
            raw.get("provider_operation_id"), "device_management_deenrollment_verification_receipt_invalid"
        ),
        device_id=_nonempty(raw.get("device_id"), "device_management_deenrollment_verification_receipt_invalid"),
        member_id=_nonempty(raw.get("member_id"), "device_management_deenrollment_verification_receipt_invalid"),
        execution_generation=_positive_int(
            raw.get("execution_generation"), "device_management_deenrollment_verification_receipt_invalid"
        ),
        verification_evidence_sha256=_digest(
            raw.get("evidence_sha256"), "device_management_deenrollment_verification_receipt_invalid"
        ),
    )


def build_deenrollment_plan(
    *,
    verification_receipt: object,
    household_id: object,
    snapshot_id: object,
    resource_version: object,
    generation: object,
    actor_member_id: object,
    requested_at: object,
    max_observed_age_seconds: object = 300,
) -> DeviceManagementDeenrollmentPlan:
    binding = _verified_binding(verification_receipt)
    household = _nonempty(household_id, "device_management_deenrollment_context_invalid")
    snapshot = _nonempty(snapshot_id, "device_management_deenrollment_context_invalid")
    resource = _nonempty(resource_version, "device_management_deenrollment_context_invalid")
    current_generation = _positive_int(generation, "device_management_deenrollment_context_invalid")
    actor = _nonempty(actor_member_id, "device_management_deenrollment_context_invalid")
    requested = _timestamp(requested_at, "device_management_deenrollment_context_invalid")
    if (
        isinstance(max_observed_age_seconds, bool)
        or not isinstance(max_observed_age_seconds, int)
        or not 1 <= max_observed_age_seconds <= 3600
    ):
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_context_invalid")
    canonical = {
        **binding.to_dict(),
        "household_id": household,
        "snapshot_id": snapshot,
        "resource_version": resource,
        "generation": current_generation,
        "actor_member_id": actor,
        "requested_at": requested,
        "max_observed_age_seconds": max_observed_age_seconds,
    }
    plan_id = "dmdel-" + _canonical_sha256(canonical)[:24]
    return DeviceManagementDeenrollmentPlan(
        plan_id=plan_id,
        binding=binding,
        household_id=household,
        snapshot_id=snapshot,
        resource_version=resource,
        generation=current_generation,
        actor_member_id=actor,
        requested_at=requested,
        max_observed_age_seconds=max_observed_age_seconds,
    )


def confirm_deenrollment(
    *,
    plan: DeviceManagementDeenrollmentPlan,
    actor_member_id: object,
    confirmed_at: object,
) -> DeviceManagementDeenrollmentConfirmation:
    if not isinstance(plan, DeviceManagementDeenrollmentPlan):
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_plan_invalid")
    actor = _nonempty(actor_member_id, "device_management_deenrollment_confirmation_invalid")
    if actor != plan.actor_member_id:
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_confirmation_invalid")
    confirmed = _timestamp(confirmed_at, "device_management_deenrollment_confirmation_invalid")
    if _timestamp_value(confirmed) < _timestamp_value(plan.requested_at):
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_confirmation_invalid")
    return DeviceManagementDeenrollmentConfirmation(
        plan_id=plan.plan_id,
        actor_member_id=actor,
        confirmed_at=confirmed,
        plan_sha256=_canonical_sha256(plan.to_dict()),
    )


def readback_from_dict(value: object) -> DeviceManagementDeenrollmentReadbackResult:
    expected = {
        "schema", "plan_id", "provider_id", "provider_operation_id", "device_id", "member_id",
        "observed_at", "state", "provider_read_performed",
    }
    raw = _closed_dict(value, expected, "device_management_deenrollment_readback_rejected")
    plan_id = raw.get("plan_id")
    state = raw.get("state")
    if (
        raw.get("schema") != DEENROLLMENT_READBACK_SCHEMA
        or not isinstance(plan_id, str)
        or DEENROLLMENT_PLAN_ID.fullmatch(plan_id) is None
        or not isinstance(state, str)
        or state not in READBACK_STATES
        or raw.get("provider_read_performed") is not True
    ):
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_readback_rejected")
    result = DeviceManagementDeenrollmentReadbackResult(
        plan_id=plan_id,
        provider_id=_provider_id(raw.get("provider_id"), "device_management_deenrollment_readback_rejected"),
        provider_operation_id=_provider_operation_id(
            raw.get("provider_operation_id"), "device_management_deenrollment_readback_rejected"
        ),
        device_id=_nonempty(raw.get("device_id"), "device_management_deenrollment_readback_rejected"),
        member_id=_nonempty(raw.get("member_id"), "device_management_deenrollment_readback_rejected"),
        observed_at=_timestamp(raw.get("observed_at"), "device_management_deenrollment_readback_rejected"),
        state=state,
    )
    if result.to_dict() != raw:
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_readback_rejected")
    return result


def verify_deenrollment(
    *,
    plan: DeviceManagementDeenrollmentPlan,
    confirmation: DeviceManagementDeenrollmentConfirmation,
    readback: object,
    now: object,
    job_id: object,
) -> DeviceManagementDeenrollmentVerificationReceipt:
    if not isinstance(plan, DeviceManagementDeenrollmentPlan) or not isinstance(
        confirmation, DeviceManagementDeenrollmentConfirmation
    ):
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_verification_invalid")
    if confirmation.plan_id != plan.plan_id or confirmation.plan_sha256 != _canonical_sha256(plan.to_dict()):
        raise DeviceManagementDeenrollmentError("device_management_deenrollment_verification_invalid")
    result = readback_from_dict(readback)
    now_value = _timestamp_value(_timestamp(now, "device_management_deenrollment_verification_invalid"))
    job = _nonempty(job_id, "device_management_deenrollment_verification_invalid", max_length=128)
    failure: str | None = None
    if (
        result.plan_id != plan.plan_id
        or result.provider_id != plan.binding.provider_id
        or result.provider_operation_id != plan.binding.provider_operation_id
        or result.device_id != plan.binding.device_id
        or result.member_id != plan.binding.member_id
    ):
        failure = "binding-mismatch"
    else:
        observed = _timestamp_value(result.observed_at)
        if observed > now_value:
            failure = "future-observation"
        elif (now_value - observed).total_seconds() > plan.max_observed_age_seconds:
            failure = "stale-observation"
        elif result.state == "managed":
            failure = "provider-still-managed"
        elif result.state == "unknown":
            failure = "provider-state-unknown"
        elif result.state == "ambiguous":
            failure = "provider-state-ambiguous"
        elif result.state not in SUCCESS_READBACK_STATES:
            failure = "provider-state-not-verified"
    return DeviceManagementDeenrollmentVerificationReceipt(
        job_id=job,
        plan_id=plan.plan_id,
        readback_sha256=_canonical_sha256(result.to_dict()),
        verified=failure is None,
        observed_state=result.state,
        failure_reason=failure,
    )


def _failed_verification_receipt(receipt: object) -> EnrollmentVerificationBinding:
    expected = {
        "schema", "state", "job_id", "plan_id", "provider_id", "provider_operation_id", "device_id",
        "member_id", "execution_generation", "evidence_sha256", "enrollment_completed",
        "post_condition_verified", "managed_state_change_authorized", "cleanup_required",
        "policy_application_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    raw = _closed_dict(receipt, expected, "device_management_cleanup_verification_receipt_invalid")
    if (
        raw.get("schema") != NR1_RECEIPT_SCHEMA
        or raw.get("state") != "rejected"
        or raw.get("enrollment_completed") is not False
        or raw.get("post_condition_verified") is not False
        or raw.get("managed_state_change_authorized") is not False
        or raw.get("cleanup_required") is not True
        or raw.get("policy_application_authorized") is not False
        or raw.get("infrastructure_mutation_authorized") is not False
        or raw.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementDeenrollmentError("device_management_cleanup_verification_receipt_invalid")
    plan_id = raw.get("plan_id")
    if not isinstance(plan_id, str) or EXECUTION_PLAN_ID.fullmatch(plan_id) is None:
        raise DeviceManagementDeenrollmentError("device_management_cleanup_verification_receipt_invalid")
    return EnrollmentVerificationBinding(
        enrollment_plan_id=plan_id,
        provider_id=_provider_id(raw.get("provider_id"), "device_management_cleanup_verification_receipt_invalid"),
        provider_operation_id=_provider_operation_id(
            raw.get("provider_operation_id"), "device_management_cleanup_verification_receipt_invalid"
        ),
        device_id=_nonempty(raw.get("device_id"), "device_management_cleanup_verification_receipt_invalid"),
        member_id=_nonempty(raw.get("member_id"), "device_management_cleanup_verification_receipt_invalid"),
        execution_generation=_positive_int(
            raw.get("execution_generation"), "device_management_cleanup_verification_receipt_invalid"
        ),
        verification_evidence_sha256=_digest(
            raw.get("evidence_sha256"), "device_management_cleanup_verification_receipt_invalid"
        ),
    )


def build_failed_enrollment_cleanup_plan(
    *,
    rejected_verification_receipt: object,
    cleanup_generation: object,
    created_at: object,
    max_observed_age_seconds: object = 300,
) -> DeviceManagementFailedEnrollmentCleanupPlan:
    binding = _failed_verification_receipt(rejected_verification_receipt)
    generation = _positive_int(cleanup_generation, "device_management_cleanup_plan_invalid")
    timestamp = _timestamp(created_at, "device_management_cleanup_plan_invalid")
    if (
        isinstance(max_observed_age_seconds, bool)
        or not isinstance(max_observed_age_seconds, int)
        or not 1 <= max_observed_age_seconds <= 3600
    ):
        raise DeviceManagementDeenrollmentError("device_management_cleanup_plan_invalid")
    canonical = {
        **binding.to_dict(),
        "cleanup_generation": generation,
        "created_at": timestamp,
        "max_observed_age_seconds": max_observed_age_seconds,
    }
    return DeviceManagementFailedEnrollmentCleanupPlan(
        plan_id="dmclean-" + _canonical_sha256(canonical)[:24],
        enrollment_plan_id=binding.enrollment_plan_id,
        provider_id=binding.provider_id,
        provider_operation_id=binding.provider_operation_id,
        device_id=binding.device_id,
        member_id=binding.member_id,
        verification_evidence_sha256=binding.verification_evidence_sha256,
        cleanup_generation=generation,
        created_at=timestamp,
        max_observed_age_seconds=max_observed_age_seconds,
    )


def cleanup_readback_from_dict(value: object) -> DeviceManagementFailedEnrollmentCleanupReadbackResult:
    expected = {
        "schema", "plan_id", "provider_id", "provider_operation_id", "device_id", "member_id",
        "observed_at", "state", "provider_read_performed",
    }
    raw = _closed_dict(value, expected, "device_management_cleanup_readback_rejected")
    plan_id = raw.get("plan_id")
    state = raw.get("state")
    if (
        raw.get("schema") != CLEANUP_READBACK_SCHEMA
        or not isinstance(plan_id, str)
        or CLEANUP_PLAN_ID.fullmatch(plan_id) is None
        or not isinstance(state, str)
        or state not in READBACK_STATES
        or raw.get("provider_read_performed") is not True
    ):
        raise DeviceManagementDeenrollmentError("device_management_cleanup_readback_rejected")
    result = DeviceManagementFailedEnrollmentCleanupReadbackResult(
        plan_id=plan_id,
        provider_id=_provider_id(raw.get("provider_id"), "device_management_cleanup_readback_rejected"),
        provider_operation_id=_provider_operation_id(
            raw.get("provider_operation_id"), "device_management_cleanup_readback_rejected"
        ),
        device_id=_nonempty(raw.get("device_id"), "device_management_cleanup_readback_rejected"),
        member_id=_nonempty(raw.get("member_id"), "device_management_cleanup_readback_rejected"),
        observed_at=_timestamp(raw.get("observed_at"), "device_management_cleanup_readback_rejected"),
        state=state,
    )
    if result.to_dict() != raw:
        raise DeviceManagementDeenrollmentError("device_management_cleanup_readback_rejected")
    return result


def authorize_failed_enrollment_cleanup(
    *,
    plan: DeviceManagementFailedEnrollmentCleanupPlan,
    readback: object,
    now: object,
) -> DeviceManagementFailedEnrollmentCleanupReceipt:
    if not isinstance(plan, DeviceManagementFailedEnrollmentCleanupPlan):
        raise DeviceManagementDeenrollmentError("device_management_cleanup_plan_invalid")
    raw = cleanup_readback_from_dict(readback)
    now_value = _timestamp_value(_timestamp(now, "device_management_cleanup_readback_invalid"))
    binding_matches = (
        raw.plan_id == plan.plan_id
        and raw.provider_id == plan.provider_id
        and raw.provider_operation_id == plan.provider_operation_id
        and raw.device_id == plan.device_id
        and raw.member_id == plan.member_id
    )
    observed = _timestamp_value(raw.observed_at)
    fresh = observed <= now_value and (now_value - observed).total_seconds() <= plan.max_observed_age_seconds
    cleanup_authorized = binding_matches and fresh and raw.state in SUCCESS_READBACK_STATES
    escalation = binding_matches and fresh and raw.state == "managed"
    return DeviceManagementFailedEnrollmentCleanupReceipt(
        plan_id=plan.plan_id,
        readback_sha256=_canonical_sha256(raw.to_dict()),
        provider_state=raw.state,
        cleanup_authorized=cleanup_authorized,
        escalation_required=escalation,
    )
