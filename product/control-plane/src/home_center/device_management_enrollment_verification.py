"""Fail-closed 0.58 enrollment post-condition verification domain.

Provider command acceptance from 0.57 is not enrollment success. This module
validates an exact 0.57 execution receipt, binds a read-only provider
observation to the same provider operation/device/Household snapshot, and
authorizes a later managed-state transition only when required post-conditions
are positively observed.

No function in this module mutates Household state, applies policy, resolves
credentials, changes infrastructure, or publishes anything externally.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

EXECUTION_RECEIPT_SCHEMA = "home-center.device-management-enrollment-execution-receipt.v1"
VERIFICATION_PLAN_SCHEMA = "home-center.device-management-enrollment-verification-plan.v1"
PROVIDER_OBSERVATION_SCHEMA = "home-center.device-management-enrollment-provider-observation.v1"
VERIFICATION_RESULT_SCHEMA = "home-center.device-management-enrollment-verification-result.v1"

VERIFICATION_ID = re.compile(r"^dmpverify-[0-9a-f]{24}$")
PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CHECK_KINDS = ("certificate", "profile", "agent")
CHECK_STATUSES = frozenset({"present", "missing", "unknown", "not-applicable"})
PROVIDER_STATES = frozenset({"enrolled", "not-enrolled", "cancelled", "unknown"})


class DeviceManagementEnrollmentVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationPlan:
    verification_id: str
    execution_job_id: str
    execution_plan_id: str
    selection_proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    provider_id: str
    provider_operation_id: str
    required_checks: tuple[str, ...]
    schema: str = field(default=VERIFICATION_PLAN_SCHEMA, init=False)
    read_only_provider_observation: bool = field(default=True, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    credential_access_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verification_id": self.verification_id,
            "execution_job_id": self.execution_job_id,
            "execution_plan_id": self.execution_plan_id,
            "selection_proposal_id": self.selection_proposal_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "required_checks": list(self.required_checks),
            "read_only_provider_observation": True,
            "provider_mutation_authorized": False,
            "credential_access_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentProviderObservation:
    provider_id: str
    provider_operation_id: str
    device_id: str
    provider_state: str
    certificate: str
    profile: str
    agent: str
    observed_at: str
    schema: str = field(default=PROVIDER_OBSERVATION_SCHEMA, init=False)
    read_only: bool = field(default=True, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "provider_state": self.provider_state,
            "checks": {
                "certificate": self.certificate,
                "profile": self.profile,
                "agent": self.agent,
            },
            "observed_at": self.observed_at,
            "read_only": True,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationResult:
    verification_id: str
    execution_job_id: str
    execution_plan_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    device_id: str
    member_id: str
    provider_id: str
    provider_operation_id: str
    observed_at: str
    state: str
    reason: str
    required_checks: tuple[str, ...]
    schema: str = field(default=VERIFICATION_RESULT_SCHEMA, init=False)

    @property
    def verified(self) -> bool:
        return self.state == "verified"

    def to_dict(self) -> dict[str, object]:
        verified = self.verified
        return {
            "schema": self.schema,
            "verification_id": self.verification_id,
            "execution_job_id": self.execution_job_id,
            "execution_plan_id": self.execution_plan_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "observed_at": self.observed_at,
            "state": self.state,
            "reason": self.reason,
            "required_checks": list(self.required_checks),
            "enrollment_completed": verified,
            "post_condition_verified": verified,
            "managed_state_change_authorized": verified,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _text(value: object, code: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeviceManagementEnrollmentVerificationError(code)
    return value


def _execution_receipt(value: object) -> dict[str, object]:
    expected = {
        "schema", "state", "job_id", "retry_of_job_id", "plan_id",
        "selection_proposal_id", "provider_id", "provider_operation_id",
        "device_id", "member_id", "one_time_artifact",
        "enrollment_completed", "post_condition_verified",
        "managed_state_change_authorized", "policy_application_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_execution_receipt_invalid"
        )
    if (
        value.get("schema") != EXECUTION_RECEIPT_SCHEMA
        or value.get("state") != "provider-accepted"
        or value.get("enrollment_completed") is not False
        or value.get("post_condition_verified") is not False
        or value.get("managed_state_change_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_execution_receipt_invalid"
        )
    for field_name in (
        "job_id", "plan_id", "selection_proposal_id", "provider_id",
        "device_id", "member_id",
    ):
        _text(value.get(field_name), "device_management_enrollment_execution_receipt_invalid")
    operation_id = value.get("provider_operation_id")
    if not isinstance(operation_id, str) or PROVIDER_OPERATION_ID.fullmatch(operation_id) is None:
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_execution_receipt_invalid"
        )
    retry_of = value.get("retry_of_job_id")
    if retry_of is not None and (not isinstance(retry_of, str) or not retry_of):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_execution_receipt_invalid"
        )
    artifact = value.get("one_time_artifact")
    if artifact is not None and not isinstance(artifact, dict):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_execution_receipt_invalid"
        )
    return dict(value)


def _required_checks(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise DeviceManagementEnrollmentVerificationError(
            "invalid_device_management_enrollment_verification_checks"
        )
    checks: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or item not in CHECK_KINDS or item in seen:
            raise DeviceManagementEnrollmentVerificationError(
                "invalid_device_management_enrollment_verification_checks"
            )
        seen.add(item)
        checks.append(item)
    return tuple(sorted(checks))


def _verification_identity(
    *,
    receipt: dict[str, object],
    household_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    actor_member_id: str,
    required_checks: tuple[str, ...],
) -> str:
    canonical = {
        "execution_job_id": receipt["job_id"],
        "execution_plan_id": receipt["plan_id"],
        "selection_proposal_id": receipt["selection_proposal_id"],
        "household_id": household_id,
        "snapshot_id": snapshot_id,
        "resource_version": resource_version,
        "generation": generation,
        "actor_member_id": actor_member_id,
        "device_id": receipt["device_id"],
        "member_id": receipt["member_id"],
        "provider_id": receipt["provider_id"],
        "provider_operation_id": receipt["provider_operation_id"],
        "required_checks": list(required_checks),
    }
    encoded = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "dmpverify-" + hashlib.sha256(encoded).hexdigest()[:24]


def build_enrollment_verification_plan(
    *,
    execution_receipt: object,
    household_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    actor_member_id: str,
    required_checks: object,
) -> DeviceManagementEnrollmentVerificationPlan:
    receipt = _execution_receipt(execution_receipt)
    for value, code in (
        (household_id, "invalid_household_id"),
        (snapshot_id, "invalid_household_snapshot_id"),
        (resource_version, "invalid_household_resource_version"),
        (actor_member_id, "invalid_household_actor_member_id"),
    ):
        _text(value, code)
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise DeviceManagementEnrollmentVerificationError("invalid_household_generation")
    checks = _required_checks(required_checks)
    verification_id = _verification_identity(
        receipt=receipt,
        household_id=household_id,
        snapshot_id=snapshot_id,
        resource_version=resource_version,
        generation=generation,
        actor_member_id=actor_member_id,
        required_checks=checks,
    )
    return DeviceManagementEnrollmentVerificationPlan(
        verification_id=verification_id,
        execution_job_id=receipt["job_id"],
        execution_plan_id=receipt["plan_id"],
        selection_proposal_id=receipt["selection_proposal_id"],
        household_id=household_id,
        snapshot_id=snapshot_id,
        resource_version=resource_version,
        generation=generation,
        actor_member_id=actor_member_id,
        device_id=receipt["device_id"],
        member_id=receipt["member_id"],
        provider_id=receipt["provider_id"],
        provider_operation_id=receipt["provider_operation_id"],
        required_checks=checks,
    )


def provider_observation_from_dict(
    value: object,
) -> DeviceManagementEnrollmentProviderObservation:
    expected = {
        "schema", "provider_id", "provider_operation_id", "device_id",
        "provider_state", "checks", "observed_at", "read_only",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_provider_observation_rejected"
        )
    provider_id = _text(
        value.get("provider_id"),
        "device_management_enrollment_provider_observation_rejected",
    )
    device_id = _text(
        value.get("device_id"),
        "device_management_enrollment_provider_observation_rejected",
    )
    operation_id = value.get("provider_operation_id")
    observed_at = value.get("observed_at")
    checks = value.get("checks")
    if (
        value.get("schema") != PROVIDER_OBSERVATION_SCHEMA
        or not isinstance(operation_id, str)
        or PROVIDER_OPERATION_ID.fullmatch(operation_id) is None
        or value.get("provider_state") not in PROVIDER_STATES
        or not isinstance(observed_at, str)
        or RFC3339_UTC_SECONDS.fullmatch(observed_at) is None
        or value.get("read_only") is not True
        or not isinstance(checks, dict)
        or set(checks) != set(CHECK_KINDS)
        or any(checks[name] not in CHECK_STATUSES for name in CHECK_KINDS)
    ):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_provider_observation_rejected"
        )
    observation = DeviceManagementEnrollmentProviderObservation(
        provider_id=provider_id,
        provider_operation_id=operation_id,
        device_id=device_id,
        provider_state=value["provider_state"],
        certificate=checks["certificate"],
        profile=checks["profile"],
        agent=checks["agent"],
        observed_at=observed_at,
    )
    if observation.to_dict() != value:
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_provider_observation_rejected"
        )
    return observation


def evaluate_enrollment_post_condition(
    plan: DeviceManagementEnrollmentVerificationPlan,
    provider_observation: object,
) -> DeviceManagementEnrollmentVerificationResult:
    if not isinstance(plan, DeviceManagementEnrollmentVerificationPlan):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_verification_plan_invalid"
        )
    if VERIFICATION_ID.fullmatch(plan.verification_id) is None:
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_verification_plan_invalid"
        )
    observation = provider_observation_from_dict(provider_observation)
    if (
        observation.provider_id != plan.provider_id
        or observation.provider_operation_id != plan.provider_operation_id
        or observation.device_id != plan.device_id
    ):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_verification_binding_mismatch"
        )

    checks = {
        "certificate": observation.certificate,
        "profile": observation.profile,
        "agent": observation.agent,
    }
    if observation.provider_state == "unknown":
        state, reason = "not-verified", "provider-state-unknown"
    elif observation.provider_state != "enrolled":
        state, reason = "not-verified", "provider-not-enrolled"
    elif any(checks[name] in {"missing", "unknown"} for name in plan.required_checks):
        state, reason = "not-verified", "required-evidence-not-present"
    elif any(checks[name] != "present" for name in plan.required_checks):
        state, reason = "not-verified", "required-evidence-not-applicable"
    else:
        state, reason = "verified", "post-condition-satisfied"

    return DeviceManagementEnrollmentVerificationResult(
        verification_id=plan.verification_id,
        execution_job_id=plan.execution_job_id,
        execution_plan_id=plan.execution_plan_id,
        household_id=plan.household_id,
        snapshot_id=plan.snapshot_id,
        resource_version=plan.resource_version,
        generation=plan.generation,
        device_id=plan.device_id,
        member_id=plan.member_id,
        provider_id=plan.provider_id,
        provider_operation_id=plan.provider_operation_id,
        observed_at=observation.observed_at,
        state=state,
        reason=reason,
        required_checks=plan.required_checks,
    )
