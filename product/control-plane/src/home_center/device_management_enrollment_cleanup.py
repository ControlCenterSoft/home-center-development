"""Fail-closed failed-enrollment cleanup and retry planning for Home Center 0.58.

Post-condition verification may prove that a provider accepted enrollment while
the device is still not safely managed.  This module converts negative
verification evidence into bounded cleanup planning.  It never calls a provider,
never resolves secrets, never mutates Household state and never authorizes a
retry by itself.

A retry may only become *plannable* after a fresh read-back shows that no
provider-side enrollment traces remain.  Even then, provider execution still
requires the normal 0.57 plan/confirm/execution boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationEvidence,
)


CLEANUP_PLAN_SCHEMA = "home-center.device-management-enrollment-cleanup-plan.v1"
RETRY_ASSESSMENT_SCHEMA = (
    "home-center.device-management-enrollment-cleanup-retry-assessment.v1"
)
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class DeviceManagementEnrollmentCleanupError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentCleanupPlan:
    cleanup_id: str
    verification_id: str
    execution_job_id: str
    plan_id: str
    provider_id: str
    provider_operation_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    device_id: str
    member_id: str
    observed_at: str
    failure_reasons: tuple[str, ...]
    action: str
    explicit_confirmation_required: bool
    schema: str = field(default=CLEANUP_PLAN_SCHEMA, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    retry_planning_allowed: bool = field(default=False, init=False)
    retry_execution_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cleanup_id": self.cleanup_id,
            "verification_id": self.verification_id,
            "execution_job_id": self.execution_job_id,
            "plan_id": self.plan_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "observed_at": self.observed_at,
            "failure_reasons": list(self.failure_reasons),
            "action": self.action,
            "explicit_confirmation_required": self.explicit_confirmation_required,
            "provider_mutation_authorized": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentRetryAssessment:
    assessment_id: str
    cleanup_id: str
    verification_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    cleanup_observed_at: str
    post_cleanup_observed_at: str
    residual_provider_state: bool
    retry_planning_allowed: bool
    reason: str
    schema: str = field(default=RETRY_ASSESSMENT_SCHEMA, init=False)
    retry_execution_authorized: bool = field(default=False, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "assessment_id": self.assessment_id,
            "cleanup_id": self.cleanup_id,
            "verification_id": self.verification_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "cleanup_observed_at": self.cleanup_observed_at,
            "post_cleanup_observed_at": self.post_cleanup_observed_at,
            "residual_provider_state": self.residual_provider_state,
            "retry_planning_allowed": self.retry_planning_allowed,
            "reason": self.reason,
            "retry_execution_authorized": False,
            "provider_mutation_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _canonical_digest(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _expected_failures(
    evidence: DeviceManagementEnrollmentVerificationEvidence,
) -> tuple[str, ...]:
    failures: list[str] = []
    if not evidence.certificate_present:
        failures.append("certificate-missing")
    if not evidence.profile_present:
        failures.append("profile-missing")
    if not evidence.agent_present:
        failures.append("agent-missing")
    if not evidence.management_active:
        failures.append("management-inactive")
    return tuple(failures)


def _validated_observation_evidence(
    value: object,
) -> DeviceManagementEnrollmentVerificationEvidence:
    """Validate read-back evidence without assuming whether state is present or absent."""

    if not isinstance(value, DeviceManagementEnrollmentVerificationEvidence):
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_verification_evidence_invalid"
        )
    expected_failures = _expected_failures(value)
    expected_verified = not expected_failures
    if (
        value.failure_reasons != expected_failures
        or value.verified is not expected_verified
        or value.managed_state_change_authorized is not expected_verified
        or RFC3339_UTC_SECONDS.fullmatch(value.observed_at) is None
    ):
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_verification_evidence_invalid"
        )
    return value


def _validated_negative_evidence(
    value: object,
) -> DeviceManagementEnrollmentVerificationEvidence:
    evidence = _validated_observation_evidence(value)
    if evidence.verified or evidence.managed_state_change_authorized or not evidence.failure_reasons:
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_verification_evidence_invalid"
        )
    return evidence


def build_failed_enrollment_cleanup_plan(
    verification_evidence: object,
) -> DeviceManagementEnrollmentCleanupPlan:
    """Build non-authorizing cleanup planning from one failed verification."""

    evidence = _validated_negative_evidence(verification_evidence)
    residual_provider_state = any(
        (
            evidence.certificate_present,
            evidence.profile_present,
            evidence.agent_present,
            evidence.management_active,
        )
    )
    action = "de-enroll-required" if residual_provider_state else "no-provider-cleanup"
    confirmation_required = residual_provider_state

    canonical = {
        "verification_id": evidence.verification_id,
        "execution_job_id": evidence.execution_job_id,
        "plan_id": evidence.plan_id,
        "provider_id": evidence.provider_id,
        "provider_operation_id": evidence.provider_operation_id,
        "household_id": evidence.household_id,
        "snapshot_id": evidence.snapshot_id,
        "resource_version": evidence.resource_version,
        "generation": evidence.generation,
        "device_id": evidence.device_id,
        "member_id": evidence.member_id,
        "observed_at": evidence.observed_at,
        "failure_reasons": list(evidence.failure_reasons),
        "action": action,
    }
    cleanup_id = "dmpclean-" + _canonical_digest(canonical)[:24]
    return DeviceManagementEnrollmentCleanupPlan(
        cleanup_id=cleanup_id,
        verification_id=evidence.verification_id,
        execution_job_id=evidence.execution_job_id,
        plan_id=evidence.plan_id,
        provider_id=evidence.provider_id,
        provider_operation_id=evidence.provider_operation_id,
        household_id=evidence.household_id,
        snapshot_id=evidence.snapshot_id,
        resource_version=evidence.resource_version,
        generation=evidence.generation,
        device_id=evidence.device_id,
        member_id=evidence.member_id,
        observed_at=evidence.observed_at,
        failure_reasons=evidence.failure_reasons,
        action=action,
        explicit_confirmation_required=confirmation_required,
    )


def assess_retry_after_cleanup(
    cleanup_plan: object,
    post_cleanup_evidence: object,
) -> DeviceManagementEnrollmentRetryAssessment:
    """Assess whether a *new retry plan* may be considered after fresh read-back.

    This function never authorizes provider execution.  A fully residual provider
    state is a valid observation and remains fail closed with retry planning
    denied; it is not treated as malformed evidence merely because all enrollment
    post-conditions still happen to be present.
    """

    if not isinstance(cleanup_plan, DeviceManagementEnrollmentCleanupPlan):
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_cleanup_plan_invalid"
        )
    evidence = _validated_observation_evidence(post_cleanup_evidence)

    if (
        evidence.verification_id != cleanup_plan.verification_id
        or evidence.execution_job_id != cleanup_plan.execution_job_id
        or evidence.plan_id != cleanup_plan.plan_id
        or evidence.provider_id != cleanup_plan.provider_id
        or evidence.provider_operation_id != cleanup_plan.provider_operation_id
        or evidence.household_id != cleanup_plan.household_id
        or evidence.snapshot_id != cleanup_plan.snapshot_id
        or evidence.resource_version != cleanup_plan.resource_version
        or evidence.generation != cleanup_plan.generation
        or evidence.device_id != cleanup_plan.device_id
        or evidence.member_id != cleanup_plan.member_id
    ):
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_cleanup_binding_mismatch"
        )
    if evidence.observed_at <= cleanup_plan.observed_at:
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_cleanup_readback_not_fresh"
        )

    residual_provider_state = any(
        (
            evidence.certificate_present,
            evidence.profile_present,
            evidence.agent_present,
            evidence.management_active,
        )
    )
    retry_planning_allowed = not residual_provider_state
    reason = (
        "cleanup-verified-no-residual-state"
        if retry_planning_allowed
        else "residual-provider-state"
    )
    canonical = {
        "cleanup_id": cleanup_plan.cleanup_id,
        "verification_id": evidence.verification_id,
        "provider_id": evidence.provider_id,
        "provider_operation_id": evidence.provider_operation_id,
        "device_id": evidence.device_id,
        "cleanup_observed_at": cleanup_plan.observed_at,
        "post_cleanup_observed_at": evidence.observed_at,
        "residual_provider_state": residual_provider_state,
        "retry_planning_allowed": retry_planning_allowed,
        "reason": reason,
    }
    assessment_id = "dmpretry-" + _canonical_digest(canonical)[:24]
    return DeviceManagementEnrollmentRetryAssessment(
        assessment_id=assessment_id,
        cleanup_id=cleanup_plan.cleanup_id,
        verification_id=evidence.verification_id,
        provider_id=evidence.provider_id,
        provider_operation_id=evidence.provider_operation_id,
        device_id=evidence.device_id,
        cleanup_observed_at=cleanup_plan.observed_at,
        post_cleanup_observed_at=evidence.observed_at,
        residual_provider_state=residual_provider_state,
        retry_planning_allowed=retry_planning_allowed,
        reason=reason,
    )
