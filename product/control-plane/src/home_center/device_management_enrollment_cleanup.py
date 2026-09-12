"""Fail-closed failed-enrollment cleanup planning for Home Center 0.58.

A failed post-condition check must not silently retry provider execution or mark a
device managed.  This module classifies the verified failure evidence into a
bounded cleanup intent.  The result is planning evidence only: it never calls a
provider, never authorizes a retry, and never mutates Household state.

Provider de-enrollment, when required, remains a separately confirmed typed
provider operation whose completion must itself be re-read and verified before a
new enrollment attempt may be planned.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationResult,
)
from .home_services import HomeServiceCatalogError, _identifier


CLEANUP_PLAN_SCHEMA = "home-center.device-management-enrollment-cleanup-plan.v1"
CLEANUP_ACTIONS = frozenset({
    "observe-provider-state",
    "no-provider-cleanup",
    "de-enroll-required",
})


class DeviceManagementEnrollmentCleanupError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentCleanupPlan:
    cleanup_id: str
    verification_id: str
    execution_job_id: str
    execution_plan_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    provider_id: str
    provider_operation_id: str
    verification_reason: str
    action: str
    explicit_confirmation_required: bool
    schema: str = field(default=CLEANUP_PLAN_SCHEMA, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    retry_authorized: bool = field(default=False, init=False)
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
            "execution_plan_id": self.execution_plan_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "verification_reason": self.verification_reason,
            "action": self.action,
            "explicit_confirmation_required": self.explicit_confirmation_required,
            "provider_mutation_authorized": False,
            "retry_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _actor_member_id(value: object) -> str:
    try:
        return _identifier(value, "invalid_household_member_id")
    except HomeServiceCatalogError as exc:
        raise DeviceManagementEnrollmentCleanupError(exc.code) from exc


def _cleanup_action(result: DeviceManagementEnrollmentVerificationResult) -> tuple[str, bool]:
    if result.reason == "provider-state-unknown":
        return "observe-provider-state", False
    if result.reason == "provider-not-enrolled":
        return "no-provider-cleanup", False
    if result.reason in {
        "required-evidence-not-present",
        "required-evidence-not-applicable",
    }:
        return "de-enroll-required", True
    raise DeviceManagementEnrollmentCleanupError(
        "device_management_enrollment_cleanup_reason_unsupported"
    )


def _cleanup_id(
    *,
    result: DeviceManagementEnrollmentVerificationResult,
    actor_member_id: str,
    action: str,
) -> str:
    canonical = {
        "verification_id": result.verification_id,
        "execution_job_id": result.execution_job_id,
        "execution_plan_id": result.execution_plan_id,
        "household_id": result.household_id,
        "snapshot_id": result.snapshot_id,
        "resource_version": result.resource_version,
        "generation": result.generation,
        "actor_member_id": actor_member_id,
        "device_id": result.device_id,
        "member_id": result.member_id,
        "provider_id": result.provider_id,
        "provider_operation_id": result.provider_operation_id,
        "verification_reason": result.reason,
        "action": action,
    }
    encoded = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "dmpclean-" + hashlib.sha256(encoded).hexdigest()[:24]


def build_failed_enrollment_cleanup_plan(
    verification_result: object,
    *,
    actor_member_id: object,
) -> DeviceManagementEnrollmentCleanupPlan:
    """Classify one failed verification into a non-authorizing cleanup plan."""

    if not isinstance(verification_result, DeviceManagementEnrollmentVerificationResult):
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_verification_result_invalid"
        )
    result = verification_result
    evidence = result.to_dict()
    if (
        result.state != "not-verified"
        or evidence.get("enrollment_completed") is not False
        or evidence.get("post_condition_verified") is not False
        or evidence.get("managed_state_change_authorized") is not False
        or evidence.get("policy_application_authorized") is not False
        or evidence.get("infrastructure_mutation_authorized") is not False
        or evidence.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentCleanupError(
            "device_management_enrollment_cleanup_not_required"
        )

    actor_id = _actor_member_id(actor_member_id)
    action, confirmation_required = _cleanup_action(result)
    return DeviceManagementEnrollmentCleanupPlan(
        cleanup_id=_cleanup_id(
            result=result,
            actor_member_id=actor_id,
            action=action,
        ),
        verification_id=result.verification_id,
        execution_job_id=result.execution_job_id,
        execution_plan_id=result.execution_plan_id,
        household_id=result.household_id,
        snapshot_id=result.snapshot_id,
        resource_version=result.resource_version,
        generation=result.generation,
        actor_member_id=actor_id,
        device_id=result.device_id,
        member_id=result.member_id,
        provider_id=result.provider_id,
        provider_operation_id=result.provider_operation_id,
        verification_reason=result.reason,
        action=action,
        explicit_confirmation_required=confirmation_required,
    )
