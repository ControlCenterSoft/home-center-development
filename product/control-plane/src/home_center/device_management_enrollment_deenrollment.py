"""Explicit, fail-closed de-enrollment boundary for Home Center 0.58.

A failed enrollment cleanup plan may require provider-side de-enrollment before a
new enrollment attempt is safe.  This module turns that requirement into a
separate administrator-approved provider operation.  It deliberately does not
mark a device managed/unmanaged, apply policy, expose credentials, authorize a
retry, or treat provider command acceptance as cleanup success.

After provider acceptance callers must perform a fresh post-cleanup read-back and
use the cleanup retry-assessment boundary before a new enrollment may even be
planned.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Protocol

from .device_management_enrollment_cleanup import (
    DeviceManagementEnrollmentCleanupPlan,
)
from .household import ROLE_PRESETS
from .household_store import HouseholdSnapshot


DEENROLLMENT_PLAN_SCHEMA = "home-center.device-management-enrollment-deenrollment-plan.v1"
DEENROLLMENT_CONFIRMATION_SCHEMA = (
    "home-center.device-management-enrollment-deenrollment-confirmation.v1"
)
DEENROLLMENT_ADAPTER_REQUEST_SCHEMA = (
    "home-center.device-management-enrollment-deenrollment-adapter-request.v1"
)
DEENROLLMENT_ADAPTER_RESULT_SCHEMA = (
    "home-center.device-management-enrollment-deenrollment-adapter-result.v1"
)
DEENROLLMENT_RECEIPT_SCHEMA = (
    "home-center.device-management-enrollment-deenrollment-receipt.v1"
)

IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class DeviceManagementEnrollmentDeenrollmentError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentDeenrollmentPlan:
    de_enrollment_id: str
    cleanup_id: str
    verification_id: str
    execution_job_id: str
    enrollment_plan_id: str
    provider_id: str
    provider_operation_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    failure_reasons: tuple[str, ...]
    schema: str = field(default=DEENROLLMENT_PLAN_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    durable_job_required: bool = field(default=True, init=False)
    audit_required: bool = field(default=True, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    retry_planning_allowed: bool = field(default=False, init=False)
    retry_execution_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "de_enrollment_id": self.de_enrollment_id,
            "cleanup_id": self.cleanup_id,
            "verification_id": self.verification_id,
            "execution_job_id": self.execution_job_id,
            "enrollment_plan_id": self.enrollment_plan_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "failure_reasons": list(self.failure_reasons),
            "confirmation_required": True,
            "durable_job_required": True,
            "audit_required": True,
            "provider_mutation_authorized": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
            "credential_value_access_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentDeenrollmentConfirmation:
    confirmation_id: str
    de_enrollment_id: str
    cleanup_id: str
    actor_member_id: str
    idempotency_key: str
    confirmed_at: str
    schema: str = field(default=DEENROLLMENT_CONFIRMATION_SCHEMA, init=False)
    confirmed: bool = field(default=True, init=False)
    provider_mutation_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    retry_execution_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "confirmation_id": self.confirmation_id,
            "de_enrollment_id": self.de_enrollment_id,
            "cleanup_id": self.cleanup_id,
            "actor_member_id": self.actor_member_id,
            "idempotency_key": self.idempotency_key,
            "confirmed_at": self.confirmed_at,
            "confirmed": True,
            "provider_mutation_authorized": True,
            "credential_value_access_authorized": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentDeenrollmentAdapterRequest:
    job_id: str
    de_enrollment_id: str
    cleanup_id: str
    confirmation_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    deadline_at: str
    schema: str = field(default=DEENROLLMENT_ADAPTER_REQUEST_SCHEMA, init=False)
    provider_mutation_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    retry_execution_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "de_enrollment_id": self.de_enrollment_id,
            "cleanup_id": self.cleanup_id,
            "confirmation_id": self.confirmation_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "deadline_at": self.deadline_at,
            "provider_mutation_authorized": True,
            "credential_value_access_authorized": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentDeenrollmentAdapterResult:
    cleanup_operation_id: str
    schema: str = field(default=DEENROLLMENT_ADAPTER_RESULT_SCHEMA, init=False)
    state: str = field(default="accepted", init=False)
    post_cleanup_verified: bool = field(default=False, init=False)
    retry_planning_allowed: bool = field(default=False, init=False)
    retry_execution_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "accepted",
            "cleanup_operation_id": self.cleanup_operation_id,
            "post_cleanup_verified": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentDeenrollmentReceipt:
    job_id: str
    de_enrollment_id: str
    cleanup_id: str
    confirmation_id: str
    provider_id: str
    provider_operation_id: str
    cleanup_operation_id: str
    device_id: str
    schema: str = field(default=DEENROLLMENT_RECEIPT_SCHEMA, init=False)
    state: str = field(default="provider-cleanup-accepted", init=False)
    post_cleanup_verified: bool = field(default=False, init=False)
    retry_planning_allowed: bool = field(default=False, init=False)
    retry_execution_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "provider-cleanup-accepted",
            "job_id": self.job_id,
            "de_enrollment_id": self.de_enrollment_id,
            "cleanup_id": self.cleanup_id,
            "confirmation_id": self.confirmation_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "cleanup_operation_id": self.cleanup_operation_id,
            "device_id": self.device_id,
            "post_cleanup_verified": False,
            "retry_planning_allowed": False,
            "retry_execution_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


class DeviceManagementEnrollmentDeenrollmentAdapter(Protocol):
    def de_enroll(
        self,
        request: DeviceManagementEnrollmentDeenrollmentAdapterRequest,
    ) -> object: ...


def _canonical_digest(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _administration_allowed(snapshot: HouseholdSnapshot, actor_member_id: str) -> bool:
    try:
        member = snapshot.household.member(actor_member_id)
    except ValueError:
        return False
    preset = ROLE_PRESETS[member.role]
    return member.enabled and preset.administration_allowed


def build_deenrollment_plan(
    cleanup_plan: object,
    *,
    current: HouseholdSnapshot,
    actor_member_id: str,
) -> DeviceManagementEnrollmentDeenrollmentPlan:
    """Build a destructive-provider plan only from exact negative cleanup evidence."""

    if not isinstance(cleanup_plan, DeviceManagementEnrollmentCleanupPlan):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_cleanup_plan_invalid"
        )
    if not isinstance(current, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if (
        cleanup_plan.action != "de-enroll-required"
        or cleanup_plan.explicit_confirmation_required is not True
        or cleanup_plan.provider_mutation_authorized
        or cleanup_plan.retry_planning_allowed
        or cleanup_plan.retry_execution_authorized
        or cleanup_plan.managed_state_change_authorized
    ):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_not_required"
        )
    if (
        current.household_id != cleanup_plan.household_id
        or current.snapshot_id != cleanup_plan.snapshot_id
        or current.resource_version != cleanup_plan.resource_version
        or current.generation != cleanup_plan.generation
    ):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_stale"
        )
    device = next(
        (
            item
            for item in current.household.devices
            if item.device_id == cleanup_plan.device_id
        ),
        None,
    )
    if device is None or device.member_id != cleanup_plan.member_id or device.managed:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_device_binding_mismatch"
        )
    if not isinstance(actor_member_id, str) or not actor_member_id:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_actor_invalid"
        )
    if not _administration_allowed(current, actor_member_id):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_forbidden"
        )

    canonical = {
        "cleanup_id": cleanup_plan.cleanup_id,
        "verification_id": cleanup_plan.verification_id,
        "execution_job_id": cleanup_plan.execution_job_id,
        "enrollment_plan_id": cleanup_plan.plan_id,
        "provider_id": cleanup_plan.provider_id,
        "provider_operation_id": cleanup_plan.provider_operation_id,
        "household_id": cleanup_plan.household_id,
        "snapshot_id": cleanup_plan.snapshot_id,
        "resource_version": cleanup_plan.resource_version,
        "generation": cleanup_plan.generation,
        "actor_member_id": actor_member_id,
        "device_id": cleanup_plan.device_id,
        "member_id": cleanup_plan.member_id,
        "failure_reasons": list(cleanup_plan.failure_reasons),
    }
    de_enrollment_id = "dmpdeenroll-" + _canonical_digest(canonical)[:24]
    return DeviceManagementEnrollmentDeenrollmentPlan(
        de_enrollment_id=de_enrollment_id,
        cleanup_id=cleanup_plan.cleanup_id,
        verification_id=cleanup_plan.verification_id,
        execution_job_id=cleanup_plan.execution_job_id,
        enrollment_plan_id=cleanup_plan.plan_id,
        provider_id=cleanup_plan.provider_id,
        provider_operation_id=cleanup_plan.provider_operation_id,
        household_id=cleanup_plan.household_id,
        snapshot_id=cleanup_plan.snapshot_id,
        resource_version=cleanup_plan.resource_version,
        generation=cleanup_plan.generation,
        actor_member_id=actor_member_id,
        device_id=cleanup_plan.device_id,
        member_id=cleanup_plan.member_id,
        failure_reasons=cleanup_plan.failure_reasons,
    )


def confirm_deenrollment(
    plan: object,
    *,
    actor_member_id: str,
    confirmed: bool,
    idempotency_key: str,
    confirmed_at: str,
) -> DeviceManagementEnrollmentDeenrollmentConfirmation:
    """Record one explicit confirmation; this still does not call a provider."""

    if not isinstance(plan, DeviceManagementEnrollmentDeenrollmentPlan):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_plan_invalid"
        )
    if confirmed is not True:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_confirmation_required"
        )
    if actor_member_id != plan.actor_member_id:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_actor_mismatch"
        )
    if not isinstance(idempotency_key, str) or IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_idempotency_key_invalid"
        )
    if not isinstance(confirmed_at, str) or RFC3339_UTC_SECONDS.fullmatch(confirmed_at) is None:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_confirmation_time_invalid"
        )
    canonical = {
        "de_enrollment_id": plan.de_enrollment_id,
        "cleanup_id": plan.cleanup_id,
        "actor_member_id": actor_member_id,
        "idempotency_key": idempotency_key,
        "confirmed_at": confirmed_at,
    }
    confirmation_id = "dmpdeconfirm-" + _canonical_digest(canonical)[:24]
    return DeviceManagementEnrollmentDeenrollmentConfirmation(
        confirmation_id=confirmation_id,
        de_enrollment_id=plan.de_enrollment_id,
        cleanup_id=plan.cleanup_id,
        actor_member_id=actor_member_id,
        idempotency_key=idempotency_key,
        confirmed_at=confirmed_at,
    )


def build_deenrollment_adapter_request(
    plan: object,
    confirmation: object,
    *,
    job_id: str,
    deadline_at: str,
) -> DeviceManagementEnrollmentDeenrollmentAdapterRequest:
    if not isinstance(plan, DeviceManagementEnrollmentDeenrollmentPlan):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_plan_invalid"
        )
    if not isinstance(
        confirmation,
        DeviceManagementEnrollmentDeenrollmentConfirmation,
    ):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_confirmation_invalid"
        )
    if (
        confirmation.de_enrollment_id != plan.de_enrollment_id
        or confirmation.cleanup_id != plan.cleanup_id
        or confirmation.actor_member_id != plan.actor_member_id
        or confirmation.confirmed is not True
        or confirmation.provider_mutation_authorized is not True
    ):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_confirmation_mismatch"
        )
    if not isinstance(job_id, str) or not job_id or len(job_id) > 128:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_job_id_invalid"
        )
    if not isinstance(deadline_at, str) or RFC3339_UTC_SECONDS.fullmatch(deadline_at) is None:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_deadline_invalid"
        )
    return DeviceManagementEnrollmentDeenrollmentAdapterRequest(
        job_id=job_id,
        de_enrollment_id=plan.de_enrollment_id,
        cleanup_id=plan.cleanup_id,
        confirmation_id=confirmation.confirmation_id,
        provider_id=plan.provider_id,
        provider_operation_id=plan.provider_operation_id,
        device_id=plan.device_id,
        deadline_at=deadline_at,
    )


def deenrollment_adapter_result_from_dict(
    value: object,
) -> DeviceManagementEnrollmentDeenrollmentAdapterResult:
    expected = {
        "schema",
        "state",
        "cleanup_operation_id",
        "post_cleanup_verified",
        "retry_planning_allowed",
        "retry_execution_authorized",
        "managed_state_change_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_result_rejected"
        )
    cleanup_operation_id = value.get("cleanup_operation_id")
    if (
        value.get("schema") != DEENROLLMENT_ADAPTER_RESULT_SCHEMA
        or value.get("state") != "accepted"
        or not isinstance(cleanup_operation_id, str)
        or PROVIDER_OPERATION_ID.fullmatch(cleanup_operation_id) is None
        or value.get("post_cleanup_verified") is not False
        or value.get("retry_planning_allowed") is not False
        or value.get("retry_execution_authorized") is not False
        or value.get("managed_state_change_authorized") is not False
    ):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_result_rejected"
        )
    return DeviceManagementEnrollmentDeenrollmentAdapterResult(
        cleanup_operation_id=cleanup_operation_id
    )


def build_deenrollment_receipt(
    request: object,
    result: object,
) -> DeviceManagementEnrollmentDeenrollmentReceipt:
    if not isinstance(request, DeviceManagementEnrollmentDeenrollmentAdapterRequest):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_request_invalid"
        )
    if not isinstance(result, DeviceManagementEnrollmentDeenrollmentAdapterResult):
        raise DeviceManagementEnrollmentDeenrollmentError(
            "device_management_enrollment_deenrollment_result_invalid"
        )
    return DeviceManagementEnrollmentDeenrollmentReceipt(
        job_id=request.job_id,
        de_enrollment_id=request.de_enrollment_id,
        cleanup_id=request.cleanup_id,
        confirmation_id=request.confirmation_id,
        provider_id=request.provider_id,
        provider_operation_id=request.provider_operation_id,
        cleanup_operation_id=result.cleanup_operation_id,
        device_id=request.device_id,
    )
