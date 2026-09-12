"""0.58 fail-closed post-condition verification for provider-backed enrollment.

0.57 proves only that a provider accepted an enrollment command. This module
defines the next authority boundary: provider evidence is validated against the
exact execution receipt and Household snapshot before Home Center may transition
one registered device from ``managed=false`` to ``managed=true``.

Provider adapters never receive authority to mutate Household state. Their
verification result can prove the post-condition only; Home Center derives the
managed-state authorization after validating every binding.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Protocol

from .device_management_enrollment_execution import (
    DeviceManagementEnrollmentExecutionError,
    execution_plan_from_dict,
)
from .home_services import HomeServiceCatalogError
from .household import Household, ManagedDevice
from .household_store import (
    HouseholdCommit,
    HouseholdSnapshot,
    build_household_replacement,
)


VERIFICATION_PLAN_SCHEMA = "home-center.device-management-enrollment-verification-plan.v1"
ADAPTER_VERIFY_REQUEST_SCHEMA = "home-center.device-management-enrollment-adapter-verify-request.v1"
ADAPTER_VERIFY_RESULT_SCHEMA = "home-center.device-management-enrollment-adapter-verify-result.v1"
VERIFICATION_RECEIPT_SCHEMA = "home-center.device-management-enrollment-verification-receipt.v1"
EXECUTION_RECEIPT_SCHEMA = "home-center.device-management-enrollment-execution-receipt.v1"

VERIFY_ID = re.compile(r"^dmpverify-[0-9a-f]{24}$")
PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
PROVIDER_DEVICE_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$")


class DeviceManagementEnrollmentVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationPlan:
    verification_id: str
    execution_plan_id: str
    execution_job_id: str
    provider_id: str
    provider_operation_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    device_id: str
    member_id: str
    schema: str = field(default=VERIFICATION_PLAN_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verification_id": self.verification_id,
            "execution_plan_id": self.execution_plan_id,
            "execution_job_id": self.execution_job_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "confirmation_required": True,
            "post_condition_verified": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentAdapterVerifyRequest:
    verification_id: str
    execution_plan_id: str
    execution_job_id: str
    provider_id: str
    provider_operation_id: str
    device_id: str
    member_id: str
    schema: str = field(default=ADAPTER_VERIFY_REQUEST_SCHEMA, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verification_id": self.verification_id,
            "execution_plan_id": self.execution_plan_id,
            "execution_job_id": self.execution_job_id,
            "provider_id": self.provider_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentAdapterVerifyResult:
    verification_id: str
    provider_operation_id: str
    device_id: str
    provider_device_reference: str
    schema: str = field(default=ADAPTER_VERIFY_RESULT_SCHEMA, init=False)
    state: str = field(default="verified", init=False)
    enrollment_completed: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=True, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "verified",
            "verification_id": self.verification_id,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "provider_device_reference": self.provider_device_reference,
            "enrollment_completed": True,
            "post_condition_verified": True,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


class DeviceManagementEnrollmentVerificationAdapter(Protocol):
    """Read/verify provider state; implementations must not mutate Household state."""

    def verify(self, request: DeviceManagementEnrollmentAdapterVerifyRequest) -> object: ...


def _execution_receipt(value: object) -> dict[str, object]:
    expected = {
        "schema", "state", "job_id", "retry_of_job_id", "plan_id", "selection_proposal_id",
        "provider_id", "provider_operation_id", "device_id", "member_id", "one_time_artifact",
        "enrollment_completed", "post_condition_verified", "managed_state_change_authorized",
        "policy_application_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_execution_receipt_invalid")
    if (
        value.get("schema") != EXECUTION_RECEIPT_SCHEMA
        or value.get("state") != "provider-accepted"
        or not isinstance(value.get("job_id"), str) or not value["job_id"]
        or not isinstance(value.get("plan_id"), str)
        or not isinstance(value.get("provider_id"), str) or not value["provider_id"]
        or not isinstance(value.get("provider_operation_id"), str)
        or PROVIDER_OPERATION_ID.fullmatch(value["provider_operation_id"]) is None
        or not isinstance(value.get("device_id"), str) or not value["device_id"]
        or not isinstance(value.get("member_id"), str) or not value["member_id"]
        or value.get("enrollment_completed") is not False
        or value.get("post_condition_verified") is not False
        or value.get("managed_state_change_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_execution_receipt_invalid")
    return dict(value)


def adapter_verification_result_from_dict(
    value: object,
    *,
    expected: DeviceManagementEnrollmentAdapterVerifyRequest,
) -> DeviceManagementEnrollmentAdapterVerifyResult:
    fields = {
        "schema", "state", "verification_id", "provider_operation_id", "device_id",
        "provider_device_reference", "enrollment_completed", "post_condition_verified",
        "managed_state_change_authorized", "policy_application_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_adapter_verification_rejected")
    reference = value.get("provider_device_reference")
    if (
        value.get("schema") != ADAPTER_VERIFY_RESULT_SCHEMA
        or value.get("state") != "verified"
        or value.get("verification_id") != expected.verification_id
        or value.get("provider_operation_id") != expected.provider_operation_id
        or value.get("device_id") != expected.device_id
        or not isinstance(reference, str)
        or PROVIDER_DEVICE_REFERENCE.fullmatch(reference) is None
        or value.get("enrollment_completed") is not True
        or value.get("post_condition_verified") is not True
        or value.get("managed_state_change_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_adapter_verification_rejected")
    return DeviceManagementEnrollmentAdapterVerifyResult(
        verification_id=expected.verification_id,
        provider_operation_id=expected.provider_operation_id,
        device_id=expected.device_id,
        provider_device_reference=reference,
    )


def _verification_id(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "dmpverify-" + hashlib.sha256(encoded).hexdigest()[:24]


def build_enrollment_verification_plan(
    *,
    snapshot: HouseholdSnapshot,
    execution_plan: object,
    execution_receipt: object,
) -> DeviceManagementEnrollmentVerificationPlan:
    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    try:
        plan = execution_plan_from_dict(execution_plan)
    except DeviceManagementEnrollmentExecutionError as exc:
        raise DeviceManagementEnrollmentVerificationError(exc.code) from exc
    receipt = _execution_receipt(execution_receipt)

    if (
        receipt["plan_id"] != plan.plan_id
        or receipt["selection_proposal_id"] != plan.selection_proposal_id
        or receipt["provider_id"] != plan.provider_id
        or receipt["device_id"] != plan.device_id
        or receipt["member_id"] != plan.member_id
        or snapshot.household_id != plan.household_id
        or snapshot.snapshot_id != plan.snapshot_id
        or snapshot.resource_version != plan.resource_version
        or snapshot.generation != plan.generation
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_binding_mismatch")
    device = next((item for item in snapshot.household.devices if item.device_id == plan.device_id), None)
    if device is None:
        raise DeviceManagementEnrollmentVerificationError("household_device_not_found")
    if device.member_id != plan.member_id:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_binding_mismatch")
    if device.managed:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_device_already_managed")

    identity = {
        "execution_plan_id": plan.plan_id,
        "execution_job_id": receipt["job_id"],
        "provider_id": plan.provider_id,
        "provider_operation_id": receipt["provider_operation_id"],
        "household_id": snapshot.household_id,
        "snapshot_id": snapshot.snapshot_id,
        "resource_version": snapshot.resource_version,
        "generation": snapshot.generation,
        "device_id": plan.device_id,
        "member_id": plan.member_id,
    }
    return DeviceManagementEnrollmentVerificationPlan(
        verification_id=_verification_id(identity),
        execution_plan_id=plan.plan_id,
        execution_job_id=receipt["job_id"],
        provider_id=plan.provider_id,
        provider_operation_id=receipt["provider_operation_id"],
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        device_id=plan.device_id,
        member_id=plan.member_id,
    )


def adapter_request_for_plan(
    plan: DeviceManagementEnrollmentVerificationPlan,
) -> DeviceManagementEnrollmentAdapterVerifyRequest:
    if not isinstance(plan, DeviceManagementEnrollmentVerificationPlan):
        raise TypeError("invalid_device_management_enrollment_verification_plan")
    return DeviceManagementEnrollmentAdapterVerifyRequest(
        verification_id=plan.verification_id,
        execution_plan_id=plan.execution_plan_id,
        execution_job_id=plan.execution_job_id,
        provider_id=plan.provider_id,
        provider_operation_id=plan.provider_operation_id,
        device_id=plan.device_id,
        member_id=plan.member_id,
    )


def apply_verified_managed_state(
    *,
    snapshot: HouseholdSnapshot,
    plan: DeviceManagementEnrollmentVerificationPlan,
    adapter_result: DeviceManagementEnrollmentAdapterVerifyResult,
) -> tuple[HouseholdSnapshot, HouseholdCommit, dict[str, object]]:
    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(plan, DeviceManagementEnrollmentVerificationPlan):
        raise TypeError("invalid_device_management_enrollment_verification_plan")
    if not isinstance(adapter_result, DeviceManagementEnrollmentAdapterVerifyResult):
        raise TypeError("invalid_device_management_enrollment_adapter_verification")

    if (
        snapshot.household_id != plan.household_id
        or snapshot.snapshot_id != plan.snapshot_id
        or snapshot.resource_version != plan.resource_version
        or snapshot.generation != plan.generation
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_stale")
    if (
        adapter_result.verification_id != plan.verification_id
        or adapter_result.provider_operation_id != plan.provider_operation_id
        or adapter_result.device_id != plan.device_id
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_binding_mismatch")

    matched = False
    devices: list[ManagedDevice] = []
    for device in snapshot.household.devices:
        if device.device_id != plan.device_id:
            devices.append(device)
            continue
        matched = True
        if device.member_id != plan.member_id:
            raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_binding_mismatch")
        if device.managed:
            raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_device_already_managed")
        devices.append(
            ManagedDevice(
                device_id=device.device_id,
                member_id=device.member_id,
                display_name=device.display_name,
                managed=True,
            )
        )
    if not matched:
        raise DeviceManagementEnrollmentVerificationError("household_device_not_found")

    try:
        household = Household(
            household_id=snapshot.household.household_id,
            members=snapshot.household.members,
            devices=tuple(devices),
        )
        next_snapshot, commit = build_household_replacement(
            snapshot,
            household,
            expected_resource_version=snapshot.resource_version,
        )
    except HomeServiceCatalogError as exc:
        raise DeviceManagementEnrollmentVerificationError(exc.code) from exc

    receipt = {
        "schema": VERIFICATION_RECEIPT_SCHEMA,
        "state": "managed-state-applied",
        "verification_id": plan.verification_id,
        "execution_plan_id": plan.execution_plan_id,
        "execution_job_id": plan.execution_job_id,
        "provider_id": plan.provider_id,
        "provider_operation_id": plan.provider_operation_id,
        "provider_device_reference": adapter_result.provider_device_reference,
        "device_id": plan.device_id,
        "member_id": plan.member_id,
        "previous_snapshot_id": snapshot.snapshot_id,
        "previous_resource_version": snapshot.resource_version,
        "snapshot_id": next_snapshot.snapshot_id,
        "resource_version": next_snapshot.resource_version,
        "generation": next_snapshot.generation,
        "commit_id": commit.commit_id,
        "enrollment_completed": True,
        "post_condition_verified": True,
        "managed_state_change_authorized": True,
        "policy_application_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    return next_snapshot, commit, receipt
