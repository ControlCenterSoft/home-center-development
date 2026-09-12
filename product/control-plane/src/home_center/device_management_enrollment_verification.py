"""Fail-closed post-condition verification for provider-backed enrollment.

0.57 only proves that a provider accepted an enrollment command. This module
introduces the 0.58 read-back boundary: provider state is observed separately,
bound to one durable execution receipt and one exact current Household snapshot,
and only complete verified evidence can authorize ``ManagedDevice.managed=True``.

The boundary is deliberately read-only with respect to provider infrastructure.
It never receives credential values or one-time enrollment artifacts.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Protocol

from .home_services import HomeServiceCatalogError
from .household import Household, ManagedDevice
from .household_store import HouseholdCommit, HouseholdSnapshot, build_household_replacement


VERIFICATION_REQUEST_SCHEMA = "home-center.device-management-enrollment-verification-request.v1"
VERIFICATION_RESULT_SCHEMA = "home-center.device-management-enrollment-verification-result.v1"
VERIFICATION_EVIDENCE_SCHEMA = "home-center.device-management-enrollment-verification-evidence.v1"
EXECUTION_RECEIPT_SCHEMA = "home-center.device-management-enrollment-execution-receipt.v1"

PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SECRET_REFERENCE = re.compile(r"^secret://[A-Za-z0-9][A-Za-z0-9._/-]{0,239}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class DeviceManagementEnrollmentVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_digest(value: dict[str, object]) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


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

    retry_of = value.get("retry_of_job_id")
    operation_id = value.get("provider_operation_id")
    if (
        value.get("schema") != EXECUTION_RECEIPT_SCHEMA
        or value.get("state") != "provider-accepted"
        or not isinstance(value.get("job_id"), str)
        or not value["job_id"]
        or (retry_of is not None and (not isinstance(retry_of, str) or not retry_of))
        or not isinstance(value.get("plan_id"), str)
        or not value["plan_id"]
        or not isinstance(value.get("selection_proposal_id"), str)
        or not value["selection_proposal_id"]
        or not isinstance(value.get("provider_id"), str)
        or not value["provider_id"]
        or not isinstance(operation_id, str)
        or PROVIDER_OPERATION_ID.fullmatch(operation_id) is None
        or not isinstance(value.get("device_id"), str)
        or not value["device_id"]
        or not isinstance(value.get("member_id"), str)
        or not value["member_id"]
        or value.get("enrollment_completed") is not False
        or value.get("post_condition_verified") is not False
        or value.get("managed_state_change_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_execution_receipt_invalid")

    artifact = value.get("one_time_artifact")
    if artifact is not None:
        if not isinstance(artifact, dict) or set(artifact) != {"kind", "reference", "expires_at", "single_use"}:
            raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_execution_receipt_invalid")
        if (
            artifact.get("kind") not in {"token", "qr"}
            or not isinstance(artifact.get("reference"), str)
            or SECRET_REFERENCE.fullmatch(artifact["reference"]) is None
            or not isinstance(artifact.get("expires_at"), str)
            or RFC3339_UTC_SECONDS.fullmatch(artifact["expires_at"]) is None
            or artifact.get("single_use") is not True
        ):
            raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_execution_receipt_invalid")

    return dict(value)


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationRequest:
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
    schema: str = field(default=VERIFICATION_REQUEST_SCHEMA, init=False)
    provider_readback_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
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
            "provider_readback_authorized": True,
            "credential_value_access_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationResult:
    provider_operation_id: str
    device_id: str
    certificate_present: bool
    profile_present: bool
    agent_present: bool
    management_active: bool
    observed_at: str
    schema: str = field(default=VERIFICATION_RESULT_SCHEMA, init=False)
    secret_material_present: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_operation_id": self.provider_operation_id,
            "device_id": self.device_id,
            "certificate_present": self.certificate_present,
            "profile_present": self.profile_present,
            "agent_present": self.agent_present,
            "management_active": self.management_active,
            "observed_at": self.observed_at,
            "secret_material_present": False,
            "infrastructure_mutation_authorized": False,
        }


class DeviceManagementEnrollmentVerificationAdapter(Protocol):
    """Read-only provider boundary for observing enrollment post-conditions."""

    def verify(self, request: DeviceManagementEnrollmentVerificationRequest) -> object: ...


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationEvidence:
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
    certificate_present: bool
    profile_present: bool
    agent_present: bool
    management_active: bool
    verified: bool
    failure_reasons: tuple[str, ...]
    schema: str = field(default=VERIFICATION_EVIDENCE_SCHEMA, init=False)

    @property
    def managed_state_change_authorized(self) -> bool:
        return self.verified

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
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
            "certificate_present": self.certificate_present,
            "profile_present": self.profile_present,
            "agent_present": self.agent_present,
            "management_active": self.management_active,
            "verified": self.verified,
            "failure_reasons": list(self.failure_reasons),
            "post_condition_verified": self.verified,
            "managed_state_change_authorized": self.verified,
            "credential_value_access_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_verification_request(
    *, execution_receipt: object, snapshot: HouseholdSnapshot,
) -> DeviceManagementEnrollmentVerificationRequest:
    """Bind provider read-back to one accepted execution and exact current snapshot."""

    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    receipt = _execution_receipt(execution_receipt)

    device_id = receipt["device_id"]
    member_id = receipt["member_id"]
    device = next((item for item in snapshot.household.devices if item.device_id == device_id), None)
    if device is None:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_device_not_found")
    if device.member_id != member_id:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_device_binding_mismatch")
    if device.managed:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_already_managed")

    canonical = {
        "execution_job_id": receipt["job_id"],
        "plan_id": receipt["plan_id"],
        "provider_id": receipt["provider_id"],
        "provider_operation_id": receipt["provider_operation_id"],
        "household_id": snapshot.household_id,
        "snapshot_id": snapshot.snapshot_id,
        "resource_version": snapshot.resource_version,
        "generation": snapshot.generation,
        "device_id": device.device_id,
        "member_id": device.member_id,
    }
    verification_id = "dmpverify-" + _canonical_digest(canonical)[:24]
    return DeviceManagementEnrollmentVerificationRequest(
        verification_id=verification_id,
        execution_job_id=receipt["job_id"],
        plan_id=receipt["plan_id"],
        provider_id=receipt["provider_id"],
        provider_operation_id=receipt["provider_operation_id"],
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        device_id=device.device_id,
        member_id=device.member_id,
    )


def verification_result_from_dict(
    value: object, *, request: DeviceManagementEnrollmentVerificationRequest,
) -> DeviceManagementEnrollmentVerificationResult:
    expected = {
        "schema", "provider_operation_id", "device_id", "certificate_present", "profile_present",
        "agent_present", "management_active", "observed_at", "secret_material_present",
        "infrastructure_mutation_authorized",
    }
    if not isinstance(request, DeviceManagementEnrollmentVerificationRequest):
        raise TypeError("invalid_device_management_enrollment_verification_request")
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_result_rejected")
    if (
        value.get("schema") != VERIFICATION_RESULT_SCHEMA
        or value.get("provider_operation_id") != request.provider_operation_id
        or value.get("device_id") != request.device_id
        or any(not isinstance(value.get(name), bool) for name in (
            "certificate_present", "profile_present", "agent_present", "management_active"
        ))
        or not isinstance(value.get("observed_at"), str)
        or RFC3339_UTC_SECONDS.fullmatch(value["observed_at"]) is None
        or value.get("secret_material_present") is not False
        or value.get("infrastructure_mutation_authorized") is not False
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_result_rejected")
    return DeviceManagementEnrollmentVerificationResult(
        provider_operation_id=request.provider_operation_id,
        device_id=request.device_id,
        certificate_present=value["certificate_present"],
        profile_present=value["profile_present"],
        agent_present=value["agent_present"],
        management_active=value["management_active"],
        observed_at=value["observed_at"],
    )


def evaluate_verification_result(
    *, request: DeviceManagementEnrollmentVerificationRequest,
    result: DeviceManagementEnrollmentVerificationResult,
) -> DeviceManagementEnrollmentVerificationEvidence:
    """Produce deterministic evidence; partial provider state always fails closed."""

    if not isinstance(request, DeviceManagementEnrollmentVerificationRequest):
        raise TypeError("invalid_device_management_enrollment_verification_request")
    if not isinstance(result, DeviceManagementEnrollmentVerificationResult):
        raise TypeError("invalid_device_management_enrollment_verification_result")
    if result.provider_operation_id != request.provider_operation_id or result.device_id != request.device_id:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_binding_mismatch")

    failures: list[str] = []
    if not result.certificate_present:
        failures.append("certificate-missing")
    if not result.profile_present:
        failures.append("profile-missing")
    if not result.agent_present:
        failures.append("agent-missing")
    if not result.management_active:
        failures.append("management-inactive")

    return DeviceManagementEnrollmentVerificationEvidence(
        verification_id=request.verification_id,
        execution_job_id=request.execution_job_id,
        plan_id=request.plan_id,
        provider_id=request.provider_id,
        provider_operation_id=request.provider_operation_id,
        household_id=request.household_id,
        snapshot_id=request.snapshot_id,
        resource_version=request.resource_version,
        generation=request.generation,
        device_id=request.device_id,
        member_id=request.member_id,
        observed_at=result.observed_at,
        certificate_present=result.certificate_present,
        profile_present=result.profile_present,
        agent_present=result.agent_present,
        management_active=result.management_active,
        verified=not failures,
        failure_reasons=tuple(failures),
    )


def build_managed_state_replacement(
    current: HouseholdSnapshot,
    evidence: DeviceManagementEnrollmentVerificationEvidence,
) -> tuple[HouseholdSnapshot, HouseholdCommit]:
    """Build the only 0.58 transition that may set ``managed=True``.

    The operation is pure and optimistic-concurrency bound. Persistence must
    still compare-and-swap the exact resource version represented by ``current``.
    """

    if not isinstance(current, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    if not isinstance(evidence, DeviceManagementEnrollmentVerificationEvidence):
        raise TypeError("invalid_device_management_enrollment_verification_evidence")
    if not evidence.verified or not evidence.managed_state_change_authorized:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_post_condition_not_verified")
    if (
        current.household_id != evidence.household_id
        or current.snapshot_id != evidence.snapshot_id
        or current.resource_version != evidence.resource_version
        or current.generation != evidence.generation
    ):
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_stale")

    device = next((item for item in current.household.devices if item.device_id == evidence.device_id), None)
    if device is None:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_device_not_found")
    if device.member_id != evidence.member_id:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_device_binding_mismatch")
    if device.managed:
        raise DeviceManagementEnrollmentVerificationError("device_management_enrollment_verification_already_managed")

    replacement_device = ManagedDevice(
        device_id=device.device_id,
        member_id=device.member_id,
        display_name=device.display_name,
        managed=True,
    )
    replacement = Household(
        household_id=current.household_id,
        members=current.household.members,
        devices=tuple(replacement_device if item.device_id == device.device_id else item for item in current.household.devices),
    )
    try:
        return build_household_replacement(current, replacement, expected_resource_version=current.resource_version)
    except HomeServiceCatalogError as exc:
        raise DeviceManagementEnrollmentVerificationError(exc.code) from exc
