"""Strict persistence decoders for Home Center 0.58 verification evidence."""
from __future__ import annotations

import re

from .device_management_enrollment_verification import (
    PROVIDER_OPERATION_ID,
    RFC3339_UTC_SECONDS,
    VERIFICATION_EVIDENCE_SCHEMA,
    DeviceManagementEnrollmentVerificationEvidence,
    DeviceManagementEnrollmentVerificationError,
)


VERIFICATION_ID = re.compile(r"^dmpverify-[0-9a-f]{24}$")
PLAN_ID = re.compile(r"^dmpexec-[0-9a-f]{24}$")
SNAPSHOT_ID = re.compile(r"^hsnap-[0-9a-f]{24}$")
RESOURCE_VERSION = re.compile(r"^hrv-[0-9a-f]{24}$")
FAILURE_ORDER = (
    ("certificate_present", "certificate-missing"),
    ("profile_present", "profile-missing"),
    ("agent_present", "agent-missing"),
    ("management_active", "management-inactive"),
)


def verification_evidence_from_dict(
    value: object,
) -> DeviceManagementEnrollmentVerificationEvidence:
    """Decode persisted evidence only when every fail-closed invariant holds."""

    expected = {
        "schema",
        "verification_id",
        "execution_job_id",
        "plan_id",
        "provider_id",
        "provider_operation_id",
        "household_id",
        "snapshot_id",
        "resource_version",
        "generation",
        "device_id",
        "member_id",
        "observed_at",
        "certificate_present",
        "profile_present",
        "agent_present",
        "management_active",
        "verified",
        "failure_reasons",
        "post_condition_verified",
        "managed_state_change_authorized",
        "credential_value_access_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_verification_evidence_invalid"
        )

    verification_id = value.get("verification_id")
    execution_job_id = value.get("execution_job_id")
    plan_id = value.get("plan_id")
    provider_id = value.get("provider_id")
    provider_operation_id = value.get("provider_operation_id")
    household_id = value.get("household_id")
    snapshot_id = value.get("snapshot_id")
    resource_version = value.get("resource_version")
    generation = value.get("generation")
    device_id = value.get("device_id")
    member_id = value.get("member_id")
    observed_at = value.get("observed_at")
    failure_reasons = value.get("failure_reasons")

    if (
        value.get("schema") != VERIFICATION_EVIDENCE_SCHEMA
        or not isinstance(verification_id, str)
        or VERIFICATION_ID.fullmatch(verification_id) is None
        or not isinstance(execution_job_id, str)
        or not execution_job_id
        or len(execution_job_id) > 128
        or not isinstance(plan_id, str)
        or PLAN_ID.fullmatch(plan_id) is None
        or not isinstance(provider_id, str)
        or not provider_id
        or len(provider_id) > 128
        or not isinstance(provider_operation_id, str)
        or PROVIDER_OPERATION_ID.fullmatch(provider_operation_id) is None
        or not isinstance(household_id, str)
        or not household_id
        or len(household_id) > 128
        or not isinstance(snapshot_id, str)
        or SNAPSHOT_ID.fullmatch(snapshot_id) is None
        or not isinstance(resource_version, str)
        or RESOURCE_VERSION.fullmatch(resource_version) is None
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
        or not isinstance(device_id, str)
        or not device_id
        or len(device_id) > 128
        or not isinstance(member_id, str)
        or not member_id
        or len(member_id) > 128
        or not isinstance(observed_at, str)
        or RFC3339_UTC_SECONDS.fullmatch(observed_at) is None
        or any(
            not isinstance(value.get(field), bool)
            for field, _reason in FAILURE_ORDER
        )
        or not isinstance(value.get("verified"), bool)
        or not isinstance(failure_reasons, list)
        or any(not isinstance(reason, str) for reason in failure_reasons)
        or len(failure_reasons) != len(set(failure_reasons))
        or not isinstance(value.get("post_condition_verified"), bool)
        or not isinstance(value.get("managed_state_change_authorized"), bool)
        or value.get("credential_value_access_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_verification_evidence_invalid"
        )

    expected_failures = tuple(
        reason
        for field, reason in FAILURE_ORDER
        if value[field] is False
    )
    verified = not expected_failures
    if (
        tuple(failure_reasons) != expected_failures
        or value["verified"] is not verified
        or value["post_condition_verified"] is not verified
        or value["managed_state_change_authorized"] is not verified
    ):
        raise DeviceManagementEnrollmentVerificationError(
            "device_management_enrollment_verification_evidence_invalid"
        )

    return DeviceManagementEnrollmentVerificationEvidence(
        verification_id=verification_id,
        execution_job_id=execution_job_id,
        plan_id=plan_id,
        provider_id=provider_id,
        provider_operation_id=provider_operation_id,
        household_id=household_id,
        snapshot_id=snapshot_id,
        resource_version=resource_version,
        generation=generation,
        device_id=device_id,
        member_id=member_id,
        observed_at=observed_at,
        certificate_present=value["certificate_present"],
        profile_present=value["profile_present"],
        agent_present=value["agent_present"],
        management_active=value["management_active"],
        verified=verified,
        failure_reasons=expected_failures,
    )
