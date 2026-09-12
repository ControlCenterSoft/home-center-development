"""Non-authorizing policy handoff after verified enrollment state commit.

0.58 may prove that an enrollment is active and atomically mark the device as
managed, but that must not implicitly apply MDM/family/network policy.  This
module emits a deterministic handoff reference for the later policy pipeline.  A
handoff is evidence that policy *context* exists; it carries no execution
authority and requires a new policy plan plus a separate confirmation.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field


HANDOFF_SCHEMA = "home-center.device-management-enrollment-policy-handoff.v1"
COMMIT_RECEIPT_SCHEMA = (
    "home-center.device-management-enrollment-managed-state-commit-receipt.v1"
)
HEX24 = re.compile(r"^[0-9a-f]{24}$")
VERIFICATION_ID = re.compile(r"^dmpverify-[0-9a-f]{24}$")
PLAN_ID = re.compile(r"^dmpexec-[0-9a-f]{24}$")
COMMIT_ID = re.compile(r"^hcommit-[0-9a-f]{24}$")
RESOURCE_VERSION = re.compile(r"^hrv-[0-9a-f]{24}$")
SNAPSHOT_ID = re.compile(r"^hsnap-[0-9a-f]{24}$")
AUDIT_EVENT_ID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


class DeviceManagementEnrollmentPolicyHandoffError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentPolicyHandoff:
    handoff_id: str
    commit_job_id: str
    verification_id: str
    execution_job_id: str
    enrollment_plan_id: str
    household_id: str
    device_id: str
    member_id: str
    commit_id: str
    resource_version: str
    generation: int
    snapshot_id: str
    audit_event_id: str
    schema: str = field(default=HANDOFF_SCHEMA, init=False)
    policy_context_ready: bool = field(default=True, init=False)
    separate_policy_plan_required: bool = field(default=True, init=False)
    separate_confirmation_required: bool = field(default=True, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    policy_execution_authorized: bool = field(default=False, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "handoff_id": self.handoff_id,
            "commit_job_id": self.commit_job_id,
            "verification_id": self.verification_id,
            "execution_job_id": self.execution_job_id,
            "enrollment_plan_id": self.enrollment_plan_id,
            "household_id": self.household_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "commit_id": self.commit_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "snapshot_id": self.snapshot_id,
            "audit_event_id": self.audit_event_id,
            "policy_context_ready": True,
            "separate_policy_plan_required": True,
            "separate_confirmation_required": True,
            "policy_application_authorized": False,
            "policy_execution_authorized": False,
            "provider_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _digest(value: dict[str, object]) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _bounded_string(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128


def build_policy_handoff(
    managed_state_commit_receipt: object,
) -> DeviceManagementEnrollmentPolicyHandoff:
    """Turn one exact verified managed-state receipt into non-mutating context.

    The input must be the terminal receipt from the 0.58 atomic managed-state
    commit.  Any attempt to smuggle policy/provider/infrastructure authority into
    that receipt is rejected rather than propagated.
    """

    expected = {
        "schema",
        "state",
        "job_id",
        "verification_id",
        "execution_job_id",
        "plan_id",
        "household_id",
        "device_id",
        "member_id",
        "commit_id",
        "previous_resource_version",
        "resource_version",
        "generation",
        "snapshot_id",
        "audit_event_id",
        "post_condition_verified",
        "managed_state_change_authorized",
        "managed_state_change_committed",
        "provider_mutation_authorized",
        "policy_application_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
        "audit_required",
    }
    value = managed_state_commit_receipt
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementEnrollmentPolicyHandoffError(
            "device_management_enrollment_policy_handoff_receipt_invalid"
        )

    job_id = value.get("job_id")
    verification_id = value.get("verification_id")
    execution_job_id = value.get("execution_job_id")
    plan_id = value.get("plan_id")
    household_id = value.get("household_id")
    device_id = value.get("device_id")
    member_id = value.get("member_id")
    commit_id = value.get("commit_id")
    previous_resource_version = value.get("previous_resource_version")
    resource_version = value.get("resource_version")
    generation = value.get("generation")
    snapshot_id = value.get("snapshot_id")
    audit_event_id = value.get("audit_event_id")

    if (
        value.get("schema") != COMMIT_RECEIPT_SCHEMA
        or value.get("state") != "managed-state-committed"
        or not _bounded_string(job_id)
        or not isinstance(verification_id, str)
        or VERIFICATION_ID.fullmatch(verification_id) is None
        or not _bounded_string(execution_job_id)
        or not isinstance(plan_id, str)
        or PLAN_ID.fullmatch(plan_id) is None
        or not _bounded_string(household_id)
        or not _bounded_string(device_id)
        or not _bounded_string(member_id)
        or not isinstance(commit_id, str)
        or COMMIT_ID.fullmatch(commit_id) is None
        or not isinstance(previous_resource_version, str)
        or RESOURCE_VERSION.fullmatch(previous_resource_version) is None
        or not isinstance(resource_version, str)
        or RESOURCE_VERSION.fullmatch(resource_version) is None
        or resource_version == previous_resource_version
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 2
        or not isinstance(snapshot_id, str)
        or SNAPSHOT_ID.fullmatch(snapshot_id) is None
        or not isinstance(audit_event_id, str)
        or AUDIT_EVENT_ID.fullmatch(audit_event_id) is None
        or value.get("post_condition_verified") is not True
        or value.get("managed_state_change_authorized") is not True
        or value.get("managed_state_change_committed") is not True
        or value.get("provider_mutation_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
        or value.get("audit_required") is not True
    ):
        raise DeviceManagementEnrollmentPolicyHandoffError(
            "device_management_enrollment_policy_handoff_receipt_invalid"
        )

    canonical = {
        "commit_job_id": job_id,
        "verification_id": verification_id,
        "execution_job_id": execution_job_id,
        "enrollment_plan_id": plan_id,
        "household_id": household_id,
        "device_id": device_id,
        "member_id": member_id,
        "commit_id": commit_id,
        "resource_version": resource_version,
        "generation": generation,
        "snapshot_id": snapshot_id,
        "audit_event_id": audit_event_id,
    }
    handoff_id = "dmphandoff-" + _digest(canonical)[:24]
    return DeviceManagementEnrollmentPolicyHandoff(
        handoff_id=handoff_id,
        commit_job_id=job_id,
        verification_id=verification_id,
        execution_job_id=execution_job_id,
        enrollment_plan_id=plan_id,
        household_id=household_id,
        device_id=device_id,
        member_id=member_id,
        commit_id=commit_id,
        resource_version=resource_version,
        generation=generation,
        snapshot_id=snapshot_id,
        audit_event_id=audit_event_id,
    )
