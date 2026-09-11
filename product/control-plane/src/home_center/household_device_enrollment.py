"""Confirmation-gated intent boundary for future Household device enrollment.

The contract records explicit consent to proceed from a required management plan
toward provider resolution. It never selects or invokes a provider, never changes
Household state and never marks a device managed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .home_services import _identifier
from .household_device_management import (
    DeviceManagementState,
    HouseholdDeviceManagementError,
    HouseholdDeviceManagementPlan,
    plan_device_management,
)
from .household_store import HouseholdSnapshot


DEVICE_ENROLLMENT_PROPOSAL_SCHEMA = "home-center.household-device-enrollment-proposal.v1"
DEVICE_ENROLLMENT_RECEIPT_SCHEMA = "home-center.household-device-enrollment-confirmation.v1"


class HouseholdDeviceEnrollmentError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(plan: HouseholdDeviceManagementPlan) -> dict[str, object]:
    return {
        "management_plan_id": plan.plan_id,
        "household_id": plan.household_id,
        "snapshot_id": plan.snapshot_id,
        "resource_version": plan.resource_version,
        "generation": plan.generation,
        "actor_member_id": plan.actor_member_id,
        "device_id": plan.device_id,
        "member_id": plan.member_id,
        "member_role": plan.member_role.value,
    }


def _proposal_id(canonical: dict[str, object]) -> str:
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "hdenroll-" + hashlib.sha256(encoded).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class HouseholdDeviceEnrollmentProposal:
    proposal_id: str
    management_plan_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    member_role: str
    schema: str = field(default=DEVICE_ENROLLMENT_PROPOSAL_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    provider_resolution_required: bool = field(default=True, init=False)
    provider_selected: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "management_plan_id": self.management_plan_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "member_role": self.member_role,
            "confirmation_required": True,
            "provider_resolution_required": True,
            "provider_selected": False,
            "provider_execution_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class HouseholdDeviceEnrollmentConfirmation:
    proposal_id: str
    management_plan_id: str
    device_id: str
    member_id: str
    outcome: str
    snapshot_id: str
    resource_version: str
    generation: int
    audit_event_id: str
    schema: str = field(default=DEVICE_ENROLLMENT_RECEIPT_SCHEMA, init=False)

    def __post_init__(self) -> None:
        if self.outcome not in {"confirmed-for-provider-resolution", "already-confirmed"}:
            raise HouseholdDeviceEnrollmentError("invalid_household_device_enrollment_outcome")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "management_plan_id": self.management_plan_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "outcome": self.outcome,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "audit_event_id": self.audit_event_id,
            "provider_resolution_required": True,
            "provider_selected": False,
            "provider_execution_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_device_enrollment_proposal(
    snapshot: HouseholdSnapshot,
    *,
    actor_member_id: str,
    device_id: str,
) -> HouseholdDeviceEnrollmentProposal:
    try:
        plan = plan_device_management(snapshot, actor_member_id=actor_member_id, device_id=device_id)
    except HouseholdDeviceManagementError as exc:
        raise HouseholdDeviceEnrollmentError(exc.code) from exc
    if plan.state is not DeviceManagementState.REQUIRED or plan.managed or not plan.management_required:
        raise HouseholdDeviceEnrollmentError("household_device_enrollment_not_required")
    canonical = _canonical(plan)
    return HouseholdDeviceEnrollmentProposal(
        proposal_id=_proposal_id(canonical),
        management_plan_id=plan.plan_id,
        household_id=plan.household_id,
        snapshot_id=plan.snapshot_id,
        resource_version=plan.resource_version,
        generation=plan.generation,
        actor_member_id=plan.actor_member_id,
        device_id=plan.device_id,
        member_id=plan.member_id,
        member_role=plan.member_role.value,
    )


def device_enrollment_proposal_from_dict(value: object) -> HouseholdDeviceEnrollmentProposal:
    if not isinstance(value, dict):
        raise HouseholdDeviceEnrollmentError("invalid_household_device_enrollment_proposal")
    expected = {
        "schema", "proposal_id", "management_plan_id", "household_id", "snapshot_id",
        "resource_version", "generation", "actor_member_id", "device_id", "member_id",
        "member_role", "confirmation_required", "provider_resolution_required",
        "provider_selected", "provider_execution_authorized", "policy_application_authorized",
        "managed_state_change_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if set(value) != expected or value.get("schema") != DEVICE_ENROLLMENT_PROPOSAL_SCHEMA:
        raise HouseholdDeviceEnrollmentError("invalid_household_device_enrollment_proposal")
    if (
        value.get("confirmation_required") is not True
        or value.get("provider_resolution_required") is not True
        or value.get("provider_selected") is not False
        or value.get("provider_execution_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("managed_state_change_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdDeviceEnrollmentError("invalid_household_device_enrollment_proposal")
    generation = value.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise HouseholdDeviceEnrollmentError("invalid_household_device_enrollment_proposal")
    try:
        canonical = {
            "management_plan_id": _identifier(value.get("management_plan_id"), "invalid_management_plan_id"),
            "household_id": _identifier(value.get("household_id"), "invalid_household_id"),
            "snapshot_id": _identifier(value.get("snapshot_id"), "invalid_household_snapshot_id"),
            "resource_version": _identifier(value.get("resource_version"), "invalid_household_resource_version"),
            "generation": generation,
            "actor_member_id": _identifier(value.get("actor_member_id"), "invalid_household_member_id"),
            "device_id": _identifier(value.get("device_id"), "invalid_household_device_id"),
            "member_id": _identifier(value.get("member_id"), "invalid_household_member_id"),
            "member_role": value.get("member_role"),
        }
    except Exception as exc:
        raise HouseholdDeviceEnrollmentError("invalid_household_device_enrollment_proposal") from exc
    if canonical["member_role"] not in {"parent", "child", "guest"}:
        raise HouseholdDeviceEnrollmentError("invalid_household_device_enrollment_proposal")
    expected_id = _proposal_id(canonical)
    if value.get("proposal_id") != expected_id:
        raise HouseholdDeviceEnrollmentError("household_device_enrollment_evidence_mismatch")
    return HouseholdDeviceEnrollmentProposal(
        proposal_id=expected_id,
        management_plan_id=canonical["management_plan_id"],
        household_id=canonical["household_id"],
        snapshot_id=canonical["snapshot_id"],
        resource_version=canonical["resource_version"],
        generation=generation,
        actor_member_id=canonical["actor_member_id"],
        device_id=canonical["device_id"],
        member_id=canonical["member_id"],
        member_role=canonical["member_role"],
    )


def revalidate_device_enrollment_proposal(
    current: HouseholdSnapshot,
    proposal: HouseholdDeviceEnrollmentProposal,
    *,
    actor_member_id: str,
) -> None:
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    if actor_id != proposal.actor_member_id:
        raise HouseholdDeviceEnrollmentError("household_device_enrollment_actor_mismatch")
    if (
        current.household_id != proposal.household_id
        or current.snapshot_id != proposal.snapshot_id
        or current.resource_version != proposal.resource_version
        or current.generation != proposal.generation
    ):
        raise HouseholdDeviceEnrollmentError("household_device_enrollment_stale")
    rebuilt = build_device_enrollment_proposal(current, actor_member_id=actor_id, device_id=proposal.device_id)
    if rebuilt != proposal:
        raise HouseholdDeviceEnrollmentError("household_device_enrollment_evidence_mismatch")
