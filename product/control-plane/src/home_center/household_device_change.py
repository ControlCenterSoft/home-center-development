"""Confirmation-gated Household device product-state registration.

The boundary is deliberately provider-free. A confirmed registration attaches a
known device to one exact FamilyMember with ``managed=False``. It never claims
that MDM, DNS, VPN, filtering or another effective policy has been applied.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .home_services import HomeServiceCatalogError, _identifier
from .household import Household, HouseholdRole, ManagedDevice, effective_policy
from .household_store import HouseholdSnapshot, build_household_replacement


DEVICE_ADD_PROPOSAL_SCHEMA = "home-center.household-device-add-proposal.v1"
DEVICE_ADD_RECEIPT_SCHEMA = "home-center.household-device-add-receipt.v1"


class HouseholdDeviceChangeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(
    *,
    household_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    actor_member_id: str,
    device: ManagedDevice,
    management_required: bool,
) -> dict[str, object]:
    return {
        "household_id": household_id,
        "snapshot_id": snapshot_id,
        "resource_version": resource_version,
        "generation": generation,
        "actor_member_id": actor_member_id,
        "device": device.to_dict(),
        "management_required": management_required,
    }


def _proposal_id(value: dict[str, object]) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "hdadd-" + hashlib.sha256(encoded).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class HouseholdDeviceAddProposal:
    proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device: ManagedDevice
    management_required: bool
    schema: str = field(default=DEVICE_ADD_PROPOSAL_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    managed_after_registration: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device": self.device.to_dict(),
            "management_required": self.management_required,
            "confirmation_required": True,
            "managed_after_registration": False,
            "policy_application_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class HouseholdDeviceAddReceipt:
    proposal_id: str
    outcome: str
    device: ManagedDevice
    management_required: bool
    previous_snapshot_id: str
    previous_resource_version: str
    snapshot_id: str
    resource_version: str
    generation: int
    commit_id: str
    audit_event_id: str
    schema: str = field(default=DEVICE_ADD_RECEIPT_SCHEMA, init=False)
    managed: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.outcome not in {"applied", "already-applied"}:
            raise HouseholdDeviceChangeError("invalid_household_device_receipt_outcome")
        if self.device.managed:
            raise HouseholdDeviceChangeError("household_device_false_managed_claim")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "outcome": self.outcome,
            "device": self.device.to_dict(),
            "management_required": self.management_required,
            "previous_snapshot_id": self.previous_snapshot_id,
            "previous_resource_version": self.previous_resource_version,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "commit_id": self.commit_id,
            "audit_event_id": self.audit_event_id,
            "managed": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_device_add_proposal(
    snapshot: HouseholdSnapshot,
    *,
    actor_member_id: str,
    device_id: str,
    subject_member_id: str,
    display_name: str,
) -> HouseholdDeviceAddProposal:
    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    subject_id = _identifier(subject_member_id, "invalid_household_member_id")
    try:
        actor = snapshot.household.member(actor_id)
        actor_policy = effective_policy(snapshot.household, actor_id)
        subject = snapshot.household.member(subject_id)
        subject_policy = effective_policy(snapshot.household, subject_id)
    except HomeServiceCatalogError as exc:
        raise HouseholdDeviceChangeError(exc.code) from exc
    if actor.role is not HouseholdRole.PARENT or not actor_policy.administration_allowed:
        raise HouseholdDeviceChangeError("household_device_change_not_authorized")
    if not subject.enabled:
        raise HouseholdDeviceChangeError("household_device_subject_disabled")
    if any(item.device_id == device_id for item in snapshot.household.devices):
        raise HouseholdDeviceChangeError("household_device_already_exists")
    try:
        device = ManagedDevice(
            device_id=device_id,
            member_id=subject_id,
            display_name=display_name,
            managed=False,
        )
        Household(
            household_id=snapshot.household_id,
            members=snapshot.household.members,
            devices=(*snapshot.household.devices, device),
        )
    except HomeServiceCatalogError as exc:
        raise HouseholdDeviceChangeError(exc.code) from exc
    management_required = subject_policy.managed_device_required
    canonical = _canonical(
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        device=device,
        management_required=management_required,
    )
    return HouseholdDeviceAddProposal(
        proposal_id=_proposal_id(canonical),
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        device=device,
        management_required=management_required,
    )


def device_add_proposal_from_dict(value: object) -> HouseholdDeviceAddProposal:
    if not isinstance(value, dict):
        raise HouseholdDeviceChangeError("invalid_household_device_proposal")
    expected = {
        "schema", "proposal_id", "household_id", "snapshot_id", "resource_version", "generation",
        "actor_member_id", "device", "management_required", "confirmation_required",
        "managed_after_registration", "policy_application_authorized", "provider_execution_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if set(value) != expected or value.get("schema") != DEVICE_ADD_PROPOSAL_SCHEMA:
        raise HouseholdDeviceChangeError("invalid_household_device_proposal")
    if (
        value.get("confirmation_required") is not True
        or value.get("managed_after_registration") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("provider_execution_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
        or not isinstance(value.get("management_required"), bool)
    ):
        raise HouseholdDeviceChangeError("invalid_household_device_proposal")
    raw_device = value.get("device")
    if not isinstance(raw_device, dict) or set(raw_device) != {"device_id", "member_id", "display_name", "managed"}:
        raise HouseholdDeviceChangeError("invalid_household_device_proposal")
    try:
        device = ManagedDevice(
            device_id=raw_device["device_id"],
            member_id=raw_device["member_id"],
            display_name=raw_device["display_name"],
            managed=raw_device["managed"],
        )
        if device.managed:
            raise HouseholdDeviceChangeError("household_device_false_managed_claim")
        generation = value["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HouseholdDeviceChangeError("invalid_household_device_proposal")
        canonical = _canonical(
            household_id=_identifier(value["household_id"], "invalid_household_id"),
            snapshot_id=_identifier(value["snapshot_id"], "invalid_household_snapshot_id"),
            resource_version=_identifier(value["resource_version"], "invalid_household_resource_version"),
            generation=generation,
            actor_member_id=_identifier(value["actor_member_id"], "invalid_household_member_id"),
            device=device,
            management_required=value["management_required"],
        )
    except HouseholdDeviceChangeError:
        raise
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError) as exc:
        raise HouseholdDeviceChangeError("invalid_household_device_proposal") from exc
    expected_id = _proposal_id(canonical)
    if value.get("proposal_id") != expected_id:
        raise HouseholdDeviceChangeError("household_device_proposal_evidence_mismatch")
    return HouseholdDeviceAddProposal(
        proposal_id=expected_id,
        household_id=canonical["household_id"],
        snapshot_id=canonical["snapshot_id"],
        resource_version=canonical["resource_version"],
        generation=generation,
        actor_member_id=canonical["actor_member_id"],
        device=device,
        management_required=value["management_required"],
    )


def apply_device_add_proposal(
    current: HouseholdSnapshot,
    proposal: HouseholdDeviceAddProposal,
    *,
    actor_member_id: str,
):
    if not isinstance(current, HouseholdSnapshot) or not isinstance(proposal, HouseholdDeviceAddProposal):
        raise TypeError("invalid_household_device_change")
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    if actor_id != proposal.actor_member_id:
        raise HouseholdDeviceChangeError("household_device_change_actor_mismatch")
    if (
        current.household_id != proposal.household_id
        or current.snapshot_id != proposal.snapshot_id
        or current.resource_version != proposal.resource_version
        or current.generation != proposal.generation
    ):
        raise HouseholdDeviceChangeError("household_device_change_stale")
    rebuilt = build_device_add_proposal(
        current,
        actor_member_id=actor_id,
        device_id=proposal.device.device_id,
        subject_member_id=proposal.device.member_id,
        display_name=proposal.device.display_name,
    )
    if rebuilt != proposal:
        raise HouseholdDeviceChangeError("household_device_proposal_evidence_mismatch")
    replacement = Household(
        household_id=current.household_id,
        members=current.household.members,
        devices=(*current.household.devices, proposal.device),
    )
    return build_household_replacement(
        current,
        replacement,
        expected_resource_version=proposal.resource_version,
    )
