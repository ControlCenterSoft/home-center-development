"""Confirmation-gated Household member product-state change contracts.

This module is deliberately pure: it plans and validates one member addition
against an exact Household snapshot but never persists state or executes a
provider. Runtime persistence and audit ordering live in household_runtime.py.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .home_services import HomeServiceCatalogError, _identifier
from .household import FamilyMember, Household, HouseholdRole, effective_policy
from .household_store import HouseholdSnapshot, build_household_replacement


MEMBER_ADD_PROPOSAL_SCHEMA = "home-center.household-member-add-proposal.v1"
MEMBER_ADD_RECEIPT_SCHEMA = "home-center.household-member-add-receipt.v1"


class HouseholdMemberChangeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _proposal_canonical(
    *,
    household_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    actor_member_id: str,
    member: FamilyMember,
) -> dict[str, object]:
    return {
        "household_id": household_id,
        "snapshot_id": snapshot_id,
        "resource_version": resource_version,
        "generation": generation,
        "actor_member_id": actor_member_id,
        "member": member.to_dict(),
    }


def _proposal_id(canonical: dict[str, object]) -> str:
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return "hmadd-" + hashlib.sha256(encoded).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class HouseholdMemberAddProposal:
    proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    member: FamilyMember
    schema: str = field(default=MEMBER_ADD_PROPOSAL_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    mutation_authorized: bool = field(default=False, init=False)
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
            "member": self.member.to_dict(),
            "confirmation_required": True,
            "mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class HouseholdMemberAddReceipt:
    proposal_id: str
    outcome: str
    member: FamilyMember
    previous_snapshot_id: str
    previous_resource_version: str
    snapshot_id: str
    resource_version: str
    generation: int
    commit_id: str
    audit_event_id: str
    schema: str = field(default=MEMBER_ADD_RECEIPT_SCHEMA, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.outcome not in {"applied", "already-applied"}:
            raise HouseholdMemberChangeError("invalid_household_member_receipt_outcome")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "outcome": self.outcome,
            "member": self.member.to_dict(),
            "previous_snapshot_id": self.previous_snapshot_id,
            "previous_resource_version": self.previous_resource_version,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "commit_id": self.commit_id,
            "audit_event_id": self.audit_event_id,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def build_member_add_proposal(
    snapshot: HouseholdSnapshot,
    *,
    actor_member_id: str,
    member_id: str,
    display_name: str,
    role: HouseholdRole,
) -> HouseholdMemberAddProposal:
    if not isinstance(snapshot, HouseholdSnapshot):
        raise TypeError("invalid_household_snapshot")
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    try:
        actor_policy = effective_policy(snapshot.household, actor_id)
    except HomeServiceCatalogError as exc:
        raise HouseholdMemberChangeError(exc.code) from exc
    if not actor_policy.administration_allowed:
        raise HouseholdMemberChangeError("household_member_change_not_authorized")
    if not isinstance(role, HouseholdRole):
        raise HouseholdMemberChangeError("invalid_household_role")
    if any(item.member_id == member_id for item in snapshot.household.members):
        raise HouseholdMemberChangeError("household_member_already_exists")
    try:
        member = FamilyMember(member_id=member_id, display_name=display_name, role=role)
        # Construct the resulting domain object now so capacity, duplicate and
        # parent invariants fail at planning time rather than after confirmation.
        Household(
            household_id=snapshot.household_id,
            members=(*snapshot.household.members, member),
            devices=snapshot.household.devices,
        )
    except HomeServiceCatalogError as exc:
        raise HouseholdMemberChangeError(exc.code) from exc
    canonical = _proposal_canonical(
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        member=member,
    )
    return HouseholdMemberAddProposal(
        proposal_id=_proposal_id(canonical),
        household_id=snapshot.household_id,
        snapshot_id=snapshot.snapshot_id,
        resource_version=snapshot.resource_version,
        generation=snapshot.generation,
        actor_member_id=actor_id,
        member=member,
    )


def member_add_proposal_from_dict(value: object) -> HouseholdMemberAddProposal:
    if not isinstance(value, dict):
        raise HouseholdMemberChangeError("invalid_household_member_proposal")
    expected = {
        "schema",
        "proposal_id",
        "household_id",
        "snapshot_id",
        "resource_version",
        "generation",
        "actor_member_id",
        "member",
        "confirmation_required",
        "mutation_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if set(value) != expected or value.get("schema") != MEMBER_ADD_PROPOSAL_SCHEMA:
        raise HouseholdMemberChangeError("invalid_household_member_proposal")
    if (
        value.get("confirmation_required") is not True
        or value.get("mutation_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdMemberChangeError("invalid_household_member_proposal")
    raw_member = value.get("member")
    if not isinstance(raw_member, dict) or set(raw_member) != {"member_id", "display_name", "role", "enabled"}:
        raise HouseholdMemberChangeError("invalid_household_member_proposal")
    try:
        member = FamilyMember(
            member_id=raw_member["member_id"],
            display_name=raw_member["display_name"],
            role=HouseholdRole(raw_member["role"]),
            enabled=raw_member["enabled"],
        )
        if member.enabled is not True:
            raise HouseholdMemberChangeError("invalid_household_member_proposal")
        generation = value["generation"]
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HouseholdMemberChangeError("invalid_household_member_proposal")
        canonical = _proposal_canonical(
            household_id=_identifier(value["household_id"], "invalid_household_id"),
            snapshot_id=_identifier(value["snapshot_id"], "invalid_household_snapshot_id"),
            resource_version=_identifier(value["resource_version"], "invalid_household_resource_version"),
            generation=generation,
            actor_member_id=_identifier(value["actor_member_id"], "invalid_household_member_id"),
            member=member,
        )
    except HouseholdMemberChangeError:
        raise
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError) as exc:
        raise HouseholdMemberChangeError("invalid_household_member_proposal") from exc
    expected_id = _proposal_id(canonical)
    if value.get("proposal_id") != expected_id:
        raise HouseholdMemberChangeError("household_member_proposal_evidence_mismatch")
    return HouseholdMemberAddProposal(
        proposal_id=expected_id,
        household_id=canonical["household_id"],
        snapshot_id=canonical["snapshot_id"],
        resource_version=canonical["resource_version"],
        generation=generation,
        actor_member_id=canonical["actor_member_id"],
        member=member,
    )


def apply_member_add_proposal(
    current: HouseholdSnapshot,
    proposal: HouseholdMemberAddProposal,
    *,
    actor_member_id: str,
):
    """Revalidate exact state and build the next snapshot/commit evidence."""

    if not isinstance(current, HouseholdSnapshot) or not isinstance(proposal, HouseholdMemberAddProposal):
        raise TypeError("invalid_household_member_change")
    actor_id = _identifier(actor_member_id, "invalid_household_member_id")
    if actor_id != proposal.actor_member_id:
        raise HouseholdMemberChangeError("household_member_change_actor_mismatch")
    if (
        current.household_id != proposal.household_id
        or current.snapshot_id != proposal.snapshot_id
        or current.resource_version != proposal.resource_version
        or current.generation != proposal.generation
    ):
        raise HouseholdMemberChangeError("household_member_change_stale")
    # Rebuild from exact current state to detect proposal tampering and re-check
    # current parent authorization at confirmation time.
    rebuilt = build_member_add_proposal(
        current,
        actor_member_id=actor_id,
        member_id=proposal.member.member_id,
        display_name=proposal.member.display_name,
        role=proposal.member.role,
    )
    if rebuilt != proposal:
        raise HouseholdMemberChangeError("household_member_proposal_evidence_mismatch")
    replacement = Household(
        household_id=current.household_id,
        members=(*current.household.members, proposal.member),
        devices=current.household.devices,
    )
    return build_household_replacement(
        current,
        replacement,
        expected_resource_version=proposal.resource_version,
    )
