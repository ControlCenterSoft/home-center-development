"""Confirmation-gated provider selection without enrollment or execution authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .device_management_provider import (
    DeviceManagementProviderCatalog,
    DeviceManagementProviderError,
    DevicePlatform,
    plan_provider_resolution,
)
from .home_services import HomeServiceCatalogError, _identifier
from .household_device_enrollment import HouseholdDeviceEnrollmentProposal
from .household_store import HouseholdSnapshot


PROVIDER_SELECTION_PROPOSAL_SCHEMA = "home-center.device-management-provider-selection-proposal.v1"
PROVIDER_SELECTION_CONFIRMATION_SCHEMA = "home-center.device-management-provider-selection-confirmation.v1"


class DeviceManagementProviderSelectionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DeviceManagementProviderSelectionProposal:
    proposal_id: str
    resolution_plan_id: str
    enrollment_proposal_id: str
    household_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    actor_member_id: str
    device_id: str
    member_id: str
    catalog_id: str
    device_platform: DevicePlatform
    proposed_provider_id: str
    schema: str = field(default=PROVIDER_SELECTION_PROPOSAL_SCHEMA, init=False)
    platform_claim_source: str = field(default="user", init=False)
    platform_verified: bool = field(default=False, init=False)
    provider_ready: bool = field(default=True, init=False)
    platform_supported: bool = field(default=True, init=False)
    confirmation_required: bool = field(default=True, init=False)
    provider_selected: bool = field(default=False, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    credential_access_authorized: bool = field(default=False, init=False)
    enrollment_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "resolution_plan_id": self.resolution_plan_id,
            "enrollment_proposal_id": self.enrollment_proposal_id,
            "household_id": self.household_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "actor_member_id": self.actor_member_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "catalog_id": self.catalog_id,
            "device_platform": self.device_platform.value,
            "platform_claim_source": "user",
            "platform_verified": False,
            "proposed_provider_id": self.proposed_provider_id,
            "provider_ready": True,
            "platform_supported": True,
            "confirmation_required": True,
            "provider_selected": False,
            "provider_execution_authorized": False,
            "credential_access_authorized": False,
            "enrollment_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementProviderSelectionConfirmation:
    proposal_id: str
    resolution_plan_id: str
    enrollment_proposal_id: str
    device_id: str
    member_id: str
    selected_provider_id: str
    snapshot_id: str
    resource_version: str
    generation: int
    catalog_id: str
    audit_event_id: str
    outcome: str
    schema: str = field(default=PROVIDER_SELECTION_CONFIRMATION_SCHEMA, init=False)
    provider_selected: bool = field(default=True, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    credential_access_authorized: bool = field(default=False, init=False)
    enrollment_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "proposal_id": self.proposal_id,
            "resolution_plan_id": self.resolution_plan_id,
            "enrollment_proposal_id": self.enrollment_proposal_id,
            "device_id": self.device_id,
            "member_id": self.member_id,
            "selected_provider_id": self.selected_provider_id,
            "snapshot_id": self.snapshot_id,
            "resource_version": self.resource_version,
            "generation": self.generation,
            "catalog_id": self.catalog_id,
            "audit_event_id": self.audit_event_id,
            "outcome": self.outcome,
            "provider_selected": True,
            "provider_execution_authorized": False,
            "credential_access_authorized": False,
            "enrollment_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _provider_id(value: object) -> str:
    try:
        return _identifier(value, "invalid_device_management_provider_id")
    except HomeServiceCatalogError as exc:
        raise DeviceManagementProviderSelectionError(exc.code) from exc


def build_provider_selection_proposal(
    snapshot: HouseholdSnapshot,
    enrollment_proposal: HouseholdDeviceEnrollmentProposal,
    catalog: DeviceManagementProviderCatalog,
    *,
    actor_member_id: str,
    resolution_plan_id: str,
    device_platform: DevicePlatform,
    provider_id: str,
) -> DeviceManagementProviderSelectionProposal:
    if not isinstance(resolution_plan_id, str) or not resolution_plan_id.startswith("dmpr-"):
        raise DeviceManagementProviderSelectionError("invalid_device_management_provider_resolution_plan_id")
    provider_id = _provider_id(provider_id)
    try:
        resolution = plan_provider_resolution(
            snapshot,
            enrollment_proposal,
            catalog,
            actor_member_id=actor_member_id,
            device_platform=device_platform,
        )
    except (DeviceManagementProviderError, TypeError) as exc:
        raise DeviceManagementProviderSelectionError(getattr(exc, "code", str(exc))) from exc
    if resolution.plan_id != resolution_plan_id:
        raise DeviceManagementProviderSelectionError("device_management_provider_resolution_stale")
    candidate = next((item for item in resolution.candidates if item.provider_id == provider_id), None)
    if candidate is None or not candidate.ready or device_platform not in candidate.supported_platforms:
        raise DeviceManagementProviderSelectionError("device_management_provider_not_available")

    canonical = {
        "resolution_plan_id": resolution.plan_id,
        "enrollment_proposal_id": resolution.enrollment_proposal_id,
        "household_id": resolution.household_id,
        "snapshot_id": resolution.snapshot_id,
        "resource_version": resolution.resource_version,
        "generation": resolution.generation,
        "actor_member_id": resolution.actor_member_id,
        "device_id": resolution.device_id,
        "member_id": resolution.member_id,
        "catalog_id": resolution.catalog_id,
        "device_platform": resolution.device_platform.value,
        "proposed_provider_id": provider_id,
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return DeviceManagementProviderSelectionProposal(
        proposal_id="dmpsel-" + hashlib.sha256(encoded).hexdigest()[:24],
        resolution_plan_id=resolution.plan_id,
        enrollment_proposal_id=resolution.enrollment_proposal_id,
        household_id=resolution.household_id,
        snapshot_id=resolution.snapshot_id,
        resource_version=resolution.resource_version,
        generation=resolution.generation,
        actor_member_id=resolution.actor_member_id,
        device_id=resolution.device_id,
        member_id=resolution.member_id,
        catalog_id=resolution.catalog_id,
        device_platform=resolution.device_platform,
        proposed_provider_id=provider_id,
    )


def provider_selection_proposal_from_dict(value: object) -> DeviceManagementProviderSelectionProposal:
    expected = {
        "schema", "proposal_id", "resolution_plan_id", "enrollment_proposal_id", "household_id",
        "snapshot_id", "resource_version", "generation", "actor_member_id", "device_id", "member_id",
        "catalog_id", "device_platform", "platform_claim_source", "platform_verified",
        "proposed_provider_id", "provider_ready", "platform_supported", "confirmation_required",
        "provider_selected", "provider_execution_authorized", "credential_access_authorized",
        "enrollment_authorized", "policy_application_authorized", "managed_state_change_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DeviceManagementProviderSelectionError("device_management_provider_selection_evidence_rejected")
    if value.get("schema") != PROVIDER_SELECTION_PROPOSAL_SCHEMA:
        raise DeviceManagementProviderSelectionError("device_management_provider_selection_evidence_rejected")
    try:
        platform = DevicePlatform(value.get("device_platform"))
    except (TypeError, ValueError) as exc:
        raise DeviceManagementProviderSelectionError("device_management_provider_selection_evidence_rejected") from exc
    provider_id = _provider_id(value.get("proposed_provider_id"))
    if (
        not isinstance(value.get("proposal_id"), str)
        or not value["proposal_id"].startswith("dmpsel-")
        or not isinstance(value.get("resolution_plan_id"), str)
        or not value["resolution_plan_id"].startswith("dmpr-")
        or not isinstance(value.get("enrollment_proposal_id"), str)
        or not isinstance(value.get("household_id"), str)
        or not isinstance(value.get("snapshot_id"), str)
        or not isinstance(value.get("resource_version"), str)
        or isinstance(value.get("generation"), bool)
        or not isinstance(value.get("generation"), int)
        or value["generation"] < 1
        or not isinstance(value.get("actor_member_id"), str)
        or not isinstance(value.get("device_id"), str)
        or not isinstance(value.get("member_id"), str)
        or not isinstance(value.get("catalog_id"), str)
        or value.get("platform_claim_source") != "user"
        or value.get("platform_verified") is not False
        or value.get("provider_ready") is not True
        or value.get("platform_supported") is not True
        or value.get("confirmation_required") is not True
        or value.get("provider_selected") is not False
        or value.get("provider_execution_authorized") is not False
        or value.get("credential_access_authorized") is not False
        or value.get("enrollment_authorized") is not False
        or value.get("policy_application_authorized") is not False
        or value.get("managed_state_change_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise DeviceManagementProviderSelectionError("device_management_provider_selection_evidence_rejected")
    proposal = DeviceManagementProviderSelectionProposal(
        proposal_id=value["proposal_id"],
        resolution_plan_id=value["resolution_plan_id"],
        enrollment_proposal_id=value["enrollment_proposal_id"],
        household_id=value["household_id"],
        snapshot_id=value["snapshot_id"],
        resource_version=value["resource_version"],
        generation=value["generation"],
        actor_member_id=value["actor_member_id"],
        device_id=value["device_id"],
        member_id=value["member_id"],
        catalog_id=value["catalog_id"],
        device_platform=platform,
        proposed_provider_id=provider_id,
    )
    if proposal.to_dict() != value:
        raise DeviceManagementProviderSelectionError("device_management_provider_selection_evidence_rejected")
    return proposal


def revalidate_provider_selection_proposal(
    snapshot: HouseholdSnapshot,
    enrollment_proposal: HouseholdDeviceEnrollmentProposal,
    catalog: DeviceManagementProviderCatalog,
    proposal: DeviceManagementProviderSelectionProposal,
    *,
    actor_member_id: str,
) -> DeviceManagementProviderSelectionProposal:
    if proposal.actor_member_id != actor_member_id:
        raise DeviceManagementProviderSelectionError("device_management_provider_selection_actor_mismatch")
    current = build_provider_selection_proposal(
        snapshot,
        enrollment_proposal,
        catalog,
        actor_member_id=actor_member_id,
        resolution_plan_id=proposal.resolution_plan_id,
        device_platform=proposal.device_platform,
        provider_id=proposal.proposed_provider_id,
    )
    if current != proposal:
        raise DeviceManagementProviderSelectionError("device_management_provider_selection_stale")
    return current
