"""Trusted provider catalog and non-authorizing resolution plans for Cozy device management."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum

from .home_services import HomeServiceCatalogError, _identifier
from .household_device_enrollment import (
    HouseholdDeviceEnrollmentError,
    HouseholdDeviceEnrollmentProposal,
    revalidate_device_enrollment_proposal,
)
from .household_store import HouseholdSnapshot


PROVIDER_CATALOG_SCHEMA = "home-center.device-management-provider-catalog.v1"
PROVIDER_RESOLUTION_PLAN_SCHEMA = "home-center.device-management-provider-resolution-plan.v1"
MAX_PROVIDERS = 64


class DeviceManagementProviderError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DevicePlatform(StrEnum):
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    LINUX = "linux"
    OTHER = "other"


class ProviderResolutionState(StrEnum):
    UNAVAILABLE = "unavailable"
    SINGLE_CANDIDATE = "single-candidate"
    CHOICE_REQUIRED = "choice-required"


@dataclass(frozen=True, slots=True)
class DeviceManagementProviderProfile:
    provider_id: str
    display_name: str
    supported_platforms: tuple[DevicePlatform, ...]
    enrollment_modes: tuple[str, ...]
    ready: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "supported_platforms": [item.value for item in self.supported_platforms],
            "enrollment_modes": list(self.enrollment_modes),
            "ready": self.ready,
            "execution_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementProviderCatalog:
    providers: tuple[DeviceManagementProviderProfile, ...]
    schema: str = field(default=PROVIDER_CATALOG_SCHEMA, init=False)
    source: str = field(default="local-trusted-registry", init=False)
    production_mutation_enabled: bool = field(default=False, init=False)

    @property
    def catalog_id(self) -> str:
        canonical = [profile.to_dict() for profile in self.providers]
        encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        return "dmpcat-" + hashlib.sha256(encoded).hexdigest()[:24]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "source": self.source,
            "catalog_id": self.catalog_id,
            "providers": [item.to_dict() for item in self.providers],
            "production_mutation_enabled": False,
        }


def empty_provider_catalog() -> DeviceManagementProviderCatalog:
    return DeviceManagementProviderCatalog(providers=())


def normalize_provider_catalog(value: object) -> DeviceManagementProviderCatalog:
    if not isinstance(value, dict) or set(value) != {"schema", "source", "providers"}:
        raise DeviceManagementProviderError("invalid_device_management_provider_catalog")
    if value.get("schema") != PROVIDER_CATALOG_SCHEMA or value.get("source") != "local-trusted-registry":
        raise DeviceManagementProviderError("unsupported_device_management_provider_catalog")
    raw_providers = value.get("providers")
    if not isinstance(raw_providers, list) or len(raw_providers) > MAX_PROVIDERS:
        raise DeviceManagementProviderError("invalid_device_management_provider_catalog")

    providers: list[DeviceManagementProviderProfile] = []
    seen: set[str] = set()
    for raw in raw_providers:
        if not isinstance(raw, dict) or set(raw) != {
            "provider_id", "display_name", "supported_platforms", "enrollment_modes", "ready"
        }:
            raise DeviceManagementProviderError("invalid_device_management_provider_profile")
        try:
            provider_id = _identifier(raw.get("provider_id"), "invalid_device_management_provider_id")
        except HomeServiceCatalogError as exc:
            raise DeviceManagementProviderError(exc.code) from exc
        if provider_id in seen:
            raise DeviceManagementProviderError("duplicate_device_management_provider_id")
        seen.add(provider_id)
        display_name = raw.get("display_name")
        if not isinstance(display_name, str) or not 1 <= len(display_name.strip()) <= 80:
            raise DeviceManagementProviderError("invalid_device_management_provider_name")
        platforms_raw = raw.get("supported_platforms")
        if not isinstance(platforms_raw, list) or not platforms_raw or len(platforms_raw) > len(DevicePlatform):
            raise DeviceManagementProviderError("invalid_device_management_provider_platforms")
        try:
            platforms = tuple(sorted({DevicePlatform(item) for item in platforms_raw}, key=lambda item: item.value))
        except (TypeError, ValueError) as exc:
            raise DeviceManagementProviderError("invalid_device_management_provider_platforms") from exc
        if len(platforms) != len(platforms_raw):
            raise DeviceManagementProviderError("duplicate_device_management_provider_platform")
        modes_raw = raw.get("enrollment_modes")
        if not isinstance(modes_raw, list) or not modes_raw or len(modes_raw) > 16:
            raise DeviceManagementProviderError("invalid_device_management_enrollment_modes")
        try:
            modes = tuple(sorted(_identifier(item, "invalid_device_management_enrollment_mode") for item in modes_raw))
        except HomeServiceCatalogError as exc:
            raise DeviceManagementProviderError(exc.code) from exc
        if len(modes) != len(set(modes)):
            raise DeviceManagementProviderError("duplicate_device_management_enrollment_mode")
        if not isinstance(raw.get("ready"), bool):
            raise DeviceManagementProviderError("invalid_device_management_provider_readiness")
        providers.append(
            DeviceManagementProviderProfile(
                provider_id=provider_id,
                display_name=display_name.strip(),
                supported_platforms=platforms,
                enrollment_modes=modes,
                ready=raw["ready"],
            )
        )
    return DeviceManagementProviderCatalog(providers=tuple(sorted(providers, key=lambda item: item.provider_id)))


@dataclass(frozen=True, slots=True)
class DeviceManagementProviderResolutionPlan:
    plan_id: str
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
    state: ProviderResolutionState
    candidates: tuple[DeviceManagementProviderProfile, ...]
    schema: str = field(default=PROVIDER_RESOLUTION_PLAN_SCHEMA, init=False)
    platform_claim_source: str = field(default="user", init=False)
    platform_verified: bool = field(default=False, init=False)
    provider_selection_required: bool = field(default=True, init=False)
    selected_provider_id: None = field(default=None, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
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
            "state": self.state.value,
            "candidates": [item.to_dict() for item in self.candidates],
            "provider_selection_required": True,
            "selected_provider_id": None,
            "provider_execution_authorized": False,
            "policy_application_authorized": False,
            "managed_state_change_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def plan_provider_resolution(
    snapshot: HouseholdSnapshot,
    proposal: HouseholdDeviceEnrollmentProposal,
    catalog: DeviceManagementProviderCatalog,
    *,
    actor_member_id: str,
    device_platform: DevicePlatform,
) -> DeviceManagementProviderResolutionPlan:
    if not isinstance(catalog, DeviceManagementProviderCatalog):
        raise TypeError("invalid_device_management_provider_catalog")
    if not isinstance(device_platform, DevicePlatform):
        raise DeviceManagementProviderError("invalid_device_platform")
    try:
        revalidate_device_enrollment_proposal(snapshot, proposal, actor_member_id=actor_member_id)
    except HouseholdDeviceEnrollmentError as exc:
        raise DeviceManagementProviderError(exc.code) from exc

    candidates = tuple(
        profile
        for profile in catalog.providers
        if profile.ready and device_platform in profile.supported_platforms
    )
    if not candidates:
        state = ProviderResolutionState.UNAVAILABLE
    elif len(candidates) == 1:
        state = ProviderResolutionState.SINGLE_CANDIDATE
    else:
        state = ProviderResolutionState.CHOICE_REQUIRED

    canonical = {
        "enrollment_proposal_id": proposal.proposal_id,
        "household_id": proposal.household_id,
        "snapshot_id": proposal.snapshot_id,
        "resource_version": proposal.resource_version,
        "generation": proposal.generation,
        "actor_member_id": proposal.actor_member_id,
        "device_id": proposal.device_id,
        "member_id": proposal.member_id,
        "catalog_id": catalog.catalog_id,
        "device_platform": device_platform.value,
        "state": state.value,
        "candidate_ids": [item.provider_id for item in candidates],
    }
    encoded = json.dumps(canonical, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return DeviceManagementProviderResolutionPlan(
        plan_id="dmpr-" + hashlib.sha256(encoded).hexdigest()[:24],
        enrollment_proposal_id=proposal.proposal_id,
        household_id=proposal.household_id,
        snapshot_id=proposal.snapshot_id,
        resource_version=proposal.resource_version,
        generation=proposal.generation,
        actor_member_id=proposal.actor_member_id,
        device_id=proposal.device_id,
        member_id=proposal.member_id,
        catalog_id=catalog.catalog_id,
        device_platform=device_platform,
        state=state,
        candidates=candidates,
    )
