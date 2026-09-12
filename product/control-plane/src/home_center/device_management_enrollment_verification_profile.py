"""Trusted provider-specific verification profiles for Home Center 0.58.

Verification requirements are controller-owned product policy.  A caller may
request verification of an existing 0.57 execution job, but it must not choose
which post-conditions are sufficient for a provider.  This module binds each
provider to a closed, deterministic verification profile and feeds only that
trusted profile into the 0.58 post-condition verifier.

Profiles are descriptive/read-only.  They resolve no secrets, call no provider,
change no Household state and grant no policy/infrastructure/publication
authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .device_management_enrollment_verification import (
    DeviceManagementEnrollmentVerificationPlan,
    _execution_receipt,
    build_enrollment_verification_plan,
)
from .home_services import HomeServiceCatalogError, _identifier


VERIFICATION_PROFILE_SCHEMA = (
    "home-center.device-management-enrollment-verification-profile.v1"
)
VERIFICATION_PROFILE_CATALOG_SCHEMA = (
    "home-center.device-management-enrollment-verification-profile-catalog.v1"
)
CHECK_KINDS = ("certificate", "profile", "agent")


class DeviceManagementEnrollmentVerificationProfileError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _provider_id(value: object) -> str:
    try:
        return _identifier(value, "invalid_device_management_provider_id")
    except HomeServiceCatalogError as exc:
        raise DeviceManagementEnrollmentVerificationProfileError(exc.code) from exc


def _checks(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise DeviceManagementEnrollmentVerificationProfileError(
            "invalid_device_management_enrollment_verification_profile_checks"
        )
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or item not in CHECK_KINDS or item in seen:
            raise DeviceManagementEnrollmentVerificationProfileError(
                "invalid_device_management_enrollment_verification_profile_checks"
            )
        seen.add(item)
        normalized.append(item)
    return tuple(sorted(normalized))


def _profile_id(provider_id: str, required_checks: tuple[str, ...]) -> str:
    canonical = {
        "provider_id": provider_id,
        "required_checks": list(required_checks),
    }
    encoded = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    return "dmpvprof-" + hashlib.sha256(encoded).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationProfile:
    profile_id: str
    provider_id: str
    required_checks: tuple[str, ...]
    schema: str = field(default=VERIFICATION_PROFILE_SCHEMA, init=False)
    trusted: bool = field(default=True, init=False)
    read_only: bool = field(default=True, init=False)
    provider_mutation_authorized: bool = field(default=False, init=False)
    credential_access_authorized: bool = field(default=False, init=False)
    managed_state_change_authorized: bool = field(default=False, init=False)
    policy_application_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "profile_id": self.profile_id,
            "provider_id": self.provider_id,
            "required_checks": list(self.required_checks),
            "trusted": True,
            "read_only": True,
            "provider_mutation_authorized": False,
            "credential_access_authorized": False,
            "managed_state_change_authorized": False,
            "policy_application_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class DeviceManagementEnrollmentVerificationProfileCatalog:
    catalog_id: str
    profiles: tuple[DeviceManagementEnrollmentVerificationProfile, ...]
    schema: str = field(default=VERIFICATION_PROFILE_CATALOG_SCHEMA, init=False)
    trusted: bool = field(default=True, init=False)
    read_only: bool = field(default=True, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "catalog_id": self.catalog_id,
            "profiles": [profile.to_dict() for profile in self.profiles],
            "trusted": True,
            "read_only": True,
        }


def build_verification_profile(
    *,
    provider_id: object,
    required_checks: object,
) -> DeviceManagementEnrollmentVerificationProfile:
    normalized_provider = _provider_id(provider_id)
    normalized_checks = _checks(required_checks)
    return DeviceManagementEnrollmentVerificationProfile(
        profile_id=_profile_id(normalized_provider, normalized_checks),
        provider_id=normalized_provider,
        required_checks=normalized_checks,
    )


def build_verification_profile_catalog(
    profiles: object,
) -> DeviceManagementEnrollmentVerificationProfileCatalog:
    if not isinstance(profiles, (list, tuple)) or not profiles:
        raise DeviceManagementEnrollmentVerificationProfileError(
            "invalid_device_management_enrollment_verification_profile_catalog"
        )

    normalized: list[DeviceManagementEnrollmentVerificationProfile] = []
    provider_ids: set[str] = set()
    profile_ids: set[str] = set()
    for profile in profiles:
        if not isinstance(profile, DeviceManagementEnrollmentVerificationProfile):
            raise DeviceManagementEnrollmentVerificationProfileError(
                "invalid_device_management_enrollment_verification_profile_catalog"
            )
        rebuilt = build_verification_profile(
            provider_id=profile.provider_id,
            required_checks=profile.required_checks,
        )
        if rebuilt != profile:
            raise DeviceManagementEnrollmentVerificationProfileError(
                "device_management_enrollment_verification_profile_tampered"
            )
        if profile.provider_id in provider_ids or profile.profile_id in profile_ids:
            raise DeviceManagementEnrollmentVerificationProfileError(
                "duplicate_device_management_enrollment_verification_profile"
            )
        provider_ids.add(profile.provider_id)
        profile_ids.add(profile.profile_id)
        normalized.append(profile)

    ordered = tuple(sorted(normalized, key=lambda item: item.provider_id))
    canonical = [profile.to_dict() for profile in ordered]
    encoded = json.dumps(
        canonical, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    catalog_id = "dmpvcat-" + hashlib.sha256(encoded).hexdigest()[:24]
    return DeviceManagementEnrollmentVerificationProfileCatalog(
        catalog_id=catalog_id,
        profiles=ordered,
    )


def resolve_verification_profile(
    catalog: DeviceManagementEnrollmentVerificationProfileCatalog,
    provider_id: object,
) -> DeviceManagementEnrollmentVerificationProfile:
    if not isinstance(catalog, DeviceManagementEnrollmentVerificationProfileCatalog):
        raise DeviceManagementEnrollmentVerificationProfileError(
            "invalid_device_management_enrollment_verification_profile_catalog"
        )
    normalized_provider = _provider_id(provider_id)
    matches = [
        profile for profile in catalog.profiles
        if profile.provider_id == normalized_provider
    ]
    if len(matches) != 1:
        raise DeviceManagementEnrollmentVerificationProfileError(
            "device_management_enrollment_verification_profile_unavailable"
        )
    return matches[0]


def build_enrollment_verification_plan_from_profile(
    *,
    execution_receipt: object,
    household_id: str,
    snapshot_id: str,
    resource_version: str,
    generation: int,
    actor_member_id: str,
    catalog: DeviceManagementEnrollmentVerificationProfileCatalog,
) -> DeviceManagementEnrollmentVerificationPlan:
    """Build a verifier plan using only controller-owned profile requirements."""

    receipt = _execution_receipt(execution_receipt)
    profile = resolve_verification_profile(catalog, receipt["provider_id"])
    return build_enrollment_verification_plan(
        execution_receipt=receipt,
        household_id=household_id,
        snapshot_id=snapshot_id,
        resource_version=resource_version,
        generation=generation,
        actor_member_id=actor_member_id,
        required_checks=profile.required_checks,
    )
