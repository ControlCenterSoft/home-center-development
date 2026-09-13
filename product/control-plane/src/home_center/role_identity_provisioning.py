"""Home Center 0.62 role-driven identity/account provisioning foundation.

This module is deliberately plan-only. It binds a Household member and effective
policy to an exact Household snapshot and a typed provider capability record.
No account, directory object, home directory, roaming/portable profile, secret,
infrastructure state, or emergency administrator identity is mutated here.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from .home_services import HomeServiceCatalogError, _identifier
from .household import EffectivePolicy, HouseholdRole
from .household_policy_composer import ComposedPolicy
from .household_store import HouseholdSnapshot

IDENTITY_PROVIDER_SCHEMA = "home-center.role-identity-provider-capability.v1"
IDENTITY_PLAN_SCHEMA = "home-center.role-identity-provisioning-plan.v1"
_ACCOUNT = re.compile(r"[a-z][a-z0-9._-]{0,31}\Z")
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED_ACCOUNTS = frozenset({"admin", "administrator", "root"})


class IdentityProvisioningError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class IdentityProviderKind(StrEnum):
    LOCAL = "local"
    DIRECTORY = "directory"


class StorageMode(StrEnum):
    LOCAL = "local"
    PORTABLE = "portable"


def _semver(value: object, code: str) -> str:
    if not isinstance(value, str) or _SEMVER.fullmatch(value) is None:
        raise IdentityProvisioningError(code)
    return value


def _sha256(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise IdentityProvisioningError(code)
    return value


def _account(value: object) -> str:
    if not isinstance(value, str):
        raise IdentityProvisioningError("identity_account_name_invalid")
    normalized = value.strip().lower()
    if _ACCOUNT.fullmatch(normalized) is None or normalized in _RESERVED_ACCOUNTS:
        raise IdentityProvisioningError("identity_account_name_invalid")
    return normalized


def _canonical_sha(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class IdentityProviderCapability:
    provider_id: str
    provider_version: str
    provider_kind: IdentityProviderKind
    supported_roles: tuple[HouseholdRole, ...]
    account_create_supported: bool
    portable_home_supported: bool
    portable_profile_supported: bool
    secret_reference_supported: bool
    evidence_sha256: str
    schema: str = field(default=IDENTITY_PROVIDER_SCHEMA, init=False)
    emergency_admin_isolated: bool = field(default=True, init=False)
    arbitrary_privilege_grant_supported: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "provider_id", _identifier(self.provider_id, "identity_provider_id_invalid"))
        except HomeServiceCatalogError as exc:
            raise IdentityProvisioningError(exc.code) from exc
        object.__setattr__(
            self,
            "provider_version",
            _semver(self.provider_version, "identity_provider_version_invalid"),
        )
        if not isinstance(self.provider_kind, IdentityProviderKind):
            raise IdentityProvisioningError("identity_provider_kind_invalid")
        if (
            not isinstance(self.supported_roles, tuple)
            or not self.supported_roles
            or any(not isinstance(role, HouseholdRole) for role in self.supported_roles)
            or len(set(self.supported_roles)) != len(self.supported_roles)
        ):
            raise IdentityProvisioningError("identity_provider_roles_invalid")
        object.__setattr__(self, "supported_roles", tuple(sorted(self.supported_roles, key=lambda role: role.value)))
        for value in (
            self.account_create_supported,
            self.portable_home_supported,
            self.portable_profile_supported,
            self.secret_reference_supported,
        ):
            if type(value) is not bool:
                raise IdentityProvisioningError("identity_provider_capability_invalid")
        object.__setattr__(
            self,
            "evidence_sha256",
            _sha256(self.evidence_sha256, "identity_provider_evidence_invalid"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind.value,
            "supported_roles": [role.value for role in self.supported_roles],
            "account_create_supported": self.account_create_supported,
            "portable_home_supported": self.portable_home_supported,
            "portable_profile_supported": self.portable_profile_supported,
            "secret_reference_supported": self.secret_reference_supported,
            "evidence_sha256": self.evidence_sha256,
            "emergency_admin_isolated": True,
            "arbitrary_privilege_grant_supported": False,
            "execution_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class RoleIdentityProvisioningPlan:
    plan_id: str
    household_id: str
    member_id: str
    role: HouseholdRole
    household_snapshot_id: str
    household_resource_version: str
    household_generation: int
    policy_id: str
    provider_id: str
    provider_version: str
    provider_kind: IdentityProviderKind
    provider_evidence_sha256: str
    account_name: str
    home_directory_mode: StorageMode
    profile_mode: StorageMode
    schema: str = field(default=IDENTITY_PLAN_SCHEMA, init=False)
    confirmation_required: bool = field(default=True, init=False)
    account_absence_preflight_required: bool = field(default=True, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    credential_material_authorized: bool = field(default=False, init=False)
    emergency_admin_mutation_authorized: bool = field(default=False, init=False)
    arbitrary_privilege_grant_authorized: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "role": self.role.value,
            "household_snapshot_id": self.household_snapshot_id,
            "household_resource_version": self.household_resource_version,
            "household_generation": self.household_generation,
            "policy_id": self.policy_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind.value,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "account_name": self.account_name,
            "home_directory_mode": self.home_directory_mode.value,
            "profile_mode": self.profile_mode.value,
            "confirmation_required": True,
            "account_absence_preflight_required": True,
            "post_condition_verification_required": True,
            "credential_material_authorized": False,
            "emergency_admin_mutation_authorized": False,
            "arbitrary_privilege_grant_authorized": False,
            "execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _policy_binding(policy: EffectivePolicy | ComposedPolicy) -> tuple[str, str, str, HouseholdRole]:
    if not isinstance(policy, (EffectivePolicy, ComposedPolicy)):
        raise IdentityProvisioningError("identity_policy_invalid")
    return policy.policy_id, policy.household_id, policy.member_id, policy.role


def build_role_identity_provisioning_plan(
    *,
    snapshot: HouseholdSnapshot,
    policy: EffectivePolicy | ComposedPolicy,
    provider: IdentityProviderCapability,
    member_id: str,
    account_name: str,
    home_directory_mode: StorageMode,
    profile_mode: StorageMode,
) -> RoleIdentityProvisioningPlan:
    """Build exact-bound plan evidence without granting provider execution."""

    if not isinstance(snapshot, HouseholdSnapshot):
        raise IdentityProvisioningError("identity_household_snapshot_invalid")
    if not isinstance(provider, IdentityProviderCapability):
        raise IdentityProvisioningError("identity_provider_capability_invalid")
    if not isinstance(home_directory_mode, StorageMode) or not isinstance(profile_mode, StorageMode):
        raise IdentityProvisioningError("identity_storage_mode_invalid")
    try:
        normalized_member_id = _identifier(member_id, "identity_member_id_invalid")
        member = snapshot.household.member(normalized_member_id)
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningError(exc.code) from exc
    if not member.enabled:
        raise IdentityProvisioningError("identity_member_disabled")

    policy_id, policy_household_id, policy_member_id, policy_role = _policy_binding(policy)
    if (
        policy_household_id != snapshot.household_id
        or policy_member_id != member.member_id
        or policy_role is not member.role
    ):
        raise IdentityProvisioningError("identity_policy_binding_mismatch")
    if member.role not in provider.supported_roles:
        raise IdentityProvisioningError("identity_provider_role_unsupported")
    if not provider.account_create_supported:
        raise IdentityProvisioningError("identity_provider_account_create_unsupported")
    if home_directory_mode is StorageMode.PORTABLE and not provider.portable_home_supported:
        raise IdentityProvisioningError("identity_portable_home_unsupported")
    if profile_mode is StorageMode.PORTABLE and not provider.portable_profile_supported:
        raise IdentityProvisioningError("identity_portable_profile_unsupported")

    normalized_account = _account(account_name)
    canonical = {
        "schema": IDENTITY_PLAN_SCHEMA,
        "household_id": snapshot.household_id,
        "member_id": member.member_id,
        "role": member.role.value,
        "household_snapshot_id": snapshot.snapshot_id,
        "household_resource_version": snapshot.resource_version,
        "household_generation": snapshot.generation,
        "policy_id": policy_id,
        "provider_id": provider.provider_id,
        "provider_version": provider.provider_version,
        "provider_kind": provider.provider_kind.value,
        "provider_evidence_sha256": provider.evidence_sha256,
        "account_name": normalized_account,
        "home_directory_mode": home_directory_mode.value,
        "profile_mode": profile_mode.value,
    }
    return RoleIdentityProvisioningPlan(
        plan_id="hcidp-" + _canonical_sha(canonical)[:24],
        household_id=snapshot.household_id,
        member_id=member.member_id,
        role=member.role,
        household_snapshot_id=snapshot.snapshot_id,
        household_resource_version=snapshot.resource_version,
        household_generation=snapshot.generation,
        policy_id=policy_id,
        provider_id=provider.provider_id,
        provider_version=provider.provider_version,
        provider_kind=provider.provider_kind,
        provider_evidence_sha256=provider.evidence_sha256,
        account_name=normalized_account,
        home_directory_mode=home_directory_mode,
        profile_mode=profile_mode,
    )


def provider_capability_from_dict(value: object) -> IdentityProviderCapability:
    expected = {
        "schema",
        "provider_id",
        "provider_version",
        "provider_kind",
        "supported_roles",
        "account_create_supported",
        "portable_home_supported",
        "portable_profile_supported",
        "secret_reference_supported",
        "evidence_sha256",
        "emergency_admin_isolated",
        "arbitrary_privilege_grant_supported",
        "execution_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != IDENTITY_PROVIDER_SCHEMA:
        raise IdentityProvisioningError("identity_provider_evidence_rejected")
    if (
        value.get("emergency_admin_isolated") is not True
        or value.get("arbitrary_privilege_grant_supported") is not False
        or value.get("execution_authorized") is not False
    ):
        raise IdentityProvisioningError("identity_provider_evidence_rejected")
    roles = value.get("supported_roles")
    if not isinstance(roles, list):
        raise IdentityProvisioningError("identity_provider_evidence_rejected")
    try:
        result = IdentityProviderCapability(
            provider_id=value["provider_id"],
            provider_version=value["provider_version"],
            provider_kind=IdentityProviderKind(value["provider_kind"]),
            supported_roles=tuple(HouseholdRole(role) for role in roles),
            account_create_supported=value["account_create_supported"],
            portable_home_supported=value["portable_home_supported"],
            portable_profile_supported=value["portable_profile_supported"],
            secret_reference_supported=value["secret_reference_supported"],
            evidence_sha256=value["evidence_sha256"],
        )
    except (KeyError, TypeError, ValueError, IdentityProvisioningError) as exc:
        raise IdentityProvisioningError("identity_provider_evidence_rejected") from exc
    if result.to_dict() != value:
        raise IdentityProvisioningError("identity_provider_evidence_rejected")
    return result


def plan_from_dict(value: object) -> RoleIdentityProvisioningPlan:
    expected = {
        "schema",
        "plan_id",
        "household_id",
        "member_id",
        "role",
        "household_snapshot_id",
        "household_resource_version",
        "household_generation",
        "policy_id",
        "provider_id",
        "provider_version",
        "provider_kind",
        "provider_evidence_sha256",
        "account_name",
        "home_directory_mode",
        "profile_mode",
        "confirmation_required",
        "account_absence_preflight_required",
        "post_condition_verification_required",
        "credential_material_authorized",
        "emergency_admin_mutation_authorized",
        "arbitrary_privilege_grant_authorized",
        "execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != IDENTITY_PLAN_SCHEMA:
        raise IdentityProvisioningError("identity_plan_rejected")
    for key in (
        "confirmation_required",
        "account_absence_preflight_required",
        "post_condition_verification_required",
    ):
        if value.get(key) is not True:
            raise IdentityProvisioningError("identity_plan_rejected")
    for key in (
        "credential_material_authorized",
        "emergency_admin_mutation_authorized",
        "arbitrary_privilege_grant_authorized",
        "execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    ):
        if value.get(key) is not False:
            raise IdentityProvisioningError("identity_plan_rejected")
    try:
        household_id = _identifier(value["household_id"], "identity_household_id_invalid")
        member_id = _identifier(value["member_id"], "identity_member_id_invalid")
        snapshot_id = _identifier(value["household_snapshot_id"], "identity_snapshot_id_invalid")
        resource_version = _identifier(value["household_resource_version"], "identity_resource_version_invalid")
        policy_id = _identifier(value["policy_id"], "identity_policy_id_invalid")
        provider_id = _identifier(value["provider_id"], "identity_provider_id_invalid")
        provider_version = _semver(value["provider_version"], "identity_provider_version_invalid")
        provider_sha = _sha256(value["provider_evidence_sha256"], "identity_provider_evidence_invalid")
        role = HouseholdRole(value["role"])
        provider_kind = IdentityProviderKind(value["provider_kind"])
        account_name = _account(value["account_name"])
        home_mode = StorageMode(value["home_directory_mode"])
        profile_mode = StorageMode(value["profile_mode"])
        generation = value["household_generation"]
        if type(generation) is not int or generation < 1:
            raise IdentityProvisioningError("identity_generation_invalid")
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError, IdentityProvisioningError) as exc:
        raise IdentityProvisioningError("identity_plan_rejected") from exc

    canonical = {
        "schema": IDENTITY_PLAN_SCHEMA,
        "household_id": household_id,
        "member_id": member_id,
        "role": role.value,
        "household_snapshot_id": snapshot_id,
        "household_resource_version": resource_version,
        "household_generation": generation,
        "policy_id": policy_id,
        "provider_id": provider_id,
        "provider_version": provider_version,
        "provider_kind": provider_kind.value,
        "provider_evidence_sha256": provider_sha,
        "account_name": account_name,
        "home_directory_mode": home_mode.value,
        "profile_mode": profile_mode.value,
    }
    expected_plan_id = "hcidp-" + _canonical_sha(canonical)[:24]
    if value.get("plan_id") != expected_plan_id:
        raise IdentityProvisioningError("identity_plan_rejected")
    result = RoleIdentityProvisioningPlan(
        plan_id=expected_plan_id,
        household_id=household_id,
        member_id=member_id,
        role=role,
        household_snapshot_id=snapshot_id,
        household_resource_version=resource_version,
        household_generation=generation,
        policy_id=policy_id,
        provider_id=provider_id,
        provider_version=provider_version,
        provider_kind=provider_kind,
        provider_evidence_sha256=provider_sha,
        account_name=account_name,
        home_directory_mode=home_mode,
        profile_mode=profile_mode,
    )
    if result.to_dict() != value:
        raise IdentityProvisioningError("identity_plan_rejected")
    return result


def cozy_identity_plan_projection(plan: RoleIdentityProvisioningPlan) -> dict[str, object]:
    if not isinstance(plan, RoleIdentityProvisioningPlan):
        raise IdentityProvisioningError("identity_plan_invalid")
    return {
        "schema": "home-center.cozy-role-identity-plan.v1",
        "member_id": plan.member_id,
        "role": plan.role.value,
        "account_name": plan.account_name,
        "title": "Учётная запись готова к подтверждению",
        "portable_home": plan.home_directory_mode is StorageMode.PORTABLE,
        "portable_profile": plan.profile_mode is StorageMode.PORTABLE,
        "will_create_now": False,
        "confirmation_required": True,
        "emergency_admin_unchanged": True,
    }


def full_identity_plan_projection(plan: RoleIdentityProvisioningPlan) -> dict[str, object]:
    if not isinstance(plan, RoleIdentityProvisioningPlan):
        raise IdentityProvisioningError("identity_plan_invalid")
    return {
        "schema": "home-center.full-role-identity-plan.v1",
        "plan": plan.to_dict(),
        "provider_execution_state": "not-authorized",
        "credential_material_state": "not-authorized",
        "emergency_admin_state": "independent-unchanged",
        "post_condition_verification_required": True,
    }
