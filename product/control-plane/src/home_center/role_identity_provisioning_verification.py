"""Fail-closed read-back verification for Home Center 0.62 identity provisioning.

Provider command acceptance is never treated as account-creation success.  This
module consumes an exact-bound, read-only provider observation and emits
verification evidence only when the requested account, home directory and
profile are all observed in the expected state within a bounded freshness
window.  It grants no execution, privilege or publication authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import re

from .home_services import HomeServiceCatalogError, _identifier
from .role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    RoleIdentityProvisioningPlan,
    StorageMode,
)
from .role_identity_provisioning_execution import RoleIdentityProvisioningAdapterResult

OBSERVATION_SCHEMA = "home-center.role-identity-provisioning-readback-observation.v1"
VERIFICATION_SCHEMA = "home-center.role-identity-provisioning-verification.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ACCOUNT = re.compile(r"[a-z][a-z0-9._-]{0,31}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_RESERVED = frozenset({"admin", "administrator", "root"})


class IdentityProvisioningVerificationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class AccountReadbackState(StrEnum):
    PRESENT = "present"
    ABSENT = "absent"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class ResourceReadbackState(StrEnum):
    READY = "ready"
    MISSING = "missing"
    UNKNOWN = "unknown"


def _id(value: object, code: str) -> str:
    try:
        return _identifier(value, code)
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningVerificationError(exc.code) from exc


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise IdentityProvisioningVerificationError(code)
    return value


def _semver(value: object) -> str:
    if not isinstance(value, str) or _SEMVER.fullmatch(value) is None:
        raise IdentityProvisioningVerificationError("identity_verification_provider_version_invalid")
    return value


def _account(value: object) -> str:
    if not isinstance(value, str):
        raise IdentityProvisioningVerificationError("identity_verification_account_invalid")
    normalized = value.strip().lower()
    if _ACCOUNT.fullmatch(normalized) is None or normalized in _RESERVED:
        raise IdentityProvisioningVerificationError("identity_verification_account_invalid")
    return normalized


def _instant(value: object, code: str) -> datetime:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise IdentityProvisioningVerificationError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise IdentityProvisioningVerificationError(code) from exc


@dataclass(frozen=True, slots=True)
class IdentityProvisioningReadbackObservation:
    provider_id: str
    provider_version: str
    provider_kind: IdentityProviderKind
    provider_evidence_sha256: str
    provider_operation_id: str
    account_name: str
    account_state: AccountReadbackState
    account_identity_sha256: str | None
    home_directory_state: ResourceReadbackState
    profile_state: ResourceReadbackState
    observed_at: str
    valid_until: str
    evidence_sha256: str
    schema: str = field(default=OBSERVATION_SCHEMA, init=False)
    read_only: bool = field(default=True, init=False)
    credential_material_included: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    privilege_grant_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _id(self.provider_id, "identity_verification_provider_id_invalid"))
        object.__setattr__(self, "provider_version", _semver(self.provider_version))
        if not isinstance(self.provider_kind, IdentityProviderKind):
            raise IdentityProvisioningVerificationError("identity_verification_provider_kind_invalid")
        object.__setattr__(self, "provider_evidence_sha256", _sha(self.provider_evidence_sha256, "identity_verification_provider_evidence_invalid"))
        if not isinstance(self.provider_operation_id, str) or _OPERATION.fullmatch(self.provider_operation_id) is None:
            raise IdentityProvisioningVerificationError("identity_verification_operation_id_invalid")
        object.__setattr__(self, "account_name", _account(self.account_name))
        if not isinstance(self.account_state, AccountReadbackState):
            raise IdentityProvisioningVerificationError("identity_verification_account_state_invalid")
        if self.account_state is AccountReadbackState.PRESENT:
            if self.account_identity_sha256 is None:
                raise IdentityProvisioningVerificationError("identity_verification_account_identity_missing")
            object.__setattr__(self, "account_identity_sha256", _sha(self.account_identity_sha256, "identity_verification_account_identity_invalid"))
        elif self.account_identity_sha256 is not None:
            raise IdentityProvisioningVerificationError("identity_verification_account_identity_unexpected")
        if not isinstance(self.home_directory_state, ResourceReadbackState) or not isinstance(self.profile_state, ResourceReadbackState):
            raise IdentityProvisioningVerificationError("identity_verification_resource_state_invalid")
        observed = _instant(self.observed_at, "identity_verification_observed_at_invalid")
        valid_until = _instant(self.valid_until, "identity_verification_valid_until_invalid")
        if valid_until <= observed:
            raise IdentityProvisioningVerificationError("identity_verification_window_invalid")
        object.__setattr__(self, "evidence_sha256", _sha(self.evidence_sha256, "identity_verification_evidence_invalid"))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind.value,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "provider_operation_id": self.provider_operation_id,
            "account_name": self.account_name,
            "account_state": self.account_state.value,
            "account_identity_sha256": self.account_identity_sha256,
            "home_directory_state": self.home_directory_state.value,
            "profile_state": self.profile_state.value,
            "observed_at": self.observed_at,
            "valid_until": self.valid_until,
            "evidence_sha256": self.evidence_sha256,
            "read_only": True,
            "credential_material_included": False,
            "execution_authorized": False,
            "privilege_grant_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class IdentityProvisioningVerification:
    plan_id: str
    provider_operation_id: str
    account_name: str
    account_identity_sha256: str | None
    observation_evidence_sha256: str
    verified: bool
    blockers: tuple[str, ...]
    schema: str = field(default=VERIFICATION_SCHEMA, init=False)
    account_created_verified: bool = field(default=False, init=False)
    home_directory_verified: bool = field(default=False, init=False)
    profile_verified: bool = field(default=False, init=False)
    durable_state_change_authorized: bool = field(default=False, init=False)
    privilege_grant_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "provider_operation_id": self.provider_operation_id,
            "account_name": self.account_name,
            "account_identity_sha256": self.account_identity_sha256,
            "observation_evidence_sha256": self.observation_evidence_sha256,
            "verified": self.verified,
            "blockers": list(self.blockers),
            "account_created_verified": self.verified,
            "home_directory_verified": self.verified,
            "profile_verified": self.verified,
            "durable_state_change_authorized": False,
            "privilege_grant_authorized": False,
            "external_publication_authorized": False,
        }


def observation_from_dict(value: object) -> IdentityProvisioningReadbackObservation:
    expected = {
        "schema", "provider_id", "provider_version", "provider_kind", "provider_evidence_sha256",
        "provider_operation_id", "account_name", "account_state", "account_identity_sha256",
        "home_directory_state", "profile_state", "observed_at", "valid_until", "evidence_sha256",
        "read_only", "credential_material_included", "execution_authorized",
        "privilege_grant_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != OBSERVATION_SCHEMA:
        raise IdentityProvisioningVerificationError("identity_verification_observation_rejected")
    if (
        value.get("read_only") is not True
        or value.get("credential_material_included") is not False
        or value.get("execution_authorized") is not False
        or value.get("privilege_grant_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise IdentityProvisioningVerificationError("identity_verification_observation_rejected")
    try:
        result = IdentityProvisioningReadbackObservation(
            provider_id=value["provider_id"],
            provider_version=value["provider_version"],
            provider_kind=IdentityProviderKind(value["provider_kind"]),
            provider_evidence_sha256=value["provider_evidence_sha256"],
            provider_operation_id=value["provider_operation_id"],
            account_name=value["account_name"],
            account_state=AccountReadbackState(value["account_state"]),
            account_identity_sha256=value["account_identity_sha256"],
            home_directory_state=ResourceReadbackState(value["home_directory_state"]),
            profile_state=ResourceReadbackState(value["profile_state"]),
            observed_at=value["observed_at"],
            valid_until=value["valid_until"],
            evidence_sha256=value["evidence_sha256"],
        )
    except (KeyError, TypeError, ValueError, IdentityProvisioningVerificationError) as exc:
        raise IdentityProvisioningVerificationError("identity_verification_observation_rejected") from exc
    if result.to_dict() != value:
        raise IdentityProvisioningVerificationError("identity_verification_observation_rejected")
    return result


def verify_identity_provisioning(
    *,
    plan: RoleIdentityProvisioningPlan,
    provider: IdentityProviderCapability,
    accepted: RoleIdentityProvisioningAdapterResult,
    observation: IdentityProvisioningReadbackObservation,
    now: str,
) -> IdentityProvisioningVerification:
    """Verify exact post-conditions without authorizing unrelated state changes."""

    if not isinstance(plan, RoleIdentityProvisioningPlan):
        raise IdentityProvisioningVerificationError("identity_verification_plan_invalid")
    if not isinstance(provider, IdentityProviderCapability):
        raise IdentityProvisioningVerificationError("identity_verification_provider_invalid")
    if not isinstance(accepted, RoleIdentityProvisioningAdapterResult):
        raise IdentityProvisioningVerificationError("identity_verification_acceptance_invalid")
    if not isinstance(observation, IdentityProvisioningReadbackObservation):
        raise IdentityProvisioningVerificationError("identity_verification_observation_invalid")
    now_dt = _instant(now, "identity_verification_now_invalid")

    if (
        provider.provider_id != plan.provider_id
        or provider.provider_version != plan.provider_version
        or provider.provider_kind is not plan.provider_kind
        or provider.evidence_sha256 != plan.provider_evidence_sha256
    ):
        raise IdentityProvisioningVerificationError("identity_verification_provider_binding_mismatch")
    if accepted.account_name != plan.account_name:
        raise IdentityProvisioningVerificationError("identity_verification_acceptance_binding_mismatch")
    if (
        observation.provider_id != plan.provider_id
        or observation.provider_version != plan.provider_version
        or observation.provider_kind is not plan.provider_kind
        or observation.provider_evidence_sha256 != plan.provider_evidence_sha256
        or observation.provider_operation_id != accepted.provider_operation_id
        or observation.account_name != plan.account_name
    ):
        raise IdentityProvisioningVerificationError("identity_verification_observation_binding_mismatch")

    blockers: list[str] = []
    observed = _instant(observation.observed_at, "identity_verification_observed_at_invalid")
    valid_until = _instant(observation.valid_until, "identity_verification_valid_until_invalid")
    if observed > now_dt:
        blockers.append("observation_from_future")
    if now_dt > valid_until:
        blockers.append("observation_expired")
    if observation.account_state is AccountReadbackState.ABSENT:
        blockers.append("account_absent_after_provider_acceptance")
    elif observation.account_state is AccountReadbackState.CONFLICT:
        blockers.append("account_identity_conflict")
    elif observation.account_state is AccountReadbackState.UNKNOWN:
        blockers.append("account_state_unknown")
    if observation.home_directory_state is ResourceReadbackState.MISSING:
        blockers.append("home_directory_missing")
    elif observation.home_directory_state is ResourceReadbackState.UNKNOWN:
        blockers.append("home_directory_unknown")
    if observation.profile_state is ResourceReadbackState.MISSING:
        blockers.append("profile_missing")
    elif observation.profile_state is ResourceReadbackState.UNKNOWN:
        blockers.append("profile_unknown")

    verified = (
        not blockers
        and observation.account_state is AccountReadbackState.PRESENT
        and observation.account_identity_sha256 is not None
        and observation.home_directory_state is ResourceReadbackState.READY
        and observation.profile_state is ResourceReadbackState.READY
    )
    return IdentityProvisioningVerification(
        plan_id=plan.plan_id,
        provider_operation_id=accepted.provider_operation_id,
        account_name=plan.account_name,
        account_identity_sha256=observation.account_identity_sha256,
        observation_evidence_sha256=observation.evidence_sha256,
        verified=verified,
        blockers=tuple(blockers),
    )
