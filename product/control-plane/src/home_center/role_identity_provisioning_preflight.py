"""Read-only account-absence/name-conflict preflight for Home Center 0.62."""
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
)

OBSERVATION_SCHEMA = "home-center.role-identity-account-preflight-observation.v1"
DECISION_SCHEMA = "home-center.role-identity-provisioning-preflight-decision.v1"
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ACCOUNT = re.compile(r"[a-z][a-z0-9._-]{0,31}\Z")
_PLAN_ID = re.compile(r"hcidp-[0-9a-f]{24}\Z")
_RFC3339 = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_RESERVED = frozenset({"admin", "administrator", "root"})


class IdentityProvisioningPreflightError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class AccountObservationState(StrEnum):
    ABSENT = "absent"
    EXISTS = "exists"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


def _id(value: object, code: str) -> str:
    try:
        return _identifier(value, code)
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningPreflightError(exc.code) from exc


def _semver(value: object) -> str:
    if not isinstance(value, str) or _SEMVER.fullmatch(value) is None:
        raise IdentityProvisioningPreflightError("identity_preflight_provider_version_invalid")
    return value


def _sha(value: object, code: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise IdentityProvisioningPreflightError(code)
    return value


def _account(value: object) -> str:
    if not isinstance(value, str):
        raise IdentityProvisioningPreflightError("identity_preflight_account_invalid")
    normalized = value.strip().lower()
    if _ACCOUNT.fullmatch(normalized) is None or normalized in _RESERVED:
        raise IdentityProvisioningPreflightError("identity_preflight_account_invalid")
    return normalized


def _instant(value: object, code: str) -> datetime:
    if not isinstance(value, str) or _RFC3339.fullmatch(value) is None:
        raise IdentityProvisioningPreflightError(code)
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise IdentityProvisioningPreflightError(code) from exc


@dataclass(frozen=True, slots=True)
class AccountPreflightObservation:
    provider_id: str
    provider_version: str
    provider_kind: IdentityProviderKind
    provider_evidence_sha256: str
    account_name: str
    state: AccountObservationState
    observed_at: str
    valid_until: str
    evidence_sha256: str
    schema: str = field(default=OBSERVATION_SCHEMA, init=False)
    read_only: bool = field(default=True, init=False)
    execution_authorized: bool = field(default=False, init=False)
    credential_access_authorized: bool = field(default=False, init=False)
    emergency_admin_mutation_authorized: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _id(self.provider_id, "identity_preflight_provider_id_invalid"))
        object.__setattr__(self, "provider_version", _semver(self.provider_version))
        if not isinstance(self.provider_kind, IdentityProviderKind):
            raise IdentityProvisioningPreflightError("identity_preflight_provider_kind_invalid")
        object.__setattr__(self, "provider_evidence_sha256", _sha(self.provider_evidence_sha256, "identity_preflight_provider_evidence_invalid"))
        object.__setattr__(self, "account_name", _account(self.account_name))
        if not isinstance(self.state, AccountObservationState):
            raise IdentityProvisioningPreflightError("identity_preflight_state_invalid")
        observed = _instant(self.observed_at, "identity_preflight_observed_at_invalid")
        valid_until = _instant(self.valid_until, "identity_preflight_valid_until_invalid")
        if valid_until <= observed:
            raise IdentityProvisioningPreflightError("identity_preflight_window_invalid")
        object.__setattr__(self, "evidence_sha256", _sha(self.evidence_sha256, "identity_preflight_evidence_invalid"))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind.value,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "account_name": self.account_name,
            "state": self.state.value,
            "observed_at": self.observed_at,
            "valid_until": self.valid_until,
            "evidence_sha256": self.evidence_sha256,
            "read_only": True,
            "execution_authorized": False,
            "credential_access_authorized": False,
            "emergency_admin_mutation_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class IdentityProvisioningPreflightDecision:
    plan_id: str
    account_name: str
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    observation_evidence_sha256: str
    state: AccountObservationState
    ready: bool
    blockers: tuple[str, ...]
    schema: str = field(default=DECISION_SCHEMA, init=False)
    execution_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "account_name": self.account_name,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "observation_evidence_sha256": self.observation_evidence_sha256,
            "state": self.state.value,
            "ready": self.ready,
            "blockers": list(self.blockers),
            "execution_authorized": False,
            "external_publication_authorized": False,
        }


def observation_from_dict(value: object) -> AccountPreflightObservation:
    expected = {
        "schema", "provider_id", "provider_version", "provider_kind", "provider_evidence_sha256",
        "account_name", "state", "observed_at", "valid_until", "evidence_sha256", "read_only",
        "execution_authorized", "credential_access_authorized", "emergency_admin_mutation_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != OBSERVATION_SCHEMA:
        raise IdentityProvisioningPreflightError("identity_preflight_observation_rejected")
    if (
        value.get("read_only") is not True
        or value.get("execution_authorized") is not False
        or value.get("credential_access_authorized") is not False
        or value.get("emergency_admin_mutation_authorized") is not False
    ):
        raise IdentityProvisioningPreflightError("identity_preflight_observation_rejected")
    try:
        result = AccountPreflightObservation(
            provider_id=value["provider_id"],
            provider_version=value["provider_version"],
            provider_kind=IdentityProviderKind(value["provider_kind"]),
            provider_evidence_sha256=value["provider_evidence_sha256"],
            account_name=value["account_name"],
            state=AccountObservationState(value["state"]),
            observed_at=value["observed_at"],
            valid_until=value["valid_until"],
            evidence_sha256=value["evidence_sha256"],
        )
    except (KeyError, TypeError, ValueError, IdentityProvisioningPreflightError) as exc:
        raise IdentityProvisioningPreflightError("identity_preflight_observation_rejected") from exc
    if result.to_dict() != value:
        raise IdentityProvisioningPreflightError("identity_preflight_observation_rejected")
    return result


def evaluate_account_preflight(
    *,
    plan: RoleIdentityProvisioningPlan,
    provider: IdentityProviderCapability,
    observation: AccountPreflightObservation,
    now: str,
) -> IdentityProvisioningPreflightDecision:
    """Return readiness evidence without granting execution authority."""

    if not isinstance(plan, RoleIdentityProvisioningPlan) or _PLAN_ID.fullmatch(plan.plan_id) is None:
        raise IdentityProvisioningPreflightError("identity_preflight_plan_invalid")
    if not isinstance(provider, IdentityProviderCapability):
        raise IdentityProvisioningPreflightError("identity_preflight_provider_invalid")
    if not isinstance(observation, AccountPreflightObservation):
        raise IdentityProvisioningPreflightError("identity_preflight_observation_invalid")
    now_dt = _instant(now, "identity_preflight_now_invalid")

    if (
        provider.provider_id != plan.provider_id
        or provider.provider_version != plan.provider_version
        or provider.provider_kind is not plan.provider_kind
        or provider.evidence_sha256 != plan.provider_evidence_sha256
    ):
        raise IdentityProvisioningPreflightError("identity_preflight_provider_binding_mismatch")
    if (
        observation.provider_id != plan.provider_id
        or observation.provider_version != plan.provider_version
        or observation.provider_kind is not plan.provider_kind
        or observation.provider_evidence_sha256 != plan.provider_evidence_sha256
        or observation.account_name != plan.account_name
    ):
        raise IdentityProvisioningPreflightError("identity_preflight_observation_binding_mismatch")

    blockers: list[str] = []
    observed = _instant(observation.observed_at, "identity_preflight_observed_at_invalid")
    valid_until = _instant(observation.valid_until, "identity_preflight_valid_until_invalid")
    if observed > now_dt:
        blockers.append("observation_from_future")
    if now_dt > valid_until:
        blockers.append("observation_expired")
    if observation.state is AccountObservationState.EXISTS:
        blockers.append("account_already_exists")
    elif observation.state is AccountObservationState.CONFLICT:
        blockers.append("account_name_conflict")
    elif observation.state is AccountObservationState.UNKNOWN:
        blockers.append("account_state_unknown")

    return IdentityProvisioningPreflightDecision(
        plan_id=plan.plan_id,
        account_name=plan.account_name,
        provider_id=plan.provider_id,
        provider_version=plan.provider_version,
        provider_evidence_sha256=plan.provider_evidence_sha256,
        observation_evidence_sha256=observation.evidence_sha256,
        state=observation.state,
        ready=not blockers and observation.state is AccountObservationState.ABSENT,
        blockers=tuple(blockers),
    )
