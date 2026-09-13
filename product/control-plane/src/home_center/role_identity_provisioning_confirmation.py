"""Confirmation and read-only account preflight for Home Center 0.62 identity provisioning.

This layer extends the 0.62 plan-only foundation without granting provider execution.
It requires explicit confirmation and fresh, exact-bound account-absence evidence
before producing deterministic admission evidence. No account, credential, home
folder, portable profile, emergency administrator identity, provider state,
infrastructure state, or external publication is mutated here.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .home_services import HomeServiceCatalogError, _identifier
from .household import EffectivePolicy
from .household_policy_composer import ComposedPolicy
from .household_store import HouseholdSnapshot
from .role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProvisioningError,
    RoleIdentityProvisioningPlan,
    StorageMode,
    _account,
    _semver,
    _sha256,
    build_role_identity_provisioning_plan,
    plan_from_dict,
)

ACCOUNT_PREFLIGHT_SCHEMA = "home-center.role-identity-account-preflight.v1"
IDENTITY_CONFIRM_REQUEST_SCHEMA = "home-center.role-identity-provisioning-confirm-request.v1"
IDENTITY_CONFIRM_RECEIPT_SCHEMA = "home-center.role-identity-provisioning-confirm-receipt.v1"
MAX_PREFLIGHT_AGE_SECONDS = 300


class IdentityProvisioningConfirmationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_sha(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _utc_timestamp(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise IdentityProvisioningConfirmationError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise IdentityProvisioningConfirmationError(code) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise IdentityProvisioningConfirmationError(code)
    return parsed


@dataclass(frozen=True, slots=True)
class IdentityAccountPreflightEvidence:
    evidence_id: str
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    account_name: str
    observed_state: str
    observed_at: str
    schema: str = field(default=ACCOUNT_PREFLIGHT_SCHEMA, init=False)
    read_only: bool = field(default=True, init=False)
    credential_material_observed: bool = field(default=False, init=False)
    emergency_admin_observed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "evidence_id": self.evidence_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "account_name": self.account_name,
            "observed_state": self.observed_state,
            "observed_at": self.observed_at,
            "read_only": True,
            "credential_material_observed": False,
            "emergency_admin_observed": False,
            "execution_authorized": False,
        }


def build_account_preflight_evidence(
    *,
    plan: RoleIdentityProvisioningPlan,
    observed_state: str,
    observed_at: str,
) -> IdentityAccountPreflightEvidence:
    if not isinstance(plan, RoleIdentityProvisioningPlan):
        raise IdentityProvisioningConfirmationError("identity_preflight_plan_invalid")
    if observed_state not in {"absent", "exists", "unknown"}:
        raise IdentityProvisioningConfirmationError("identity_preflight_state_invalid")
    _utc_timestamp(observed_at, "identity_preflight_time_invalid")
    canonical = {
        "schema": ACCOUNT_PREFLIGHT_SCHEMA,
        "provider_id": plan.provider_id,
        "provider_version": plan.provider_version,
        "provider_evidence_sha256": plan.provider_evidence_sha256,
        "account_name": plan.account_name,
        "observed_state": observed_state,
        "observed_at": observed_at,
        "read_only": True,
        "credential_material_observed": False,
        "emergency_admin_observed": False,
        "execution_authorized": False,
    }
    return IdentityAccountPreflightEvidence(
        evidence_id="hcidpre-" + _canonical_sha(canonical)[:24],
        provider_id=plan.provider_id,
        provider_version=plan.provider_version,
        provider_evidence_sha256=plan.provider_evidence_sha256,
        account_name=plan.account_name,
        observed_state=observed_state,
        observed_at=observed_at,
    )


def account_preflight_from_dict(value: object) -> IdentityAccountPreflightEvidence:
    expected = {
        "schema", "evidence_id", "provider_id", "provider_version", "provider_evidence_sha256",
        "account_name", "observed_state", "observed_at", "read_only",
        "credential_material_observed", "emergency_admin_observed", "execution_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != ACCOUNT_PREFLIGHT_SCHEMA:
        raise IdentityProvisioningConfirmationError("identity_preflight_evidence_rejected")
    if (
        value.get("read_only") is not True
        or value.get("credential_material_observed") is not False
        or value.get("emergency_admin_observed") is not False
        or value.get("execution_authorized") is not False
    ):
        raise IdentityProvisioningConfirmationError("identity_preflight_evidence_rejected")
    try:
        provider_id = _identifier(value["provider_id"], "identity_provider_id_invalid")
        provider_version = _semver(value["provider_version"], "identity_provider_version_invalid")
        provider_sha = _sha256(value["provider_evidence_sha256"], "identity_provider_evidence_invalid")
        account_name = _account(value["account_name"])
        observed_state = value["observed_state"]
        if observed_state not in {"absent", "exists", "unknown"}:
            raise IdentityProvisioningConfirmationError("identity_preflight_state_invalid")
        observed_at = value["observed_at"]
        _utc_timestamp(observed_at, "identity_preflight_time_invalid")
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError, IdentityProvisioningError, IdentityProvisioningConfirmationError) as exc:
        raise IdentityProvisioningConfirmationError("identity_preflight_evidence_rejected") from exc
    canonical = {
        "schema": ACCOUNT_PREFLIGHT_SCHEMA,
        "provider_id": provider_id,
        "provider_version": provider_version,
        "provider_evidence_sha256": provider_sha,
        "account_name": account_name,
        "observed_state": observed_state,
        "observed_at": observed_at,
        "read_only": True,
        "credential_material_observed": False,
        "emergency_admin_observed": False,
        "execution_authorized": False,
    }
    evidence_id = "hcidpre-" + _canonical_sha(canonical)[:24]
    if value.get("evidence_id") != evidence_id:
        raise IdentityProvisioningConfirmationError("identity_preflight_evidence_rejected")
    return IdentityAccountPreflightEvidence(
        evidence_id=evidence_id,
        provider_id=provider_id,
        provider_version=provider_version,
        provider_evidence_sha256=provider_sha,
        account_name=account_name,
        observed_state=observed_state,
        observed_at=observed_at,
    )


@dataclass(frozen=True, slots=True)
class RoleIdentityProvisioningConfirmationReceipt:
    receipt_id: str
    plan_id: str
    household_id: str
    member_id: str
    account_name: str
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    preflight_evidence_id: str
    home_directory_mode: StorageMode
    profile_mode: StorageMode
    outcome: str = "confirmed-awaiting-execution"
    schema: str = field(default=IDENTITY_CONFIRM_RECEIPT_SCHEMA, init=False)
    provider_execution_authorized: bool = field(default=False, init=False)
    credential_material_authorized: bool = field(default=False, init=False)
    emergency_admin_mutation_authorized: bool = field(default=False, init=False)
    arbitrary_privilege_grant_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "account_name": self.account_name,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "preflight_evidence_id": self.preflight_evidence_id,
            "home_directory_mode": self.home_directory_mode.value,
            "profile_mode": self.profile_mode.value,
            "outcome": self.outcome,
            "provider_execution_authorized": False,
            "credential_material_authorized": False,
            "emergency_admin_mutation_authorized": False,
            "arbitrary_privilege_grant_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
            "post_condition_verification_required": True,
        }


def confirm_role_identity_provisioning(
    *,
    snapshot: HouseholdSnapshot,
    policy: EffectivePolicy | ComposedPolicy,
    provider: IdentityProviderCapability,
    plan: RoleIdentityProvisioningPlan | dict[str, object],
    preflight: IdentityAccountPreflightEvidence | dict[str, object],
    confirmed: bool,
    now: str,
    max_preflight_age_seconds: int = MAX_PREFLIGHT_AGE_SECONDS,
) -> RoleIdentityProvisioningConfirmationReceipt:
    """Revalidate exact plan + fresh account absence and record explicit consent.

    The returned receipt is admission evidence only. It never authorizes provider execution.
    """
    if confirmed is not True:
        raise IdentityProvisioningConfirmationError("identity_confirmation_required")
    if type(max_preflight_age_seconds) is not int or not 1 <= max_preflight_age_seconds <= MAX_PREFLIGHT_AGE_SECONDS:
        raise IdentityProvisioningConfirmationError("identity_preflight_freshness_policy_invalid")
    current_time = _utc_timestamp(now, "identity_confirmation_time_invalid")
    if not isinstance(snapshot, HouseholdSnapshot):
        raise IdentityProvisioningConfirmationError("identity_household_snapshot_invalid")
    if not isinstance(provider, IdentityProviderCapability):
        raise IdentityProvisioningConfirmationError("identity_provider_capability_invalid")

    try:
        parsed_plan = plan_from_dict(plan.to_dict() if isinstance(plan, RoleIdentityProvisioningPlan) else plan)
    except IdentityProvisioningError as exc:
        raise IdentityProvisioningConfirmationError("identity_plan_rejected") from exc
    parsed_preflight = account_preflight_from_dict(
        preflight.to_dict() if isinstance(preflight, IdentityAccountPreflightEvidence) else preflight
    )

    try:
        rebuilt = build_role_identity_provisioning_plan(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            member_id=parsed_plan.member_id,
            account_name=parsed_plan.account_name,
            home_directory_mode=parsed_plan.home_directory_mode,
            profile_mode=parsed_plan.profile_mode,
        )
    except (IdentityProvisioningError, HomeServiceCatalogError) as exc:
        raise IdentityProvisioningConfirmationError(
            getattr(exc, "code", "identity_plan_revalidation_failed")
        ) from exc
    if rebuilt.to_dict() != parsed_plan.to_dict():
        raise IdentityProvisioningConfirmationError("identity_plan_stale")

    if (
        parsed_preflight.provider_id != parsed_plan.provider_id
        or parsed_preflight.provider_version != parsed_plan.provider_version
        or parsed_preflight.provider_evidence_sha256 != parsed_plan.provider_evidence_sha256
        or parsed_preflight.account_name != parsed_plan.account_name
    ):
        raise IdentityProvisioningConfirmationError("identity_preflight_binding_mismatch")
    if parsed_preflight.observed_state == "exists":
        raise IdentityProvisioningConfirmationError("identity_account_conflict")
    if parsed_preflight.observed_state != "absent":
        raise IdentityProvisioningConfirmationError("identity_account_state_unknown")

    observed_time = _utc_timestamp(parsed_preflight.observed_at, "identity_preflight_time_invalid")
    age = (current_time - observed_time).total_seconds()
    if age < 0 or age > max_preflight_age_seconds:
        raise IdentityProvisioningConfirmationError("identity_preflight_stale")

    canonical = {
        "schema": IDENTITY_CONFIRM_RECEIPT_SCHEMA,
        "plan_id": parsed_plan.plan_id,
        "household_id": parsed_plan.household_id,
        "member_id": parsed_plan.member_id,
        "account_name": parsed_plan.account_name,
        "provider_id": parsed_plan.provider_id,
        "provider_version": parsed_plan.provider_version,
        "provider_evidence_sha256": parsed_plan.provider_evidence_sha256,
        "preflight_evidence_id": parsed_preflight.evidence_id,
        "home_directory_mode": parsed_plan.home_directory_mode.value,
        "profile_mode": parsed_plan.profile_mode.value,
        "outcome": "confirmed-awaiting-execution",
        "provider_execution_authorized": False,
        "credential_material_authorized": False,
        "emergency_admin_mutation_authorized": False,
        "arbitrary_privilege_grant_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
        "post_condition_verification_required": True,
    }
    return RoleIdentityProvisioningConfirmationReceipt(
        receipt_id="hcidcr-" + _canonical_sha(canonical)[:24],
        plan_id=parsed_plan.plan_id,
        household_id=parsed_plan.household_id,
        member_id=parsed_plan.member_id,
        account_name=parsed_plan.account_name,
        provider_id=parsed_plan.provider_id,
        provider_version=parsed_plan.provider_version,
        provider_evidence_sha256=parsed_plan.provider_evidence_sha256,
        preflight_evidence_id=parsed_preflight.evidence_id,
        home_directory_mode=parsed_plan.home_directory_mode,
        profile_mode=parsed_plan.profile_mode,
    )
