"""Read-only post-condition verification for Home Center 0.62 identity provisioning.

Provider command acceptance is not success. This module binds a fresh read-only
provider observation to the exact execution request and provider operation, then
produces verified evidence only when the account, home directory and profile are all
observed ready. It never invokes a provider and never returns credential material.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .home_services import HomeServiceCatalogError, _identifier
from .role_identity_provisioning import IdentityProvisioningError, StorageMode, _account, _semver, _sha256
from .role_identity_provisioning_execution import (
    PROVIDER_CREATE_REQUEST_SCHEMA,
    IdentityCredentialReference,
    IdentityProvisioningExecutionError,
    RoleIdentityProviderCreateRequest,
    RoleIdentityProviderCreateResult,
    normalize_identity_credential_references,
    provider_create_result_from_dict,
)

READBACK_OBSERVATION_SCHEMA = "home-center.role-identity-provider-readback-observation.v1"
VERIFICATION_RECEIPT_SCHEMA = "home-center.role-identity-provisioning-verification-receipt.v1"
MAX_OBSERVATION_AGE_SECONDS = 300


class IdentityProvisioningPostConditionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _utc(value: object, code: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise IdentityProvisioningPostConditionError(code)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise IdentityProvisioningPostConditionError(code) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise IdentityProvisioningPostConditionError(code)
    return parsed


def _request_from_dict(value: object) -> RoleIdentityProviderCreateRequest:
    expected = {
        "schema", "job_id", "plan_id", "confirmation_receipt_id", "household_id", "member_id",
        "role", "provider_id", "provider_version", "provider_evidence_sha256", "account_name",
        "home_directory_mode", "profile_mode", "credential_references", "deadline_at",
        "identity_account_creation_authorized", "provider_execution_authorized",
        "credential_value_access_authorized", "emergency_admin_mutation_authorized",
        "arbitrary_privilege_grant_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized", "post_condition_verification_required",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != PROVIDER_CREATE_REQUEST_SCHEMA:
        raise IdentityProvisioningPostConditionError("identity_provider_create_request_rejected")
    if (
        value.get("identity_account_creation_authorized") is not True
        or value.get("provider_execution_authorized") is not True
        or value.get("credential_value_access_authorized") is not False
        or value.get("emergency_admin_mutation_authorized") is not False
        or value.get("arbitrary_privilege_grant_authorized") is not False
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
        or value.get("post_condition_verification_required") is not True
    ):
        raise IdentityProvisioningPostConditionError("identity_provider_create_request_rejected")
    try:
        job_id = _identifier(value["job_id"], "identity_job_id_invalid")
        plan_id = _identifier(value["plan_id"], "identity_plan_id_invalid")
        confirmation_receipt_id = _identifier(value["confirmation_receipt_id"], "identity_confirmation_id_invalid")
        household_id = _identifier(value["household_id"], "identity_household_id_invalid")
        member_id = _identifier(value["member_id"], "identity_member_id_invalid")
        role = value["role"]
        if role not in {"parent", "child", "guest"}:
            raise IdentityProvisioningPostConditionError("identity_role_invalid")
        provider_id = _identifier(value["provider_id"], "identity_provider_id_invalid")
        provider_version = _semver(value["provider_version"], "identity_provider_version_invalid")
        provider_sha = _sha256(value["provider_evidence_sha256"], "identity_provider_evidence_invalid")
        account_name = _account(value["account_name"])
        home_mode = StorageMode(value["home_directory_mode"])
        profile_mode = StorageMode(value["profile_mode"])
        credentials = normalize_identity_credential_references(value["credential_references"])
        deadline_at = value["deadline_at"]
        _utc(deadline_at, "identity_deadline_invalid")
    except (
        KeyError, TypeError, ValueError, HomeServiceCatalogError, IdentityProvisioningError,
        IdentityProvisioningExecutionError, IdentityProvisioningPostConditionError,
    ) as exc:
        raise IdentityProvisioningPostConditionError("identity_provider_create_request_rejected") from exc
    result = RoleIdentityProviderCreateRequest(
        job_id=job_id,
        plan_id=plan_id,
        confirmation_receipt_id=confirmation_receipt_id,
        household_id=household_id,
        member_id=member_id,
        role=role,
        provider_id=provider_id,
        provider_version=provider_version,
        provider_evidence_sha256=provider_sha,
        account_name=account_name,
        home_directory_mode=home_mode,
        profile_mode=profile_mode,
        credential_references=credentials,
        deadline_at=deadline_at,
    )
    if result.to_dict() != value:
        raise IdentityProvisioningPostConditionError("identity_provider_create_request_rejected")
    return result


@dataclass(frozen=True, slots=True)
class RoleIdentityProviderReadbackObservation:
    observation_id: str
    provider_operation_id: str
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    account_name: str
    account_state: str
    home_directory_state: str
    profile_state: str
    observed_at: str
    schema: str = field(default=READBACK_OBSERVATION_SCHEMA, init=False)
    read_only: bool = field(default=True, init=False)
    credential_material_observed: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "observation_id": self.observation_id,
            "provider_operation_id": self.provider_operation_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "account_name": self.account_name,
            "account_state": self.account_state,
            "home_directory_state": self.home_directory_state,
            "profile_state": self.profile_state,
            "observed_at": self.observed_at,
            "read_only": True,
            "credential_material_observed": False,
            "execution_authorized": False,
            "external_publication_authorized": False,
        }


def build_identity_readback_observation(
    *,
    request: RoleIdentityProviderCreateRequest,
    result: RoleIdentityProviderCreateResult,
    account_state: str,
    home_directory_state: str,
    profile_state: str,
    observed_at: str,
) -> RoleIdentityProviderReadbackObservation:
    if not isinstance(request, RoleIdentityProviderCreateRequest):
        raise IdentityProvisioningPostConditionError("identity_provider_create_request_invalid")
    if not isinstance(result, RoleIdentityProviderCreateResult):
        raise IdentityProvisioningPostConditionError("identity_provider_create_result_invalid")
    if account_state not in {"present", "absent", "unknown"}:
        raise IdentityProvisioningPostConditionError("identity_account_readback_state_invalid")
    if home_directory_state not in {"ready", "missing", "unknown"}:
        raise IdentityProvisioningPostConditionError("identity_home_readback_state_invalid")
    if profile_state not in {"ready", "missing", "unknown"}:
        raise IdentityProvisioningPostConditionError("identity_profile_readback_state_invalid")
    _utc(observed_at, "identity_readback_time_invalid")
    canonical = {
        "schema": READBACK_OBSERVATION_SCHEMA,
        "provider_operation_id": result.provider_operation_id,
        "provider_id": request.provider_id,
        "provider_version": request.provider_version,
        "provider_evidence_sha256": request.provider_evidence_sha256,
        "account_name": request.account_name,
        "account_state": account_state,
        "home_directory_state": home_directory_state,
        "profile_state": profile_state,
        "observed_at": observed_at,
        "read_only": True,
        "credential_material_observed": False,
        "execution_authorized": False,
        "external_publication_authorized": False,
    }
    return RoleIdentityProviderReadbackObservation(
        observation_id="hcidobs-" + _digest(canonical)[:24],
        provider_operation_id=result.provider_operation_id,
        provider_id=request.provider_id,
        provider_version=request.provider_version,
        provider_evidence_sha256=request.provider_evidence_sha256,
        account_name=request.account_name,
        account_state=account_state,
        home_directory_state=home_directory_state,
        profile_state=profile_state,
        observed_at=observed_at,
    )


def readback_observation_from_dict(value: object) -> RoleIdentityProviderReadbackObservation:
    expected = {
        "schema", "observation_id", "provider_operation_id", "provider_id", "provider_version",
        "provider_evidence_sha256", "account_name", "account_state", "home_directory_state",
        "profile_state", "observed_at", "read_only", "credential_material_observed",
        "execution_authorized", "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != READBACK_OBSERVATION_SCHEMA:
        raise IdentityProvisioningPostConditionError("identity_readback_observation_rejected")
    if (
        value.get("read_only") is not True
        or value.get("credential_material_observed") is not False
        or value.get("execution_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise IdentityProvisioningPostConditionError("identity_readback_observation_rejected")
    try:
        operation_id = value["provider_operation_id"]
        provider_id = _identifier(value["provider_id"], "identity_provider_id_invalid")
        provider_version = _semver(value["provider_version"], "identity_provider_version_invalid")
        provider_sha = _sha256(value["provider_evidence_sha256"], "identity_provider_evidence_invalid")
        account_name = _account(value["account_name"])
        account_state = value["account_state"]
        home_state = value["home_directory_state"]
        profile_state = value["profile_state"]
        observed_at = value["observed_at"]
        _utc(observed_at, "identity_readback_time_invalid")
        if account_state not in {"present", "absent", "unknown"}:
            raise IdentityProvisioningPostConditionError("identity_account_readback_state_invalid")
        if home_state not in {"ready", "missing", "unknown"}:
            raise IdentityProvisioningPostConditionError("identity_home_readback_state_invalid")
        if profile_state not in {"ready", "missing", "unknown"}:
            raise IdentityProvisioningPostConditionError("identity_profile_readback_state_invalid")
        if not isinstance(operation_id, str) or not operation_id:
            raise IdentityProvisioningPostConditionError("identity_provider_operation_id_invalid")
    except (
        KeyError, TypeError, ValueError, HomeServiceCatalogError, IdentityProvisioningError,
        IdentityProvisioningPostConditionError,
    ) as exc:
        raise IdentityProvisioningPostConditionError("identity_readback_observation_rejected") from exc
    canonical = {
        "schema": READBACK_OBSERVATION_SCHEMA,
        "provider_operation_id": operation_id,
        "provider_id": provider_id,
        "provider_version": provider_version,
        "provider_evidence_sha256": provider_sha,
        "account_name": account_name,
        "account_state": account_state,
        "home_directory_state": home_state,
        "profile_state": profile_state,
        "observed_at": observed_at,
        "read_only": True,
        "credential_material_observed": False,
        "execution_authorized": False,
        "external_publication_authorized": False,
    }
    observation_id = "hcidobs-" + _digest(canonical)[:24]
    if value.get("observation_id") != observation_id:
        raise IdentityProvisioningPostConditionError("identity_readback_observation_rejected")
    return RoleIdentityProviderReadbackObservation(
        observation_id=observation_id,
        provider_operation_id=operation_id,
        provider_id=provider_id,
        provider_version=provider_version,
        provider_evidence_sha256=provider_sha,
        account_name=account_name,
        account_state=account_state,
        home_directory_state=home_state,
        profile_state=profile_state,
        observed_at=observed_at,
    )


@dataclass(frozen=True, slots=True)
class RoleIdentityProvisioningVerificationReceipt:
    verification_id: str
    job_id: str
    plan_id: str
    confirmation_receipt_id: str
    provider_operation_id: str
    observation_id: str
    household_id: str
    member_id: str
    account_name: str
    schema: str = field(default=VERIFICATION_RECEIPT_SCHEMA, init=False)
    account_creation_verified: bool = field(default=True, init=False)
    home_directory_verified: bool = field(default=True, init=False)
    profile_verified: bool = field(default=True, init=False)
    post_condition_verified: bool = field(default=True, init=False)
    credential_material_returned: bool = field(default=False, init=False)
    emergency_admin_mutation_authorized: bool = field(default=False, init=False)
    arbitrary_privilege_grant_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "verification_id": self.verification_id,
            "job_id": self.job_id,
            "plan_id": self.plan_id,
            "confirmation_receipt_id": self.confirmation_receipt_id,
            "provider_operation_id": self.provider_operation_id,
            "observation_id": self.observation_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "account_name": self.account_name,
            "account_creation_verified": True,
            "home_directory_verified": True,
            "profile_verified": True,
            "post_condition_verified": True,
            "credential_material_returned": False,
            "emergency_admin_mutation_authorized": False,
            "arbitrary_privilege_grant_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def verify_identity_provisioning_post_condition(
    *,
    request: RoleIdentityProviderCreateRequest | dict[str, object],
    result: RoleIdentityProviderCreateResult | dict[str, object],
    observation: RoleIdentityProviderReadbackObservation | dict[str, object],
    now: str,
    max_observation_age_seconds: int = MAX_OBSERVATION_AGE_SECONDS,
) -> RoleIdentityProvisioningVerificationReceipt:
    if type(max_observation_age_seconds) is not int or not 1 <= max_observation_age_seconds <= MAX_OBSERVATION_AGE_SECONDS:
        raise IdentityProvisioningPostConditionError("identity_readback_freshness_policy_invalid")
    current_time = _utc(now, "identity_verification_time_invalid")
    parsed_request = _request_from_dict(request.to_dict() if isinstance(request, RoleIdentityProviderCreateRequest) else request)
    try:
        parsed_result = provider_create_result_from_dict(
            result.to_dict() if isinstance(result, RoleIdentityProviderCreateResult) else result
        )
    except IdentityProvisioningExecutionError as exc:
        raise IdentityProvisioningPostConditionError("identity_provider_create_result_rejected") from exc
    parsed_observation = readback_observation_from_dict(
        observation.to_dict() if isinstance(observation, RoleIdentityProviderReadbackObservation) else observation
    )

    if (
        parsed_observation.provider_operation_id != parsed_result.provider_operation_id
        or parsed_observation.provider_id != parsed_request.provider_id
        or parsed_observation.provider_version != parsed_request.provider_version
        or parsed_observation.provider_evidence_sha256 != parsed_request.provider_evidence_sha256
        or parsed_observation.account_name != parsed_request.account_name
    ):
        raise IdentityProvisioningPostConditionError("identity_readback_binding_mismatch")
    observed_time = _utc(parsed_observation.observed_at, "identity_readback_time_invalid")
    age = (current_time - observed_time).total_seconds()
    if age < 0 or age > max_observation_age_seconds:
        raise IdentityProvisioningPostConditionError("identity_readback_stale")
    if parsed_observation.account_state != "present":
        raise IdentityProvisioningPostConditionError("identity_account_creation_not_verified")
    if parsed_observation.home_directory_state != "ready":
        raise IdentityProvisioningPostConditionError("identity_home_directory_not_verified")
    if parsed_observation.profile_state != "ready":
        raise IdentityProvisioningPostConditionError("identity_profile_not_verified")

    canonical = {
        "schema": VERIFICATION_RECEIPT_SCHEMA,
        "job_id": parsed_request.job_id,
        "plan_id": parsed_request.plan_id,
        "confirmation_receipt_id": parsed_request.confirmation_receipt_id,
        "provider_operation_id": parsed_result.provider_operation_id,
        "observation_id": parsed_observation.observation_id,
        "household_id": parsed_request.household_id,
        "member_id": parsed_request.member_id,
        "account_name": parsed_request.account_name,
        "account_creation_verified": True,
        "home_directory_verified": True,
        "profile_verified": True,
        "post_condition_verified": True,
        "credential_material_returned": False,
        "emergency_admin_mutation_authorized": False,
        "arbitrary_privilege_grant_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    return RoleIdentityProvisioningVerificationReceipt(
        verification_id="hcidver-" + _digest(canonical)[:24],
        job_id=parsed_request.job_id,
        plan_id=parsed_request.plan_id,
        confirmation_receipt_id=parsed_request.confirmation_receipt_id,
        provider_operation_id=parsed_result.provider_operation_id,
        observation_id=parsed_observation.observation_id,
        household_id=parsed_request.household_id,
        member_id=parsed_request.member_id,
        account_name=parsed_request.account_name,
    )
