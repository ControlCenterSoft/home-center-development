"""Fail-closed role-driven identity provisioning execution contracts for Home Center 0.62.

This module deliberately stops at the typed provider adapter boundary.  It may
construct an execution request only after explicit confirmation and exact
revalidation of the provider evidence used by the provisioning plan.  Provider
acceptance is not account-creation success: post-condition read-back remains a
separate mandatory boundary.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from .home_services import HomeServiceCatalogError, _identifier
from .role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    IdentityProvisioningError,
    RoleIdentityProvisioningPlan,
    StorageMode,
)

EXECUTION_REQUEST_SCHEMA = "home-center.role-identity-provisioning-execution-request.v1"
ADAPTER_RESULT_SCHEMA = "home-center.role-identity-provisioning-adapter-result.v1"
_PLAN_ID = re.compile(r"hcidp-[0-9a-f]{24}\Z")
_SECRET_REFERENCE = re.compile(r"secret://[A-Za-z0-9][A-Za-z0-9._/-]{0,239}\Z")
_PROVIDER_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_SECRET_REFERENCES = 8


class IdentityProvisioningExecutionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class IdentitySecretReference:
    name: str
    reference: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "reference": self.reference}


@dataclass(frozen=True, slots=True)
class RoleIdentityProvisioningExecutionRequest:
    job_id: str
    plan_id: str
    household_id: str
    member_id: str
    provider_id: str
    provider_version: str
    provider_kind: IdentityProviderKind
    provider_evidence_sha256: str
    account_name: str
    home_directory_mode: StorageMode
    profile_mode: StorageMode
    credential_references: tuple[IdentitySecretReference, ...]
    schema: str = field(default=EXECUTION_REQUEST_SCHEMA, init=False)
    provider_execution_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    emergency_admin_mutation_authorized: bool = field(default=False, init=False)
    arbitrary_privilege_grant_authorized: bool = field(default=False, init=False)
    unrelated_account_mutation_authorized: bool = field(default=False, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "plan_id": self.plan_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_kind": self.provider_kind.value,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "account_name": self.account_name,
            "home_directory_mode": self.home_directory_mode.value,
            "profile_mode": self.profile_mode.value,
            "credential_references": [item.to_dict() for item in self.credential_references],
            "provider_execution_authorized": True,
            "credential_value_access_authorized": False,
            "emergency_admin_mutation_authorized": False,
            "arbitrary_privilege_grant_authorized": False,
            "unrelated_account_mutation_authorized": False,
            "post_condition_verification_required": True,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class RoleIdentityProvisioningAdapterResult:
    provider_operation_id: str
    account_name: str
    schema: str = field(default=ADAPTER_RESULT_SCHEMA, init=False)
    state: str = field(default="accepted", init=False)
    account_created_verified: bool = field(default=False, init=False)
    home_directory_verified: bool = field(default=False, init=False)
    profile_verified: bool = field(default=False, init=False)
    post_condition_verified: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "accepted",
            "provider_operation_id": self.provider_operation_id,
            "account_name": self.account_name,
            "account_created_verified": False,
            "home_directory_verified": False,
            "profile_verified": False,
            "post_condition_verified": False,
        }


class RoleIdentityProvisioningProviderAdapter(Protocol):
    """Typed provider boundary. Implementations resolve secret refs out of process."""

    def start(self, request: RoleIdentityProvisioningExecutionRequest) -> object: ...


def _identifier_value(value: object, code: str) -> str:
    try:
        return _identifier(value, code)
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningExecutionError(exc.code) from exc


def normalize_secret_references(value: object) -> tuple[IdentitySecretReference, ...]:
    if not isinstance(value, list) or len(value) > _MAX_SECRET_REFERENCES:
        raise IdentityProvisioningExecutionError("identity_secret_references_invalid")
    normalized: list[IdentitySecretReference] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {"name", "reference"}:
            raise IdentityProvisioningExecutionError("identity_secret_reference_invalid")
        name = _identifier_value(raw.get("name"), "identity_secret_reference_name_invalid")
        reference = raw.get("reference")
        if not isinstance(reference, str) or _SECRET_REFERENCE.fullmatch(reference) is None:
            raise IdentityProvisioningExecutionError("identity_secret_reference_invalid")
        if name in seen:
            raise IdentityProvisioningExecutionError("identity_secret_reference_duplicate")
        seen.add(name)
        normalized.append(IdentitySecretReference(name=name, reference=reference))
    return tuple(sorted(normalized, key=lambda item: item.name))


def build_identity_execution_request(
    *,
    plan: RoleIdentityProvisioningPlan,
    provider: IdentityProviderCapability,
    job_id: str,
    credential_references: object,
    confirmed: bool,
) -> RoleIdentityProvisioningExecutionRequest:
    """Create exact-bound adapter input only after explicit confirmation."""

    if confirmed is not True:
        raise IdentityProvisioningExecutionError("identity_execution_confirmation_required")
    if not isinstance(plan, RoleIdentityProvisioningPlan):
        raise IdentityProvisioningExecutionError("identity_execution_plan_invalid")
    if not isinstance(provider, IdentityProviderCapability):
        raise IdentityProvisioningExecutionError("identity_execution_provider_invalid")
    if _PLAN_ID.fullmatch(plan.plan_id) is None:
        raise IdentityProvisioningExecutionError("identity_execution_plan_invalid")
    if (
        provider.provider_id != plan.provider_id
        or provider.provider_version != plan.provider_version
        or provider.provider_kind is not plan.provider_kind
        or provider.evidence_sha256 != plan.provider_evidence_sha256
    ):
        raise IdentityProvisioningExecutionError("identity_execution_provider_binding_mismatch")
    if not provider.account_create_supported:
        raise IdentityProvisioningExecutionError("identity_provider_account_create_unsupported")
    if plan.role not in provider.supported_roles:
        raise IdentityProvisioningExecutionError("identity_provider_role_unsupported")
    if plan.home_directory_mode is StorageMode.PORTABLE and not provider.portable_home_supported:
        raise IdentityProvisioningExecutionError("identity_portable_home_unsupported")
    if plan.profile_mode is StorageMode.PORTABLE and not provider.portable_profile_supported:
        raise IdentityProvisioningExecutionError("identity_portable_profile_unsupported")

    refs = normalize_secret_references(credential_references)
    if refs and not provider.secret_reference_supported:
        raise IdentityProvisioningExecutionError("identity_provider_secret_reference_unsupported")

    return RoleIdentityProvisioningExecutionRequest(
        job_id=_identifier_value(job_id, "identity_execution_job_id_invalid"),
        plan_id=plan.plan_id,
        household_id=plan.household_id,
        member_id=plan.member_id,
        provider_id=plan.provider_id,
        provider_version=plan.provider_version,
        provider_kind=plan.provider_kind,
        provider_evidence_sha256=plan.provider_evidence_sha256,
        account_name=plan.account_name,
        home_directory_mode=plan.home_directory_mode,
        profile_mode=plan.profile_mode,
        credential_references=refs,
    )


def execution_request_from_dict(value: object) -> RoleIdentityProvisioningExecutionRequest:
    expected = {
        "schema", "job_id", "plan_id", "household_id", "member_id", "provider_id",
        "provider_version", "provider_kind", "provider_evidence_sha256", "account_name",
        "home_directory_mode", "profile_mode", "credential_references",
        "provider_execution_authorized", "credential_value_access_authorized",
        "emergency_admin_mutation_authorized", "arbitrary_privilege_grant_authorized",
        "unrelated_account_mutation_authorized", "post_condition_verification_required",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != EXECUTION_REQUEST_SCHEMA:
        raise IdentityProvisioningExecutionError("identity_execution_request_rejected")
    if value.get("provider_execution_authorized") is not True or value.get("post_condition_verification_required") is not True:
        raise IdentityProvisioningExecutionError("identity_execution_request_rejected")
    for key in (
        "credential_value_access_authorized", "emergency_admin_mutation_authorized",
        "arbitrary_privilege_grant_authorized", "unrelated_account_mutation_authorized",
        "external_publication_authorized",
    ):
        if value.get(key) is not False:
            raise IdentityProvisioningExecutionError("identity_execution_request_rejected")
    try:
        request = RoleIdentityProvisioningExecutionRequest(
            job_id=_identifier_value(value["job_id"], "identity_execution_job_id_invalid"),
            plan_id=value["plan_id"],
            household_id=_identifier_value(value["household_id"], "identity_household_id_invalid"),
            member_id=_identifier_value(value["member_id"], "identity_member_id_invalid"),
            provider_id=_identifier_value(value["provider_id"], "identity_provider_id_invalid"),
            provider_version=value["provider_version"],
            provider_kind=IdentityProviderKind(value["provider_kind"]),
            provider_evidence_sha256=value["provider_evidence_sha256"],
            account_name=value["account_name"],
            home_directory_mode=StorageMode(value["home_directory_mode"]),
            profile_mode=StorageMode(value["profile_mode"]),
            credential_references=normalize_secret_references(value["credential_references"]),
        )
    except (KeyError, TypeError, ValueError, IdentityProvisioningError, IdentityProvisioningExecutionError) as exc:
        raise IdentityProvisioningExecutionError("identity_execution_request_rejected") from exc
    if _PLAN_ID.fullmatch(request.plan_id) is None or request.to_dict() != value:
        raise IdentityProvisioningExecutionError("identity_execution_request_rejected")
    return request


def adapter_result_from_dict(value: object) -> RoleIdentityProvisioningAdapterResult:
    expected = {
        "schema", "state", "provider_operation_id", "account_name",
        "account_created_verified", "home_directory_verified", "profile_verified",
        "post_condition_verified",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != ADAPTER_RESULT_SCHEMA:
        raise IdentityProvisioningExecutionError("identity_adapter_result_rejected")
    if value.get("state") != "accepted":
        raise IdentityProvisioningExecutionError("identity_adapter_result_rejected")
    for key in (
        "account_created_verified", "home_directory_verified", "profile_verified",
        "post_condition_verified",
    ):
        if value.get(key) is not False:
            raise IdentityProvisioningExecutionError("identity_adapter_result_rejected")
    operation_id = value.get("provider_operation_id")
    if not isinstance(operation_id, str) or _PROVIDER_OPERATION_ID.fullmatch(operation_id) is None:
        raise IdentityProvisioningExecutionError("identity_adapter_result_rejected")
    account_name = value.get("account_name")
    if not isinstance(account_name, str):
        raise IdentityProvisioningExecutionError("identity_adapter_result_rejected")
    result = RoleIdentityProvisioningAdapterResult(provider_operation_id=operation_id, account_name=account_name)
    if result.to_dict() != value:
        raise IdentityProvisioningExecutionError("identity_adapter_result_rejected")
    return result
