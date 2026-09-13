"""Typed provider-execution contracts for Home Center 0.62 role identity provisioning.

This module creates a narrowly scoped adapter request only after strict reconstruction
of an explicit confirmation receipt, fresh exact-state plan revalidation, and exact
provider-capability revalidation. It does not invoke an adapter or claim success.
Provider command acceptance is never account-creation success; a separate read-back
and post-condition verification boundary is mandatory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from .home_services import HomeServiceCatalogError, _identifier
from .household import EffectivePolicy
from .household_policy_composer import ComposedPolicy
from .household_store import HouseholdSnapshot
from .role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProvisioningError,
    RoleIdentityProvisioningPlan,
    StorageMode,
    build_role_identity_provisioning_plan,
    plan_from_dict,
)
from .role_identity_provisioning_confirmation import (
    IdentityProvisioningConfirmationError,
    RoleIdentityProvisioningConfirmationReceipt,
)
from .role_identity_provisioning_confirmation_api import confirmation_receipt_from_dict

PROVIDER_CREATE_REQUEST_SCHEMA = "home-center.role-identity-provider-create-request.v1"
PROVIDER_CREATE_RESULT_SCHEMA = "home-center.role-identity-provider-create-result.v1"
SECRET_REFERENCE = re.compile(r"^secret://[A-Za-z0-9][A-Za-z0-9._/-]{0,239}$")
PROVIDER_OPERATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
RFC3339_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_CREDENTIAL_REFERENCES = 8


class IdentityProvisioningExecutionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class IdentityCredentialReference:
    name: str
    reference: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "reference": self.reference}


def normalize_identity_credential_references(value: object) -> tuple[IdentityCredentialReference, ...]:
    if not isinstance(value, list) or len(value) > MAX_CREDENTIAL_REFERENCES:
        raise IdentityProvisioningExecutionError("identity_credential_references_invalid")
    result: list[IdentityCredentialReference] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"name", "reference"}:
            raise IdentityProvisioningExecutionError("identity_credential_reference_invalid")
        try:
            name = _identifier(item.get("name"), "identity_credential_reference_name_invalid")
        except HomeServiceCatalogError as exc:
            raise IdentityProvisioningExecutionError(exc.code) from exc
        reference = item.get("reference")
        if (
            name in seen
            or not isinstance(reference, str)
            or SECRET_REFERENCE.fullmatch(reference) is None
            or ".." in reference.removeprefix("secret://").split("/")
        ):
            raise IdentityProvisioningExecutionError("identity_credential_reference_invalid")
        seen.add(name)
        result.append(IdentityCredentialReference(name=name, reference=reference))
    return tuple(sorted(result, key=lambda item: item.name))


@dataclass(frozen=True, slots=True)
class RoleIdentityProviderCreateRequest:
    job_id: str
    plan_id: str
    confirmation_receipt_id: str
    household_id: str
    member_id: str
    role: str
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    account_name: str
    home_directory_mode: StorageMode
    profile_mode: StorageMode
    credential_references: tuple[IdentityCredentialReference, ...]
    deadline_at: str
    schema: str = field(default=PROVIDER_CREATE_REQUEST_SCHEMA, init=False)
    identity_account_creation_authorized: bool = field(default=True, init=False)
    provider_execution_authorized: bool = field(default=True, init=False)
    credential_value_access_authorized: bool = field(default=False, init=False)
    emergency_admin_mutation_authorized: bool = field(default=False, init=False)
    arbitrary_privilege_grant_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)
    post_condition_verification_required: bool = field(default=True, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "job_id": self.job_id,
            "plan_id": self.plan_id,
            "confirmation_receipt_id": self.confirmation_receipt_id,
            "household_id": self.household_id,
            "member_id": self.member_id,
            "role": self.role,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "provider_evidence_sha256": self.provider_evidence_sha256,
            "account_name": self.account_name,
            "home_directory_mode": self.home_directory_mode.value,
            "profile_mode": self.profile_mode.value,
            "credential_references": [item.to_dict() for item in self.credential_references],
            "deadline_at": self.deadline_at,
            "identity_account_creation_authorized": True,
            "provider_execution_authorized": True,
            "credential_value_access_authorized": False,
            "emergency_admin_mutation_authorized": False,
            "arbitrary_privilege_grant_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
            "post_condition_verification_required": True,
        }


@dataclass(frozen=True, slots=True)
class RoleIdentityProviderCreateResult:
    provider_operation_id: str
    schema: str = field(default=PROVIDER_CREATE_RESULT_SCHEMA, init=False)
    state: str = field(default="accepted", init=False)
    account_creation_verified: bool = field(default=False, init=False)
    home_directory_verified: bool = field(default=False, init=False)
    profile_verified: bool = field(default=False, init=False)
    post_condition_verified: bool = field(default=False, init=False)
    credential_material_returned: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.provider_operation_id, str) or PROVIDER_OPERATION_ID.fullmatch(self.provider_operation_id) is None:
            raise IdentityProvisioningExecutionError("identity_provider_operation_id_invalid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "state": "accepted",
            "provider_operation_id": self.provider_operation_id,
            "account_creation_verified": False,
            "home_directory_verified": False,
            "profile_verified": False,
            "post_condition_verified": False,
            "credential_material_returned": False,
        }


class RoleIdentityProviderAdapter(Protocol):
    """Typed identity provider boundary; implementations resolve secret references externally."""

    def create_account(self, request: RoleIdentityProviderCreateRequest) -> object: ...


def _strict_plan(value: RoleIdentityProvisioningPlan | dict[str, object]) -> RoleIdentityProvisioningPlan:
    try:
        return plan_from_dict(value.to_dict() if isinstance(value, RoleIdentityProvisioningPlan) else value)
    except IdentityProvisioningError as exc:
        raise IdentityProvisioningExecutionError("identity_execution_plan_rejected") from exc


def _strict_receipt(
    value: RoleIdentityProvisioningConfirmationReceipt | dict[str, object],
) -> RoleIdentityProvisioningConfirmationReceipt:
    try:
        return confirmation_receipt_from_dict(
            value.to_dict() if isinstance(value, RoleIdentityProvisioningConfirmationReceipt) else value
        )
    except IdentityProvisioningConfirmationError as exc:
        raise IdentityProvisioningExecutionError("identity_confirmation_receipt_rejected") from exc


def build_identity_provider_create_request(
    *,
    snapshot: HouseholdSnapshot,
    policy: EffectivePolicy | ComposedPolicy,
    provider: IdentityProviderCapability,
    plan: RoleIdentityProvisioningPlan | dict[str, object],
    confirmation: RoleIdentityProvisioningConfirmationReceipt | dict[str, object],
    job_id: str,
    credential_references: object,
    deadline_at: str,
) -> RoleIdentityProviderCreateRequest:
    """Create exact-bound provider request evidence without invoking the provider."""
    if not isinstance(snapshot, HouseholdSnapshot):
        raise IdentityProvisioningExecutionError("identity_household_snapshot_invalid")
    if not isinstance(provider, IdentityProviderCapability):
        raise IdentityProvisioningExecutionError("identity_provider_capability_invalid")
    try:
        normalized_job_id = _identifier(job_id, "identity_job_id_invalid")
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningExecutionError(exc.code) from exc
    if not isinstance(deadline_at, str) or RFC3339_UTC_SECONDS.fullmatch(deadline_at) is None:
        raise IdentityProvisioningExecutionError("identity_deadline_invalid")

    parsed_plan = _strict_plan(plan)
    parsed_confirmation = _strict_receipt(confirmation)
    credentials = normalize_identity_credential_references(credential_references)

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
    except IdentityProvisioningError as exc:
        raise IdentityProvisioningExecutionError(getattr(exc, "code", "identity_execution_plan_stale")) from exc
    if rebuilt.to_dict() != parsed_plan.to_dict():
        raise IdentityProvisioningExecutionError("identity_execution_plan_stale")

    if (
        parsed_confirmation.plan_id != parsed_plan.plan_id
        or parsed_confirmation.household_id != parsed_plan.household_id
        or parsed_confirmation.member_id != parsed_plan.member_id
        or parsed_confirmation.account_name != parsed_plan.account_name
        or parsed_confirmation.provider_id != parsed_plan.provider_id
        or parsed_confirmation.provider_version != parsed_plan.provider_version
        or parsed_confirmation.provider_evidence_sha256 != parsed_plan.provider_evidence_sha256
        or parsed_confirmation.home_directory_mode is not parsed_plan.home_directory_mode
        or parsed_confirmation.profile_mode is not parsed_plan.profile_mode
    ):
        raise IdentityProvisioningExecutionError("identity_confirmation_binding_mismatch")
    if credentials and not provider.secret_reference_supported:
        raise IdentityProvisioningExecutionError("identity_provider_secret_reference_unsupported")

    return RoleIdentityProviderCreateRequest(
        job_id=normalized_job_id,
        plan_id=parsed_plan.plan_id,
        confirmation_receipt_id=parsed_confirmation.receipt_id,
        household_id=parsed_plan.household_id,
        member_id=parsed_plan.member_id,
        role=parsed_plan.role.value,
        provider_id=parsed_plan.provider_id,
        provider_version=parsed_plan.provider_version,
        provider_evidence_sha256=parsed_plan.provider_evidence_sha256,
        account_name=parsed_plan.account_name,
        home_directory_mode=parsed_plan.home_directory_mode,
        profile_mode=parsed_plan.profile_mode,
        credential_references=credentials,
        deadline_at=deadline_at,
    )


def provider_create_result_from_dict(value: object) -> RoleIdentityProviderCreateResult:
    expected = {
        "schema", "state", "provider_operation_id", "account_creation_verified",
        "home_directory_verified", "profile_verified", "post_condition_verified",
        "credential_material_returned",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != PROVIDER_CREATE_RESULT_SCHEMA:
        raise IdentityProvisioningExecutionError("identity_provider_create_result_rejected")
    if (
        value.get("state") != "accepted"
        or value.get("account_creation_verified") is not False
        or value.get("home_directory_verified") is not False
        or value.get("profile_verified") is not False
        or value.get("post_condition_verified") is not False
        or value.get("credential_material_returned") is not False
    ):
        raise IdentityProvisioningExecutionError("identity_provider_create_result_rejected")
    try:
        result = RoleIdentityProviderCreateResult(provider_operation_id=value["provider_operation_id"])
    except (KeyError, TypeError, IdentityProvisioningExecutionError) as exc:
        raise IdentityProvisioningExecutionError("identity_provider_create_result_rejected") from exc
    if result.to_dict() != value:
        raise IdentityProvisioningExecutionError("identity_provider_create_result_rejected")
    return result
