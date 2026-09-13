"""Transport-neutral API projections for Home Center 0.62 identity confirmation.

These helpers strictly reconstruct public request/receipt evidence and expose truthful
Cozy/Full UI projections. They never persist confirmation, invoke a provider, handle
credential values, or authorize account/infrastructure mutation.
"""
from __future__ import annotations

from .home_services import HomeServiceCatalogError, _identifier
from .role_identity_provisioning import (
    IdentityProvisioningError,
    StorageMode,
    _account,
    _semver,
    _sha256,
    plan_from_dict,
)
from .role_identity_provisioning_confirmation import (
    IDENTITY_CONFIRM_RECEIPT_SCHEMA,
    IDENTITY_CONFIRM_REQUEST_SCHEMA,
    IdentityAccountPreflightEvidence,
    IdentityProvisioningConfirmationError,
    RoleIdentityProvisioningConfirmationReceipt,
    account_preflight_from_dict,
)


def confirmation_request_from_dict(value: object) -> tuple[dict[str, object], IdentityAccountPreflightEvidence]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "plan", "preflight", "confirmed"}
        or value.get("schema") != IDENTITY_CONFIRM_REQUEST_SCHEMA
        or value.get("confirmed") is not True
    ):
        raise IdentityProvisioningConfirmationError("identity_confirmation_request_rejected")
    try:
        plan = plan_from_dict(value.get("plan"))
        preflight = account_preflight_from_dict(value.get("preflight"))
    except (IdentityProvisioningError, IdentityProvisioningConfirmationError) as exc:
        raise IdentityProvisioningConfirmationError("identity_confirmation_request_rejected") from exc
    return plan.to_dict(), preflight


def confirmation_receipt_from_dict(value: object) -> RoleIdentityProvisioningConfirmationReceipt:
    expected = {
        "schema", "receipt_id", "plan_id", "household_id", "member_id", "account_name",
        "provider_id", "provider_version", "provider_evidence_sha256", "preflight_evidence_id",
        "home_directory_mode", "profile_mode", "outcome", "provider_execution_authorized",
        "credential_material_authorized", "emergency_admin_mutation_authorized",
        "arbitrary_privilege_grant_authorized", "infrastructure_mutation_authorized",
        "external_publication_authorized", "post_condition_verification_required",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema") != IDENTITY_CONFIRM_RECEIPT_SCHEMA:
        raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_rejected")
    if value.get("outcome") != "confirmed-awaiting-execution":
        raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_rejected")
    for key in (
        "provider_execution_authorized", "credential_material_authorized",
        "emergency_admin_mutation_authorized", "arbitrary_privilege_grant_authorized",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    ):
        if value.get(key) is not False:
            raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_rejected")
    if value.get("post_condition_verification_required") is not True:
        raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_rejected")
    try:
        receipt_id = _identifier(value["receipt_id"], "identity_receipt_id_invalid")
        if not receipt_id.startswith("hcidcr-") or len(receipt_id) != 31:
            raise IdentityProvisioningConfirmationError("identity_receipt_id_invalid")
        plan_id = _identifier(value["plan_id"], "identity_plan_id_invalid")
        if not plan_id.startswith("hcidp-") or len(plan_id) != 30:
            raise IdentityProvisioningConfirmationError("identity_plan_id_invalid")
        household_id = _identifier(value["household_id"], "identity_household_id_invalid")
        member_id = _identifier(value["member_id"], "identity_member_id_invalid")
        account_name = _account(value["account_name"])
        provider_id = _identifier(value["provider_id"], "identity_provider_id_invalid")
        provider_version = _semver(value["provider_version"], "identity_provider_version_invalid")
        provider_sha = _sha256(value["provider_evidence_sha256"], "identity_provider_evidence_invalid")
        preflight_evidence_id = _identifier(value["preflight_evidence_id"], "identity_preflight_id_invalid")
        if not preflight_evidence_id.startswith("hcidpre-") or len(preflight_evidence_id) != 32:
            raise IdentityProvisioningConfirmationError("identity_preflight_id_invalid")
        home_mode = StorageMode(value["home_directory_mode"])
        profile_mode = StorageMode(value["profile_mode"])
    except (KeyError, TypeError, ValueError, HomeServiceCatalogError, IdentityProvisioningError, IdentityProvisioningConfirmationError) as exc:
        raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_rejected") from exc
    receipt = RoleIdentityProvisioningConfirmationReceipt(
        receipt_id=receipt_id,
        plan_id=plan_id,
        household_id=household_id,
        member_id=member_id,
        account_name=account_name,
        provider_id=provider_id,
        provider_version=provider_version,
        provider_evidence_sha256=provider_sha,
        preflight_evidence_id=preflight_evidence_id,
        home_directory_mode=home_mode,
        profile_mode=profile_mode,
    )
    if receipt.to_dict() != value:
        raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_rejected")
    return receipt


def cozy_identity_confirmation_projection(
    receipt: RoleIdentityProvisioningConfirmationReceipt,
) -> dict[str, object]:
    if not isinstance(receipt, RoleIdentityProvisioningConfirmationReceipt):
        raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_invalid")
    return {
        "schema": "home-center.cozy-role-identity-confirmation.v1",
        "member_id": receipt.member_id,
        "account_name": receipt.account_name,
        "title": "Настройка подтверждена",
        "status": "Ожидает создания учётной записи",
        "account_created": False,
        "provider_execution_authorized": False,
        "emergency_admin_unchanged": True,
        "post_condition_verification_required": True,
    }


def full_identity_confirmation_projection(
    receipt: RoleIdentityProvisioningConfirmationReceipt,
) -> dict[str, object]:
    if not isinstance(receipt, RoleIdentityProvisioningConfirmationReceipt):
        raise IdentityProvisioningConfirmationError("identity_confirmation_receipt_invalid")
    return {
        "schema": "home-center.full-role-identity-confirmation.v1",
        "confirmation": receipt.to_dict(),
        "provider_execution_state": "not-authorized",
        "credential_material_state": "not-authorized",
        "emergency_admin_state": "independent-unchanged",
        "account_state": "not-created",
        "post_condition_verification_required": True,
    }
