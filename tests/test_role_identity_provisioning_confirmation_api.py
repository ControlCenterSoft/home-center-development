from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_store import HouseholdStore
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    StorageMode,
    build_role_identity_provisioning_plan,
)
from home_center.role_identity_provisioning_confirmation import (
    IDENTITY_CONFIRM_REQUEST_SCHEMA,
    IdentityProvisioningConfirmationError,
    build_account_preflight_evidence,
    confirm_role_identity_provisioning,
)
from home_center.role_identity_provisioning_confirmation_api import (
    confirmation_receipt_from_dict,
    confirmation_request_from_dict,
    cozy_identity_confirmation_projection,
    full_identity_confirmation_projection,
)

DIGEST = "a" * 64


def _objects():
    household = Household(
        household_id="home",
        members=(FamilyMember("member-child", "Child", HouseholdRole.CHILD),),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    snapshot = store.read("home")
    policy = effective_policy(snapshot.household, "member-child")
    provider = IdentityProviderCapability(
        provider_id="directory-provider",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.DIRECTORY,
        supported_roles=(HouseholdRole.CHILD,),
        account_create_supported=True,
        portable_home_supported=True,
        portable_profile_supported=True,
        secret_reference_supported=True,
        evidence_sha256=DIGEST,
    )
    plan = build_role_identity_provisioning_plan(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        member_id="member-child",
        account_name="child.user",
        home_directory_mode=StorageMode.PORTABLE,
        profile_mode=StorageMode.PORTABLE,
    )
    preflight = build_account_preflight_evidence(
        plan=plan,
        observed_state="absent",
        observed_at="2026-09-13T03:50:00Z",
    )
    receipt = confirm_role_identity_provisioning(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan,
        preflight=preflight,
        confirmed=True,
        now="2026-09-13T03:51:00Z",
    )
    return plan, preflight, receipt


def test_confirmation_request_is_closed_and_reconstructs_nested_evidence() -> None:
    plan, preflight, _receipt = _objects()
    request = {
        "schema": IDENTITY_CONFIRM_REQUEST_SCHEMA,
        "plan": plan.to_dict(),
        "preflight": preflight.to_dict(),
        "confirmed": True,
    }
    parsed_plan, parsed_preflight = confirmation_request_from_dict(request)
    assert parsed_plan == plan.to_dict()
    assert parsed_preflight == preflight

    request["extra"] = True
    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_confirmation_request_rejected",
    ):
        confirmation_request_from_dict(request)


def test_confirmation_receipt_strict_reconstruction_rejects_authority_tampering() -> None:
    _plan, _preflight, receipt = _objects()
    assert confirmation_receipt_from_dict(receipt.to_dict()) == receipt

    raw = receipt.to_dict()
    raw["provider_execution_authorized"] = True
    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_confirmation_receipt_rejected",
    ):
        confirmation_receipt_from_dict(raw)

    raw = receipt.to_dict()
    raw["account_name"] = "other.user"
    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_confirmation_receipt_rejected",
    ):
        confirmation_receipt_from_dict(raw)


def test_cozy_and_full_projections_never_claim_account_creation() -> None:
    _plan, _preflight, receipt = _objects()
    cozy = cozy_identity_confirmation_projection(receipt)
    full = full_identity_confirmation_projection(receipt)

    assert cozy["account_created"] is False
    assert cozy["provider_execution_authorized"] is False
    assert cozy["emergency_admin_unchanged"] is True
    assert "Ожидает" in cozy["status"]
    assert full["provider_execution_state"] == "not-authorized"
    assert full["credential_material_state"] == "not-authorized"
    assert full["emergency_admin_state"] == "independent-unchanged"
    assert full["account_state"] == "not-created"
