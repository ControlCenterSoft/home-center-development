from __future__ import annotations

from dataclasses import replace

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
    IdentityProvisioningConfirmationError,
    account_preflight_from_dict,
    build_account_preflight_evidence,
    confirm_role_identity_provisioning,
)

DIGEST = "a" * 64


def _snapshot(*, child_name: str = "Child"):
    household = Household(
        household_id="home",
        members=(
            FamilyMember(
                member_id="member-child",
                display_name=child_name,
                role=HouseholdRole.CHILD,
            ),
            FamilyMember(
                member_id="member-parent",
                display_name="Parent",
                role=HouseholdRole.PARENT,
            ),
        ),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    return store.read("home")


def _provider(*, version: str = "1.0.0", evidence_sha256: str = DIGEST):
    return IdentityProviderCapability(
        provider_id="directory-provider",
        provider_version=version,
        provider_kind=IdentityProviderKind.DIRECTORY,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=True,
        portable_profile_supported=True,
        secret_reference_supported=True,
        evidence_sha256=evidence_sha256,
    )


def _plan(*, snapshot=None, provider=None):
    snapshot = snapshot or _snapshot()
    provider = provider or _provider()
    policy = effective_policy(snapshot.household, "member-child")
    return snapshot, policy, provider, build_role_identity_provisioning_plan(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        member_id="member-child",
        account_name="child.user",
        home_directory_mode=StorageMode.PORTABLE,
        profile_mode=StorageMode.PORTABLE,
    )


def test_confirmation_revalidates_exact_plan_and_never_authorizes_execution() -> None:
    snapshot, policy, provider, plan = _plan()
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

    assert receipt.outcome == "confirmed-awaiting-execution"
    assert receipt.plan_id == plan.plan_id
    assert receipt.preflight_evidence_id == preflight.evidence_id
    assert receipt.provider_execution_authorized is False
    assert receipt.credential_material_authorized is False
    assert receipt.emergency_admin_mutation_authorized is False
    assert receipt.arbitrary_privilege_grant_authorized is False
    assert receipt.infrastructure_mutation_authorized is False
    assert receipt.external_publication_authorized is False
    assert receipt.post_condition_verification_required is True

    replay = confirm_role_identity_provisioning(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan.to_dict(),
        preflight=preflight.to_dict(),
        confirmed=True,
        now="2026-09-13T03:51:00Z",
    )
    assert replay == receipt


def test_confirmation_is_explicit_and_fresh_preflight_is_mandatory() -> None:
    snapshot, policy, provider, plan = _plan()
    preflight = build_account_preflight_evidence(
        plan=plan,
        observed_state="absent",
        observed_at="2026-09-13T03:50:00Z",
    )

    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_confirmation_required",
    ):
        confirm_role_identity_provisioning(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
            preflight=preflight,
            confirmed=False,
            now="2026-09-13T03:51:00Z",
        )

    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_preflight_stale",
    ):
        confirm_role_identity_provisioning(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
            preflight=preflight,
            confirmed=True,
            now="2026-09-13T03:56:00Z",
        )

    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_preflight_stale",
    ):
        confirm_role_identity_provisioning(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
            preflight=preflight,
            confirmed=True,
            now="2026-09-13T03:49:59Z",
        )


@pytest.mark.parametrize(
    ("observed_state", "code"),
    [
        ("exists", "identity_account_conflict"),
        ("unknown", "identity_account_state_unknown"),
    ],
)
def test_account_conflict_or_unknown_state_fails_closed(
    observed_state: str,
    code: str,
) -> None:
    snapshot, policy, provider, plan = _plan()
    preflight = build_account_preflight_evidence(
        plan=plan,
        observed_state=observed_state,
        observed_at="2026-09-13T03:50:00Z",
    )

    with pytest.raises(IdentityProvisioningConfirmationError, match=code):
        confirm_role_identity_provisioning(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
            preflight=preflight,
            confirmed=True,
            now="2026-09-13T03:51:00Z",
        )


def test_provider_or_household_drift_invalidates_confirmation() -> None:
    snapshot, policy, provider, plan = _plan()
    preflight = build_account_preflight_evidence(
        plan=plan,
        observed_state="absent",
        observed_at="2026-09-13T03:50:00Z",
    )

    provider_v2 = _provider(version="1.0.1", evidence_sha256="b" * 64)
    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_plan_stale",
    ):
        confirm_role_identity_provisioning(
            snapshot=snapshot,
            policy=policy,
            provider=provider_v2,
            plan=plan,
            preflight=preflight,
            confirmed=True,
            now="2026-09-13T03:51:00Z",
        )

    changed_snapshot = _snapshot(child_name="Child Updated")
    changed_policy = effective_policy(changed_snapshot.household, "member-child")
    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_plan_stale",
    ):
        confirm_role_identity_provisioning(
            snapshot=changed_snapshot,
            policy=changed_policy,
            provider=provider,
            plan=plan,
            preflight=preflight,
            confirmed=True,
            now="2026-09-13T03:51:00Z",
        )


def test_preflight_evidence_is_content_addressed_and_strictly_reconstructed() -> None:
    _, _, _, plan = _plan()
    preflight = build_account_preflight_evidence(
        plan=plan,
        observed_state="absent",
        observed_at="2026-09-13T03:50:00Z",
    )
    assert account_preflight_from_dict(preflight.to_dict()) == preflight

    raw = preflight.to_dict()
    raw["execution_authorized"] = True
    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_preflight_evidence_rejected",
    ):
        account_preflight_from_dict(raw)

    raw = preflight.to_dict()
    raw["observed_at"] = "2026-09-13T03:50:01Z"
    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_preflight_evidence_rejected",
    ):
        account_preflight_from_dict(raw)


def test_direct_dataclass_tampering_does_not_bypass_content_addressed_reconstruction() -> None:
    snapshot, policy, provider, plan = _plan()
    preflight = build_account_preflight_evidence(
        plan=plan,
        observed_state="absent",
        observed_at="2026-09-13T03:50:00Z",
    )
    tampered = replace(preflight, evidence_id="hcidpre-" + "0" * 24)

    with pytest.raises(
        IdentityProvisioningConfirmationError,
        match="identity_preflight_evidence_rejected",
    ):
        confirm_role_identity_provisioning(
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
            preflight=tampered,
            confirmed=True,
            now="2026-09-13T03:51:00Z",
        )
