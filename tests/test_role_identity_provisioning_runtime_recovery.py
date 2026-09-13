from __future__ import annotations

from dataclasses import dataclass

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_store import HouseholdStore
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    StorageMode,
    build_role_identity_provisioning_plan,
)
from home_center.role_identity_provisioning_execution import RoleIdentityProvisioningAdapterResult
from home_center.role_identity_provisioning_preflight import (
    AccountObservationState,
    AccountPreflightObservation,
)
from home_center.role_identity_provisioning_runtime import (
    QualifiedIdentityAdapterRegistry,
    RoleIdentityProvisioningRuntimeService,
)
from home_center.role_identity_provisioning_verification import (
    AccountReadbackState,
    IdentityProvisioningReadbackObservation,
    ResourceReadbackState,
)
from home_center.store import StateStore

PROVIDER_DIGEST = "a" * 64
QUALIFICATION_DIGEST = "b" * 64
PREFLIGHT_DIGEST = "c" * 64
READBACK_DIGEST = "d" * 64
ACCOUNT_DIGEST = "e" * 64


@dataclass
class FakeAdapter:
    mode: str = "accepted"
    calls: int = 0

    def start(self, request):
        self.calls += 1
        if self.mode == "raise":
            raise ConnectionResetError("response lost")
        return RoleIdentityProvisioningAdapterResult(
            provider_operation_id="provider-op-1",
            account_name=request.account_name,
        ).to_dict()


def _context():
    household = Household(
        household_id="home",
        members=(
            FamilyMember("member-child", "Child", HouseholdRole.CHILD),
            FamilyMember("member-parent", "Parent", HouseholdRole.PARENT),
        ),
        devices=(),
    )
    household_store = HouseholdStore()
    household_store.create(household)
    snapshot = household_store.read("home")
    policy = effective_policy(snapshot.household, "member-child")
    provider = IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        evidence_sha256=PROVIDER_DIGEST,
    )
    plan = build_role_identity_provisioning_plan(
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        member_id="member-child",
        account_name="artemiy",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )
    preflight = AccountPreflightObservation(
        provider_id=provider.provider_id,
        provider_version=provider.provider_version,
        provider_kind=provider.provider_kind,
        provider_evidence_sha256=provider.evidence_sha256,
        account_name=plan.account_name,
        state=AccountObservationState.ABSENT,
        observed_at="2026-09-13T04:00:00Z",
        valid_until="2026-09-13T04:20:00Z",
        evidence_sha256=PREFLIGHT_DIGEST,
    )
    return snapshot, policy, provider, plan, preflight


def _registry(provider, adapter):
    registry = QualifiedIdentityAdapterRegistry()
    registry.register(
        provider=provider,
        adapter=adapter,
        qualification_evidence_sha256=QUALIFICATION_DIGEST,
    )
    return registry


def _start(service, *, snapshot, policy, provider, plan, preflight, key="recovery-idem-1"):
    return service.start(
        snapshot=snapshot,
        policy=policy,
        plan=plan,
        provider=provider,
        preflight_observation=preflight,
        credential_references=[],
        actor="member-parent",
        reason="Durable identity provisioning recovery test",
        idempotency_key=key,
        correlation_id="identity-recovery-1",
        now="2026-09-13T04:10:00Z",
        confirmed=True,
    )


def _readback():
    return IdentityProvisioningReadbackObservation(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER_DIGEST,
        provider_operation_id="provider-op-1",
        account_name="artemiy",
        account_state=AccountReadbackState.PRESENT,
        account_identity_sha256=ACCOUNT_DIGEST,
        home_directory_state=ResourceReadbackState.READY,
        profile_state=ResourceReadbackState.READY,
        observed_at="2026-09-13T04:05:00Z",
        valid_until="2026-09-13T04:20:00Z",
        evidence_sha256=READBACK_DIGEST,
    )


def test_verifying_job_survives_backup_and_idempotent_replay_does_not_reinvoke_provider(tmp_path) -> None:
    snapshot, policy, provider, plan, preflight = _context()
    source_adapter = FakeAdapter()
    source = StateStore(tmp_path / "source.db", b"k" * 32, "cluster-test")
    source_service = RoleIdentityProvisioningRuntimeService(
        store=source,
        registry=_registry(provider, source_adapter),
    )
    job = _start(
        source_service,
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan,
        preflight=preflight,
    )
    assert job["state"] == "verifying"
    assert source_adapter.calls == 1

    backup = tmp_path / "restored.db"
    source.backup_to(backup)
    source.close()

    restored_adapter = FakeAdapter()
    restored = StateStore(backup, b"k" * 32, "cluster-test")
    restored_service = RoleIdentityProvisioningRuntimeService(
        store=restored,
        registry=_registry(provider, restored_adapter),
    )
    try:
        recovery = restored_service.recovery_view(job["job_id"])
        assert recovery["state"] == "verifying"
        assert recovery["next_action"] == "fresh-readback-verification"
        assert recovery["provider_reinvocation_authorized"] is False

        replay = _start(
            restored_service,
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan.to_dict(),
            preflight=preflight,
        )
        assert replay["job_id"] == job["job_id"]
        assert replay["state"] == "verifying"
        assert restored_adapter.calls == 0

        verified = restored_service.verify(
            job_id=job["job_id"],
            plan=plan,
            provider=provider,
            observation=_readback(),
            actor="member-parent",
            correlation_id="identity-recovery-verify",
            now="2026-09-13T04:10:00Z",
        )
        assert verified["state"] == "succeeded"
        assert verified["result"]["post_condition_verified"] is True
        assert restored_adapter.calls == 0
    finally:
        restored.close()


def test_ambiguous_provider_outcome_survives_backup_without_automatic_retry(tmp_path) -> None:
    snapshot, policy, provider, plan, preflight = _context()
    source_adapter = FakeAdapter(mode="raise")
    source = StateStore(tmp_path / "source-failed.db", b"k" * 32, "cluster-test")
    source_service = RoleIdentityProvisioningRuntimeService(
        store=source,
        registry=_registry(provider, source_adapter),
    )
    failed = _start(
        source_service,
        snapshot=snapshot,
        policy=policy,
        provider=provider,
        plan=plan,
        preflight=preflight,
        key="recovery-idem-failed",
    )
    assert failed["state"] == "failed"
    assert source_adapter.calls == 1

    backup = tmp_path / "restored-failed.db"
    source.backup_to(backup)
    source.close()

    restored_adapter = FakeAdapter()
    restored = StateStore(backup, b"k" * 32, "cluster-test")
    restored_service = RoleIdentityProvisioningRuntimeService(
        store=restored,
        registry=_registry(provider, restored_adapter),
    )
    try:
        recovery = restored_service.recovery_view(failed["job_id"])
        assert recovery["state"] == "failed"
        assert recovery["automatic_provider_retry_authorized"] is False
        assert recovery["provider_reinvocation_authorized"] is False
        assert recovery["reconciliation_required"] is True

        replay = _start(
            restored_service,
            snapshot=snapshot,
            policy=policy,
            provider=provider,
            plan=plan,
            preflight=preflight,
            key="recovery-idem-failed",
        )
        assert replay["job_id"] == failed["job_id"]
        assert replay["state"] == "failed"
        assert restored_adapter.calls == 0
    finally:
        restored.close()
