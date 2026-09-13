from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.role_identity_binding_transition import (
    ACTION as BINDING_ACTION,
    RoleIdentityBindingTransitionError,
    RoleIdentityBindingTransitionService,
    binding_key,
)
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    RoleIdentityProvisioningPlan,
    StorageMode,
)
from home_center.role_identity_provisioning_execution import RoleIdentityProvisioningAdapterResult
from home_center.role_identity_provisioning_preflight import (
    AccountObservationState,
    AccountPreflightObservation,
)
from home_center.role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeService
from home_center.role_identity_provisioning_verification import (
    AccountReadbackState,
    IdentityProvisioningReadbackObservation,
    ResourceReadbackState,
)
from home_center.store import StateStore

ROOT = Path(__file__).resolve().parents[1]
PARENT_ACTOR = "local-admin:admin"
CHILD_ACTOR = "member-session:child"
PARENT = "member-parent"
CHILD = "member-child"
NOW = "2026-09-13T04:00:00Z"
PROVIDER_DIGEST = "a" * 64
PREFLIGHT_DIGEST = "b" * 64
ACCOUNT_DIGEST = "c" * 64
READBACK_DIGEST = "d" * 64


def _store_and_plan(tmp_path: Path, name: str = "state.db") -> tuple[StateStore, RoleIdentityProvisioningPlan]:
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id=PARENT, display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id=CHILD, display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    reference = HouseholdStore()
    reference.create(household)
    snapshot = reference.read("home")
    store = StateStore(tmp_path / name, audit_key=b"i" * 32, cluster_id="cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(
            snapshot,
            (
                ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),
                ActorBinding(actor=CHILD_ACTOR, member_id=CHILD),
            ),
        ),
    )
    plan = RoleIdentityProvisioningPlan(
        plan_id="hcidp-" + "e" * 24,
        household_id=snapshot.household_id,
        member_id=CHILD,
        role=HouseholdRole.CHILD,
        household_snapshot_id=snapshot.snapshot_id,
        household_resource_version=snapshot.resource_version,
        household_generation=snapshot.generation,
        policy_id="policy-child",
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER_DIGEST,
        account_name="artemiy",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )
    return store, plan


def _provider() -> IdentityProviderCapability:
    return IdentityProviderCapability(
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


def _preflight() -> AccountPreflightObservation:
    return AccountPreflightObservation(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER_DIGEST,
        account_name="artemiy",
        state=AccountObservationState.ABSENT,
        observed_at="2026-09-13T03:55:00Z",
        valid_until="2026-09-13T04:20:00Z",
        evidence_sha256=PREFLIGHT_DIGEST,
    )


def _readback() -> IdentityProvisioningReadbackObservation:
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
        observed_at="2026-09-13T03:58:00Z",
        valid_until="2026-09-13T04:20:00Z",
        evidence_sha256=READBACK_DIGEST,
    )


class _Adapter:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.start_calls = 0
        self.observe_calls = 0
        self.job_id: str | None = None

    def start(self, request):
        self.start_calls += 1
        self.job_id = request.job_id
        job = self.store.job(request.job_id)
        assert job is not None and job["state"] == "running"
        return RoleIdentityProvisioningAdapterResult(
            provider_operation_id="provider-op-1",
            account_name="artemiy",
        ).to_dict()

    def observe(self, *, provider_operation_id: str, account_name: str):
        self.observe_calls += 1
        assert provider_operation_id == "provider-op-1"
        assert account_name == "artemiy"
        assert self.job_id is not None
        job = self.store.job(self.job_id)
        assert job is not None and job["state"] == "verifying"
        return _readback().to_dict()


def _verified_execution(
    store: StateStore,
    plan: RoleIdentityProvisioningPlan,
    *,
    key: str = "identity-execution-1",
) -> tuple[dict[str, object], _Adapter]:
    adapter = _Adapter(store)
    runtime = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    runtime.register_adapter("local-account", adapter)
    receipt = runtime.execute(
        actor=PARENT_ACTOR,
        plan=plan,
        provider=_provider(),
        preflight_observation=_preflight(),
        credential_references=[
            {"name": "initial-password", "reference": "secret://identity/artemiy/initial"},
        ],
        confirmed=True,
        idempotency_key=key,
        correlation_id="identity-execution",
    )
    return receipt, adapter


def _transition(
    store: StateStore,
    plan: RoleIdentityProvisioningPlan,
    receipt: dict[str, object],
    *,
    actor: str = PARENT_ACTOR,
    key: str = "identity-binding-1",
) -> dict[str, object]:
    return RoleIdentityBindingTransitionService(store).transition(
        actor=actor,
        plan=plan,
        execution_receipt=receipt,
        idempotency_key=key,
        correlation_id="identity-binding",
    )


def test_verified_execution_binds_exact_member_without_provider_reinvocation(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, adapter = _verified_execution(store, plan)
    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)

    transition_receipt = _transition(store, plan, execution_receipt)

    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)
    assert transition_receipt["state"] == "bound"
    assert transition_receipt["identity_binding_committed"] is True
    assert transition_receipt["provider_reinvocation_performed"] is False
    assert transition_receipt["credential_material_persisted"] is False
    assert transition_receipt["emergency_admin_mutation_authorized"] is False
    assert transition_receipt["privilege_grant_authorized"] is False
    assert transition_receipt["external_publication_authorized"] is False

    state = store.get_meta(binding_key(plan.household_id, plan.member_id))
    assert isinstance(state, dict)
    assert state["verified"] is True
    assert state["active"] is True
    assert state["account_identity_sha256"] == ACCOUNT_DIGEST
    assert state["credential_material_persisted"] is False
    assert state["emergency_admin_isolated"] is True
    assert state["privilege_grant_authorized"] is False
    assert state["external_publication_authorized"] is False

    jobs = [job for job in store.jobs() if job["job_type"] == BINDING_ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "succeeded"
    assert jobs[0]["evidence"]["binding"] == state
    assert jobs[0]["evidence"]["receipt"] == transition_receipt
    assert store.verify_audit_chain()
    events = [event for event in store.audit_events() if event["action"] == BINDING_ACTION]
    assert len(events) == 1 and events[0]["outcome"] == "bound"
    store.close()


def test_transition_replay_after_restart_returns_same_receipt_without_duplicate_state(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, _adapter = _verified_execution(store, plan)
    first = _transition(store, plan, execution_receipt)

    restarted = RoleIdentityBindingTransitionService(store)
    second = restarted.transition(
        actor=PARENT_ACTOR,
        plan=plan,
        execution_receipt=execution_receipt,
        idempotency_key="identity-binding-1",
        correlation_id="identity-binding-replay",
    )

    assert second == first
    jobs = [job for job in store.jobs() if job["job_type"] == BINDING_ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "succeeded"
    events = [event for event in store.audit_events() if event["action"] == BINDING_ACTION]
    assert len([event for event in events if event["outcome"] == "bound"]) == 1
    store.close()


def test_stale_household_plan_is_rejected_before_transition_job(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, _adapter = _verified_execution(store, plan)
    stale = replace(plan, household_generation=plan.household_generation + 1)

    with pytest.raises(RoleIdentityBindingTransitionError, match="identity_binding_household_stale"):
        _transition(store, stale, execution_receipt, key="identity-binding-stale")

    assert not [job for job in store.jobs() if job["job_type"] == BINDING_ACTION]
    assert store.get_meta(binding_key(plan.household_id, plan.member_id)) is None
    store.close()


def test_non_parent_actor_cannot_commit_identity_binding(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, _adapter = _verified_execution(store, plan)

    with pytest.raises(RoleIdentityBindingTransitionError, match="identity_binding_transition_not_authorized"):
        _transition(store, plan, execution_receipt, actor=CHILD_ACTOR, key="identity-binding-child")

    assert not [job for job in store.jobs() if job["job_type"] == BINDING_ACTION]
    assert store.get_meta(binding_key(plan.household_id, plan.member_id)) is None
    store.close()


def test_tampered_execution_receipt_is_rejected_without_binding(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, _adapter = _verified_execution(store, plan)
    tampered = dict(execution_receipt)
    tampered["durable_state_change_authorized"] = True

    with pytest.raises(RoleIdentityBindingTransitionError, match="identity_binding_execution_receipt_invalid"):
        _transition(store, plan, tampered, key="identity-binding-tampered")

    assert not [job for job in store.jobs() if job["job_type"] == BINDING_ACTION]
    assert store.get_meta(binding_key(plan.household_id, plan.member_id)) is None
    store.close()


def test_existing_conflicting_binding_fails_closed_and_is_not_overwritten(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, _adapter = _verified_execution(store, plan)
    key = binding_key(plan.household_id, plan.member_id)
    existing = {"schema": "foreign.identity-binding", "binding_id": "do-not-overwrite"}
    store.set_meta(key, existing)

    with pytest.raises(RoleIdentityBindingTransitionError, match="identity_binding_conflict"):
        _transition(store, plan, execution_receipt, key="identity-binding-conflict")

    assert store.get_meta(key) == existing
    jobs = [job for job in store.jobs() if job["job_type"] == BINDING_ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "failed"
    assert jobs[0]["result"]["provider_reinvocation_performed"] is False
    store.close()


def test_binding_and_transition_receipt_match_closed_contracts(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, _adapter = _verified_execution(store, plan)
    receipt = _transition(store, plan, execution_receipt, key="identity-binding-schema")
    state = store.get_meta(binding_key(plan.household_id, plan.member_id))
    assert isinstance(state, dict)

    state_schema = json.loads(
        (ROOT / "contracts/household/role-identity-binding-state.v1.schema.json").read_text(encoding="utf-8")
    )
    receipt_schema = json.loads(
        (ROOT / "contracts/household/role-identity-binding-transition-receipt.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(state_schema).validate(state)
    jsonschema.Draft202012Validator(receipt_schema).validate(receipt)
    store.close()


def test_backup_restore_preserves_binding_job_receipt_and_audit(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, _adapter = _verified_execution(store, plan)
    receipt = _transition(store, plan, execution_receipt, key="identity-binding-backup")
    state = store.get_meta(binding_key(plan.household_id, plan.member_id))
    backup = tmp_path / "backup.db"
    store.backup_to(backup)
    store.close()

    restored = StateStore(backup, audit_key=b"i" * 32, cluster_id="cluster-test")
    assert restored.get_meta(binding_key(plan.household_id, plan.member_id)) == state
    jobs = [job for job in restored.jobs() if job["job_type"] == BINDING_ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "succeeded"
    assert jobs[0]["evidence"]["receipt"] == receipt
    assert restored.verify_audit_chain()
    restored.close()
