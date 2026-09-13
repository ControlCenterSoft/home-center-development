from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.role_identity_binding_api_runtime import (
    IdentityBindingApiRuntimeError,
    RoleIdentityBindingApiRuntimeService,
)
from home_center.role_identity_binding_transition import (
    ACTION as BINDING_ACTION,
    RoleIdentityBindingTransitionService,
    binding_key,
)
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
    RoleIdentityProvisioningPlan,
    StorageMode,
)
from home_center.role_identity_provisioning_api_runtime import PLAN_KEY_PREFIX, PLAN_STATE_SCHEMA
from home_center.role_identity_provisioning_execution import RoleIdentityProvisioningAdapterResult
from home_center.role_identity_provisioning_preflight import AccountObservationState, AccountPreflightObservation
from home_center.role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeService
from home_center.role_identity_provisioning_verification import (
    AccountReadbackState,
    IdentityProvisioningReadbackObservation,
    ResourceReadbackState,
)
from home_center.store import StateStore

ROOT = Path(__file__).resolve().parents[1]
PARENT_ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
NOW = "2026-09-13T05:00:00Z"
PROVIDER_DIGEST = "a" * 64
PREFLIGHT_DIGEST = "b" * 64
ACCOUNT_DIGEST = "c" * 64
READBACK_DIGEST = "d" * 64


def _store_and_plan(tmp_path: Path) -> tuple[StateStore, RoleIdentityProvisioningPlan]:
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
    store = StateStore(tmp_path / "state.db", audit_key=b"k" * 32, cluster_id="cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),)),
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
    store.set_meta(
        PLAN_KEY_PREFIX + plan.plan_id,
        {"schema": PLAN_STATE_SCHEMA, "actor": PARENT_ACTOR, "plan": plan.to_dict()},
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
        observed_at="2026-09-13T04:55:00Z",
        valid_until="2026-09-13T05:20:00Z",
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
        observed_at="2026-09-13T04:58:00Z",
        valid_until="2026-09-13T05:20:00Z",
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
        return RoleIdentityProvisioningAdapterResult(
            provider_operation_id="provider-op-1",
            account_name="artemiy",
        ).to_dict()

    def observe(self, *, provider_operation_id: str, account_name: str):
        self.observe_calls += 1
        assert provider_operation_id == "provider-op-1"
        assert account_name == "artemiy"
        return _readback().to_dict()


def _verified_execution(store: StateStore, plan: RoleIdentityProvisioningPlan):
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
        idempotency_key="identity-execution-api-1",
        correlation_id="identity-execution-api",
    )
    return receipt, adapter


def _service(store: StateStore) -> RoleIdentityBindingApiRuntimeService:
    return RoleIdentityBindingApiRuntimeService(store, RoleIdentityBindingTransitionService(store))


def test_bind_resolves_verified_receipt_server_side_without_provider_reinvocation(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, adapter = _verified_execution(store, plan)
    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)

    receipt = _service(store).bind(
        actor=PARENT_ACTOR,
        plan_id=plan.plan_id,
        execution_job_id=str(execution_receipt["job_id"]),
        confirmed=True,
        idempotency_key="identity-binding-api-1",
        correlation_id="identity-binding-api",
    )

    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)
    assert receipt["state"] == "bound"
    assert receipt["provider_reinvocation_performed"] is False
    assert receipt["credential_material_persisted"] is False
    assert receipt["emergency_admin_mutation_authorized"] is False
    assert receipt["privilege_grant_authorized"] is False
    assert receipt["external_publication_authorized"] is False
    state = store.get_meta(binding_key(plan.household_id, plan.member_id))
    assert isinstance(state, dict) and state["verified"] is True and state["active"] is True
    store.close()


def test_bind_replay_is_idempotent_and_does_not_create_duplicate_transition(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    execution_receipt, adapter = _verified_execution(store, plan)
    service = _service(store)
    kwargs = dict(
        actor=PARENT_ACTOR,
        plan_id=plan.plan_id,
        execution_job_id=str(execution_receipt["job_id"]),
        confirmed=True,
        idempotency_key="identity-binding-api-replay",
        correlation_id="identity-binding-api-replay",
    )
    first = service.bind(**kwargs)
    second = service.bind(**kwargs)
    assert second == first
    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)
    jobs = [job for job in store.jobs() if job["job_type"] == BINDING_ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "succeeded"
    store.close()


def test_bind_rejects_nonexecution_or_unverified_job_before_local_transition(tmp_path: Path) -> None:
    store, plan = _store_and_plan(tmp_path)
    job, _created = store.create_action_job(
        action_id="unrelated.action",
        actor=PARENT_ACTOR,
        reason="not identity execution",
        idempotency_key="unrelated-job",
        request_hash="f" * 64,
        preflight={"ready": True},
        steps=[{"step": "noop", "state": "pending"}],
    )
    with pytest.raises(IdentityBindingApiRuntimeError, match="identity_binding_api_verified_execution_required"):
        _service(store).bind(
            actor=PARENT_ACTOR,
            plan_id=plan.plan_id,
            execution_job_id=job["job_id"],
            confirmed=True,
            idempotency_key="identity-binding-api-invalid-job",
            correlation_id="identity-binding-api-invalid-job",
        )
    assert store.get_meta(binding_key(plan.household_id, plan.member_id)) is None
    assert not [item for item in store.jobs() if item["job_type"] == BINDING_ACTION]
    store.close()


def test_bind_request_schema_excludes_receipt_provider_and_credentials() -> None:
    schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-api-bind-request.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"schema", "plan_id", "execution_job_id", "confirmed"}
    serialized = json.dumps(schema, sort_keys=True).lower()
    assert "execution_receipt" not in serialized
    assert "provider_evidence" not in serialized
    assert "credential" not in serialized
    assert "secret://" not in serialized
