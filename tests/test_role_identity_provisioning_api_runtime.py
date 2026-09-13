from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.role_identity_provider_qualification import (
    IdentityProviderQualificationEvidence,
    evaluate_identity_provider_qualification,
)
from home_center.role_identity_provisioning import IdentityProviderCapability, IdentityProviderKind
from home_center.role_identity_provisioning_api_runtime import (
    IdentityProvisioningApiRuntimeError,
    RoleIdentityProvisioningApiRuntimeService,
)
from home_center.role_identity_provisioning_execution import RoleIdentityProvisioningAdapterResult
from home_center.role_identity_provisioning_preflight import AccountObservationState, AccountPreflightObservation
from home_center.role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeService
from home_center.role_identity_provisioning_verification import (
    AccountReadbackState,
    IdentityProvisioningReadbackObservation,
    ResourceReadbackState,
)
from home_center.store import StateStore

NOW = "2026-09-13T04:00:00Z"
VERSION = "0.62.0"
REVISION = "1" * 40
CANDIDATE_DIGEST = "a" * 64
ADAPTER_DIGEST = "b" * 64
PROVIDER_DIGEST = "c" * 64
PREFLIGHT_DIGEST = "d" * 64
READBACK_DIGEST = "e" * 64
ACCOUNT_DIGEST = "f" * 64
PARENT_ACTOR = "local-admin:admin"


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


def _decision(*, real_target: bool = True):
    return evaluate_identity_provider_qualification(
        IdentityProviderQualificationEvidence(
            version=VERSION,
            revision=REVISION,
            candidate_artifact_sha256=CANDIDATE_DIGEST,
            provider_id="local-account",
            provider_version="1.0.0",
            provider_kind=IdentityProviderKind.LOCAL,
            provider_evidence_sha256=PROVIDER_DIGEST,
            adapter_artifact_sha256=ADAPTER_DIGEST,
            execution_transcript_sha256="1" * 64,
            environment_evidence_sha256="2" * 64,
            recovery_evidence_sha256="3" * 64,
            real_provider_exercised=True,
            real_target_exercised=real_target,
            account_absence_preflight_validated=True,
            start_contract_validated=True,
            readback_contract_validated=True,
            secret_reference_only=True,
            secret_values_absent_from_evidence=True,
            durable_job_before_side_effect=True,
            ambiguous_outcome_fail_closed=True,
            automatic_retry_forbidden=True,
            provider_acceptance_not_success=True,
            post_condition_readback_required=True,
            emergency_admin_isolated=True,
            arbitrary_privilege_grant_forbidden=True,
            external_publication_forbidden=True,
            recovery_semantics_validated=True,
        )
    )


def _store(tmp_path: Path) -> StateStore:
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    reference = HouseholdStore()
    reference.create(household)
    snapshot = reference.read("home")
    store = StateStore(tmp_path / "state.db", audit_key=b"z" * 32, cluster_id="cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=PARENT_ACTOR, member_id="member-parent"),)),
    )
    return store


class _Adapter:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.preflight_calls = 0
        self.start_calls = 0
        self.observe_calls = 0
        self.job_id: str | None = None

    def preflight(self, *, plan):
        self.preflight_calls += 1
        return AccountPreflightObservation(
            provider_id="local-account",
            provider_version="1.0.0",
            provider_kind=IdentityProviderKind.LOCAL,
            provider_evidence_sha256=PROVIDER_DIGEST,
            account_name=plan.account_name,
            state=AccountObservationState.ABSENT,
            observed_at="2026-09-13T03:55:00Z",
            valid_until="2026-09-13T04:20:00Z",
            evidence_sha256=PREFLIGHT_DIGEST,
        ).to_dict()

    def start(self, request):
        self.start_calls += 1
        self.job_id = request.job_id
        assert self.store.job(request.job_id)["state"] == "running"
        return RoleIdentityProvisioningAdapterResult(
            provider_operation_id="provider-op-1", account_name="artemiy"
        ).to_dict()

    def observe(self, *, provider_operation_id: str, account_name: str):
        self.observe_calls += 1
        assert provider_operation_id == "provider-op-1"
        assert account_name == "artemiy"
        assert self.job_id is not None and self.store.job(self.job_id)["state"] == "verifying"
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
        ).to_dict()


def _service(store: StateStore, adapter: _Adapter, *, decision=None):
    execution = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service = RoleIdentityProvisioningApiRuntimeService(store, execution, now=lambda: NOW)
    service.register_provider(
        provider=_provider(),
        qualification=_decision() if decision is None else decision,
        adapter=adapter,
        expected_version=VERSION,
        expected_revision=REVISION,
        expected_candidate_artifact_sha256=CANDIDATE_DIGEST,
        expected_adapter_artifact_sha256=ADAPTER_DIGEST,
    )
    return service


def test_server_authoritative_api_plan_preflight_execute_revalidates_provider_and_household(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = _service(store, adapter)

    plan = service.plan(
        actor=PARENT_ACTOR,
        member_id="member-child",
        provider_id="local-account",
        account_name="artemiy",
        home_directory_mode="local",
        profile_mode="local",
        correlation_id="api-plan",
    )
    assert plan["execution_authorized"] is False

    preflight = service.preflight(
        actor=PARENT_ACTOR, plan_id=plan["plan_id"], correlation_id="api-preflight"
    )
    assert preflight["ready"] is True
    assert adapter.preflight_calls == 1

    receipt = service.execute(
        actor=PARENT_ACTOR,
        plan_id=plan["plan_id"],
        credential_references=[
            {"name": "initial-password", "reference": "secret://identity/artemiy/initial"}
        ],
        confirmed=True,
        idempotency_key="api-execute-1",
        correlation_id="api-execute",
    )
    assert receipt["state"] == "verified"
    assert receipt["post_condition_verified"] is True
    assert receipt["durable_state_change_authorized"] is False
    assert adapter.preflight_calls == 2
    assert adapter.start_calls == 1
    assert adapter.observe_calls == 1
    store.close()


def test_unqualified_provider_cannot_be_registered_for_api_execution(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    with pytest.raises(IdentityProvisioningApiRuntimeError, match="identity_provider_qualification_binding_invalid"):
        _service(store, adapter, decision=_decision(real_target=False))
    assert adapter.preflight_calls == 0 and adapter.start_calls == 0 and adapter.observe_calls == 0
    store.close()


def test_unknown_provider_fails_before_plan_or_provider_call(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = _service(store, adapter)
    with pytest.raises(IdentityProvisioningApiRuntimeError, match="identity_api_provider_unavailable"):
        service.plan(
            actor=PARENT_ACTOR,
            member_id="member-child",
            provider_id="unqualified-provider",
            account_name="artemiy",
            home_directory_mode="local",
            profile_mode="local",
            correlation_id="api-unqualified",
        )
    assert adapter.preflight_calls == 0 and adapter.start_calls == 0
    store.close()
