from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import HouseholdRole
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
from home_center.role_identity_provisioning_runtime import (
    ACTION,
    IdentityProvisioningRuntimeError,
    RoleIdentityProvisioningRuntimeService,
)
from home_center.role_identity_provisioning_verification import (
    AccountReadbackState,
    IdentityProvisioningReadbackObservation,
    ResourceReadbackState,
)
from home_center.store import StateStore

ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-09-13T04:00:00Z"
PROVIDER_DIGEST = "a" * 64
PREFLIGHT_DIGEST = "b" * 64
ACCOUNT_DIGEST = "c" * 64
READBACK_DIGEST = "d" * 64


def _provider(*, secret_refs: bool = True) -> IdentityProviderCapability:
    return IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=secret_refs,
        evidence_sha256=PROVIDER_DIGEST,
    )


def _plan() -> RoleIdentityProvisioningPlan:
    return RoleIdentityProvisioningPlan(
        plan_id="hcidp-" + "e" * 24,
        household_id="household-1",
        member_id="member-1",
        role=HouseholdRole.CHILD,
        household_snapshot_id="snapshot-1",
        household_resource_version="rv-1",
        household_generation=7,
        policy_id="policy-1",
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER_DIGEST,
        account_name="artemiy",
        home_directory_mode=StorageMode.LOCAL,
        profile_mode=StorageMode.LOCAL,
    )


def _preflight(*, valid_until: str = "2026-09-13T04:20:00Z") -> AccountPreflightObservation:
    return AccountPreflightObservation(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER_DIGEST,
        account_name="artemiy",
        state=AccountObservationState.ABSENT,
        observed_at="2026-09-13T03:55:00Z",
        valid_until=valid_until,
        evidence_sha256=PREFLIGHT_DIGEST,
    )


def _readback(
    *,
    account_state: AccountReadbackState = AccountReadbackState.PRESENT,
    home_state: ResourceReadbackState = ResourceReadbackState.READY,
    profile_state: ResourceReadbackState = ResourceReadbackState.READY,
) -> IdentityProvisioningReadbackObservation:
    return IdentityProvisioningReadbackObservation(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER_DIGEST,
        provider_operation_id="provider-op-1",
        account_name="artemiy",
        account_state=account_state,
        account_identity_sha256=ACCOUNT_DIGEST if account_state is AccountReadbackState.PRESENT else None,
        home_directory_state=home_state,
        profile_state=profile_state,
        observed_at="2026-09-13T03:58:00Z",
        valid_until="2026-09-13T04:20:00Z",
        evidence_sha256=READBACK_DIGEST,
    )


def _store(tmp_path: Path, name: str = "state.db") -> StateStore:
    return StateStore(tmp_path / name, audit_key=b"k" * 32, cluster_id="test-cluster")


class _Adapter:
    def __init__(
        self,
        store: StateStore,
        *,
        readback: IdentityProvisioningReadbackObservation | None = None,
        start_error: BaseException | None = None,
        observe_error: BaseException | None = None,
    ) -> None:
        self.store = store
        self.readback = readback or _readback()
        self.start_error = start_error
        self.observe_error = observe_error
        self.start_calls = 0
        self.observe_calls = 0
        self.job_id: str | None = None
        self.last_request = None

    def start(self, request):
        self.start_calls += 1
        self.job_id = request.job_id
        self.last_request = request
        job = self.store.job(request.job_id)
        assert job is not None and job["state"] == "running"
        if self.start_error is not None:
            raise self.start_error
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
        if self.observe_error is not None:
            raise self.observe_error
        return self.readback.to_dict()


def _execute(service: RoleIdentityProvisioningRuntimeService, *, key: str = "identity-run-1", refs=None):
    return service.execute(
        actor="parent-actor",
        plan=_plan(),
        provider=_provider(),
        preflight_observation=_preflight(),
        credential_references=(
            [{"name": "initial-password", "reference": "secret://identity/artemiy/initial"}]
            if refs is None
            else refs
        ),
        confirmed=True,
        idempotency_key=key,
        correlation_id="corr-identity-1",
    )


def test_job_is_durable_before_provider_mutation_and_success_requires_readback(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)

    receipt = _execute(service)

    assert adapter.start_calls == 1
    assert adapter.observe_calls == 1
    assert receipt["state"] == "verified"
    assert receipt["account_created_verified"] is True
    assert receipt["home_directory_verified"] is True
    assert receipt["profile_verified"] is True
    assert receipt["post_condition_verified"] is True
    assert receipt["durable_state_change_authorized"] is False
    assert receipt["emergency_admin_mutation_authorized"] is False
    assert receipt["privilege_grant_authorized"] is False
    assert receipt["external_publication_authorized"] is False

    jobs = [job for job in store.jobs() if job["job_type"] == ACTION]
    assert len(jobs) == 1
    assert jobs[0]["state"] == "succeeded"
    assert jobs[0]["evidence"]["receipt"] == receipt
    assert store.verify_audit_chain()
    events = [event for event in store.audit_events() if event["action"] == ACTION]
    assert len(events) == 1 and events[0]["outcome"] == "verified"
    store.close()


def test_replay_after_runtime_restart_returns_durable_receipt_without_provider_reinvocation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    first = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    first.register_adapter("local-account", adapter)
    expected = _execute(first)
    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)

    replay_adapter = _Adapter(store)
    restarted = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    restarted.register_adapter("local-account", replay_adapter)
    actual = _execute(restarted)

    assert actual == expected
    assert (replay_adapter.start_calls, replay_adapter.observe_calls) == (0, 0)
    store.close()


def test_idempotency_conflict_fails_closed_without_second_provider_call(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)
    _execute(service)

    with pytest.raises(IdentityProvisioningRuntimeError, match="identity_runtime_idempotency_conflict"):
        _execute(
            service,
            refs=[{"name": "initial-password", "reference": "secret://identity/artemiy/rotated"}],
        )
    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)
    store.close()


def test_stale_preflight_is_rejected_before_job_or_provider_invocation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)

    with pytest.raises(IdentityProvisioningRuntimeError, match="identity_runtime_preflight_not_ready"):
        service.execute(
            actor="parent-actor",
            plan=_plan(),
            provider=_provider(),
            preflight_observation=_preflight(valid_until="2026-09-13T03:59:59Z"),
            credential_references=[],
            confirmed=True,
            idempotency_key="identity-stale-1",
            correlation_id="corr-stale",
        )
    assert not [job for job in store.jobs() if job["job_type"] == ACTION]
    assert (adapter.start_calls, adapter.observe_calls) == (0, 0)
    store.close()


def test_provider_timeout_is_ambiguous_failed_job_and_never_auto_retries(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store, start_error=TimeoutError("transport timeout"))
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)

    with pytest.raises(IdentityProvisioningRuntimeError, match="identity_runtime_provider_timeout"):
        _execute(service, key="identity-timeout-1")
    jobs = [job for job in store.jobs() if job["job_type"] == ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "failed"
    assert jobs[0]["result"]["provider_acceptance_unknown"] is True
    assert jobs[0]["result"]["retry_safe"] is False
    assert (adapter.start_calls, adapter.observe_calls) == (1, 0)

    with pytest.raises(IdentityProvisioningRuntimeError, match="identity_runtime_previous_attempt_failed"):
        _execute(service, key="identity-timeout-1")
    assert (adapter.start_calls, adapter.observe_calls) == (1, 0)
    store.close()


def test_failed_postcondition_never_reinvokes_provider_and_never_claims_success(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store, readback=_readback(account_state=AccountReadbackState.ABSENT))
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)

    with pytest.raises(IdentityProvisioningRuntimeError, match="identity_runtime_post_condition_not_verified"):
        _execute(service, key="identity-readback-fail-1")
    jobs = [job for job in store.jobs() if job["job_type"] == ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "failed"
    assert "account_absent_after_provider_acceptance" in jobs[0]["result"]["blockers"]
    assert jobs[0]["evidence"]["provider_reinvocation_authorized"] is False
    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)

    with pytest.raises(IdentityProvisioningRuntimeError, match="identity_runtime_previous_attempt_failed"):
        _execute(service, key="identity-readback-fail-1")
    assert (adapter.start_calls, adapter.observe_calls) == (1, 1)
    store.close()


def test_unsupported_secret_reference_provider_fails_before_provider_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)

    with pytest.raises(IdentityProvisioningRuntimeError, match="identity_provider_secret_reference_unsupported"):
        service.execute(
            actor="parent-actor",
            plan=_plan(),
            provider=_provider(secret_refs=False),
            preflight_observation=_preflight(),
            credential_references=[{"name": "initial-password", "reference": "secret://identity/artemiy/initial"}],
            confirmed=True,
            idempotency_key="identity-no-secret-provider-1",
            correlation_id="corr-no-secret-provider",
        )
    jobs = [job for job in store.jobs() if job["job_type"] == ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "failed"
    assert jobs[0]["result"]["provider_invoked"] is False
    assert jobs[0]["result"]["retry_safe"] is True
    assert (adapter.start_calls, adapter.observe_calls) == (0, 0)
    store.close()


def test_secret_references_and_values_are_not_persisted_in_job_or_audit(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)
    _execute(service)

    persisted = json.dumps(
        {"jobs": store.jobs(), "audit": store.audit_events()},
        sort_keys=True,
        ensure_ascii=True,
    )
    assert "secret://identity/artemiy/initial" not in persisted
    assert "initial-password" not in persisted
    assert "PlaintextPassword" not in persisted
    assert adapter.last_request is not None
    assert adapter.last_request.credential_value_access_authorized is False
    store.close()


def test_backup_restore_preserves_verified_job_and_receipt(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)
    receipt = _execute(service, key="identity-backup-1")
    backup = tmp_path / "backup.db"
    store.backup_to(backup)
    store.close()

    restored = StateStore(backup, audit_key=b"k" * 32, cluster_id="test-cluster")
    jobs = [job for job in restored.jobs() if job["job_type"] == ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "succeeded"
    assert jobs[0]["evidence"]["receipt"] == receipt
    assert restored.verify_audit_chain()
    restored.close()


def test_verified_receipt_matches_closed_public_contract(tmp_path: Path) -> None:
    store = _store(tmp_path)
    adapter = _Adapter(store)
    service = RoleIdentityProvisioningRuntimeService(store, now=lambda: NOW)
    service.register_adapter("local-account", adapter)
    receipt = _execute(service, key="identity-schema-1")
    schema = json.loads(
        (ROOT / "contracts/household/role-identity-provisioning-execution-receipt.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(receipt)
    store.close()
