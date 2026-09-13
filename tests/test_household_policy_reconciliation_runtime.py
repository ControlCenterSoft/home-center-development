from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_reconciliation_runtime import (
    ACTION,
    HouseholdPolicyReconciliationRuntimeError,
    HouseholdPolicyReconciliationRuntimeService,
)
from home_center.household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_KEY_PREFIX,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

PARENT_ACTOR = "local-admin:admin"
PARENT = "member-parent"
CHILD = "member-child"
NOW = "2026-09-12T13:30:00Z"
BACKEND = "policy-backend.readonly"


def _store(tmp_path: Path) -> StateStore:
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
    store = StateStore(tmp_path / "state.db", b"r" * 32, "cluster-test")
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(
            snapshot,
            (ActorBinding(actor=PARENT_ACTOR, member_id=PARENT),),
        ),
    )
    return store


def _desired(store: StateStore) -> dict[str, object]:
    policy = HouseholdPolicyRuntimeService(store)
    plan = policy.plan(
        actor=PARENT_ACTOR,
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "subject_member_id": CHILD,
            "bundle": {
                "internet_policy": "guest",
                "vpn_allowed": False,
                "managed_device_required": True,
                "home_files_allowed": False,
                "smart_home_control_allowed": False,
                "administration_allowed": False,
                "external_publication_allowed": False,
            },
            "reason": "Вечерний семейный режим",
        },
        correlation_id="policy-plan",
    )
    policy.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm",
    )
    desired = store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(desired, dict)
    return desired


class ExactReadOnlyAdapter:
    reconciliation_read_only = True

    def __init__(self) -> None:
        self.calls = 0

    def read_back(self, request: dict[str, object]) -> object:
        self.calls += 1
        binding = request["binding"]
        assert isinstance(binding, dict)
        return {
            "schema": "home-center.household-policy-actual-state-observation.v1",
            "request_id": request["request_id"],
            "backend_id": request["backend_id"],
            "observed_at": NOW,
            "observed_state": "enforced",
            "binding": dict(binding),
            "actual_policy_sha256": binding["policy_sha256"],
            "read_only": True,
        }


class NotEnforcedAdapter(ExactReadOnlyAdapter):
    def read_back(self, request: dict[str, object]) -> object:
        self.calls += 1
        binding = request["binding"]
        assert isinstance(binding, dict)
        return {
            "schema": "home-center.household-policy-actual-state-observation.v1",
            "request_id": request["request_id"],
            "backend_id": request["backend_id"],
            "observed_at": NOW,
            "observed_state": "not-enforced",
            "binding": dict(binding),
            "actual_policy_sha256": None,
            "read_only": True,
        }


class DriftDuringReadAdapter(ExactReadOnlyAdapter):
    def __init__(self, store: StateStore) -> None:
        super().__init__()
        self.store = store

    def read_back(self, request: dict[str, object]) -> object:
        observation = super().read_back(request)
        key = DESIRED_KEY_PREFIX + "home." + CHILD
        desired = self.store.get_meta(key)
        assert isinstance(desired, dict)
        changed = dict(desired)
        changed["generation"] = int(changed["generation"]) + 1
        self.store.set_meta(key, changed)
        return observation


def _runtime(store: StateStore) -> HouseholdPolicyReconciliationRuntimeService:
    return HouseholdPolicyReconciliationRuntimeService(store, now=lambda: NOW)


def test_verified_readback_persists_evidence_but_does_not_flip_desired_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = _desired(store)
    adapter = ExactReadOnlyAdapter()
    service = _runtime(store)
    service.register_adapter(BACKEND, adapter)

    completion = service.reconcile(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        max_observed_age_seconds=300,
        correlation_id="policy-reconcile",
    )

    assert completion["state"] == "verified"
    assert completion["evidence"]["enforcement_verified"] is True
    assert completion["evidence"]["reconciliation_required"] is False
    assert completion["desired_state_transition_performed"] is False
    assert adapter.calls == 1

    current = store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD)
    assert current == original
    assert current["enforcement_verified"] is False
    assert current["reconciliation_required"] is True

    jobs = [item for item in store.jobs() if item["job_type"] == ACTION]
    assert len(jobs) == 1
    assert jobs[0]["state"] == "succeeded"
    evidence = jobs[0]["evidence"]
    assert evidence["reconciliation_evidence"] == completion["evidence"]
    assert evidence["desired_state_transition_performed"] is False

    replay = service.reconcile(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        max_observed_age_seconds=300,
        correlation_id="policy-reconcile-replay",
    )
    assert replay == completion
    assert adapter.calls == 1
    assert len([item for item in store.jobs() if item["job_type"] == ACTION]) == 1
    store.close()


def test_not_enforced_is_durable_pending_evidence_without_local_state_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = _desired(store)
    adapter = NotEnforcedAdapter()
    service = _runtime(store)
    service.register_adapter(BACKEND, adapter)

    completion = service.reconcile(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        max_observed_age_seconds=300,
        correlation_id="policy-pending",
    )

    assert completion["state"] == "pending"
    assert completion["evidence"]["blocker"] == "policy-not-enforced"
    assert completion["evidence"]["enforcement_verified"] is False
    assert completion["evidence"]["reconciliation_required"] is True
    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) == original
    assert adapter.calls == 1
    store.close()


def test_desired_state_drift_after_readback_fails_before_evidence_acceptance(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    adapter = DriftDuringReadAdapter(store)
    service = _runtime(store)
    service.register_adapter(BACKEND, adapter)

    with pytest.raises(
        HouseholdPolicyReconciliationRuntimeError,
        match="household_policy_reconciliation_desired_state_stale",
    ):
        service.reconcile(
            actor=PARENT_ACTOR,
            member_id=CHILD,
            backend_id=BACKEND,
            max_observed_age_seconds=300,
            correlation_id="policy-stale",
        )

    jobs = [item for item in store.jobs() if item["job_type"] == ACTION]
    assert len(jobs) == 1
    assert jobs[0]["state"] == "failed"
    assert jobs[0]["evidence"]["code"] == "household_policy_reconciliation_desired_state_stale"
    store.close()


def test_adapter_must_explicitly_declare_read_only_boundary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _desired(store)
    service = _runtime(store)

    class UnsafeAdapter:
        reconciliation_read_only = False

        def read_back(self, request: dict[str, object]) -> object:
            return request

    with pytest.raises(
        HouseholdPolicyReconciliationRuntimeError,
        match="invalid_household_policy_reconciliation_adapter_registration",
    ):
        service.register_adapter(BACKEND, UnsafeAdapter())
    store.close()
