from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_reconciliation_runtime import (
    HouseholdPolicyReconciliationRuntimeService,
)
from home_center.household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_KEY_PREFIX,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_policy_verification_transition import (
    ACTION,
    REQUEST_SCHEMA,
    HouseholdPolicyVerificationTransitionError,
    HouseholdPolicyVerificationTransitionService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

PARENT_ACTOR = "local-admin:admin"
CHILD_ACTOR = "member-session:child"
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
    store = StateStore(tmp_path / "state.db", b"v" * 32, "cluster-test")
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
    return store


def _commit_desired(store: StateStore, *, internet_policy: str = "guest") -> dict[str, object]:
    service = HouseholdPolicyRuntimeService(store)
    plan = service.plan(
        actor=PARENT_ACTOR,
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "subject_member_id": CHILD,
            "bundle": {
                "internet_policy": internet_policy,
                "vpn_allowed": False,
                "managed_device_required": True,
                "home_files_allowed": False,
                "smart_home_control_allowed": False,
                "administration_allowed": False,
                "external_publication_allowed": False,
            },
            "reason": "Семейная политика",
        },
        correlation_id="policy-plan",
    )
    service.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm",
    )
    desired = service.desired_state(actor=PARENT_ACTOR, member_id=CHILD)
    assert desired is not None
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


def _reconcile(store: StateStore, adapter: object) -> dict[str, object]:
    service = HouseholdPolicyReconciliationRuntimeService(store, now=lambda: NOW)
    service.register_adapter(BACKEND, adapter)
    return service.reconcile(
        actor=PARENT_ACTOR,
        member_id=CHILD,
        backend_id=BACKEND,
        max_observed_age_seconds=300,
        correlation_id="policy-reconcile",
    )


def _request(completion: dict[str, object]) -> dict[str, object]:
    evidence = completion["evidence"]
    assert isinstance(evidence, dict)
    return {
        "schema": REQUEST_SCHEMA,
        "request_id": completion["request_id"],
        "evidence_id": evidence["evidence_id"],
    }


def test_exact_verified_evidence_promotes_only_desired_verification_flags(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = _commit_desired(store)
    adapter = ExactReadOnlyAdapter()
    completion = _reconcile(store, adapter)
    service = HouseholdPolicyVerificationTransitionService(store)

    receipt = service.transition(
        actor=PARENT_ACTOR,
        request=_request(completion),
        correlation_id="verification-transition",
    )

    assert receipt["enforcement_verified"] is True
    assert receipt["reconciliation_required"] is False
    assert receipt["backend_reinvoked"] is False
    assert receipt["backend_mutation_performed"] is False
    assert receipt["infrastructure_mutation_performed"] is False
    assert receipt["external_publication_performed"] is False
    assert adapter.calls == 1

    current = HouseholdPolicyRuntimeService(store).desired_state(
        actor=PARENT_ACTOR, member_id=CHILD
    )
    assert current is not None
    assert current["enforcement_verified"] is True
    assert current["reconciliation_required"] is False
    for key in original:
        if key not in {"enforcement_verified", "reconciliation_required"}:
            assert current[key] == original[key]

    replay = service.transition(
        actor=PARENT_ACTOR,
        request=_request(completion),
        correlation_id="verification-transition-replay",
    )
    assert replay == receipt
    assert adapter.calls == 1
    jobs = [item for item in store.jobs() if item["job_type"] == ACTION]
    assert len(jobs) == 1
    store.close()


def test_new_policy_generation_after_verification_resets_verification_flags(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    completion = _reconcile(store, ExactReadOnlyAdapter())
    HouseholdPolicyVerificationTransitionService(store).transition(
        actor=PARENT_ACTOR,
        request=_request(completion),
        correlation_id="verification-transition",
    )

    service = HouseholdPolicyRuntimeService(store)
    plan = service.plan(
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
            "reason": "Новая версия политики",
        },
        correlation_id="policy-plan-after-verified",
    )
    assert plan["observed_desired_generation"] == 1
    assert plan["expected_desired_generation"] == 2
    service.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm-after-verified",
    )
    current = service.desired_state(actor=PARENT_ACTOR, member_id=CHILD)
    assert current is not None
    assert current["generation"] == 2
    assert current["enforcement_verified"] is False
    assert current["reconciliation_required"] is True
    store.close()


def test_pending_reconciliation_cannot_promote_desired_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    original = _commit_desired(store)
    completion = _reconcile(store, NotEnforcedAdapter())

    with pytest.raises(
        HouseholdPolicyVerificationTransitionError,
        match="household_policy_verified_reconciliation_invalid",
    ):
        HouseholdPolicyVerificationTransitionService(store).transition(
            actor=PARENT_ACTOR,
            request=_request(completion),
            correlation_id="verification-transition-pending",
        )

    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) == original
    assert not [item for item in store.jobs() if item["job_type"] == ACTION]
    store.close()


def test_desired_state_drift_after_verified_evidence_is_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    completion = _reconcile(store, ExactReadOnlyAdapter())

    changed = store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD)
    assert isinstance(changed, dict)
    changed = dict(changed)
    changed["generation"] = int(changed["generation"]) + 1
    store.set_meta(DESIRED_KEY_PREFIX + "home." + CHILD, changed)

    with pytest.raises(
        HouseholdPolicyVerificationTransitionError,
        match="household_policy_verification_desired_state_stale",
    ):
        HouseholdPolicyVerificationTransitionService(store).transition(
            actor=PARENT_ACTOR,
            request=_request(completion),
            correlation_id="verification-transition-stale",
        )

    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) == changed
    jobs = [item for item in store.jobs() if item["job_type"] == ACTION]
    assert len(jobs) == 1 and jobs[0]["state"] == "failed"
    store.close()


def test_non_parent_cannot_promote_verified_evidence(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _commit_desired(store)
    completion = _reconcile(store, ExactReadOnlyAdapter())

    with pytest.raises(
        HouseholdPolicyVerificationTransitionError,
        match="household_policy_verification_transition_not_authorized",
    ):
        HouseholdPolicyVerificationTransitionService(store).transition(
            actor=CHILD_ACTOR,
            request=_request(completion),
            correlation_id="verification-transition-denied",
        )

    assert not [item for item in store.jobs() if item["job_type"] == ACTION]
    store.close()
