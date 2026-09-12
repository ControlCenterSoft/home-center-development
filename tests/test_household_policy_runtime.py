from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_runtime import (
    CONFIRM_REQUEST_SCHEMA,
    DESIRED_KEY_PREFIX,
    PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeError,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore

PARENT_ACTOR = "local-admin:admin"
CHILD_ACTOR = "member-session:child"
PARENT = "member-parent"
CHILD = "member-child"


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
    store = StateStore(tmp_path / "state.db", b"p" * 32, "cluster-test")
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


def _bundle(**overrides):
    value = {
        "internet_policy": "filtered",
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": True,
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
    }
    value.update(overrides)
    return value


def _plan(service: HouseholdPolicyRuntimeService):
    return service.plan(
        actor=PARENT_ACTOR,
        request={
            "schema": PLAN_REQUEST_SCHEMA,
            "subject_member_id": CHILD,
            "bundle": _bundle(internet_policy="guest", home_files_allowed=False),
            "reason": "Вечерний семейный режим",
        },
        correlation_id="policy-plan",
    )


def _confirm(service: HouseholdPolicyRuntimeService, plan):
    return service.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": plan["plan_id"],
            "confirmed": True,
        },
        correlation_id="policy-confirm",
    )


def test_parent_commits_only_non_enforcing_desired_state_and_replay_is_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyRuntimeService(store)
    plan = _plan(service)

    assert plan["observed_desired_generation"] == 0
    assert plan["expected_desired_generation"] == 1
    assert plan["desired_state_write_authorized"] is False
    assert plan["enforcement_authorized"] is False
    assert plan["infrastructure_mutation_authorized"] is False
    assert plan["external_publication_authorized"] is False

    receipt = _confirm(service, plan)
    assert receipt["state"] == "desired-state-committed"
    assert receipt["desired_generation"] == 1
    assert receipt["enforcement_verified"] is False
    assert receipt["reconciliation_required"] is True
    assert receipt["infrastructure_mutation_performed"] is False
    assert receipt["external_publication_performed"] is False

    desired = service.desired_state(actor=PARENT_ACTOR, member_id=CHILD)
    assert desired is not None
    assert desired["generation"] == 1
    assert desired["plan_id"] == plan["plan_id"]
    assert desired["policy"]["internet_policy"] == "guest"
    assert desired["policy"]["home_files_allowed"] is False
    assert desired["policy"]["enforcement_verified"] is False
    assert desired["policy"]["production_mutation_enabled"] is False
    assert desired["enforcement_verified"] is False
    assert desired["reconciliation_required"] is True

    job = store.job(receipt["job_id"])
    assert job is not None and job["state"] == "succeeded"
    assert job["evidence"]["receipt"] == receipt
    replay = _confirm(service, plan)
    assert replay == receipt
    assert len([item for item in store.jobs() if item["job_type"] == "household.policy.desired-state.commit"]) == 1
    store.close()


def test_non_parent_actor_cannot_plan_policy_change(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyRuntimeService(store)
    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_change_not_authorized"):
        service.plan(
            actor=CHILD_ACTOR,
            request={
                "schema": PLAN_REQUEST_SCHEMA,
                "subject_member_id": CHILD,
                "bundle": _bundle(),
                "reason": "attempt",
            },
            correlation_id="policy-denied",
        )
    assert not [item for item in store.jobs() if item["job_type"] == "household.policy.desired-state.commit"]
    store.close()


def test_stale_household_snapshot_blocks_confirmation_before_desired_write(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyRuntimeService(store)
    plan = _plan(service)

    raw = store.get_meta(HOUSEHOLD_STATE_KEY)
    raw["bindings"] = list(reversed(raw["bindings"]))
    store.set_meta(HOUSEHOLD_STATE_KEY, raw)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_plan_stale"):
        _confirm(service, plan)
    assert store.get_meta(DESIRED_KEY_PREFIX + "home." + CHILD) is None
    store.close()


def test_desired_generation_change_blocks_stale_plan(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyRuntimeService(store)
    plan = _plan(service)
    store.set_meta(
        DESIRED_KEY_PREFIX + "home." + CHILD,
        {
            "schema": "home-center.household-policy-desired-state.v1",
            "household_id": "home",
            "member_id": CHILD,
            "generation": 1,
            "plan_id": "hpcp-" + "a" * 24,
            "policy": {"external-change": True},
            "policy_sha256": "b" * 64,
            "reason": "other writer",
            "enforcement_verified": False,
            "reconciliation_required": True,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        },
    )
    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_desired_generation_stale"):
        _confirm(service, plan)
    store.close()


def test_runtime_rejects_policy_escalation_before_plan_is_persisted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = HouseholdPolicyRuntimeService(store)
    with pytest.raises(HouseholdPolicyRuntimeError, match="policy_bundle_capability_escalation_rejected"):
        service.plan(
            actor=PARENT_ACTOR,
            request={
                "schema": PLAN_REQUEST_SCHEMA,
                "subject_member_id": CHILD,
                "bundle": _bundle(administration_allowed=True),
                "reason": "unsafe",
            },
            correlation_id="policy-escalation",
        )
    store.close()
