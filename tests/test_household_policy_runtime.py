from __future__ import annotations

import pytest

from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    POLICY_PROPOSAL_KEY_PREFIX,
    POLICY_RECOVERY_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeError,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import (
    HOUSEHOLD_BOOTSTRAP_SCHEMA,
    HOUSEHOLD_MEMBER_CONFIRM_SCHEMA,
    HOUSEHOLD_MEMBER_PLAN_SCHEMA,
    HouseholdRuntimeService,
)
from home_center.store import StateStore


ACTOR = "parent@example.test"


def _runtime(tmp_path):
    store = StateStore(tmp_path / "state.db", b"p" * 32, "test-cluster")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={
            "schema": HOUSEHOLD_BOOTSTRAP_SCHEMA,
            "display_name": "Родитель",
        },
        correlation_id="bootstrap-01",
    )
    return store, household, HouseholdPolicyRuntimeService(store)


def _plan(runtime: HouseholdPolicyRuntimeService, member_id: str, correlation_id: str = "policy-plan-01"):
    return runtime.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": member_id,
        },
        correlation_id=correlation_id,
    )


def _confirm(runtime: HouseholdPolicyRuntimeService, proposal_id: str, correlation_id: str = "policy-confirm-01"):
    return runtime.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id=correlation_id,
    )


def test_policy_runtime_persists_plan_and_confirmation_without_mutation_authority(tmp_path) -> None:
    store, household, runtime = _runtime(tmp_path)
    member_id = household.actor_member_id(ACTOR)

    proposal = _plan(runtime, member_id)
    assert proposal["expected_desired_state_generation"] == 0
    assert proposal["expected_desired_state_bundle_id"] is None
    assert proposal["confirmation_required"] is True
    assert proposal["desired_state_write_authorized"] is False
    assert proposal["infrastructure_mutation_authorized"] is False

    confirmation = _confirm(runtime, proposal["proposal_id"])
    assert confirmation["confirmation_id"].startswith("hpconfirm-")
    assert confirmation["proposal_id"] == proposal["proposal_id"]
    assert confirmation["bundle_id"] == proposal["bundle"]["bundle_id"]
    assert confirmation["outcome"] == "confirmed-for-desired-state-write"
    assert confirmation["desired_state_write_ready"] is True
    assert confirmation["desired_state_write_authorized"] is False
    assert confirmation["infrastructure_mutation_authorized"] is False
    assert confirmation["external_publication_authorized"] is False

    # Confirmation evidence is durable, but this 0.59 layer still does not write Desired State.
    assert store.desired_state() == []
    events = store.audit_events(limit=20)
    assert any(item["action"] == "household.policy.plan" for item in events)
    assert any(item["action"] == "household.policy.confirm" for item in events)
    store.close()


def test_policy_confirmation_is_idempotent_across_runtime_restart(tmp_path) -> None:
    store, household, runtime = _runtime(tmp_path)
    proposal = _plan(runtime, household.actor_member_id(ACTOR))
    first = _confirm(runtime, proposal["proposal_id"])

    restarted = HouseholdPolicyRuntimeService(store)
    second = _confirm(restarted, proposal["proposal_id"], correlation_id="policy-confirm-replay")

    assert second["confirmation_id"] == first["confirmation_id"]
    assert second["audit_event_id"] == first["audit_event_id"]
    assert second["outcome"] == "already-confirmed"
    confirm_events = [item for item in store.audit_events(limit=20) if item["action"] == "household.policy.confirm"]
    assert len(confirm_events) == 1
    store.close()


def test_policy_confirmation_fails_closed_when_household_changes_after_plan(tmp_path) -> None:
    store, household, runtime = _runtime(tmp_path)
    proposal = _plan(runtime, household.actor_member_id(ACTOR))

    member_plan = household.plan_member_add(
        actor=ACTOR,
        request={
            "schema": HOUSEHOLD_MEMBER_PLAN_SCHEMA,
            "display_name": "Ребёнок",
            "role": "child",
        },
        correlation_id="member-plan-01",
    )
    household.confirm_member_add(
        actor=ACTOR,
        request={
            "schema": HOUSEHOLD_MEMBER_CONFIRM_SCHEMA,
            "proposal_id": member_plan["proposal_id"],
            "confirmed": True,
        },
        correlation_id="member-confirm-01",
    )

    with pytest.raises(
        HouseholdPolicyRuntimeError,
        match="household_policy_proposal_evidence_mismatch|household_policy_composition_stale",
    ):
        _confirm(runtime, proposal["proposal_id"])
    assert store.desired_state() == []
    store.close()


def test_interrupted_confirmation_requires_explicit_fail_closed_recovery(tmp_path) -> None:
    store, household, runtime = _runtime(tmp_path)
    proposal = _plan(runtime, household.actor_member_id(ACTOR))
    key = POLICY_PROPOSAL_KEY_PREFIX + proposal["proposal_id"]
    envelope = store.get_meta(key)
    assert envelope["status"] == "pending"

    # Simulate a crash after the durable "confirming" marker but before a receipt was committed.
    store.set_meta(
        key,
        {
            "schema": envelope["schema"],
            "status": "confirming",
            "proposal": envelope["proposal"],
            "confirmation": None,
            "recovery_required": True,
        },
    )
    restarted = HouseholdPolicyRuntimeService(store)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_confirmation_recovery_required"):
        _confirm(restarted, proposal["proposal_id"])

    recovery = restarted.recover(
        actor=ACTOR,
        request={
            "schema": POLICY_RECOVERY_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
        },
        correlation_id="policy-recover-01",
    )
    assert recovery["status"] == "pending"
    assert recovery["recovered"] is True
    assert recovery["confirmation"] is None
    assert recovery["desired_state_write_authorized"] is False

    confirmation = _confirm(restarted, proposal["proposal_id"], correlation_id="policy-confirm-after-recovery")
    assert confirmation["outcome"] == "confirmed-for-desired-state-write"
    assert store.desired_state() == []
    store.close()


def test_policy_runtime_rejects_unbound_actor_and_negative_confirmation(tmp_path) -> None:
    store, household, runtime = _runtime(tmp_path)
    member_id = household.actor_member_id(ACTOR)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_actor_not_bound"):
        runtime.plan(
            actor="intruder@example.test",
            request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
            correlation_id="policy-plan-denied",
        )

    proposal = _plan(runtime, member_id)
    with pytest.raises(HouseholdPolicyRuntimeError, match="invalid_household_policy_confirm_request"):
        runtime.confirm(
            actor=ACTOR,
            request={
                "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
                "proposal_id": proposal["proposal_id"],
                "confirmed": False,
            },
            correlation_id="policy-confirm-denied",
        )
    assert store.desired_state() == []
    store.close()
