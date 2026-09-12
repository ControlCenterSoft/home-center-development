from __future__ import annotations

from home_center.household_policy_desired_state import (
    POLICY_APPLY_REQUEST_SCHEMA,
    HouseholdPolicyDesiredStateService,
)
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"


def _services(tmp_path):
    store = StateStore(tmp_path / "state.db", b"d" * 32, "policy-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="bootstrap-policy-ds",
    )
    return (
        store,
        household,
        HouseholdPolicyRuntimeService(store),
        HouseholdPolicyDesiredStateService(store),
    )


def _confirmed(policy: HouseholdPolicyRuntimeService, member_id: str, suffix: str):
    proposal = policy.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id=f"plan-{suffix}",
    )
    confirmation = policy.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id=f"confirm-{suffix}",
    )
    return proposal, confirmation


def _apply(service: HouseholdPolicyDesiredStateService, proposal, confirmation, suffix: str):
    return service.apply(
        actor=ACTOR,
        request={
            "schema": POLICY_APPLY_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmation_id": confirmation["confirmation_id"],
        },
        correlation_id=f"apply-{suffix}",
    )


def test_confirmed_policy_materializes_exact_local_desired_state(tmp_path) -> None:
    store, household, policy, desired = _services(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    proposal, confirmation = _confirmed(policy, member_id, "initial")

    receipt = _apply(desired, proposal, confirmation, "initial")
    assert receipt["outcome"] == "applied"
    assert receipt["changed"] is True
    assert receipt["generation"] == 1
    assert receipt["bundle_id"] == proposal["bundle"]["bundle_id"]
    assert receipt["desired_state_materialized"] is True
    assert receipt["provider_execution_authorized"] is False
    assert receipt["infrastructure_mutation_authorized"] is False
    assert receipt["external_publication_authorized"] is False

    records = store.desired_state()
    assert len(records) == 1
    assert records[0]["resource_key"] == proposal["bundle"]["desired_state_resource_key"]
    assert records[0]["generation"] == 1
    assert records[0]["value"] == proposal["bundle"]

    events = store.audit_events(limit=30)
    actions = [event["action"] for event in events]
    assert "household.policy.desired-state.apply.begin" in actions
    assert "household.policy.desired-state.apply.complete" in actions
    store.close()


def test_desired_state_apply_is_idempotent_across_service_restart(tmp_path) -> None:
    store, household, policy, desired = _services(tmp_path)
    proposal, confirmation = _confirmed(policy, household.actor_member_id(ACTOR), "replay")
    first = _apply(desired, proposal, confirmation, "first")

    restarted = HouseholdPolicyDesiredStateService(store)
    second = _apply(restarted, proposal, confirmation, "second")
    assert second["generation"] == first["generation"] == 1
    assert second["bundle_id"] == first["bundle_id"]
    assert second["outcome"] == "already-applied"
    assert store.desired_state()[0]["generation"] == 1

    completions = [
        event
        for event in store.audit_events(limit=30)
        if event["action"] == "household.policy.desired-state.apply.complete"
    ]
    assert len(completions) == 1
    store.close()


def test_identical_policy_replan_is_honest_noop_without_generation_churn(tmp_path) -> None:
    store, household, policy, desired = _services(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    first_proposal, first_confirmation = _confirmed(policy, member_id, "first-policy")
    _apply(desired, first_proposal, first_confirmation, "first-policy")

    second_proposal, second_confirmation = _confirmed(policy, member_id, "same-policy")
    assert second_proposal["expected_desired_state_generation"] == 1
    assert second_proposal["expected_desired_state_bundle_id"] == first_proposal["bundle"]["bundle_id"]
    assert second_proposal["bundle"]["bundle_id"] == first_proposal["bundle"]["bundle_id"]

    receipt = _apply(desired, second_proposal, second_confirmation, "same-policy")
    assert receipt["outcome"] == "already-current"
    assert receipt["changed"] is False
    assert receipt["generation"] == 1
    assert store.desired_state()[0]["generation"] == 1
    store.close()


def test_unconfirmed_policy_cannot_be_materialized(tmp_path) -> None:
    store, household, policy, desired = _services(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    proposal = policy.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="plan-unconfirmed",
    )

    import pytest

    with pytest.raises(Exception, match="household_policy_confirmation_required"):
        desired.apply(
            actor=ACTOR,
            request={
                "schema": POLICY_APPLY_REQUEST_SCHEMA,
                "proposal_id": proposal["proposal_id"],
                "confirmation_id": "hpconfirm-0123456789abcdef01234567",
            },
            correlation_id="apply-unconfirmed",
        )
    assert store.desired_state() == []
    store.close()
