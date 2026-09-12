from __future__ import annotations

import pytest

from home_center.household_policy_desired_state import HouseholdPolicyDesiredStateService
from home_center.household_policy_guarded_workflow import GuardedHouseholdPolicyWorkflowService
from home_center.household_policy_history import HouseholdPolicyHistoryService
from home_center.household_policy_runtime import (
    POLICY_PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeError,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"


def _workflow(tmp_path):
    store = StateStore(tmp_path / "state.db", b"g" * 32, "guarded-policy-workflow-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="bootstrap-guarded-policy-workflow",
    )
    policy = HouseholdPolicyRuntimeService(store)
    desired_state = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired_state)
    workflow = GuardedHouseholdPolicyWorkflowService(
        store,
        policy_runtime=policy,
        history=history,
    )
    return store, household, workflow


def test_guarded_workflow_presents_current_exact_policy(tmp_path) -> None:
    store, household, workflow = _workflow(tmp_path)
    member_id = household.actor_member_id(ACTOR)

    result = workflow.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="guarded-plan-current",
    )

    assert result["presentation"]["proposal_id"] == result["proposal"]["proposal_id"]
    assert result["presentation"]["bundle_id"] == result["proposal"]["bundle"]["bundle_id"]
    assert result["presentation"]["cozy"]["status"] == "ready-for-confirmation"
    assert result["confirmation_required"] is True
    assert result["desired_state_materialized"] is False
    assert result["provider_execution_authorized"] is False
    assert result["infrastructure_mutation_authorized"] is False
    assert result["external_publication_authorized"] is False
    assert store.desired_state() == []
    store.close()


def test_guarded_workflow_rejects_desired_state_revision_change_before_presentation(
    tmp_path,
    monkeypatch,
) -> None:
    store, household, workflow = _workflow(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    original_plan = workflow.policy_runtime.plan
    captured: dict[str, object] = {}

    def capture_plan(*, actor, request, correlation_id):
        raw = original_plan(actor=actor, request=request, correlation_id=correlation_id)
        captured["proposal"] = raw
        return raw

    def changed_revision(resource_key):
        raw = captured.get("proposal")
        assert isinstance(raw, dict)
        bundle = dict(raw["bundle"])
        bundle["bundle_id"] = "hpb-" + "f" * 24
        return {
            "resource_key": resource_key,
            "generation": 1,
            "value": bundle,
            "updated_at": "2026-09-12T00:00:00Z",
        }

    monkeypatch.setattr(workflow.policy_runtime, "plan", capture_plan)
    monkeypatch.setattr(workflow.history.repository, "read", changed_revision)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_composition_stale"):
        workflow.plan(
            actor=ACTOR,
            request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
            correlation_id="guarded-plan-stale-desired-state",
        )

    assert store.desired_state() == []
    store.close()


def test_guarded_workflow_rejects_household_change_before_presentation(tmp_path, monkeypatch) -> None:
    store, household, workflow = _workflow(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    original_plan = workflow.policy_runtime.plan

    def mutate_household_after_plan(*, actor, request, correlation_id):
        raw = original_plan(actor=actor, request=request, correlation_id=correlation_id)
        household.rename(
            actor=ACTOR,
            request={"display_name": "Обновлённый дом"},
            correlation_id="mutate-household-after-policy-plan",
        )
        return raw

    monkeypatch.setattr(workflow.policy_runtime, "plan", mutate_household_after_plan)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_proposal_evidence_mismatch|household_policy_composition_stale"):
        workflow.plan(
            actor=ACTOR,
            request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
            correlation_id="guarded-plan-stale-household",
        )

    assert store.desired_state() == []
    store.close()
