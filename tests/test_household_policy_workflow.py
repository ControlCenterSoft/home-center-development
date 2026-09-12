from __future__ import annotations

from pathlib import Path

from home_center.household_policy_desired_state import HouseholdPolicyDesiredStateService
from home_center.household_policy_history import HouseholdPolicyHistoryService
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_policy_workflow import HouseholdPolicyWorkflowService
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"
ROOT = Path(__file__).resolve().parents[1]
HTTP = ROOT / "product" / "control-plane" / "src" / "home_center" / "household_policy_http.py"
RUNTIME = ROOT / "product" / "control-plane" / "src" / "home_center" / "runtime.py"
SERVER = ROOT / "product" / "control-plane" / "src" / "home_center" / "server.py"


def _workflow(tmp_path):
    store = StateStore(tmp_path / "state.db", b"w" * 32, "policy-workflow-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="bootstrap-policy-workflow",
    )
    policy = HouseholdPolicyRuntimeService(store)
    desired_state = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired_state)
    workflow = HouseholdPolicyWorkflowService(
        store,
        policy_runtime=policy,
        history=history,
    )
    return store, household, workflow


def test_workflow_presents_same_exact_policy_and_materializes_only_after_confirmation(tmp_path) -> None:
    store, household, workflow = _workflow(tmp_path)
    member_id = household.actor_member_id(ACTOR)

    plan = workflow.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="workflow-plan",
    )
    proposal = plan["proposal"]
    presentation = plan["presentation"]
    assert presentation["proposal_id"] == proposal["proposal_id"]
    assert presentation["bundle_id"] == proposal["bundle"]["bundle_id"]
    assert presentation["cozy"]["confirmation_label"] == "Применить правила"
    assert presentation["full"]["technical_policy"] == proposal["bundle"]["technical_policy"]
    assert presentation["same_policy_evidence"] is True
    assert plan["desired_state_materialized"] is False
    assert store.desired_state() == []

    result = workflow.confirm_and_apply(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id="workflow-confirm",
    )
    assert result["desired_state_materialized"] is True
    assert result["receipt"]["bundle_id"] == proposal["bundle"]["bundle_id"]
    assert len(result["history_evidence_sha256"]) == 64
    assert isinstance(result["history_audit_event_id"], str) and result["history_audit_event_id"]
    assert result["provider_execution_authorized"] is False
    assert result["infrastructure_mutation_authorized"] is False
    assert result["external_publication_authorized"] is False
    assert store.desired_state()[0]["value"] == proposal["bundle"]
    store.close()


def test_workflow_confirmation_replay_does_not_advance_generation(tmp_path) -> None:
    store, household, workflow = _workflow(tmp_path)
    plan = workflow.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": household.actor_member_id(ACTOR)},
        correlation_id="workflow-plan-replay",
    )
    request = {
        "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
        "proposal_id": plan["proposal"]["proposal_id"],
        "confirmed": True,
    }
    first = workflow.confirm_and_apply(actor=ACTOR, request=request, correlation_id="workflow-confirm-first")
    second = workflow.confirm_and_apply(actor=ACTOR, request=request, correlation_id="workflow-confirm-second")

    assert first["receipt"]["generation"] == 1
    assert second["receipt"]["generation"] == 1
    assert second["receipt"]["outcome"] == "already-applied"
    assert second["history_evidence_sha256"] == first["history_evidence_sha256"]
    assert second["history_audit_event_id"] == first["history_audit_event_id"]
    assert store.desired_state()[0]["generation"] == 1
    store.close()


def test_production_http_boundary_keeps_auth_origin_external_and_no_provider_execution() -> None:
    http = HTTP.read_text(encoding="utf-8")
    runtime = RUNTIME.read_text(encoding="utf-8")
    server = SERVER.read_text(encoding="utf-8")

    for path in (
        "/api/v1/household/policies/plan",
        "/api/v1/household/policies/confirm",
        "/api/v1/household/policies/recover",
        "/api/v1/household/policies/rollback",
    ):
        assert f'"{path}"' in http
    assert "context.external or self._blocked_for_external(path, context)" in http
    assert 'action="household.policy.external-access"' in http
    assert "self._same_origin_post_allowed(context)" in http
    assert "self._require_actor(correlation_id)" in http
    assert "household_policy_workflow.plan" in http
    assert "household_policy_workflow.confirm_and_apply" in http
    assert "household_policy_workflow.rollback" in http
    assert "provider_execution_authorized" not in http
    assert "HouseholdPolicyWorkflowService" in runtime
    assert "HouseholdPolicyHistoryService" in runtime
    assert "RuntimeRequestHandlerPolicy" in server
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerPolicy, runtime)" in server
