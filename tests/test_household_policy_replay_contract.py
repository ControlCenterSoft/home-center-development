from __future__ import annotations

import json
from pathlib import Path

import jsonschema

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
CONTRACTS = ROOT / "contracts" / "household"


def _validator(name: str) -> jsonschema.Draft202012Validator:
    path = CONTRACTS / name
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    resolver = jsonschema.RefResolver(base_uri=CONTRACTS.as_uri() + "/", referrer=schema)
    return jsonschema.Draft202012Validator(schema, resolver=resolver)


def test_idempotent_confirm_apply_replay_matches_closed_contract(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"r" * 32, "policy-replay-contract-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-replay-bootstrap",
    )
    policy = HouseholdPolicyRuntimeService(store)
    desired = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired)
    workflow = HouseholdPolicyWorkflowService(store, policy_runtime=policy, history=history)

    plan = workflow.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id="policy-replay-plan",
    )
    request = {
        "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
        "proposal_id": plan["proposal"]["proposal_id"],
        "confirmed": True,
    }
    first = workflow.confirm_and_apply(
        actor=ACTOR,
        request=request,
        correlation_id="policy-replay-confirm-first",
    )
    replay = workflow.confirm_and_apply(
        actor=ACTOR,
        request=request,
        correlation_id="policy-replay-confirm-second",
    )

    assert first["confirmation"]["outcome"] == "confirmed-for-desired-state-write"
    assert replay["confirmation"]["outcome"] == "already-confirmed"
    assert replay["receipt"]["outcome"] == "already-applied"
    assert replay["receipt"]["generation"] == first["receipt"]["generation"]
    assert replay["receipt"]["bundle_id"] == first["receipt"]["bundle_id"]
    _validator("household-policy-confirm-apply-result.v1.schema.json").validate(replay)
    store.close()
