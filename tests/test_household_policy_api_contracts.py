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


def _workflow(tmp_path):
    store = StateStore(tmp_path / "state.db", b"c" * 32, "policy-contract-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-contract-bootstrap",
    )
    policy = HouseholdPolicyRuntimeService(store)
    desired = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired)
    workflow = HouseholdPolicyWorkflowService(store, policy_runtime=policy, history=history)
    return store, household, history, workflow


def test_policy_plan_confirm_history_results_match_closed_contracts(tmp_path) -> None:
    store, household, history, workflow = _workflow(tmp_path)
    plan = workflow.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id="policy-contract-plan",
    )
    _validator("household-policy-plan-result.v1.schema.json").validate(plan)
    _validator("household-policy-presentation.v1.schema.json").validate(plan["presentation"])

    result = workflow.confirm_and_apply(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": plan["proposal"]["proposal_id"],
            "confirmed": True,
        },
        correlation_id="policy-contract-confirm",
    )
    _validator("household-policy-confirmation.v1.schema.json").validate(result["confirmation"])
    _validator("household-policy-confirm-apply-result.v1.schema.json").validate(result)
    _validator("household-policy-apply-receipt.v1.schema.json").validate(result["receipt"])

    archived = history.read(
        resource_key=result["receipt"]["resource_key"],
        generation=result["receipt"]["generation"],
    )
    _validator("household-policy-history.v1.schema.json").validate(archived)

    overview = workflow.history_overview(actor=ACTOR, resource_key=result["receipt"]["resource_key"])
    _validator("household-policy-history-overview.v1.schema.json").validate(overview)
    store.close()


def test_new_policy_contracts_are_closed_and_forbid_authority_escalation() -> None:
    names = (
        "household-policy-plan-request.v1.schema.json",
        "household-policy-confirm-request.v1.schema.json",
        "household-policy-recovery-request.v1.schema.json",
        "household-policy-recovery-result.v1.schema.json",
        "household-policy-confirmation.v1.schema.json",
        "household-policy-presentation.v1.schema.json",
        "household-policy-plan-result.v1.schema.json",
        "household-policy-confirm-apply-result.v1.schema.json",
        "household-policy-apply-receipt.v1.schema.json",
        "household-policy-history.v1.schema.json",
        "household-policy-history-overview.v1.schema.json",
        "household-policy-rollback-request.v1.schema.json",
        "household-policy-rollback-receipt.v1.schema.json",
    )
    for name in names:
        schema = json.loads((CONTRACTS / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["additionalProperties"] is False
        text = json.dumps(schema, ensure_ascii=False, sort_keys=True)
        if "provider_execution_authorized" in text:
            assert '"provider_execution_authorized": {"const": false}' in text
        if "desired_state_write_authorized" in text:
            assert '"desired_state_write_authorized": {"const": false}' in text
        if "infrastructure_mutation_authorized" in text:
            assert '"infrastructure_mutation_authorized": {"const": false}' in text
        if "external_publication_authorized" in text:
            assert '"external_publication_authorized": {"const": false}' in text
