from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    POLICY_PROPOSAL_KEY_PREFIX,
    POLICY_RECOVERY_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"
ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "household"


def _validator() -> jsonschema.Draft202012Validator:
    path = CONTRACTS / "household-policy-recovery-result.v1.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    resolver = jsonschema.RefResolver(base_uri=CONTRACTS.as_uri() + "/", referrer=schema)
    return jsonschema.Draft202012Validator(schema, resolver=resolver)


def test_policy_recovery_results_match_closed_contract(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"v" * 32, "policy-recovery-contract-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-recovery-bootstrap",
    )
    policy = HouseholdPolicyRuntimeService(store)
    proposal = policy.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id="policy-recovery-plan",
    )
    proposal_id = proposal["proposal_id"]
    request = {"schema": POLICY_RECOVERY_REQUEST_SCHEMA, "proposal_id": proposal_id}
    validator = _validator()

    pending = policy.recover(actor=ACTOR, request=request, correlation_id="policy-recovery-pending")
    assert pending["status"] == "pending"
    assert pending["recovered"] is False
    validator.validate(pending)

    envelope = store.get_meta(POLICY_PROPOSAL_KEY_PREFIX + proposal_id)
    envelope["status"] = "confirming"
    envelope["confirmation"] = None
    envelope["recovery_required"] = True
    store.set_meta(POLICY_PROPOSAL_KEY_PREFIX + proposal_id, envelope)

    recovered = policy.recover(actor=ACTOR, request=request, correlation_id="policy-recovery-reopen")
    assert recovered["status"] == "pending"
    assert recovered["recovered"] is True
    validator.validate(recovered)

    policy.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="policy-recovery-confirm",
    )
    confirmed = policy.recover(actor=ACTOR, request=request, correlation_id="policy-recovery-confirmed")
    assert confirmed["status"] == "confirmed"
    assert confirmed["recovered"] is False
    assert confirmed["confirmation"]["proposal_id"] == proposal_id
    validator.validate(confirmed)
    store.close()
