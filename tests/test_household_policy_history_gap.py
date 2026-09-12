from __future__ import annotations

import sqlite3

import pytest

from home_center.household_policy_desired_state import HouseholdPolicyDesiredStateService
from home_center.household_policy_history import HouseholdPolicyHistoryError, HouseholdPolicyHistoryService, _history_key
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_policy_workflow import HouseholdPolicyWorkflowService
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore
from home_center.util import canonical_json, utc_now


ACTOR = "parent@example.test"


def test_verified_policy_history_fails_closed_when_retained_generation_is_missing(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"g" * 32, "policy-history-gap-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-history-gap-bootstrap",
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
        correlation_id="policy-history-gap-plan",
    )
    result = workflow.confirm_and_apply(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": plan["proposal"]["proposal_id"],
            "confirmed": True,
        },
        correlation_id="policy-history-gap-confirm",
    )
    resource_key = result["receipt"]["resource_key"]
    first = history.repository.read(resource_key)
    assert first is not None and first["generation"] == 1

    # Build a second valid local policy revision and archive it, then simulate
    # loss/tampering of only the retained generation-1 history payload.
    second_value = dict(first["value"])
    second_value["bundle_id"] = "hpb-" + "8" * 24
    second_value["explanation"] = [*second_value["explanation"], "Следующая подтверждённая ревизия."]
    with sqlite3.connect(store.path, timeout=5) as connection:
        connection.execute(
            "UPDATE desired_state SET generation=?,value_json=?,updated_at=? WHERE resource_key=? AND generation=?",
            (2, canonical_json(second_value), utc_now(), resource_key, 1),
        )
    second = history.repository.read(resource_key)
    assert second is not None and second["generation"] == 2
    history.archive(second)

    with sqlite3.connect(store.path, timeout=5) as connection:
        connection.execute("DELETE FROM cluster_meta WHERE key=?", (_history_key(resource_key, 1),))

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_history_gap"):
        workflow.history_overview(actor=ACTOR, resource_key=resource_key)

    # The current revision is still present; the overview fails because the
    # supposedly verified retained history is incomplete, not because state vanished.
    assert history.repository.read(resource_key)["generation"] == 2
    assert history.read(resource_key=resource_key, generation=2)["bundle_id"] == second_value["bundle_id"]
    store.close()
