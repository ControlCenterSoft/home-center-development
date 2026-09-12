from __future__ import annotations

import sqlite3

import pytest

from home_center.household_policy_composer import compose_policy_bundle
from home_center.household_policy_runtime import POLICY_PLAN_REQUEST_SCHEMA, HouseholdPolicyRuntimeError
from home_center.household_policy_semantic_runtime import SemanticHouseholdPolicyRuntimeService
from home_center.household_runtime import (
    HOUSEHOLD_BOOTSTRAP_SCHEMA,
    HOUSEHOLD_STATE_KEY,
    HouseholdRuntimeService,
    _state_from_dict,
)
from home_center.store import StateStore
from home_center.util import canonical_json, utc_now


ACTOR = "parent@example.test"


def _services(tmp_path):
    store = StateStore(tmp_path / "state.db", b"v" * 32, "policy-semantic-current-state-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-semantic-current-bootstrap",
    )
    runtime = SemanticHouseholdPolicyRuntimeService(store)
    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    member_id = household.actor_member_id(ACTOR)
    bundle = compose_policy_bundle(snapshot, member_id=member_id).to_dict()
    return store, runtime, member_id, bundle


def _insert_current(store: StateStore, bundle: dict[str, object], generation: int = 1) -> None:
    resource_key = bundle["desired_state_resource_key"]
    assert isinstance(resource_key, str)
    with sqlite3.connect(store.path, timeout=5) as connection:
        connection.execute(
            "INSERT INTO desired_state(resource_key,generation,value_json,updated_at) VALUES(?,?,?,?)",
            (resource_key, generation, canonical_json(bundle), utc_now()),
        )


def test_valid_current_policy_becomes_exact_plan_precondition(tmp_path) -> None:
    store, runtime, member_id, bundle = _services(tmp_path)
    _insert_current(store, bundle, generation=3)

    proposal = runtime.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="policy-semantic-current-valid",
    )

    assert proposal["expected_desired_state_generation"] == 3
    assert proposal["expected_desired_state_bundle_id"] == bundle["bundle_id"]
    assert proposal["bundle"] == bundle
    store.close()


def test_forged_current_policy_blocks_plan_instead_of_becoming_precondition(tmp_path) -> None:
    store, runtime, member_id, bundle = _services(tmp_path)
    forged = dict(bundle)
    forged["explanation"] = ["Подменённое описание"]
    _insert_current(store, forged)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_desired_state_invalid"):
        runtime.plan(
            actor=ACTOR,
            request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
            correlation_id="policy-semantic-current-forged",
        )

    store.close()


def test_forged_current_policy_with_valid_bundle_id_still_blocks_plan(tmp_path) -> None:
    store, runtime, member_id, bundle = _services(tmp_path)
    forged = dict(bundle)
    technical = dict(forged["technical_policy"])
    technical["vpn_allowed"] = not technical["vpn_allowed"]
    forged["technical_policy"] = technical
    _insert_current(store, forged)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_desired_state_invalid"):
        runtime.plan(
            actor=ACTOR,
            request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
            correlation_id="policy-semantic-current-valid-id-forged-payload",
        )

    store.close()
