from __future__ import annotations

import sqlite3

import pytest

from home_center.household_policy_desired_state import (
    POLICY_APPLY_REQUEST_SCHEMA,
    HouseholdPolicyDesiredStateService,
)
from home_center.household_policy_history import (
    POLICY_ROLLBACK_REQUEST_SCHEMA,
    HouseholdPolicyHistoryError,
    HouseholdPolicyHistoryService,
    _history_key,
)
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeService,
)
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore
from home_center.util import canonical_json, utc_now


ACTOR = "parent@example.test"


def _services(tmp_path):
    store = StateStore(tmp_path / "state.db", b"h" * 32, "policy-history-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="bootstrap-policy-history",
    )
    policy = HouseholdPolicyRuntimeService(store)
    desired = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired)
    return store, household, policy, desired, history


def _materialize_initial(store, household, policy, history):
    proposal = policy.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id="history-plan-1",
    )
    confirmation = policy.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id="history-confirm-1",
    )
    receipt = history.materialize(
        actor=ACTOR,
        request={
            "schema": POLICY_APPLY_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmation_id": confirmation["confirmation_id"],
        },
        correlation_id="history-apply-1",
    )
    return proposal, receipt


def _replace_with_second_valid_revision(store, history, first_record):
    second_value = dict(first_record["value"])
    second_value["bundle_id"] = "hpb-" + "2" * 24
    second_value["explanation"] = [*second_value["explanation"], "Тестовая следующая ревизия."]
    with sqlite3.connect(store.path, timeout=5) as connection:
        connection.execute(
            "UPDATE desired_state SET generation=?,value_json=?,updated_at=? WHERE resource_key=? AND generation=?",
            (
                2,
                canonical_json(second_value),
                utc_now(),
                first_record["resource_key"],
                1,
            ),
        )
    second_record = history.repository.read(first_record["resource_key"])
    assert second_record is not None
    history.archive(second_record)
    return second_record


def test_materialization_archives_exact_generation_with_hash_evidence(tmp_path) -> None:
    store, household, policy, _desired, history = _services(tmp_path)
    proposal, receipt = _materialize_initial(store, household, policy, history)

    assert receipt["generation"] == 1
    assert receipt["history_generation"] == 1
    assert len(receipt["history_evidence_sha256"]) == 64
    archived = history.read(
        resource_key=proposal["bundle"]["desired_state_resource_key"],
        generation=1,
    )
    assert archived["bundle_id"] == proposal["bundle"]["bundle_id"]
    assert archived["value"] == proposal["bundle"]
    assert archived["provider_execution_authorized"] is False
    assert archived["infrastructure_mutation_authorized"] is False
    assert archived["external_publication_authorized"] is False
    store.close()


def test_rollback_restores_history_as_new_generation_and_replay_is_idempotent(tmp_path) -> None:
    store, household, policy, _desired, history = _services(tmp_path)
    proposal, _receipt = _materialize_initial(store, household, policy, history)
    resource_key = proposal["bundle"]["desired_state_resource_key"]
    first_record = history.repository.read(resource_key)
    assert first_record is not None
    second_record = _replace_with_second_valid_revision(store, history, first_record)

    request = {
        "schema": POLICY_ROLLBACK_REQUEST_SCHEMA,
        "resource_key": resource_key,
        "expected_generation": 2,
        "expected_bundle_id": second_record["value"]["bundle_id"],
        "target_generation": 1,
        "confirmed": True,
    }
    first = history.rollback(actor=ACTOR, request=request, correlation_id="rollback-1")
    assert first["outcome"] == "rolled-back"
    assert first["changed"] is True
    assert first["generation"] == 3
    assert first["bundle_id"] == proposal["bundle"]["bundle_id"]
    assert first["provider_execution_authorized"] is False
    assert first["infrastructure_mutation_authorized"] is False

    current = history.repository.read(resource_key)
    assert current is not None
    assert current["generation"] == 3
    assert current["value"] == proposal["bundle"]
    generation_three = history.read(resource_key=resource_key, generation=3)
    assert generation_three["value"] == proposal["bundle"]

    replay = history.rollback(actor=ACTOR, request=request, correlation_id="rollback-replay")
    assert replay["outcome"] == "already-rolled-back"
    assert replay["generation"] == 3
    assert history.repository.read(resource_key)["generation"] == 3
    store.close()


def test_rollback_fails_closed_on_stale_current_revision(tmp_path) -> None:
    store, household, policy, _desired, history = _services(tmp_path)
    proposal, _receipt = _materialize_initial(store, household, policy, history)
    resource_key = proposal["bundle"]["desired_state_resource_key"]
    first_record = history.repository.read(resource_key)
    assert first_record is not None
    second_record = _replace_with_second_valid_revision(store, history, first_record)

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_precondition_failed"):
        history.rollback(
            actor=ACTOR,
            request={
                "schema": POLICY_ROLLBACK_REQUEST_SCHEMA,
                "resource_key": resource_key,
                "expected_generation": 3,
                "expected_bundle_id": "hpb-" + "3" * 24,
                "target_generation": 1,
                "confirmed": True,
            },
            correlation_id="rollback-stale",
        )
    assert history.repository.read(resource_key)["generation"] == 2
    assert history.repository.read(resource_key)["value"] == second_record["value"]
    store.close()


def test_history_evidence_tampering_is_rejected(tmp_path) -> None:
    store, household, policy, _desired, history = _services(tmp_path)
    proposal, _receipt = _materialize_initial(store, household, policy, history)
    resource_key = proposal["bundle"]["desired_state_resource_key"]
    key = _history_key(resource_key, 1)
    archived = store.get_meta(key)
    archived["evidence_sha256"] = "0" * 64
    store.set_meta(key, archived)

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_history_evidence_mismatch"):
        history.read(resource_key=resource_key, generation=1)
    store.close()
