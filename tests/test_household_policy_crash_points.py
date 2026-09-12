from __future__ import annotations

import sqlite3

import pytest

from home_center.household_policy_desired_state import (
    POLICY_APPLY_KEY_PREFIX,
    POLICY_APPLY_REQUEST_SCHEMA,
    HouseholdPolicyDesiredStateService,
)
from home_center.household_policy_history import (
    POLICY_ROLLBACK_REQUEST_SCHEMA,
    HouseholdPolicyHistoryService,
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
    store = StateStore(tmp_path / "state.db", b"c" * 32, "policy-crash-point-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-crash-bootstrap",
    )
    policy = HouseholdPolicyRuntimeService(store)
    desired = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired)
    return store, household, policy, desired, history


def _confirmed(household, policy, suffix: str):
    proposal = policy.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id=f"policy-crash-plan-{suffix}",
    )
    confirmation = policy.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id=f"policy-crash-confirm-{suffix}",
    )
    request = {
        "schema": POLICY_APPLY_REQUEST_SCHEMA,
        "proposal_id": proposal["proposal_id"],
        "confirmation_id": confirmation["confirmation_id"],
    }
    return proposal, confirmation, request


def test_apply_recovers_after_process_loss_immediately_after_committed_cas(tmp_path, monkeypatch) -> None:
    store, household, policy, desired, history = _services(tmp_path)
    proposal, confirmation, request = _confirmed(household, policy, "after-cas")
    original_compare_and_set = desired.repository.compare_and_set

    def crash_after_committed_cas(exact_proposal):
        record, changed = original_compare_and_set(exact_proposal)
        assert changed is True
        assert record["generation"] == 1
        raise RuntimeError("simulated_process_loss_after_committed_cas")

    monkeypatch.setattr(desired.repository, "compare_and_set", crash_after_committed_cas)
    with pytest.raises(RuntimeError, match="simulated_process_loss_after_committed_cas"):
        history.materialize(
            actor=ACTOR,
            request=request,
            correlation_id="policy-crash-apply-after-cas",
        )

    current = desired.repository.read(proposal["bundle"]["desired_state_resource_key"])
    assert current is not None
    assert current["generation"] == 1
    assert current["value"] == proposal["bundle"]
    apply_state = store.get_meta(POLICY_APPLY_KEY_PREFIX + confirmation["confirmation_id"])
    assert apply_state["status"] == "applying"
    assert apply_state["receipt"] is None

    restarted_desired = HouseholdPolicyDesiredStateService(store)
    restarted_history = HouseholdPolicyHistoryService(store, desired_state=restarted_desired)
    receipt = restarted_history.materialize(
        actor=ACTOR,
        request=request,
        correlation_id="policy-crash-recover-after-cas",
    )
    assert receipt["outcome"] == "applied"
    assert receipt["changed"] is True
    assert receipt["recovered"] is True
    assert receipt["generation"] == 1
    assert receipt["bundle_id"] == proposal["bundle"]["bundle_id"]
    archived = restarted_history.read(
        resource_key=proposal["bundle"]["desired_state_resource_key"],
        generation=1,
    )
    assert archived["value"] == proposal["bundle"]
    store.close()


def test_apply_recovers_after_completion_audit_before_applied_marker(tmp_path, monkeypatch) -> None:
    store, household, policy, desired, history = _services(tmp_path)
    proposal, confirmation, request = _confirmed(household, policy, "after-complete-audit")
    apply_key = POLICY_APPLY_KEY_PREFIX + confirmation["confirmation_id"]
    original_set_meta = store.set_meta
    crashed = False

    def crash_before_applied_marker(key, value):
        nonlocal crashed
        if (
            not crashed
            and key == apply_key
            and isinstance(value, dict)
            and value.get("status") == "applied"
        ):
            crashed = True
            raise RuntimeError("simulated_process_loss_before_applied_marker")
        return original_set_meta(key, value)

    monkeypatch.setattr(store, "set_meta", crash_before_applied_marker)
    with pytest.raises(RuntimeError, match="simulated_process_loss_before_applied_marker"):
        history.materialize(
            actor=ACTOR,
            request=request,
            correlation_id="policy-crash-before-applied-marker",
        )

    current = desired.repository.read(proposal["bundle"]["desired_state_resource_key"])
    assert current is not None
    assert current["generation"] == 1
    assert store.get_meta(apply_key)["status"] == "applying"

    restarted_desired = HouseholdPolicyDesiredStateService(store)
    restarted_history = HouseholdPolicyHistoryService(store, desired_state=restarted_desired)
    receipt = restarted_history.materialize(
        actor=ACTOR,
        request=request,
        correlation_id="policy-crash-recover-before-applied-marker",
    )
    assert receipt["outcome"] == "applied"
    assert receipt["changed"] is True
    assert receipt["recovered"] is True
    assert receipt["generation"] == 1
    assert store.get_meta(apply_key)["status"] == "applied"
    store.close()


def test_rollback_recovers_after_desired_state_commit_before_history_archive(tmp_path, monkeypatch) -> None:
    store, household, policy, _desired, history = _services(tmp_path)
    proposal, _confirmation, request = _confirmed(household, policy, "rollback-base")
    history.materialize(
        actor=ACTOR,
        request=request,
        correlation_id="policy-crash-rollback-base-apply",
    )
    resource_key = proposal["bundle"]["desired_state_resource_key"]
    first_record = history.repository.read(resource_key)
    assert first_record is not None

    second_value = dict(first_record["value"])
    second_value["bundle_id"] = "hpb-" + "2" * 24
    second_value["explanation"] = [*second_value["explanation"], "Промежуточная ревизия для crash drill."]
    with sqlite3.connect(store.path, timeout=5) as connection:
        connection.execute(
            "UPDATE desired_state SET generation=?,value_json=?,updated_at=? WHERE resource_key=? AND generation=?",
            (2, canonical_json(second_value), utc_now(), resource_key, 1),
        )
    second_record = history.repository.read(resource_key)
    assert second_record is not None
    history.archive(second_record)

    rollback_request = {
        "schema": POLICY_ROLLBACK_REQUEST_SCHEMA,
        "resource_key": resource_key,
        "expected_generation": 2,
        "expected_bundle_id": second_record["value"]["bundle_id"],
        "target_generation": 1,
        "confirmed": True,
    }
    original_archive = history.archive
    crashed = False

    def crash_before_result_history(record):
        nonlocal crashed
        if not crashed and record.get("generation") == 3:
            crashed = True
            raise RuntimeError("simulated_process_loss_before_rollback_history")
        return original_archive(record)

    monkeypatch.setattr(history, "archive", crash_before_result_history)
    with pytest.raises(RuntimeError, match="simulated_process_loss_before_rollback_history"):
        history.rollback(
            actor=ACTOR,
            request=rollback_request,
            correlation_id="policy-crash-rollback-write",
        )

    current = history.repository.read(resource_key)
    assert current is not None
    assert current["generation"] == 3
    assert current["value"] == first_record["value"]

    restarted_desired = HouseholdPolicyDesiredStateService(store)
    restarted_history = HouseholdPolicyHistoryService(store, desired_state=restarted_desired)
    receipt = restarted_history.rollback(
        actor=ACTOR,
        request=rollback_request,
        correlation_id="policy-crash-rollback-recover",
    )
    assert receipt["outcome"] == "rolled-back"
    assert receipt["changed"] is True
    assert receipt["recovered"] is True
    assert receipt["generation"] == 3
    assert receipt["bundle_id"] == proposal["bundle"]["bundle_id"]
    archived = restarted_history.read(resource_key=resource_key, generation=3)
    assert archived["value"] == first_record["value"]
    store.close()
