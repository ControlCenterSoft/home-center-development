from __future__ import annotations

import sqlite3

import pytest

from home_center.household_policy_confirmation_audit import AuditBoundHouseholdPolicyDesiredStateService
from home_center.household_policy_desired_state import HouseholdPolicyDesiredStateError
from home_center.household_policy_history import HouseholdPolicyHistoryService
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    POLICY_PROPOSAL_KEY_PREFIX,
    HouseholdPolicyRuntimeService,
)
from home_center.household_policy_workflow import HouseholdPolicyWorkflowService
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"


def _services(tmp_path):
    store = StateStore(tmp_path / "state.db", b"a" * 32, "policy-confirmation-audit-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-confirmation-audit-bootstrap",
    )
    policy_runtime = HouseholdPolicyRuntimeService(store)
    desired_state = AuditBoundHouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired_state)
    workflow = HouseholdPolicyWorkflowService(
        store,
        policy_runtime=policy_runtime,
        history=history,
    )
    return store, household, policy_runtime, desired_state, workflow


def _plan(workflow, household):
    return workflow.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id="policy-confirmation-audit-plan",
    )


def _confirm(policy_runtime, proposal_id: str):
    return policy_runtime.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="policy-confirmation-audit-confirm",
    )


def _confirm_and_apply(workflow, proposal_id: str):
    return workflow.confirm_and_apply(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="policy-confirmation-audit-apply",
    )


def test_exact_confirmation_audit_binding_allows_materialization(tmp_path) -> None:
    store, household, _policy_runtime, _desired_state, workflow = _services(tmp_path)
    plan = _plan(workflow, household)
    result = _confirm_and_apply(workflow, plan["proposal"]["proposal_id"])

    assert result["desired_state_materialized"] is True
    assert result["provider_execution_authorized"] is False
    assert result["infrastructure_mutation_authorized"] is False
    assert len(store.desired_state()) == 1
    store.close()


def test_missing_confirmation_audit_event_blocks_materialization(tmp_path) -> None:
    store, household, policy_runtime, _desired_state, workflow = _services(tmp_path)
    plan = _plan(workflow, household)
    proposal_id = plan["proposal"]["proposal_id"]
    _confirm(policy_runtime, proposal_id)

    key = POLICY_PROPOSAL_KEY_PREFIX + proposal_id
    envelope = store.get_meta(key)
    assert isinstance(envelope, dict)
    confirmation = envelope.get("confirmation")
    assert isinstance(confirmation, dict)
    tampered = dict(envelope)
    tampered_confirmation = dict(confirmation)
    tampered_confirmation["audit_event_id"] = "00000000-0000-0000-0000-000000000000"
    tampered["confirmation"] = tampered_confirmation
    store.set_meta(key, tampered)

    with pytest.raises(HouseholdPolicyDesiredStateError, match="household_policy_confirmation_audit_missing"):
        _confirm_and_apply(workflow, proposal_id)

    assert store.desired_state() == []
    store.close()


def test_unrelated_valid_audit_event_blocks_materialization(tmp_path) -> None:
    store, household, policy_runtime, _desired_state, workflow = _services(tmp_path)
    plan = _plan(workflow, household)
    proposal_id = plan["proposal"]["proposal_id"]
    _confirm(policy_runtime, proposal_id)

    unrelated_event_id = store.audit(
        actor=ACTOR,
        action="household.policy.plan",
        target="unrelated-policy-resource",
        outcome="accepted",
        correlation_id="policy-confirmation-audit-unrelated",
        details={"proposal_id": proposal_id},
    )
    key = POLICY_PROPOSAL_KEY_PREFIX + proposal_id
    envelope = store.get_meta(key)
    assert isinstance(envelope, dict)
    confirmation = envelope.get("confirmation")
    assert isinstance(confirmation, dict)
    tampered = dict(envelope)
    tampered_confirmation = dict(confirmation)
    tampered_confirmation["audit_event_id"] = unrelated_event_id
    tampered["confirmation"] = tampered_confirmation
    store.set_meta(key, tampered)

    with pytest.raises(HouseholdPolicyDesiredStateError, match="household_policy_confirmation_audit_mismatch"):
        _confirm_and_apply(workflow, proposal_id)

    assert store.desired_state() == []
    store.close()


def test_corrupted_keyed_audit_chain_blocks_materialization(tmp_path) -> None:
    store, household, policy_runtime, _desired_state, workflow = _services(tmp_path)
    plan = _plan(workflow, household)
    proposal_id = plan["proposal"]["proposal_id"]
    confirmation = _confirm(policy_runtime, proposal_id)

    with sqlite3.connect(store.path, timeout=5) as connection:
        connection.execute(
            "UPDATE audit SET details_json=? WHERE event_id=?",
            ('{"tampered":true}', confirmation["audit_event_id"]),
        )

    with pytest.raises(HouseholdPolicyDesiredStateError, match="household_policy_confirmation_audit_invalid"):
        _confirm_and_apply(workflow, proposal_id)

    assert store.desired_state() == []
    store.close()


def test_audit_bound_writer_preserves_closed_apply_request_contract(tmp_path) -> None:
    store, _household, _policy_runtime, desired_state, _workflow = _services(tmp_path)

    with pytest.raises(HouseholdPolicyDesiredStateError, match="invalid_household_policy_apply_request"):
        desired_state.apply(
            actor=ACTOR,
            request={"schema": "home-center.household-policy-apply-request.v1"},
            correlation_id="policy-confirmation-audit-invalid-request",
        )

    assert store.desired_state() == []
    store.close()
