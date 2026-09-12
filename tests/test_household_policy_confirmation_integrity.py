from __future__ import annotations

import pytest

from home_center.household_policy_desired_state import HouseholdPolicyDesiredStateService
from home_center.household_policy_history import HouseholdPolicyHistoryService
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    POLICY_PROPOSAL_KEY_PREFIX,
    HouseholdPolicyRuntimeError,
    HouseholdPolicyRuntimeService,
)
from home_center.household_policy_workflow import HouseholdPolicyWorkflowService
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.store import StateStore


ACTOR = "parent@example.test"


def _services(tmp_path):
    store = StateStore(tmp_path / "state.db", b"i" * 32, "policy-confirmation-integrity-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="bootstrap-policy-confirmation-integrity",
    )
    policy_runtime = HouseholdPolicyRuntimeService(store)
    desired_state = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired_state)
    workflow = HouseholdPolicyWorkflowService(
        store,
        policy_runtime=policy_runtime,
        history=history,
    )
    return store, household, policy_runtime, workflow


def test_workflow_rejects_confirmation_id_not_derived_from_exact_proposal(tmp_path) -> None:
    store, household, policy_runtime, workflow = _services(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    plan = workflow.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="plan-confirmation-integrity",
    )
    proposal_id = plan["proposal"]["proposal_id"]
    policy_runtime.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="confirm-before-tamper",
    )

    key = POLICY_PROPOSAL_KEY_PREFIX + proposal_id
    envelope = store.get_meta(key)
    assert isinstance(envelope, dict)
    confirmation = envelope.get("confirmation")
    assert isinstance(confirmation, dict)
    original_confirmation_id = confirmation["confirmation_id"]
    tampered_confirmation_id = "hpconfirm-000000000000000000000000"
    assert tampered_confirmation_id != original_confirmation_id

    tampered_envelope = dict(envelope)
    tampered_confirmation = dict(confirmation)
    tampered_confirmation["confirmation_id"] = tampered_confirmation_id
    tampered_envelope["confirmation"] = tampered_confirmation
    store.set_meta(key, tampered_envelope)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_confirmation_evidence_mismatch"):
        workflow.confirm_and_apply(
            actor=ACTOR,
            request={
                "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
                "proposal_id": proposal_id,
                "confirmed": True,
            },
            correlation_id="confirm-after-tamper",
        )

    assert store.desired_state() == []
    store.close()


def test_workflow_rejects_confirmation_that_claims_mutation_authority(tmp_path) -> None:
    store, household, policy_runtime, workflow = _services(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    plan = workflow.plan(
        actor=ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="plan-authority-integrity",
    )
    proposal_id = plan["proposal"]["proposal_id"]
    policy_runtime.confirm(
        actor=ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="confirm-before-authority-tamper",
    )

    key = POLICY_PROPOSAL_KEY_PREFIX + proposal_id
    envelope = store.get_meta(key)
    assert isinstance(envelope, dict)
    confirmation = envelope.get("confirmation")
    assert isinstance(confirmation, dict)

    tampered_envelope = dict(envelope)
    tampered_confirmation = dict(confirmation)
    tampered_confirmation["infrastructure_mutation_authorized"] = True
    tampered_envelope["confirmation"] = tampered_confirmation
    store.set_meta(key, tampered_envelope)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_confirmation_evidence_mismatch"):
        workflow.confirm_and_apply(
            actor=ACTOR,
            request={
                "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
                "proposal_id": proposal_id,
                "confirmed": True,
            },
            correlation_id="confirm-after-authority-tamper",
        )

    assert store.desired_state() == []
    store.close()
