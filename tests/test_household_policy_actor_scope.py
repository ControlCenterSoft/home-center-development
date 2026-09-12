from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_PLAN_REQUEST_SCHEMA,
    POLICY_RECOVERY_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeError,
)
from home_center.household_policy_semantic_runtime import SemanticHouseholdPolicyRuntimeService
from home_center.household_runtime import (
    HOUSEHOLD_BOOTSTRAP_SCHEMA,
    HOUSEHOLD_STATE_KEY,
    ActorBinding,
    HouseholdRuntimeService,
    _persisted,
    _state_from_dict,
)
from home_center.household_store import build_household_replacement
from home_center.store import StateStore


PARENT_ACTOR = "parent@example.test"
CHILD_ACTOR = "child@example.test"


def _services_with_child_actor(tmp_path):
    store = StateStore(tmp_path / "state.db", b"q" * 32, "policy-actor-scope-test")
    household_runtime = HouseholdRuntimeService(store)
    household_runtime.bootstrap(
        actor=PARENT_ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-actor-scope-bootstrap",
    )
    snapshot, bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    child = FamilyMember(
        member_id="member-child-test",
        display_name="Ребёнок",
        role=HouseholdRole.CHILD,
    )
    replacement = Household(
        household_id=snapshot.household_id,
        members=(*snapshot.household.members, child),
        devices=snapshot.household.devices,
    )
    next_snapshot, _commit = build_household_replacement(
        snapshot,
        replacement,
        expected_resource_version=snapshot.resource_version,
    )
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(
            next_snapshot,
            (*bindings, ActorBinding(actor=CHILD_ACTOR, member_id=child.member_id)),
        ),
    )
    runtime = SemanticHouseholdPolicyRuntimeService(store)
    parent_member_id = household_runtime.actor_member_id(PARENT_ACTOR)
    return store, runtime, parent_member_id


def _plan(runtime, member_id: str):
    return runtime.plan(
        actor=PARENT_ACTOR,
        request={"schema": POLICY_PLAN_REQUEST_SCHEMA, "member_id": member_id},
        correlation_id="policy-actor-scope-plan",
    )


def test_other_household_member_cannot_observe_pending_recovery_state(tmp_path) -> None:
    store, runtime, parent_member_id = _services_with_child_actor(tmp_path)
    proposal = _plan(runtime, parent_member_id)

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_composition_actor_mismatch"):
        runtime.recover(
            actor=CHILD_ACTOR,
            request={
                "schema": POLICY_RECOVERY_REQUEST_SCHEMA,
                "proposal_id": proposal["proposal_id"],
            },
            correlation_id="policy-actor-scope-child-pending-recover",
        )

    store.close()


def test_other_household_member_cannot_read_confirmed_recovery_evidence(tmp_path) -> None:
    store, runtime, parent_member_id = _services_with_child_actor(tmp_path)
    proposal = _plan(runtime, parent_member_id)
    runtime.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id="policy-actor-scope-parent-confirm",
    )

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_composition_actor_mismatch"):
        runtime.recover(
            actor=CHILD_ACTOR,
            request={
                "schema": POLICY_RECOVERY_REQUEST_SCHEMA,
                "proposal_id": proposal["proposal_id"],
            },
            correlation_id="policy-actor-scope-child-confirmed-recover",
        )

    store.close()


def test_other_household_member_cannot_replay_confirmed_proposal(tmp_path) -> None:
    store, runtime, parent_member_id = _services_with_child_actor(tmp_path)
    proposal = _plan(runtime, parent_member_id)
    runtime.confirm(
        actor=PARENT_ACTOR,
        request={
            "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id="policy-actor-scope-parent-confirm-replay",
    )

    with pytest.raises(HouseholdPolicyRuntimeError, match="household_policy_composition_actor_mismatch"):
        runtime.confirm(
            actor=CHILD_ACTOR,
            request={
                "schema": POLICY_CONFIRM_REQUEST_SCHEMA,
                "proposal_id": proposal["proposal_id"],
                "confirmed": True,
            },
            correlation_id="policy-actor-scope-child-confirm-replay",
        )

    store.close()
