from __future__ import annotations

import sqlite3

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_authorized_history import ScopedHouseholdPolicyHistoryService
from home_center.household_policy_composer import compose_policy_bundle
from home_center.household_policy_confirmation_audit import AuditBoundHouseholdPolicyDesiredStateService
from home_center.household_policy_history import HouseholdPolicyHistoryError
from home_center.household_runtime import (
    HOUSEHOLD_BOOTSTRAP_SCHEMA,
    HOUSEHOLD_STATE_KEY,
    HouseholdRuntimeService,
    _state_from_dict,
)
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore
from home_center.util import canonical_json, utc_now


ACTOR = "parent@example.test"


def _services(tmp_path):
    store = StateStore(tmp_path / "state.db", b"s" * 32, "policy-history-scope-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-history-scope-bootstrap",
    )
    desired_state = AuditBoundHouseholdPolicyDesiredStateService(store)
    history = ScopedHouseholdPolicyHistoryService(store, desired_state=desired_state)
    snapshot, _bindings = _state_from_dict(store.get_meta(HOUSEHOLD_STATE_KEY))
    return store, household, history, snapshot


def _insert_bundle(store: StateStore, bundle: dict[str, object]) -> None:
    resource_key = bundle["desired_state_resource_key"]
    assert isinstance(resource_key, str)
    with sqlite3.connect(store.path, timeout=5) as connection:
        connection.execute(
            "INSERT INTO desired_state(resource_key,generation,value_json,updated_at) VALUES(?,?,?,?)",
            (resource_key, 1, canonical_json(bundle), utc_now()),
        )


def test_exact_current_household_policy_resource_is_authorized(tmp_path) -> None:
    store, household, history, snapshot = _services(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    bundle = compose_policy_bundle(snapshot, member_id=member_id).to_dict()
    _insert_bundle(store, bundle)

    history._authorized_actor(ACTOR, bundle["desired_state_resource_key"])
    store.close()


def test_delimiter_prefix_of_foreign_household_does_not_authorize_history(tmp_path) -> None:
    store, _household, history, local_snapshot = _services(tmp_path)
    foreign_household_id = f"{local_snapshot.household_id}:shadow"
    foreign_member = FamilyMember(
        member_id="foreign-parent",
        display_name="Foreign Parent",
        role=HouseholdRole.PARENT,
    )
    foreign_household = Household(
        household_id=foreign_household_id,
        members=(foreign_member,),
        devices=(),
    )
    foreign_snapshot = build_household_snapshot(
        foreign_household,
        generation=1,
        previous_snapshot_id=None,
    )
    foreign_bundle = compose_policy_bundle(
        foreign_snapshot,
        member_id=foreign_member.member_id,
    ).to_dict()
    resource_key = foreign_bundle["desired_state_resource_key"]
    assert isinstance(resource_key, str)
    assert resource_key.startswith(f"household-policy:{local_snapshot.household_id}:")
    _insert_bundle(store, foreign_bundle)

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_resource_mismatch"):
        history._authorized_actor(ACTOR, resource_key)

    store.close()


def test_semantically_invalid_current_bundle_blocks_history_authorization(tmp_path) -> None:
    store, household, history, snapshot = _services(tmp_path)
    member_id = household.actor_member_id(ACTOR)
    bundle = compose_policy_bundle(snapshot, member_id=member_id).to_dict()
    resource_key = bundle["desired_state_resource_key"]
    assert isinstance(resource_key, str)
    forged = dict(bundle)
    forged["explanation"] = ["Подменённое описание"]
    _insert_bundle(store, forged)

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_history_evidence_mismatch"):
        history._authorized_actor(ACTOR, resource_key)

    store.close()
