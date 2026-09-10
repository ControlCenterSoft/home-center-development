from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household_runtime import (
    HOUSEHOLD_STATE_KEY,
    HouseholdRuntimeError,
    HouseholdRuntimeService,
)
from home_center.store import StateStore


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"h" * 32, "cluster-test")


def _bootstrap(service: HouseholdRuntimeService, actor: str = "local-admin:admin") -> dict[str, object]:
    return service.bootstrap(
        actor=actor,
        request={"schema": "home-center.household-bootstrap.v1", "display_name": "Павел"},
        correlation_id="corr-bootstrap",
    )


def test_household_status_is_unconfigured_by_default(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        value = HouseholdRuntimeService(store).status()
        assert value["configured"] is False
        assert value["snapshot"] is None
        assert value["infrastructure_mutation_authorized"] is False
        assert value["external_publication_authorized"] is False
    finally:
        store.close()


def test_bootstrap_persists_parent_and_actor_binding_atomically(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        result = _bootstrap(service)
        snapshot = result["snapshot"]
        assert isinstance(snapshot, dict)
        household = snapshot["household"]
        assert isinstance(household, dict)
        members = household["members"]
        assert isinstance(members, list) and len(members) == 1
        assert members[0]["display_name"] == "Павел"
        assert members[0]["role"] == "parent"
        assert result["infrastructure_mutation_authorized"] is False
        assert result["external_publication_authorized"] is False

        persisted = store.get_meta(HOUSEHOLD_STATE_KEY)
        assert persisted["schema"] == "home-center.household-persisted-state.v1"
        assert persisted["snapshot"] == snapshot
        assert len(persisted["bindings"]) == 1
        assert persisted["bindings"][0]["actor"] == "local-admin:admin"
        assert persisted["bindings"][0]["member_id"] == members[0]["member_id"]

        # A fresh service instance proves the state survives the facade lifetime.
        restored = HouseholdRuntimeService(store)
        assert restored.status()["configured"] is True
        assert restored.actor_member_id("local-admin:admin") == members[0]["member_id"]
        events = store.audit_events(10)
        assert any(event["action"] == "household.bootstrap" for event in events)
    finally:
        store.close()


def test_bootstrap_is_create_once(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        with pytest.raises(HouseholdRuntimeError, match="household_already_configured"):
            _bootstrap(service)
    finally:
        store.close()


def test_planning_uses_server_side_actor_binding_and_never_authorizes_mutation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        boot = _bootstrap(service)
        parent_id = boot["actor_binding"]["member_id"]
        proposal = service.plan_intent(
            actor="local-admin:admin",
            request={
                "schema": "home-center.household-intent-request.v1",
                "intent_id": "intent-child-001",
                "kind": "onboard-member",
                "target_id": "child-001",
                "requested_role": "child",
                "subject_member_id": None,
            },
            correlation_id="corr-plan",
        )
        assert proposal["intent"]["actor_member_id"] == parent_id
        assert proposal["confirmation_required"] is True
        assert proposal["mutation_authorized"] is False
        assert proposal["infrastructure_mutation_authorized"] is False
        assert proposal["external_publication_authorized"] is False
        assert [item["action_type"] for item in proposal["plan"]["actions"]] == [
            "household.member.create",
            "household.policy.compose",
        ]
    finally:
        store.close()


def test_unbound_authenticated_actor_cannot_plan_for_parent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        with pytest.raises(HouseholdRuntimeError, match="household_actor_not_bound"):
            service.plan_intent(
                actor="ad-admin:other@example.test",
                request={
                    "schema": "home-center.household-intent-request.v1",
                    "intent_id": "intent-child-002",
                    "kind": "onboard-member",
                    "target_id": "child-002",
                    "requested_role": "child",
                    "subject_member_id": None,
                },
                correlation_id="corr-unbound",
            )
    finally:
        store.close()


def test_tampered_persisted_snapshot_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        persisted = store.get_meta(HOUSEHOLD_STATE_KEY)
        persisted["snapshot"]["resource_version"] = "hrv-000000000000000000000000"
        store.set_meta(HOUSEHOLD_STATE_KEY, persisted)
        with pytest.raises(HouseholdRuntimeError, match="household_state_evidence_mismatch"):
            service.status()
    finally:
        store.close()
