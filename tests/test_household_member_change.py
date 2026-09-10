from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_member_change import (
    HouseholdMemberChangeError,
    apply_member_add_proposal,
    build_member_add_proposal,
    member_add_proposal_from_dict,
)
from home_center.household_runtime import HouseholdRuntimeError, HouseholdRuntimeService
from home_center.household_store import HouseholdStore, build_household_replacement
from home_center.store import StateStore


def _base_snapshot():
    household = Household(
        household_id="home",
        members=(FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),),
        devices=(),
    )
    store = HouseholdStore()
    store.create(household)
    return store.read("home")


def _state_store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"m" * 32, "cluster-test")


def _bootstrap(service: HouseholdRuntimeService) -> None:
    service.bootstrap(
        actor="local-admin:admin",
        request={"schema": "home-center.household-bootstrap.v1", "display_name": "Parent"},
        correlation_id="corr-bootstrap",
    )


def _plan(service: HouseholdRuntimeService, *, name: str = "Child", role: str = "child") -> dict[str, object]:
    return service.plan_member_add(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-member-add-plan.v1",
            "display_name": name,
            "role": role,
        },
        correlation_id="corr-plan",
    )


def _confirm(service: HouseholdRuntimeService, proposal_id: str) -> dict[str, object]:
    return service.confirm_member_add(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-member-add-confirm.v1",
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="corr-confirm",
    )


def test_pure_proposal_binds_exact_snapshot_actor_and_member() -> None:
    snapshot = _base_snapshot()
    proposal = build_member_add_proposal(
        snapshot,
        actor_member_id="member-parent",
        member_id="member-child",
        display_name="Child",
        role=HouseholdRole.CHILD,
    )
    assert proposal.snapshot_id == snapshot.snapshot_id
    assert proposal.resource_version == snapshot.resource_version
    assert proposal.generation == snapshot.generation
    assert proposal.actor_member_id == "member-parent"
    assert proposal.member.role is HouseholdRole.CHILD
    assert proposal.confirmation_required is True
    assert proposal.mutation_authorized is False
    assert proposal.infrastructure_mutation_authorized is False
    assert proposal.external_publication_authorized is False
    assert member_add_proposal_from_dict(proposal.to_dict()) == proposal


def test_tampered_proposal_is_rejected() -> None:
    snapshot = _base_snapshot()
    proposal = build_member_add_proposal(
        snapshot,
        actor_member_id="member-parent",
        member_id="member-child",
        display_name="Child",
        role=HouseholdRole.CHILD,
    ).to_dict()
    proposal["member"]["role"] = "parent"
    with pytest.raises(HouseholdMemberChangeError, match="household_member_proposal_evidence_mismatch"):
        member_add_proposal_from_dict(proposal)


def test_non_parent_cannot_build_administrative_member_change() -> None:
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    ref = HouseholdStore()
    ref.create(household)
    with pytest.raises(HouseholdMemberChangeError, match="household_member_change_not_authorized"):
        build_member_add_proposal(
            ref.read("home"),
            actor_member_id="member-child",
            member_id="member-guest",
            display_name="Guest",
            role=HouseholdRole.GUEST,
        )


def test_pure_apply_rejects_stale_snapshot() -> None:
    base = _base_snapshot()
    proposal = build_member_add_proposal(
        base,
        actor_member_id="member-parent",
        member_id="member-child",
        display_name="Child",
        role=HouseholdRole.CHILD,
    )
    changed = Household(
        household_id="home",
        members=(
            *base.household.members,
            FamilyMember(member_id="member-other", display_name="Other", role=HouseholdRole.GUEST),
        ),
        devices=(),
    )
    newer, _commit = build_household_replacement(
        base,
        changed,
        expected_resource_version=base.resource_version,
    )
    with pytest.raises(HouseholdMemberChangeError, match="household_member_change_stale"):
        apply_member_add_proposal(newer, proposal, actor_member_id="member-parent")


def test_runtime_plan_does_not_mutate_household(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        before = service.status()["snapshot"]
        proposal = _plan(service)
        after = service.status()["snapshot"]
        assert before == after
        assert proposal["confirmation_required"] is True
        assert proposal["mutation_authorized"] is False
    finally:
        store.close()


def test_runtime_confirm_adds_child_and_advances_generation_once(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        proposal = _plan(service, name="Child", role="child")
        receipt = _confirm(service, proposal["proposal_id"])
        assert receipt["outcome"] == "applied"
        assert receipt["member"]["display_name"] == "Child"
        assert receipt["member"]["role"] == "child"
        assert receipt["generation"] == 2
        assert receipt["infrastructure_mutation_authorized"] is False
        assert receipt["external_publication_authorized"] is False
        status = service.status()
        members = status["snapshot"]["household"]["members"]
        assert {item["display_name"] for item in members} == {"Parent", "Child"}
        assert status["snapshot"]["generation"] == 2
        actions = [event["action"] for event in store.audit_events(20)]
        assert "household.member.plan" in actions
        assert "household.member.create.requested" in actions
        assert "household.member.create" in actions
    finally:
        store.close()


def test_runtime_confirm_retry_is_idempotent(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        proposal = _plan(service)
        first = _confirm(service, proposal["proposal_id"])
        second = _confirm(service, proposal["proposal_id"])
        assert first["outcome"] == "applied"
        assert second["outcome"] == "already-applied"
        assert first["snapshot_id"] == second["snapshot_id"]
        assert service.status()["snapshot"]["generation"] == 2
        assert len(service.status()["snapshot"]["household"]["members"]) == 2
    finally:
        store.close()


def test_second_plan_becomes_stale_after_first_plan_is_confirmed(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        first = _plan(service, name="Child", role="child")
        second = _plan(service, name="Guest", role="guest")
        _confirm(service, first["proposal_id"])
        with pytest.raises(HouseholdRuntimeError, match="household_member_change_stale"):
            _confirm(service, second["proposal_id"])
        assert {item["display_name"] for item in service.status()["snapshot"]["household"]["members"]} == {"Parent", "Child"}
    finally:
        store.close()


def test_confirmation_must_be_explicit_true(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        service = HouseholdRuntimeService(store)
        _bootstrap(service)
        proposal = _plan(service)
        with pytest.raises(HouseholdRuntimeError, match="invalid_household_member_confirm_request"):
            service.confirm_member_add(
                actor="local-admin:admin",
                request={
                    "schema": "home-center.household-member-add-confirm.v1",
                    "proposal_id": proposal["proposal_id"],
                    "confirmed": False,
                },
                correlation_id="corr-no",
            )
        assert service.status()["snapshot"]["generation"] == 1
    finally:
        store.close()
