from __future__ import annotations

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_change_preview import (
    POLICY_CHANGE_PREVIEW_SCHEMA,
    HouseholdPolicyChangePreviewError,
    build_policy_change_preview,
)
from home_center.household_policy_composer import (
    build_policy_composition_proposal,
    compose_policy_bundle,
)
from home_center.household_policy_desired_state import HouseholdPolicyDesiredStateService
from home_center.household_policy_guarded_workflow import GuardedHouseholdPolicyWorkflowService
from home_center.household_policy_history import HouseholdPolicyHistoryService
from home_center.household_policy_runtime import POLICY_PLAN_REQUEST_SCHEMA, HouseholdPolicyRuntimeService
from home_center.household_runtime import HOUSEHOLD_BOOTSTRAP_SCHEMA, HouseholdRuntimeService
from home_center.household_store import build_household_snapshot
from home_center.store import StateStore


ACTOR = "parent@example.test"


def _snapshot(target_role: HouseholdRole):
    household = Household(
        household_id="home-main",
        members=(
            FamilyMember(member_id="parent", display_name="Родитель", role=HouseholdRole.PARENT),
            FamilyMember(member_id="target", display_name="Пользователь", role=target_role),
        ),
        devices=(),
    )
    return build_household_snapshot(household, generation=1, previous_snapshot_id=None)


def _record(bundle: dict[str, object], generation: int = 1) -> dict[str, object]:
    return {
        "resource_key": bundle["desired_state_resource_key"],
        "generation": generation,
        "value": bundle,
        "updated_at": "2026-09-12T00:00:00Z",
    }


def test_initial_change_preview_is_explicit_and_non_mutating() -> None:
    snapshot = _snapshot(HouseholdRole.CHILD)
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="target",
    )

    preview = build_policy_change_preview(proposal, None)

    assert preview["schema"] == POLICY_CHANGE_PREVIEW_SCHEMA
    assert preview["change_state"] == "initial"
    assert preview["baseline_generation"] == 0
    assert preview["baseline_bundle_id"] is None
    assert preview["target_bundle_id"] == proposal.bundle.bundle_id
    assert "role" in preview["changed_fields"]
    assert preview["confirmation_required"] is True
    assert preview["mutation_started"] is False
    assert preview["provider_execution_authorized"] is False
    assert preview["infrastructure_mutation_authorized"] is False
    assert preview["external_publication_authorized"] is False


def test_identical_verified_policy_is_presented_as_unchanged() -> None:
    snapshot = _snapshot(HouseholdRole.CHILD)
    bundle = compose_policy_bundle(snapshot, member_id="target").to_dict()
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="target",
        expected_desired_state_generation=1,
        expected_desired_state_bundle_id=bundle["bundle_id"],
    )

    preview = build_policy_change_preview(proposal, _record(bundle))

    assert preview["change_state"] == "unchanged"
    assert preview["changed_fields"] == []
    assert preview["baseline_generation"] == 1
    assert preview["baseline_bundle_id"] == bundle["bundle_id"]
    assert preview["cozy_summary"] == ["Текущие правила уже совпадают с предлагаемыми."]


def test_role_change_preview_explains_only_semantic_policy_delta() -> None:
    old_snapshot = _snapshot(HouseholdRole.GUEST)
    current_bundle = compose_policy_bundle(old_snapshot, member_id="target").to_dict()
    new_snapshot = _snapshot(HouseholdRole.CHILD)
    proposal = build_policy_composition_proposal(
        new_snapshot,
        actor_member_id="parent",
        member_id="target",
        expected_desired_state_generation=1,
        expected_desired_state_bundle_id=current_bundle["bundle_id"],
    )

    preview = build_policy_change_preview(proposal, _record(current_bundle))

    assert preview["change_state"] == "changed"
    assert "role" in preview["changed_fields"]
    assert preview["target_bundle_id"] != preview["baseline_bundle_id"]
    assert preview["cozy_summary"][0].startswith("Изменятся:")


def test_semantically_forged_current_bundle_is_rejected() -> None:
    snapshot = _snapshot(HouseholdRole.CHILD)
    bundle = compose_policy_bundle(snapshot, member_id="target").to_dict()
    proposal = build_policy_composition_proposal(
        snapshot,
        actor_member_id="parent",
        member_id="target",
        expected_desired_state_generation=1,
        expected_desired_state_bundle_id=bundle["bundle_id"],
    )
    forged = dict(bundle)
    forged["explanation"] = ["Подменённое описание"]

    with pytest.raises(
        HouseholdPolicyChangePreviewError,
        match="household_policy_change_preview_evidence_invalid",
    ):
        build_policy_change_preview(proposal, _record(forged))


def test_guarded_workflow_exposes_initial_preview_without_starting_mutation(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"p" * 32, "policy-change-preview-test")
    household = HouseholdRuntimeService(store)
    household.bootstrap(
        actor=ACTOR,
        request={"schema": HOUSEHOLD_BOOTSTRAP_SCHEMA, "display_name": "Родитель"},
        correlation_id="policy-change-preview-bootstrap",
    )
    runtime = HouseholdPolicyRuntimeService(store)
    desired_state = HouseholdPolicyDesiredStateService(store)
    history = HouseholdPolicyHistoryService(store, desired_state=desired_state)
    workflow = GuardedHouseholdPolicyWorkflowService(store, policy_runtime=runtime, history=history)

    result = workflow.plan(
        actor=ACTOR,
        request={
            "schema": POLICY_PLAN_REQUEST_SCHEMA,
            "member_id": household.actor_member_id(ACTOR),
        },
        correlation_id="policy-change-preview-plan",
    )

    assert result["change_preview"]["change_state"] == "initial"
    assert result["change_preview"]["mutation_started"] is False
    assert result["desired_state_materialized"] is False
    assert store.desired_state() == []
    store.close()
