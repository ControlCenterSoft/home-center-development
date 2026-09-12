from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import build_household_snapshot
from home_center.policy_composer import (
    build_policy_bundle,
    compose_policy_change_plan,
    confirm_policy_change_plan,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "contracts" / "household"


def _schema(name: str) -> dict[str, object]:
    return json.loads((CONTRACTS / name).read_text(encoding="utf-8"))


def _evidence() -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
    household = Household(
        household_id="home-contract",
        members=(
            FamilyMember("parent-contract", "Родитель", HouseholdRole.PARENT),
            FamilyMember("child-contract", "Ребёнок", HouseholdRole.CHILD),
        ),
        devices=(),
    )
    snapshot = build_household_snapshot(household, generation=1, previous_snapshot_id=None)
    bundle = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)
    plan = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-contract",
        target_member_id="child-contract",
        target_bundle=bundle,
    )
    confirmation = confirm_policy_change_plan(snapshot, plan, actor_member_id="parent-contract")
    return bundle.to_dict(), plan.desired_state.to_dict(), plan.to_dict(), confirmation.to_dict()


def test_policy_composer_contract_schemas_are_draft_2020_12() -> None:
    for name in (
        "policy-bundle.v1.schema.json",
        "policy-desired-state.v1.schema.json",
        "policy-change-plan.v1.schema.json",
        "policy-change-confirmation.v1.schema.json",
    ):
        schema = _schema(name)
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_policy_composer_evidence_matches_contracts() -> None:
    bundle, desired_state, plan, confirmation = _evidence()

    bundle_schema = _schema("policy-bundle.v1.schema.json")
    desired_schema = _schema("policy-desired-state.v1.schema.json")
    plan_schema = _schema("policy-change-plan.v1.schema.json")
    confirmation_schema = _schema("policy-change-confirmation.v1.schema.json")

    # Keep qualification self-contained and deterministic. The production
    # schemas retain their relative references; tests inline the already
    # checked local schemas rather than resolving any network resource.
    desired_schema["properties"]["bundle"] = bundle_schema
    plan_schema["properties"]["desired_state"] = desired_schema

    Draft202012Validator(bundle_schema).validate(bundle)
    Draft202012Validator(desired_schema).validate(desired_state)
    Draft202012Validator(plan_schema).validate(plan)
    Draft202012Validator(confirmation_schema).validate(confirmation)


def test_policy_contracts_keep_execution_and_publication_closed() -> None:
    _, desired_state, plan, confirmation = _evidence()

    assert desired_state["provider_execution_authorized"] is False
    assert desired_state["infrastructure_mutation_authorized"] is False
    assert desired_state["external_publication_authorized"] is False
    assert plan["desired_state_write_authorized"] is False
    assert plan["provider_execution_authorized"] is False
    assert plan["infrastructure_mutation_authorized"] is False
    assert plan["external_publication_authorized"] is False
    assert confirmation["desired_state_write_authorized"] is True
    assert confirmation["provider_execution_authorized"] is False
    assert confirmation["infrastructure_mutation_authorized"] is False
    assert confirmation["external_publication_authorized"] is False
    assert confirmation["automatic_recovery_authorized"] is False
