from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import (
    EffectivePolicy,
    FamilyMember,
    Household,
    HouseholdRole,
    InternetPolicy,
    effective_policy,
)
from home_center.household_desired_state_0500 import (
    MAX_GENERATION,
    HouseholdDesiredStatePlan,
    plan_household_desired_state,
    validate_household_desired_state_plan,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "contracts" / "household" / "household-desired-state-plan.v1.schema.json"


def _household() -> Household:
    return Household(
        household_id="home-01",
        members=(
            FamilyMember(member_id="parent-01", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child-01", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )


def _policy(member_id: str = "child-01") -> EffectivePolicy:
    return effective_policy(_household(), member_id)


def test_plan_is_deterministic_and_non_authorizing() -> None:
    policy = _policy()
    first = plan_household_desired_state(policy, current_generation=7)
    second = plan_household_desired_state(policy, current_generation=7)

    assert first == second
    assert first.policy_id == policy.policy_id
    assert first.role is HouseholdRole.CHILD
    assert first.internet_policy is InternetPolicy.FILTERED
    assert first.managed_device_required is True
    assert first.vpn_allowed is False
    assert first.expected_generation == 7
    assert first.next_generation == 8
    assert first.approval_required is True
    assert first.mutation_authorized is False
    assert first.provider_execution_enabled is False
    assert first.production_mutation_enabled is False
    assert first.external_publication_allowed is False


def test_generation_and_policy_are_bound_into_plan_identity() -> None:
    child = _policy("child-01")
    parent = _policy("parent-01")

    generation_1 = plan_household_desired_state(child, current_generation=1)
    generation_2 = plan_household_desired_state(child, current_generation=2)
    parent_plan = plan_household_desired_state(parent, current_generation=1)

    assert generation_1.plan_id != generation_2.plan_id
    assert generation_1.plan_id != parent_plan.plan_id


def test_validation_accepts_exact_plan_and_rejects_stale_generation() -> None:
    policy = _policy()
    plan = plan_household_desired_state(policy, current_generation=4)

    validate_household_desired_state_plan(plan, policy, current_generation=4)

    with pytest.raises(HomeServiceCatalogError, match="household_desired_state_plan_mismatch"):
        validate_household_desired_state_plan(plan, policy, current_generation=5)


def test_validation_rejects_policy_substitution() -> None:
    child_policy = _policy("child-01")
    parent_policy = _policy("parent-01")
    plan = plan_household_desired_state(child_policy, current_generation=0)

    with pytest.raises(HomeServiceCatalogError, match="household_desired_state_plan_mismatch"):
        validate_household_desired_state_plan(plan, parent_policy, current_generation=0)


def test_external_publication_and_non_boolean_policy_values_fail_closed() -> None:
    policy = _policy()

    with pytest.raises(HomeServiceCatalogError, match="household_external_publication_forbidden"):
        plan_household_desired_state(replace(policy, external_publication_allowed=True), current_generation=0)

    with pytest.raises(HomeServiceCatalogError, match="invalid_household_desired_state_boolean"):
        plan_household_desired_state(replace(policy, vpn_allowed=1), current_generation=0)


def test_generation_bounds_fail_closed() -> None:
    policy = _policy()

    for value in (True, -1, MAX_GENERATION + 1):
        with pytest.raises(HomeServiceCatalogError, match="invalid_household_desired_state_generation"):
            plan_household_desired_state(policy, current_generation=value)

    with pytest.raises(HomeServiceCatalogError, match="household_desired_state_generation_exhausted"):
        plan_household_desired_state(policy, current_generation=MAX_GENERATION)


def test_direct_plan_requires_exact_next_generation_and_forbids_publication() -> None:
    policy = _policy()
    plan = plan_household_desired_state(policy, current_generation=3)

    with pytest.raises(HomeServiceCatalogError, match="household_desired_state_generation_mismatch"):
        replace(plan, next_generation=9)

    with pytest.raises(HomeServiceCatalogError, match="household_external_publication_forbidden"):
        replace(plan, external_publication_allowed=True)


def test_contract_is_closed_and_accepts_runtime_shape() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    document = plan_household_desired_state(_policy(), current_generation=11).to_dict()

    validator.validate(document)
    invalid = dict(document)
    invalid["unexpected"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid)


def test_contract_keeps_all_mutation_authority_disabled() -> None:
    document = plan_household_desired_state(_policy(), current_generation=0).to_dict()

    assert document["approval_required"] is True
    assert document["mutation_authorized"] is False
    assert document["provider_execution_enabled"] is False
    assert document["production_mutation_enabled"] is False
