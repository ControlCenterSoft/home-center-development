from __future__ import annotations

import copy

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_store import build_household_snapshot
from home_center.policy_composer import (
    PolicyComposerError,
    build_policy_bundle,
    compose_policy_change_plan,
    confirm_policy_change_plan,
)
from home_center.policy_composer_contract import (
    policy_bundle_from_dict,
    policy_change_confirmation_from_dict,
    policy_change_plan_from_dict,
    policy_desired_state_from_dict,
)


def _values():
    household = Household(
        household_id="home-parser",
        members=(
            FamilyMember("parent-parser", "Родитель", HouseholdRole.PARENT),
            FamilyMember("child-parser", "Ребёнок", HouseholdRole.CHILD),
        ),
        devices=(),
    )
    snapshot = build_household_snapshot(household, generation=1, previous_snapshot_id=None)
    bundle = build_policy_bundle(HouseholdRole.CHILD, home_files_allowed=False)
    plan = compose_policy_change_plan(
        snapshot,
        actor_member_id="parent-parser",
        target_member_id="child-parser",
        target_bundle=bundle,
    )
    confirmation = confirm_policy_change_plan(snapshot, plan, actor_member_id="parent-parser")
    return bundle, plan, confirmation


def test_policy_contract_round_trip() -> None:
    bundle, plan, confirmation = _values()

    assert policy_bundle_from_dict(bundle.to_dict()) == bundle
    assert policy_desired_state_from_dict(plan.desired_state.to_dict()) == plan.desired_state
    assert policy_change_plan_from_dict(plan.to_dict()) == plan
    assert policy_change_confirmation_from_dict(confirmation.to_dict()) == confirmation


def test_bundle_parser_rejects_unknown_fields_and_forged_identity() -> None:
    bundle, _, _ = _values()
    unknown = bundle.to_dict()
    unknown["unexpected"] = True
    with pytest.raises(PolicyComposerError, match="invalid_policy_bundle"):
        policy_bundle_from_dict(unknown)

    forged = bundle.to_dict()
    forged["bundle_id"] = "hpb-000000000000000000000000"
    with pytest.raises(PolicyComposerError, match="policy_bundle_evidence_mismatch"):
        policy_bundle_from_dict(forged)


def test_desired_state_parser_rejects_authority_escalation() -> None:
    _, plan, _ = _values()
    value = plan.desired_state.to_dict()
    value["provider_execution_authorized"] = True
    with pytest.raises(PolicyComposerError, match="invalid_policy_desired_state"):
        policy_desired_state_from_dict(value)


def test_plan_parser_rejects_authority_and_recovery_tampering() -> None:
    _, plan, _ = _values()

    authority = plan.to_dict()
    authority["desired_state_write_authorized"] = True
    with pytest.raises(PolicyComposerError, match="invalid_policy_change_plan"):
        policy_change_plan_from_dict(authority)

    recovery = plan.to_dict()
    recovery["recovery_bundle_id"] = "hpb-000000000000000000000000"
    with pytest.raises(PolicyComposerError, match="invalid_policy_change_plan"):
        policy_change_plan_from_dict(recovery)

    desired = copy.deepcopy(plan.to_dict())
    desired["desired_state"]["desired_state_id"] = "hpds-000000000000000000000000"
    with pytest.raises(PolicyComposerError, match="policy_desired_state_evidence_mismatch"):
        policy_change_plan_from_dict(desired)


def test_confirmation_parser_rejects_execution_or_recovery_authority() -> None:
    _, _, confirmation = _values()

    for field in (
        "provider_execution_authorized",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
        "automatic_recovery_authorized",
    ):
        value = confirmation.to_dict()
        value[field] = True
        with pytest.raises(PolicyComposerError, match="invalid_policy_change_confirmation"):
            policy_change_confirmation_from_dict(value)
