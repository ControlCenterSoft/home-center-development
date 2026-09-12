from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole
from home_center.household_policy_composer import compose_policy_bundle, policy_resource_key
from home_center.household_policy_evidence import HouseholdPolicyEvidenceError, validate_policy_bundle_evidence
from home_center.household_store import build_household_snapshot


def _snapshot(household_id: str, target_member_id: str):
    household = Household(
        household_id=household_id,
        members=(
            FamilyMember(member_id="parent", display_name="Родитель", role=HouseholdRole.PARENT),
            FamilyMember(member_id=target_member_id, display_name="Ребёнок", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    return build_household_snapshot(household, generation=1, previous_snapshot_id=None)


def test_policy_resource_key_preserves_existing_safe_identity() -> None:
    assert policy_resource_key("home-main", "child") == "household-policy:home-main:child"


def test_policy_resource_key_cannot_alias_when_identifier_contains_delimiter() -> None:
    left = compose_policy_bundle(_snapshot("home:alpha", "child"), member_id="child")
    right = compose_policy_bundle(_snapshot("home", "alpha:child"), member_id="alpha:child")

    # The former raw concatenation produced the same durable key for these two
    # different resources: household-policy:home:alpha:child.
    assert f"household-policy:{left.household_id}:{left.member_id}" == f"household-policy:{right.household_id}:{right.member_id}"
    assert left.desired_state_resource_key != right.desired_state_resource_key
    assert ":hpk-" in left.desired_state_resource_key
    assert ":hpk-" in right.desired_state_resource_key
    assert len(left.desired_state_resource_key.rsplit(":hpk-", 1)[1]) == 64
    assert len(right.desired_state_resource_key.rsplit(":hpk-", 1)[1]) == 64

    assert validate_policy_bundle_evidence(
        left.to_dict(), expected_resource_key=left.desired_state_resource_key
    ) == left.to_dict()
    assert validate_policy_bundle_evidence(
        right.to_dict(), expected_resource_key=right.desired_state_resource_key
    ) == right.to_dict()


def test_policy_evidence_rejects_legacy_ambiguous_key_for_delimited_identity() -> None:
    bundle = compose_policy_bundle(_snapshot("home:alpha", "child"), member_id="child").to_dict()
    bundle["desired_state_resource_key"] = "household-policy:home:alpha:child"

    with pytest.raises(HouseholdPolicyEvidenceError):
        validate_policy_bundle_evidence(bundle)


def test_policy_bundle_schema_accepts_safe_and_hardened_resource_keys() -> None:
    schema = json.loads(
        Path("contracts/household/household-policy-bundle.v1.schema.json").read_text(encoding="utf-8")
    )
    pattern = schema["properties"]["desired_state_resource_key"]["pattern"]

    safe = policy_resource_key("home-main", "child")
    hardened = policy_resource_key("home:alpha", "child")
    assert re.fullmatch(pattern, safe)
    assert re.fullmatch(pattern, hardened)
    assert not re.fullmatch(pattern, "household-policy:home:alpha:child")
