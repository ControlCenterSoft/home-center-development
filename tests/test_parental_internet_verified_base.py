from __future__ import annotations

import hashlib

import pytest

from home_center.household import FamilyMember, Household, HouseholdRole, effective_policy
from home_center.household_policy_composer import build_policy_bundle, compose_policy
from home_center.parental_internet_verified_base import (
    ParentalInternetVerifiedBaseError,
    verified_parental_policy_base_from_dict,
)
from home_center.util import canonical_json


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _policy():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(),
    )
    base = effective_policy(household, "child")
    bundle = build_policy_bundle(
        role=HouseholdRole.CHILD,
        value={
            "internet_policy": "filtered",
            "vpn_allowed": False,
            "managed_device_required": True,
            "home_files_allowed": True,
            "smart_home_control_allowed": False,
            "administration_allowed": False,
            "external_publication_allowed": False,
        },
    )
    return compose_policy(base=base, bundle=bundle)


def _verified():
    policy = _policy().to_dict()
    policy_sha = _digest(policy)
    desired = {
        "schema": "home-center.household-policy-desired-state.v1",
        "household_id": "home",
        "member_id": "child",
        "generation": 3,
        "plan_id": "hpcp-" + "a" * 24,
        "policy": policy,
        "policy_sha256": policy_sha,
        "reason": "family policy",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
    return {
        "schema": "home-center.household-policy-verified-desired-state.v1",
        "household_id": "home",
        "member_id": "child",
        "desired_generation": 3,
        "desired_plan_id": desired["plan_id"],
        "policy_id": policy["policy_id"],
        "policy_sha256": policy_sha,
        "source_desired_state_sha256": _digest(desired),
        "request_id": "hprq-" + "b" * 24,
        "backend_id": "parental-base-test",
        "evidence_id": "hpev-" + "c" * 24,
        "evidence_sha256": "d" * 64,
        "observed_at": "2026-09-13T00:00:00Z",
        "enforcement_verified": True,
        "reconciliation_required": False,
        "backend_mutation_performed": False,
        "infrastructure_mutation_performed": False,
        "external_publication_performed": False,
        "desired_state": desired,
    }


def test_verified_child_policy_is_accepted_and_content_bound() -> None:
    raw = _verified()
    verified = verified_parental_policy_base_from_dict(raw)
    assert verified.household_id == "home"
    assert verified.member_id == "child"
    assert verified.policy.policy_id == raw["policy_id"]
    assert verified.policy_sha256 == raw["policy_sha256"]
    assert verified.source_desired_state_sha256 == raw["source_desired_state_sha256"]
    assert verified.verified_state_sha256 == _digest(raw)
    assert verified.policy.vpn_allowed is False
    assert verified.policy.managed_device_required is True


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("enforcement_verified", False, "parental_verified_base_not_verified"),
        ("reconciliation_required", True, "parental_verified_base_not_verified"),
        ("backend_mutation_performed", True, "parental_verified_base_not_verified"),
        ("infrastructure_mutation_performed", True, "parental_verified_base_not_verified"),
        ("external_publication_performed", True, "parental_verified_base_not_verified"),
        ("policy_sha256", "e" * 64, "parental_verified_base_binding_mismatch"),
        ("source_desired_state_sha256", "e" * 64, "parental_verified_base_binding_mismatch"),
        ("member_id", "other-child", "parental_verified_base_binding_mismatch"),
    ],
)
def test_tampered_verified_state_is_rejected(field, value, code) -> None:
    raw = _verified()
    raw[field] = value
    with pytest.raises(ParentalInternetVerifiedBaseError, match=code):
        verified_parental_policy_base_from_dict(raw)


def test_nested_desired_policy_tamper_breaks_exact_binding() -> None:
    raw = _verified()
    raw["desired_state"]["policy"]["home_files_allowed"] = False
    with pytest.raises(ParentalInternetVerifiedBaseError):
        verified_parental_policy_base_from_dict(raw)


def test_unverified_nested_desired_state_is_rejected() -> None:
    raw = _verified()
    raw["desired_state"]["enforcement_verified"] = True
    with pytest.raises(
        ParentalInternetVerifiedBaseError,
        match="parental_verified_base_desired_state_invalid",
    ):
        verified_parental_policy_base_from_dict(raw)
