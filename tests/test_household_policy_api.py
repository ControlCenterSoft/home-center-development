from __future__ import annotations

import pytest

from home_center.household_policy_api import (
    HouseholdPolicyAPIError,
    cozy_policy_projection,
    full_policy_projection,
    parse_policy_confirm_request,
    parse_policy_plan_request,
)
from home_center.household_policy_runtime import CONFIRM_REQUEST_SCHEMA, PLAN_REQUEST_SCHEMA


def _bundle():
    return {
        "internet_policy": "filtered",
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": True,
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
    }


def _desired():
    return {
        "schema": "home-center.household-policy-desired-state.v1",
        "household_id": "home",
        "member_id": "member-child",
        "generation": 2,
        "plan_id": "hpcp-" + "a" * 24,
        "policy_sha256": "b" * 64,
        "reason": "family policy",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
        "policy": {
            "schema": "home-center.household-composed-policy.v1",
            "policy_id": "hcpol-" + "c" * 24,
            "household_id": "home",
            "member_id": "member-child",
            "role": "child",
            "base_policy_id": "hpol-" + "d" * 24,
            "bundle_id": "hpb-" + "e" * 24,
            "internet_policy": "filtered",
            "vpn_allowed": False,
            "managed_device_required": True,
            "home_files_allowed": True,
            "smart_home_control_allowed": False,
            "administration_allowed": False,
            "external_publication_allowed": False,
            "enforcement_verified": False,
            "production_mutation_enabled": False,
            "explanation_ru": "интернет с семейной фильтрацией; VPN запрещён.",
        },
    }


def test_plan_and_confirm_parsers_are_closed_and_normalize_reason() -> None:
    parsed = parse_policy_plan_request(
        {
            "schema": PLAN_REQUEST_SCHEMA,
            "subject_member_id": "member-child",
            "bundle": _bundle(),
            "reason": "  семейный режим  ",
        }
    )
    assert parsed["reason"] == "семейный режим"
    assert parsed["bundle"] == _bundle()

    confirm = parse_policy_confirm_request(
        {
            "schema": CONFIRM_REQUEST_SCHEMA,
            "plan_id": "hpcp-" + "a" * 24,
            "confirmed": True,
        }
    )
    assert confirm["confirmed"] is True

    with pytest.raises(HouseholdPolicyAPIError):
        parse_policy_plan_request({**parsed, "client_role": "parent"})
    with pytest.raises(HouseholdPolicyAPIError):
        parse_policy_confirm_request({**confirm, "confirmed": False})


def test_cozy_projection_never_claims_enforcement_success() -> None:
    projection = cozy_policy_projection(_desired())
    assert projection["title"] == "Правила сохранены"
    assert projection["status"] == "Ожидают применения и проверки"
    assert projection["enforcement_verified"] is False
    assert projection["reconciliation_required"] is True
    assert "применены" not in projection["status"].lower()


def test_full_projection_preserves_exact_policy_and_negative_authority() -> None:
    desired = _desired()
    projection = full_policy_projection(desired)
    assert projection["generation"] == 2
    assert projection["policy"] == desired["policy"]
    assert projection["enforcement_verified"] is False
    assert projection["infrastructure_mutation_authorized"] is False
    assert projection["external_publication_authorized"] is False


def test_projection_rejects_false_success_state() -> None:
    desired = _desired()
    desired["enforcement_verified"] = True
    with pytest.raises(HouseholdPolicyAPIError):
        cozy_policy_projection(desired)
    with pytest.raises(HouseholdPolicyAPIError):
        full_policy_projection(desired)
