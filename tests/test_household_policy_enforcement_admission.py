from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household_policy_enforcement_admission import (
    HouseholdPolicyEnforcementAdmissionError,
    build_policy_enforcement_plan,
    evaluate_policy_enforcement_admission,
    policy_enforcement_plan_from_dict,
)
from home_center.util import canonical_json


ROOT = Path(__file__).resolve().parents[1]


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _desired() -> dict[str, object]:
    policy = {
        "schema": "home-center.household-composed-policy.v1",
        "policy_id": "hcpol-0123456789abcdef01234567",
        "household_id": "household-1",
        "member_id": "member-1",
        "role": "child",
        "base_policy_id": "policy-base-1",
        "bundle_id": "hpb-0123456789abcdef01234567",
        "internet_policy": "filtered",
        "vpn_allowed": False,
        "managed_device_required": True,
        "home_files_allowed": False,
        "smart_home_control_allowed": False,
        "administration_allowed": False,
        "external_publication_allowed": False,
        "enforcement_verified": False,
        "production_mutation_enabled": False,
        "explanation_ru": "Интернет с семейной фильтрацией.",
    }
    return {
        "schema": "home-center.household-policy-desired-state.v1",
        "household_id": "household-1",
        "member_id": "member-1",
        "generation": 3,
        "plan_id": "hpcp-0123456789abcdef01234567",
        "policy": policy,
        "policy_sha256": _sha(policy),
        "reason": "Apply family policy",
        "enforcement_verified": False,
        "reconciliation_required": True,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _plan():
    return build_policy_enforcement_plan(
        desired_state=_desired(),
        backend_id="policy-backend.example",
        backend_version="1.0.0",
        backend_capability_evidence_sha256="a" * 64,
    )


def test_plan_is_deterministic_exact_bound_and_non_authorizing() -> None:
    first = _plan()
    second = _plan()
    assert first == second
    value = first.to_dict()
    assert value["desired_generation"] == 3
    assert value["policy_id"] == "hcpol-0123456789abcdef01234567"
    assert value["desired_state_sha256"] == _sha(_desired())
    assert value["backend_capability_evidence_sha256"] == "a" * 64
    assert value["post_condition_verification_required"] is True
    assert value["fresh_revalidation_required"] is True
    assert value["automatic_retry_authorized"] is False
    assert value["execution_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False


def test_desired_policy_digest_tamper_fails_closed() -> None:
    desired = _desired()
    desired["policy_sha256"] = "b" * 64
    with pytest.raises(
        HouseholdPolicyEnforcementAdmissionError,
        match="household_policy_policy_digest_mismatch",
    ):
        build_policy_enforcement_plan(
            desired_state=desired,
            backend_id="policy-backend.example",
            backend_version="1.0.0",
            backend_capability_evidence_sha256="a" * 64,
        )


def test_plan_round_trip_rejects_tampered_plan_identity() -> None:
    value = _plan().to_dict()
    parsed = policy_enforcement_plan_from_dict(value)
    assert parsed.to_dict() == value

    tampered = dict(value)
    tampered["backend_version"] = "2.0.0"
    with pytest.raises(
        HouseholdPolicyEnforcementAdmissionError,
        match="household_policy_enforcement_plan_invalid",
    ):
        policy_enforcement_plan_from_dict(tampered)


def test_ready_admission_still_does_not_grant_execution_authority() -> None:
    decision = evaluate_policy_enforcement_admission(
        plan=_plan(),
        explicit_confirmation=True,
        actor_authority_current=True,
        scoped_reauth_current=True,
        desired_state_current=True,
        backend_registered=True,
        backend_mutation_capable=True,
        backend_readback_capable=True,
        backend_capability_evidence_current=True,
    )
    assert decision.ready is True
    assert decision.blockers == ()
    value = decision.to_dict()
    assert value["execution_authorized"] is False
    assert value["automatic_retry_authorized"] is False
    assert value["post_condition_verification_required"] is True
    assert value["fresh_revalidation_required"] is True
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False


def test_admission_collects_independent_blockers_without_partial_authority() -> None:
    decision = evaluate_policy_enforcement_admission(
        plan=_plan(),
        explicit_confirmation=False,
        actor_authority_current=True,
        scoped_reauth_current=False,
        desired_state_current=False,
        backend_registered=True,
        backend_mutation_capable=True,
        backend_readback_capable=False,
        backend_capability_evidence_current=False,
    )
    assert decision.ready is False
    assert decision.blockers == (
        "explicit_confirmation_required",
        "scoped_reauth_required",
        "desired_state_stale_or_mismatched",
        "backend_readback_capability_missing",
        "backend_capability_evidence_stale_or_mismatched",
    )
    assert decision.execution_authorized is False


def test_plan_and_decision_match_closed_contracts() -> None:
    plan_schema = json.loads(
        (
            ROOT
            / "contracts/household/household-policy-enforcement-plan.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    decision_schema = json.loads(
        (
            ROOT
            / "contracts/household/household-policy-enforcement-admission.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(plan_schema).validate(_plan().to_dict())
    jsonschema.Draft202012Validator(decision_schema).validate(
        evaluate_policy_enforcement_admission(
            plan=_plan(),
            explicit_confirmation=True,
            actor_authority_current=True,
            scoped_reauth_current=True,
            desired_state_current=True,
            backend_registered=True,
            backend_mutation_capable=True,
            backend_readback_capable=True,
            backend_capability_evidence_current=True,
        ).to_dict()
    )
