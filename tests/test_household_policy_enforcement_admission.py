from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household_policy_enforcement_admission import (
    HouseholdPolicyEnforcementAdmissionError,
    evaluate_policy_enforcement_admission,
)

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64


def _plan() -> dict[str, object]:
    return {
        "schema": "home-center.household-policy-enforcement-plan.v1",
        "plan_id": "hpep-" + "1" * 24,
        "household_id": "household-1",
        "member_id": "member-1",
        "backend_id": "backend.example",
        "desired_generation": 4,
        "desired_plan_id": "hpcp-" + "2" * 24,
        "policy_id": "hcpol-" + "3" * 24,
        "policy_sha256": "4" * 64,
        "desired_state_sha256": "5" * 64,
        "backend_mutation_authorized": False,
        "automatic_retry_authorized": False,
        "enforcement_success_claim_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _evaluate(**overrides: object):
    values: dict[str, object] = {
        "plan": _plan(),
        "backend_version": "1.2.3",
        "backend_capability_evidence_sha256": DIGEST,
        "explicit_confirmation": True,
        "actor_authority_current": True,
        "scoped_reauth_current": True,
        "desired_state_current": True,
        "backend_registered": True,
        "backend_mutation_capable": True,
        "backend_readback_capable": True,
        "backend_qualification_current": True,
    }
    values.update(overrides)
    return evaluate_policy_enforcement_admission(**values)


def test_ready_decision_never_creates_execution_or_success_authority() -> None:
    decision = _evaluate()
    assert decision.ready is True
    assert decision.blockers == ()
    document = decision.to_dict()
    assert document["post_condition_verification_required"] is True
    assert document["fresh_revalidation_required"] is True
    assert document["automatic_retry_authorized"] is False
    assert document["execution_authorized"] is False
    assert document["enforcement_success_claim_authorized"] is False
    assert document["infrastructure_mutation_authorized"] is False
    assert document["external_publication_authorized"] is False


def test_scoped_reauth_and_independent_readback_are_mandatory() -> None:
    decision = _evaluate(scoped_reauth_current=False, backend_readback_capable=False)
    assert decision.ready is False
    assert decision.blockers == (
        "scoped_reauth_required",
        "backend_readback_capability_missing",
    )


def test_all_missing_evidence_is_reported_deterministically() -> None:
    decision = _evaluate(
        explicit_confirmation=False,
        actor_authority_current=False,
        scoped_reauth_current=False,
        desired_state_current=False,
        backend_registered=False,
        backend_mutation_capable=False,
        backend_readback_capable=False,
        backend_qualification_current=False,
    )
    assert decision.ready is False
    assert decision.blockers == (
        "explicit_confirmation_required",
        "actor_authority_stale_or_missing",
        "scoped_reauth_required",
        "desired_state_stale_or_mismatched",
        "backend_not_registered",
        "backend_mutation_capability_missing",
        "backend_readback_capability_missing",
        "backend_qualification_stale_or_mismatched",
    )


def test_existing_plan_cannot_smuggle_authority_into_admission() -> None:
    plan = _plan()
    plan["backend_mutation_authorized"] = True
    with pytest.raises(
        HouseholdPolicyEnforcementAdmissionError,
        match="household_policy_enforcement_admission_plan_invalid",
    ):
        _evaluate(plan=plan)


def test_admission_rejects_foreign_or_malformed_exact_plan_identity() -> None:
    plan = _plan()
    plan["desired_state_sha256"] = "not-a-digest"
    with pytest.raises(HouseholdPolicyEnforcementAdmissionError):
        _evaluate(plan=plan)

    plan = _plan()
    plan["unexpected"] = "field"
    with pytest.raises(HouseholdPolicyEnforcementAdmissionError):
        _evaluate(plan=plan)


def test_admission_requires_strict_boolean_evidence() -> None:
    with pytest.raises(
        HouseholdPolicyEnforcementAdmissionError,
        match="household_policy_enforcement_admission_input_invalid",
    ):
        _evaluate(scoped_reauth_current=1)


def test_decision_matches_closed_public_contract() -> None:
    schema = json.loads(
        (ROOT / "contracts/household/household-policy-enforcement-admission.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(_evaluate().to_dict())
    validator.validate(_evaluate(scoped_reauth_current=False).to_dict())


def test_contract_rejects_false_ready_with_no_blockers() -> None:
    schema = json.loads(
        (ROOT / "contracts/household/household-policy-enforcement-admission.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    document = _evaluate().to_dict()
    document["ready"] = False
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(document)
