from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_admission import (
    RepairAdmissionBlocker,
    evaluate_safe_auto_repair_admission,
)

ROOT = Path(__file__).resolve().parents[1]


def candidate(*, generation: int = 1, risk: RepairRisk = RepairRisk.LOW) -> RepairCandidate:
    return RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=generation,
        evidence_sha256="a" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=risk,
        recovery_proven=True,
        post_condition_verifiable=True,
    )


def policy(*, digest: str = "b" * 64) -> SafeRepairPolicy:
    return SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256=digest,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )


def test_exact_current_revalidation_is_admissible_but_not_executable() -> None:
    reviewed = evaluate_safe_auto_repair(candidate=candidate(), policy=policy())
    decision = evaluate_safe_auto_repair_admission(
        reviewed=reviewed,
        current_candidate=candidate(),
        current_policy=policy(),
    )
    payload = decision.to_dict()
    assert decision.admissible_for_job is True
    assert decision.blockers == ()
    assert payload["durable_job_required"] is True
    assert payload["execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False


def test_generation_drift_blocks_admission() -> None:
    reviewed = evaluate_safe_auto_repair(candidate=candidate(), policy=policy())
    decision = evaluate_safe_auto_repair_admission(
        reviewed=reviewed,
        current_candidate=candidate(generation=2),
        current_policy=policy(),
    )
    assert decision.admissible_for_job is False
    assert RepairAdmissionBlocker.CURRENT_RECOMMENDATION_CHANGED in decision.blockers


def test_policy_drift_blocks_admission() -> None:
    reviewed = evaluate_safe_auto_repair(candidate=candidate(), policy=policy())
    decision = evaluate_safe_auto_repair_admission(
        reviewed=reviewed,
        current_candidate=candidate(),
        current_policy=policy(digest="c" * 64),
    )
    assert decision.admissible_for_job is False
    assert RepairAdmissionBlocker.CURRENT_RECOMMENDATION_CHANGED in decision.blockers


def test_reviewed_or_current_ineligible_state_fails_closed() -> None:
    reviewed_blocked = evaluate_safe_auto_repair(
        candidate=candidate(risk=RepairRisk.HIGH), policy=policy()
    )
    blocked = evaluate_safe_auto_repair_admission(
        reviewed=reviewed_blocked,
        current_candidate=candidate(risk=RepairRisk.HIGH),
        current_policy=policy(),
    )
    assert RepairAdmissionBlocker.REVIEWED_RECOMMENDATION_NOT_ELIGIBLE in blocked.blockers
    assert RepairAdmissionBlocker.CURRENT_RECOMMENDATION_NOT_ELIGIBLE in blocked.blockers
    assert blocked.admissible_for_job is False


def test_admission_matches_closed_contract() -> None:
    reviewed = evaluate_safe_auto_repair(candidate=candidate(), policy=policy())
    decision = evaluate_safe_auto_repair_admission(
        reviewed=reviewed,
        current_candidate=candidate(),
        current_policy=policy(),
    )
    schema = json.loads(
        (ROOT / "contracts/automation/safe-auto-repair-admission.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(decision.to_dict())
