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
from home_center.safe_auto_repair_adapter import (
    PostConditionState,
    SafeRepairAdapterResult,
    SafeRepairPostConditionObservation,
)
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_job import (
    RepairExecutionOutcome,
    build_safe_repair_job,
    record_safe_repair_execution,
    start_safe_repair_job,
)
from home_center.safe_auto_repair_verification import evaluate_safe_repair_post_condition


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = "c" * 64
OBSERVATION = "d" * 64


def _fixture():
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=7,
        evidence_sha256="a" * 64,
        action=RepairAction.REBUILD_DERIVED_INDEX,
        risk=RepairRisk.LOW,
        recovery_proven=True,
        post_condition_verifiable=True,
    )
    policy = SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256="b" * 64,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )
    recommendation = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    admission = evaluate_safe_auto_repair_admission(
        reviewed=recommendation,
        current_candidate=candidate,
        current_policy=policy,
    )
    job = build_safe_repair_job(
        admission=admission,
        idempotency_key="repair-verify-001",
        created_at_epoch=100,
    )
    running = start_safe_repair_job(job, updated_at_epoch=110)
    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256=RECEIPT,
        updated_at_epoch=120,
    )
    result = SafeRepairAdapterResult(
        job_id=verifying.job_id,
        recommendation_id=recommendation.recommendation_id,
        action=candidate.action,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256=RECEIPT,
    )
    observation = SafeRepairPostConditionObservation(
        job_id=verifying.job_id,
        recommendation_id=recommendation.recommendation_id,
        household_id=candidate.household_id,
        resource_id=candidate.resource_id,
        observed_generation=candidate.resource_generation,
        observation_sha256=OBSERVATION,
        state=PostConditionState.MATCHED,
    )
    return candidate, recommendation, verifying, result, observation


def test_exact_matched_observation_verifies_without_claiming_repair_success() -> None:
    _candidate, recommendation, job, result, observation = _fixture()
    decision = evaluate_safe_repair_post_condition(
        job=job,
        recommendation=recommendation,
        result=result,
        observation=observation,
    )
    assert decision.verified is True
    assert decision.blockers == ()
    payload = decision.to_dict()
    assert payload["repair_success_claimed"] is False
    assert payload["execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["generic_infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False


def test_adapter_matched_label_with_wrong_generation_fails_closed() -> None:
    candidate, recommendation, job, result, _observation = _fixture()
    wrong = SafeRepairPostConditionObservation(
        job_id=job.job_id,
        recommendation_id=recommendation.recommendation_id,
        household_id=candidate.household_id,
        resource_id=candidate.resource_id,
        observed_generation=candidate.resource_generation + 1,
        observation_sha256=OBSERVATION,
        state=PostConditionState.MATCHED,
    )
    assert wrong.verified is True
    decision = evaluate_safe_repair_post_condition(
        job=job,
        recommendation=recommendation,
        result=result,
        observation=wrong,
    )
    assert decision.verified is False
    assert decision.blockers == ("observation_generation_mismatch",)


def test_mismatched_or_unknown_observation_never_verifies() -> None:
    candidate, recommendation, job, result, _observation = _fixture()
    for state in (PostConditionState.MISMATCHED, PostConditionState.UNKNOWN):
        observation = SafeRepairPostConditionObservation(
            job_id=job.job_id,
            recommendation_id=recommendation.recommendation_id,
            household_id=candidate.household_id,
            resource_id=candidate.resource_id,
            observed_generation=candidate.resource_generation,
            observation_sha256=OBSERVATION,
            state=state,
        )
        decision = evaluate_safe_repair_post_condition(
            job=job,
            recommendation=recommendation,
            result=result,
            observation=observation,
        )
        assert decision.verified is False
        assert "post_condition_not_matched" in decision.blockers


def test_result_receipt_and_acceptance_are_bound_to_exact_verifying_job() -> None:
    candidate, recommendation, job, _result, observation = _fixture()
    wrong_result = SafeRepairAdapterResult(
        job_id=job.job_id,
        recommendation_id=recommendation.recommendation_id,
        action=candidate.action,
        outcome=RepairExecutionOutcome.FAILED,
        effect_receipt_sha256="e" * 64,
    )
    decision = evaluate_safe_repair_post_condition(
        job=job,
        recommendation=recommendation,
        result=wrong_result,
        observation=observation,
    )
    assert decision.verified is False
    assert "result_not_accepted" in decision.blockers
    assert "effect_receipt_mismatch" in decision.blockers


def test_observation_target_identity_is_exact_bound() -> None:
    candidate, recommendation, job, result, _observation = _fixture()
    wrong = SafeRepairPostConditionObservation(
        job_id=job.job_id,
        recommendation_id=recommendation.recommendation_id,
        household_id="another-household",
        resource_id="another-resource",
        observed_generation=candidate.resource_generation,
        observation_sha256=OBSERVATION,
        state=PostConditionState.MATCHED,
    )
    decision = evaluate_safe_repair_post_condition(
        job=job,
        recommendation=recommendation,
        result=result,
        observation=wrong,
    )
    assert decision.verified is False
    assert decision.blockers == (
        "observation_household_mismatch",
        "observation_resource_mismatch",
    )


def test_verification_evidence_is_deterministic_and_schema_closed() -> None:
    _candidate, recommendation, job, result, observation = _fixture()
    first = evaluate_safe_repair_post_condition(
        job=job,
        recommendation=recommendation,
        result=result,
        observation=observation,
    )
    second = evaluate_safe_repair_post_condition(
        job=job,
        recommendation=recommendation,
        result=result,
        observation=observation,
    )
    assert first.verification_evidence_sha256 == second.verification_evidence_sha256
    schema = json.loads(
        (ROOT / "contracts/automation/safe-auto-repair-verification-decision.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(first.to_dict())
