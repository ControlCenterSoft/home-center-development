from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from home_center.safe_auto_repair import RepairAction, RepairCandidate, RepairRisk, SafeRepairPolicy, evaluate_safe_auto_repair
from home_center.safe_auto_repair_adapter import PostConditionState, SafeRepairAdapterResult, SafeRepairPostConditionObservation, build_safe_repair_adapter_request
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_job import RepairExecutionOutcome, build_safe_repair_job

ROOT = Path(__file__).resolve().parents[1]


def _objects():
    candidate = RepairCandidate(household_id="household-1", resource_id="derived-index-1", resource_generation=3, evidence_sha256="a" * 64, action=RepairAction.REBUILD_DERIVED_INDEX, risk=RepairRisk.LOW, recovery_proven=True, post_condition_verifiable=True)
    policy = SafeRepairPolicy(policy_id="policy-1", policy_sha256="b" * 64, allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}), allowed_risks=frozenset({RepairRisk.LOW}))
    reviewed = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    admission = evaluate_safe_auto_repair_admission(reviewed=reviewed, current_candidate=candidate, current_policy=policy)
    job = build_safe_repair_job(admission=admission, idempotency_key="repair-contract-001", created_at_epoch=100)
    request = build_safe_repair_adapter_request(job=job, recommendation=reviewed)
    result = SafeRepairAdapterResult(job_id=job.job_id, recommendation_id=reviewed.recommendation_id, action=candidate.action, outcome=RepairExecutionOutcome.ACCEPTED, effect_receipt_sha256="c" * 64)
    observation = SafeRepairPostConditionObservation(job_id=job.job_id, recommendation_id=reviewed.recommendation_id, household_id=candidate.household_id, resource_id=candidate.resource_id, observed_generation=4, observation_sha256="d" * 64, state=PostConditionState.MATCHED)
    return request, result, observation


def _schema(name: str):
    return json.loads((ROOT / "contracts/automation" / name).read_text(encoding="utf-8"))


def test_adapter_request_result_and_post_condition_match_closed_contracts() -> None:
    request, result, observation = _objects()
    jsonschema.Draft202012Validator(_schema("safe-auto-repair-adapter-request.v1.schema.json")).validate(request.to_dict())
    jsonschema.Draft202012Validator(_schema("safe-auto-repair-adapter-result.v1.schema.json")).validate(result.to_dict())
    jsonschema.Draft202012Validator(_schema("safe-auto-repair-post-condition.v1.schema.json")).validate(observation.to_dict())


def test_post_condition_contract_rejects_false_success_projection() -> None:
    _, _, observation = _objects()
    invalid = dict(observation.to_dict())
    invalid["state"] = "unknown"
    validator = jsonschema.Draft202012Validator(_schema("safe-auto-repair-post-condition.v1.schema.json"))
    errors = list(validator.iter_errors(invalid))
    assert errors
