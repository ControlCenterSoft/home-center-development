from __future__ import annotations

import pytest

from home_center.safe_auto_repair import RepairAction, RepairCandidate, RepairRisk, SafeRepairPolicy, evaluate_safe_auto_repair
from home_center.safe_auto_repair_adapter import PostConditionState, SafeRepairAdapterError, SafeRepairAdapterRegistry, SafeRepairAdapterResult, SafeRepairPostConditionObservation, build_safe_repair_adapter_request
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_job import RepairExecutionOutcome, build_safe_repair_job


def _pair():
    candidate = RepairCandidate(household_id="household-1", resource_id="derived-index-1", resource_generation=3, evidence_sha256="a" * 64, action=RepairAction.REBUILD_DERIVED_INDEX, risk=RepairRisk.LOW, recovery_proven=True, post_condition_verifiable=True)
    policy = SafeRepairPolicy(policy_id="policy-1", policy_sha256="b" * 64, allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}), allowed_risks=frozenset({RepairRisk.LOW}))
    reviewed = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    admission = evaluate_safe_auto_repair_admission(reviewed=reviewed, current_candidate=candidate, current_policy=policy)
    job = build_safe_repair_job(admission=admission, idempotency_key="repair-adapter-test-001", created_at_epoch=100)
    return job, reviewed


def test_adapter_request_has_no_generic_authority() -> None:
    job, reviewed = _pair()
    request = build_safe_repair_adapter_request(job=job, recommendation=reviewed)
    payload = request.to_dict()
    assert request.resource_generation == 3
    assert payload["credential_value_access_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["generic_infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False


def test_registry_fails_closed_for_unavailable_and_duplicate_adapter() -> None:
    class Adapter:
        action = RepairAction.REBUILD_DERIVED_INDEX
    registry = SafeRepairAdapterRegistry()
    with pytest.raises(SafeRepairAdapterError, match="safe_repair_adapter_unavailable"):
        registry.require(RepairAction.REBUILD_DERIVED_INDEX)
    adapter = Adapter()
    registry.register(adapter)
    assert registry.require(RepairAction.REBUILD_DERIVED_INDEX) is adapter
    with pytest.raises(SafeRepairAdapterError, match="safe_repair_adapter_duplicate"):
        registry.register(adapter)


def test_adapter_acceptance_never_claims_post_condition_success() -> None:
    job, reviewed = _pair()
    request = build_safe_repair_adapter_request(job=job, recommendation=reviewed)
    result = SafeRepairAdapterResult(job_id=request.job_id, recommendation_id=request.recommendation_id, action=request.action, outcome=RepairExecutionOutcome.ACCEPTED, effect_receipt_sha256="c" * 64)
    assert result.to_dict()["post_condition_verified"] is False
    assert result.to_dict()["automatic_retry_authorized"] is False


def test_only_matched_readback_is_verified() -> None:
    matched = SafeRepairPostConditionObservation(job_id="hcrpj-aaaaaaaaaaaaaaaaaaaaaaaa", recommendation_id="hcrpr-bbbbbbbbbbbbbbbbbbbbbbbb", household_id="household-1", resource_id="derived-index-1", observed_generation=4, observation_sha256="d" * 64, state=PostConditionState.MATCHED)
    unknown = SafeRepairPostConditionObservation(job_id=matched.job_id, recommendation_id=matched.recommendation_id, household_id=matched.household_id, resource_id=matched.resource_id, observed_generation=4, observation_sha256="e" * 64, state=PostConditionState.UNKNOWN)
    assert matched.verified is True
    assert unknown.verified is False
