from __future__ import annotations

from dataclasses import replace

import pytest

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_job import (
    RepairExecutionOutcome,
    RepairJobState,
    build_safe_repair_job,
    record_safe_repair_execution,
    start_safe_repair_job,
    verify_safe_repair_post_condition,
)
from home_center.safe_auto_repair_projection import (
    SafeRepairHistoryProjectionError,
    project_safe_repair_history_entry,
)


def _entry_and_job():
    candidate = RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=1,
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
        idempotency_key="projection-test-0640",
        created_at_epoch=100,
    )
    return {"recommendation": recommendation.to_dict(), "recorded_at_epoch": 90}, job


def test_only_verified_terminal_job_is_fixed() -> None:
    entry, job = _entry_and_job()
    assert project_safe_repair_history_entry(entry)["status"] == "suggested"
    running = start_safe_repair_job(job, updated_at_epoch=110)
    assert project_safe_repair_history_entry(entry, job=running)["status"] == "in-progress"
    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    assert project_safe_repair_history_entry(entry, job=verifying)["status"] == "verifying"
    succeeded = verify_safe_repair_post_condition(
        verifying,
        evidence_sha256="d" * 64,
        verified=True,
        updated_at_epoch=130,
    )
    result = project_safe_repair_history_entry(entry, job=succeeded)
    assert result["status"] == "fixed"
    assert result["repair_verified"] is True
    assert result["post_condition_evidence_sha256"] == "d" * 64


def test_projection_rejects_mismatch_and_authority_tampering() -> None:
    entry, job = _entry_and_job()
    mismatched = replace(job, recommendation_id="hcrpr-other")
    with pytest.raises(SafeRepairHistoryProjectionError, match="safe_repair_history_job_binding_invalid"):
        project_safe_repair_history_entry(entry, job=mismatched)

    entry["recommendation"]["execution_authorized"] = True
    with pytest.raises(SafeRepairHistoryProjectionError, match="safe_repair_history_authority_invalid"):
        project_safe_repair_history_entry(entry)


def test_projection_rejects_shape_drift() -> None:
    entry, _ = _entry_and_job()
    del entry["recommendation"]["repair_history_required"]
    with pytest.raises(SafeRepairHistoryProjectionError, match="safe_repair_history_fields_invalid"):
        project_safe_repair_history_entry(entry)
