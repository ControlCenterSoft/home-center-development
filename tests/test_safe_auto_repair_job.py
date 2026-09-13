from __future__ import annotations

import json
from pathlib import Path

import jsonschema
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
    SafeRepairJobError,
    build_safe_repair_job,
    record_safe_repair_execution,
    start_safe_repair_job,
    verify_safe_repair_post_condition,
)

ROOT = Path(__file__).resolve().parents[1]


def admission():
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
    reviewed = evaluate_safe_auto_repair(candidate=candidate, policy=policy)
    return evaluate_safe_auto_repair_admission(
        reviewed=reviewed,
        current_candidate=candidate,
        current_policy=policy,
    )


def test_job_identity_is_deterministic_and_raw_idempotency_key_is_not_persisted() -> None:
    first = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-001", created_at_epoch=100
    )
    replay = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-001", created_at_epoch=200
    )
    assert first.job_id == replay.job_id
    assert first.idempotency_key_sha256 == replay.idempotency_key_sha256
    assert "repair-request-001" not in json.dumps(first.to_dict(), sort_keys=True)
    assert first.to_dict()["raw_idempotency_key_persisted"] is False


def test_accepted_effect_requires_separate_post_condition_verification() -> None:
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-002", created_at_epoch=100
    )
    running = start_safe_repair_job(job, updated_at_epoch=110)
    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    assert verifying.state is RepairJobState.VERIFYING
    assert verifying.post_condition_verified is False
    success = verify_safe_repair_post_condition(
        verifying,
        evidence_sha256="d" * 64,
        verified=True,
        updated_at_epoch=130,
    )
    assert success.state is RepairJobState.SUCCEEDED
    assert success.post_condition_verified is True


def test_failed_post_condition_never_becomes_success() -> None:
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-003", created_at_epoch=100
    )
    verifying = record_safe_repair_execution(
        start_safe_repair_job(job, updated_at_epoch=110),
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    failed = verify_safe_repair_post_condition(
        verifying,
        evidence_sha256="d" * 64,
        verified=False,
        updated_at_epoch=130,
    )
    assert failed.state is RepairJobState.FAILED
    assert failed.post_condition_verified is False


def test_ambiguous_execution_requires_reconciliation_and_has_no_automatic_retry() -> None:
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-004", created_at_epoch=100
    )
    ambiguous = record_safe_repair_execution(
        start_safe_repair_job(job, updated_at_epoch=110),
        outcome=RepairExecutionOutcome.AMBIGUOUS,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    assert ambiguous.state is RepairJobState.RECONCILE_REQUIRED
    assert ambiguous.to_dict()["automatic_retry_authorized"] is False
    with pytest.raises(SafeRepairJobError, match="safe_repair_job_verification_state_invalid"):
        verify_safe_repair_post_condition(
            ambiguous,
            evidence_sha256="d" * 64,
            verified=True,
            updated_at_epoch=130,
        )


def test_transition_timestamps_never_move_backwards() -> None:
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-006", created_at_epoch=100
    )
    with pytest.raises(SafeRepairJobError, match="safe_repair_job_updated_at_non_monotonic"):
        start_safe_repair_job(job, updated_at_epoch=99)

    running = start_safe_repair_job(job, updated_at_epoch=110)
    with pytest.raises(SafeRepairJobError, match="safe_repair_job_updated_at_non_monotonic"):
        record_safe_repair_execution(
            running,
            outcome=RepairExecutionOutcome.ACCEPTED,
            effect_receipt_sha256="c" * 64,
            updated_at_epoch=109,
        )

    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=120,
    )
    with pytest.raises(SafeRepairJobError, match="safe_repair_job_updated_at_non_monotonic"):
        verify_safe_repair_post_condition(
            verifying,
            evidence_sha256="d" * 64,
            verified=True,
            updated_at_epoch=119,
        )


def test_equal_timestamp_is_allowed_for_deterministic_same_tick_transitions() -> None:
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-007", created_at_epoch=100
    )
    running = start_safe_repair_job(job, updated_at_epoch=100)
    verifying = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=100,
    )
    success = verify_safe_repair_post_condition(
        verifying,
        evidence_sha256="d" * 64,
        verified=True,
        updated_at_epoch=100,
    )
    assert success.state is RepairJobState.SUCCEEDED
    assert success.updated_at_epoch == 100


def test_job_contract_is_closed_and_authority_remains_false() -> None:
    job = build_safe_repair_job(
        admission=admission(), idempotency_key="repair-request-005", created_at_epoch=100
    )
    payload = job.to_dict()
    schema = json.loads(
        (ROOT / "contracts/automation/safe-auto-repair-job.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(payload)
    assert payload["execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False
