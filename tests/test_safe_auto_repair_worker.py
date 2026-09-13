from __future__ import annotations

import pytest

from home_center.safe_auto_repair import (
    RepairAction,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)
from home_center.safe_auto_repair_adapter import (
    PostConditionState,
    SafeRepairAdapterRegistry,
    SafeRepairAdapterResult,
    SafeRepairPostConditionObservation,
)
from home_center.safe_auto_repair_admission import evaluate_safe_auto_repair_admission
from home_center.safe_auto_repair_job import (
    RepairExecutionOutcome,
    RepairJobState,
    build_safe_repair_job,
    record_safe_repair_execution,
    start_safe_repair_job,
)
from home_center.safe_auto_repair_worker import SafeRepairWorkerError, SafeRepairWorkerService


class Repository:
    def __init__(self, job):
        self.job = job

    def get(self, job_id):
        return self.job if self.job.job_id == job_id else None

    def save(self, job, *, expected_state):
        assert self.job.state is expected_state
        self.job = job


class Adapter:
    action = RepairAction.REBUILD_DERIVED_INDEX

    def __init__(
        self,
        *,
        outcome=RepairExecutionOutcome.ACCEPTED,
        readback=PostConditionState.MATCHED,
        fail_execute=False,
        generation_delta=0,
    ):
        self.outcome = outcome
        self.readback = readback
        self.fail_execute = fail_execute
        self.generation_delta = generation_delta
        self.execute_calls = 0
        self.read_calls = 0

    def execute(self, request):
        self.execute_calls += 1
        if self.fail_execute:
            raise RuntimeError("transport-lost")
        return SafeRepairAdapterResult(
            job_id=request.job_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            outcome=self.outcome,
            effect_receipt_sha256="c" * 64,
        )

    def read_back(self, request):
        self.read_calls += 1
        return SafeRepairPostConditionObservation(
            job_id=request.job_id,
            recommendation_id=request.recommendation_id,
            household_id=request.household_id,
            resource_id=request.resource_id,
            observed_generation=request.resource_generation + self.generation_delta,
            observation_sha256="d" * 64,
            state=self.readback,
        )


def setup(
    *,
    outcome=RepairExecutionOutcome.ACCEPTED,
    readback=PostConditionState.MATCHED,
    fail_execute=False,
    generation_delta=0,
):
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
        idempotency_key="repair-worker-test-001",
        created_at_epoch=100,
    )
    repository = Repository(job)
    adapter = Adapter(
        outcome=outcome,
        readback=readback,
        fail_execute=fail_execute,
        generation_delta=generation_delta,
    )
    registry = SafeRepairAdapterRegistry()
    registry.register(adapter)
    return SafeRepairWorkerService(repository, registry), repository, adapter, recommendation


def test_worker_executes_once_then_requires_exact_verified_readback_for_success() -> None:
    worker, repository, adapter, recommendation = setup()
    completed = worker.run(
        job_id=repository.job.job_id,
        recommendation=recommendation,
        now_epoch=110,
    )
    assert completed.state is RepairJobState.SUCCEEDED
    assert completed.post_condition_verified is True
    assert completed.post_condition_evidence_sha256 is not None
    assert adapter.execute_calls == 1
    assert adapter.read_calls == 1

    replay = worker.run(
        job_id=repository.job.job_id,
        recommendation=recommendation,
        now_epoch=120,
    )
    assert replay.state is RepairJobState.SUCCEEDED
    assert adapter.execute_calls == 1
    assert adapter.read_calls == 1


def test_crash_after_running_persistence_never_reinvokes_action_adapter() -> None:
    worker, repository, adapter, recommendation = setup(fail_execute=True)
    with pytest.raises(RuntimeError, match="transport-lost"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=110)
    assert repository.job.state is RepairJobState.RUNNING
    assert adapter.execute_calls == 1

    with pytest.raises(SafeRepairWorkerError, match="safe_repair_worker_outcome_uncertain"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=120)
    assert adapter.execute_calls == 1
    assert adapter.read_calls == 0


def test_verifying_restart_resumes_readback_without_second_execution() -> None:
    worker, repository, adapter, recommendation = setup()
    running = start_safe_repair_job(repository.job, updated_at_epoch=110)
    repository.job = record_safe_repair_execution(
        running,
        outcome=RepairExecutionOutcome.ACCEPTED,
        effect_receipt_sha256="c" * 64,
        updated_at_epoch=111,
    )

    completed = worker.run(
        job_id=repository.job.job_id,
        recommendation=recommendation,
        now_epoch=120,
    )
    assert completed.state is RepairJobState.SUCCEEDED
    assert adapter.execute_calls == 0
    assert adapter.read_calls == 1


def test_unknown_readback_persists_failed_without_false_success() -> None:
    worker, repository, adapter, recommendation = setup(readback=PostConditionState.UNKNOWN)
    with pytest.raises(SafeRepairWorkerError, match="safe_repair_worker_post_condition_failed"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=110)
    assert repository.job.state is RepairJobState.FAILED
    assert repository.job.post_condition_verified is False
    assert repository.job.post_condition_evidence_sha256 is not None


def test_matched_label_with_wrong_generation_still_fails_exact_bound_verification() -> None:
    worker, repository, adapter, recommendation = setup(generation_delta=1)
    with pytest.raises(SafeRepairWorkerError, match="safe_repair_worker_post_condition_failed"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=110)
    assert repository.job.state is RepairJobState.FAILED
    assert repository.job.post_condition_verified is False
    assert adapter.execute_calls == 1
    assert adapter.read_calls == 1


def test_ambiguous_adapter_result_requires_reconciliation_without_retry() -> None:
    worker, repository, adapter, recommendation = setup(outcome=RepairExecutionOutcome.AMBIGUOUS)
    with pytest.raises(SafeRepairWorkerError, match="safe_repair_worker_reconciliation_required"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=110)
    assert repository.job.state is RepairJobState.RECONCILE_REQUIRED
    assert adapter.execute_calls == 1

    with pytest.raises(SafeRepairWorkerError, match="safe_repair_worker_reconciliation_required"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=120)
    assert adapter.execute_calls == 1
    assert adapter.read_calls == 0


def test_explicit_failed_adapter_result_is_terminal_and_not_retried() -> None:
    worker, repository, adapter, recommendation = setup(outcome=RepairExecutionOutcome.FAILED)
    with pytest.raises(SafeRepairWorkerError, match="safe_repair_worker_execution_failed"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=110)
    assert repository.job.state is RepairJobState.FAILED
    assert adapter.execute_calls == 1

    with pytest.raises(SafeRepairWorkerError, match="safe_repair_worker_job_failed"):
        worker.run(job_id=repository.job.job_id, recommendation=recommendation, now_epoch=120)
    assert adapter.execute_calls == 1
