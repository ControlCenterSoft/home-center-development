from __future__ import annotations

import sqlite3

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
from home_center.safe_auto_repair_job import RepairExecutionOutcome, RepairJobState, build_safe_repair_job
from home_center.safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository
from home_center.safe_auto_repair_worker import SafeRepairWorkerService


class _Adapter:
    action = RepairAction.REBUILD_DERIVED_INDEX

    def __init__(self) -> None:
        self.execute_calls = 0
        self.read_back_calls = 0

    def execute(self, request):
        self.execute_calls += 1
        return SafeRepairAdapterResult(
            job_id=request.job_id,
            recommendation_id=request.recommendation_id,
            action=request.action,
            outcome=RepairExecutionOutcome.ACCEPTED,
            effect_receipt_sha256="c" * 64,
        )

    def read_back(self, request):
        self.read_back_calls += 1
        return SafeRepairPostConditionObservation(
            job_id=request.job_id,
            recommendation_id=request.recommendation_id,
            household_id=request.household_id,
            resource_id=request.resource_id,
            observed_generation=request.resource_generation,
            observation_sha256="d" * 64,
            state=PostConditionState.MATCHED,
        )


def _recommendation_and_job():
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
    return recommendation, build_safe_repair_job(
        admission=admission,
        idempotency_key="sqlite-worker-0640",
        created_at_epoch=100,
    )


def test_restart_safe_worker_uses_sqlite_repository_with_exact_timestamp_cas() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(SQLiteSafeAutoRepairJobRepository.schema_sql())
    repository = SQLiteSafeAutoRepairJobRepository(connection)
    recommendation, job = _recommendation_and_job()
    assert repository.create(job) is True

    adapter = _Adapter()
    adapters = SafeRepairAdapterRegistry()
    adapters.register(adapter)
    worker = SafeRepairWorkerService(repository, adapters)

    completed = worker.run(
        job_id=job.job_id,
        recommendation=recommendation,
        now_epoch=110,
    )
    assert completed.state is RepairJobState.SUCCEEDED
    assert completed.post_condition_verified is True
    assert adapter.execute_calls == 1
    assert adapter.read_back_calls == 1
    assert repository.get(job.job_id) == completed

    replay = worker.run(
        job_id=job.job_id,
        recommendation=recommendation,
        now_epoch=120,
    )
    assert replay == completed
    assert adapter.execute_calls == 1
    assert adapter.read_back_calls == 1
    connection.close()
