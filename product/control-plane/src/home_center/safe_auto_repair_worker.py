"""Restart-safe worker orchestration for Home Center 0.64 safe auto-repair.

The worker starts only from an already durable typed repair Job. It never retries a
`running` Job because interruption after an external/local effect was started makes
the outcome uncertain. A `verifying` Job may resume authoritative read-back only.
An adapter result marked accepted is never user-visible success until matched
post-condition evidence is persisted through the Job lifecycle.
"""
from __future__ import annotations

from typing import Protocol

from .safe_auto_repair import SafeAutoRepairRecommendation
from .safe_auto_repair_adapter import SafeRepairAdapterRegistry, build_safe_repair_adapter_request
from .safe_auto_repair_job import (
    RepairExecutionOutcome,
    RepairJobState,
    SafeAutoRepairJob,
    SafeRepairJobError,
    record_safe_repair_execution,
    start_safe_repair_job,
    verify_safe_repair_post_condition,
)


class SafeRepairWorkerError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class SafeRepairJobRepository(Protocol):
    def get(self, job_id: str) -> SafeAutoRepairJob | None: ...

    def save(self, job: SafeAutoRepairJob, *, expected_state: RepairJobState) -> None: ...


class SafeRepairWorkerService:
    """Drive one persisted repair Job without implicit retry or authority expansion."""

    def __init__(self, repository: SafeRepairJobRepository, adapters: SafeRepairAdapterRegistry) -> None:
        if repository is None:
            raise SafeRepairWorkerError("safe_repair_worker_repository_invalid")
        if not isinstance(adapters, SafeRepairAdapterRegistry):
            raise SafeRepairWorkerError("safe_repair_worker_adapter_registry_invalid")
        self.repository = repository
        self.adapters = adapters

    def run(
        self,
        *,
        job_id: str,
        recommendation: SafeAutoRepairRecommendation,
        now_epoch: int,
    ) -> SafeAutoRepairJob:
        if not isinstance(job_id, str) or not job_id:
            raise SafeRepairWorkerError("safe_repair_worker_job_id_invalid")
        if not isinstance(recommendation, SafeAutoRepairRecommendation):
            raise SafeRepairWorkerError("safe_repair_worker_recommendation_invalid")
        if type(now_epoch) is not int or now_epoch < 0:
            raise SafeRepairWorkerError("safe_repair_worker_now_invalid")

        job = self.repository.get(job_id)
        if job is None:
            raise SafeRepairWorkerError("safe_repair_worker_job_missing")
        if job.recommendation_id != recommendation.recommendation_id:
            raise SafeRepairWorkerError("safe_repair_worker_recommendation_mismatch")

        if job.state is RepairJobState.SUCCEEDED:
            if not job.post_condition_verified or job.post_condition_evidence_sha256 is None:
                raise SafeRepairWorkerError("safe_repair_worker_success_evidence_invalid")
            return job
        if job.state is RepairJobState.FAILED:
            raise SafeRepairWorkerError("safe_repair_worker_job_failed")
        if job.state is RepairJobState.RECONCILE_REQUIRED:
            raise SafeRepairWorkerError("safe_repair_worker_reconciliation_required")
        if job.state is RepairJobState.RUNNING:
            # The process may have crashed after the adapter accepted or performed the
            # effect but before a receipt was durably recorded. Reinvocation is unsafe.
            raise SafeRepairWorkerError("safe_repair_worker_outcome_uncertain")

        request = build_safe_repair_adapter_request(job=job, recommendation=recommendation)
        adapter = self.adapters.require(request.action)

        if job.state is RepairJobState.ADMITTED:
            running = start_safe_repair_job(job, updated_at_epoch=now_epoch)
            self.repository.save(running, expected_state=RepairJobState.ADMITTED)
            result = adapter.execute(request)
            if result.job_id != job.job_id or result.recommendation_id != job.recommendation_id:
                raise SafeRepairWorkerError("safe_repair_worker_adapter_result_binding_invalid")
            if result.action is not request.action:
                raise SafeRepairWorkerError("safe_repair_worker_adapter_result_action_invalid")
            next_job = record_safe_repair_execution(
                running,
                outcome=result.outcome,
                effect_receipt_sha256=result.effect_receipt_sha256,
                updated_at_epoch=now_epoch,
            )
            self.repository.save(next_job, expected_state=RepairJobState.RUNNING)
            if next_job.state is RepairJobState.FAILED:
                raise SafeRepairWorkerError("safe_repair_worker_execution_failed")
            if next_job.state is RepairJobState.RECONCILE_REQUIRED:
                raise SafeRepairWorkerError("safe_repair_worker_reconciliation_required")
            job = next_job

        if job.state is not RepairJobState.VERIFYING:
            raise SafeRepairWorkerError("safe_repair_worker_job_state_invalid")

        observation = adapter.read_back(request)
        if observation.job_id != job.job_id or observation.recommendation_id != job.recommendation_id:
            raise SafeRepairWorkerError("safe_repair_worker_readback_binding_invalid")
        if observation.household_id != request.household_id or observation.resource_id != request.resource_id:
            raise SafeRepairWorkerError("safe_repair_worker_readback_target_invalid")
        completed = verify_safe_repair_post_condition(
            job,
            evidence_sha256=observation.observation_sha256,
            verified=observation.verified,
            updated_at_epoch=now_epoch,
        )
        self.repository.save(completed, expected_state=RepairJobState.VERIFYING)
        if completed.state is not RepairJobState.SUCCEEDED:
            raise SafeRepairWorkerError("safe_repair_worker_post_condition_failed")
        return completed


__all__ = ["SafeRepairJobRepository", "SafeRepairWorkerError", "SafeRepairWorkerService", "SafeRepairJobError"]
