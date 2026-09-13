"""Restart-safe worker orchestration for Home Center 0.63 QR effects.

The worker starts only from an already durable typed QR effect Job. It recovers the
exact handoff/admission evidence from StateStore, re-reads the authoritative current
Household state under the canonical StateStore lock and delegates to the qualified
execution/read-back boundary.

Preflight Jobs may execute once. Verifying Jobs may resume read-back only. Running
Jobs are treated as outcome-uncertain and are never automatically reinvoked. A
verified succeeded Job is returned idempotently without touching the effect again.
"""
from __future__ import annotations

import re

from .household_runtime import HOUSEHOLD_STATE_KEY, HouseholdRuntimeError, _state_from_dict
from .qr_onboarding_effect_admission import (
    QrOnboardingEffectAdmissionError,
    QrOnboardingEffectAdmissionService,
)
from .qr_onboarding_effect_execution import (
    QrOnboardingEffectExecutionError,
    QrOnboardingEffectExecutionService,
)
from .store import StateStore

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class QrOnboardingEffectWorkerError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QrOnboardingEffectWorkerService:
    """Drive one durable QR effect Job without broadening its authority."""

    def __init__(self, store: StateStore, execution: QrOnboardingEffectExecutionService) -> None:
        if not isinstance(store, StateStore):
            raise QrOnboardingEffectWorkerError("qr_effect_worker_store_invalid")
        if not isinstance(execution, QrOnboardingEffectExecutionService) or execution.store is not store:
            raise QrOnboardingEffectWorkerError("qr_effect_worker_execution_invalid")
        self.store = store
        self.execution = execution
        self.admissions = QrOnboardingEffectAdmissionService(store)

    def _current_snapshot(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise QrOnboardingEffectWorkerError("qr_effect_worker_household_not_configured")
        try:
            snapshot, _bindings = _state_from_dict(raw)
        except HouseholdRuntimeError as exc:
            raise QrOnboardingEffectWorkerError("qr_effect_worker_household_state_invalid") from exc
        return snapshot

    def run(self, *, actor: str, correlation_id: str, job_id: str) -> dict[str, object]:
        if not isinstance(actor, str) or not actor:
            raise QrOnboardingEffectWorkerError("qr_effect_worker_actor_invalid")
        if not isinstance(correlation_id, str) or not correlation_id:
            raise QrOnboardingEffectWorkerError("qr_effect_worker_correlation_invalid")
        if not isinstance(job_id, str) or _ID.fullmatch(job_id) is None:
            raise QrOnboardingEffectWorkerError("qr_effect_worker_job_id_invalid")

        # Household revalidation and the local product-state mutation/read-back share
        # the canonical StateStore RLock. This prevents a same-process Household
        # replacement from racing the exact-state execution boundary.
        with self.store._lock:  # noqa: SLF001 - canonical same-package state boundary
            try:
                admission, handoff = self.admissions.recover(job_id)
            except QrOnboardingEffectAdmissionError as exc:
                raise QrOnboardingEffectWorkerError(exc.code) from exc
            snapshot = self._current_snapshot()
            job = self.store.job(job_id)
            if job is None:
                raise QrOnboardingEffectWorkerError("qr_effect_worker_job_missing")
            state = job.get("state")

            if state == "preflight":
                return self.execution.execute_and_verify(
                    actor=actor,
                    correlation_id=correlation_id,
                    admission=admission,
                    handoff=handoff,
                    current_snapshot=snapshot,
                )
            if state == "verifying":
                return self.execution.reconcile_verifying(
                    actor=actor,
                    correlation_id=correlation_id,
                    admission=admission,
                    handoff=handoff,
                    current_snapshot=snapshot,
                )
            if state == "succeeded":
                evidence = job.get("evidence")
                if not isinstance(evidence, dict) or evidence.get("post_condition_verified") is not True:
                    raise QrOnboardingEffectWorkerError("qr_effect_worker_success_evidence_invalid")
                return job
            if state == "running":
                raise QrOnboardingEffectWorkerError("qr_effect_worker_outcome_uncertain")
            if state == "failed":
                raise QrOnboardingEffectWorkerError("qr_effect_worker_job_failed")
            raise QrOnboardingEffectWorkerError("qr_effect_worker_job_state_invalid")


__all__ = [
    "QrOnboardingEffectWorkerError",
    "QrOnboardingEffectWorkerService",
    "QrOnboardingEffectExecutionError",
]
