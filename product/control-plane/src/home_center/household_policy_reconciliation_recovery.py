"""Crash recovery for durable Home Center 0.59 policy reconciliation evidence.

This module finalizes only reconciliation attempts that already persisted exact,
read-only Actual State evidence before an interruption.  Recovery never calls a
backend adapter, never mutates protected policy Desired State, and never grants
infrastructure or external-publication authority.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .household_policy_reconciliation import (
    EVIDENCE_SCHEMA,
    HouseholdPolicyReconciliationError,
    request_from_dict,
)
from .household_policy_reconciliation_runtime import (
    ACTION,
    COMPLETION_SCHEMA,
    FAILURE_SCHEMA,
    STATE_KEY_PREFIX,
    STATE_SCHEMA,
)
from .household_policy_runtime import DESIRED_KEY_PREFIX
from .store import StateStore
from .util import canonical_json

RECOVERY_EVIDENCE_SCHEMA = (
    "home-center.household-policy-reconciliation-recovery-evidence.v1"
)
RECOVERY_FAILURE_SCHEMA = (
    "home-center.household-policy-reconciliation-recovery-failure.v1"
)


class HouseholdPolicyReconciliationRecoveryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _validate_evidence(
    *,
    evidence: object,
    request: object,
) -> dict[str, object]:
    if not isinstance(evidence, dict) or evidence.get("schema") != EVIDENCE_SCHEMA:
        raise HouseholdPolicyReconciliationRecoveryError(
            "household_policy_reconciliation_recovery_evidence_invalid"
        )
    if (
        evidence.get("request_id") != request.request_id
        or evidence.get("backend_id") != request.backend_id
        or evidence.get("binding") != request.binding.to_dict()
        or evidence.get("status") not in {"verified", "mismatch", "pending", "blocked"}
        or evidence.get("backend_mutation_performed") is not False
        or evidence.get("infrastructure_mutation_performed") is not False
        or evidence.get("external_publication_performed") is not False
    ):
        raise HouseholdPolicyReconciliationRecoveryError(
            "household_policy_reconciliation_recovery_evidence_invalid"
        )
    verified = evidence.get("status") == "verified"
    if (
        evidence.get("enforcement_verified") is not verified
        or evidence.get("reconciliation_required") is not (not verified)
    ):
        raise HouseholdPolicyReconciliationRecoveryError(
            "household_policy_reconciliation_recovery_evidence_invalid"
        )
    evidence_id = evidence.get("evidence_id")
    if (
        not isinstance(evidence_id, str)
        or not evidence_id.startswith("hpev-")
        or len(evidence_id) != 29
    ):
        raise HouseholdPolicyReconciliationRecoveryError(
            "household_policy_reconciliation_recovery_evidence_invalid"
        )
    return dict(evidence)


class HouseholdPolicyReconciliationRecoveryService:
    """Finalize interrupted evidence-persisted reconciliation without backend replay."""

    def __init__(self, store: StateStore) -> None:
        self.store = store

    def _state_keys(self) -> tuple[str, ...]:
        connection = getattr(self.store, "_connection", None)
        lock = getattr(self.store, "_lock", None)
        if connection is None or lock is None:
            return ()
        with lock:
            rows = connection.execute(
                "SELECT key FROM cluster_meta WHERE key LIKE ? ORDER BY key",
                (STATE_KEY_PREFIX + "%",),
            ).fetchall()
        return tuple(str(row["key"]) for row in rows)

    def recover_incomplete(self) -> int:
        recovered = 0
        for state_key in self._state_keys():
            envelope = self.store.get_meta(state_key)
            if (
                not isinstance(envelope, dict)
                or envelope.get("schema") != STATE_SCHEMA
                or envelope.get("status") != "evidence-persisted"
            ):
                continue
            try:
                self._recover_one(state_key=state_key, envelope=envelope)
            except HouseholdPolicyReconciliationRecoveryError as exc:
                self._block_recovery(
                    state_key=state_key,
                    envelope=envelope,
                    code=exc.code,
                )
                continue
            recovered += 1
        return recovered

    def _recover_one(
        self,
        *,
        state_key: str,
        envelope: dict[str, Any],
    ) -> None:
        try:
            request = request_from_dict(envelope.get("request"))
        except HouseholdPolicyReconciliationError as exc:
            raise HouseholdPolicyReconciliationRecoveryError(
                "household_policy_reconciliation_recovery_request_invalid"
            ) from exc

        job_id = envelope.get("job_id")
        actor = envelope.get("actor")
        member_id = envelope.get("member_id")
        if (
            not isinstance(job_id, str)
            or not job_id
            or not isinstance(actor, str)
            or not actor
            or member_id != request.binding.member_id
        ):
            raise HouseholdPolicyReconciliationRecoveryError(
                "household_policy_reconciliation_recovery_state_invalid"
            )

        evidence = _validate_evidence(
            evidence=envelope.get("evidence"),
            request=request,
        )
        desired_key = (
            DESIRED_KEY_PREFIX
            + request.binding.household_id
            + "."
            + request.binding.member_id
        )
        desired = self.store.get_meta(desired_key)
        expected_desired_sha256 = envelope.get("desired_state_sha256")
        if (
            not isinstance(desired, dict)
            or not isinstance(expected_desired_sha256, str)
            or _digest(desired) != expected_desired_sha256
            or desired.get("generation") != request.binding.desired_generation
            or desired.get("plan_id") != request.binding.desired_plan_id
            or desired.get("policy_sha256") != request.binding.policy_sha256
            or not isinstance(desired.get("policy"), dict)
            or desired["policy"].get("policy_id") != request.binding.policy_id
            or desired.get("enforcement_verified") is not False
            or desired.get("reconciliation_required") is not True
        ):
            raise HouseholdPolicyReconciliationRecoveryError(
                "household_policy_reconciliation_recovery_desired_state_stale"
            )

        job = self.store.job(job_id)
        if (
            not isinstance(job, dict)
            or job.get("job_type") != ACTION
            or job.get("state") != "verifying"
            or job.get("idempotency_key") != request.request_id
        ):
            raise HouseholdPolicyReconciliationRecoveryError(
                "household_policy_reconciliation_recovery_job_state_invalid"
            )

        completion = {
            "schema": COMPLETION_SCHEMA,
            "state": evidence["status"],
            "request_id": request.request_id,
            "backend_id": request.backend_id,
            "member_id": request.binding.member_id,
            "job_id": job_id,
            "evidence": evidence,
            "desired_state_transition_performed": False,
            "backend_mutation_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }
        self.store.transition_action_job(
            job_id,
            expected_state="verifying",
            new_state="succeeded",
            evidence={
                "schema": RECOVERY_EVIDENCE_SCHEMA,
                "request_id": request.request_id,
                "reconciliation_evidence": evidence,
                "desired_state_transition_performed": False,
                "backend_reinvoked": False,
                "recovered_after_interruption": True,
            },
            steps=[
                {"step": "backend-read-back", "state": "succeeded"},
                {"step": "re-read-exact-desired-state", "state": "succeeded"},
                {"step": "verify-actual-state", "state": "succeeded"},
                {"step": "persist-reconciliation-evidence", "state": "succeeded"},
            ],
        )
        completed = dict(envelope)
        completed.update(status="completed", completion=completion)
        self.store.set_meta(state_key, completed)
        if self.store.get_meta(state_key) != completed:
            raise HouseholdPolicyReconciliationRecoveryError(
                "household_policy_reconciliation_recovery_state_readback_failed"
            )
        self.store.audit(
            actor="system:recovery",
            action=ACTION + ".recover",
            target=request.binding.member_id,
            outcome=str(evidence["status"]),
            correlation_id="recovery-" + request.request_id,
            details={
                "request_id": request.request_id,
                "backend_id": request.backend_id,
                "evidence_id": evidence["evidence_id"],
                "recovered_after_interruption": True,
                "backend_reinvoked": False,
                "desired_state_transition_performed": False,
            },
        )

    def _block_recovery(
        self,
        *,
        state_key: str,
        envelope: dict[str, Any],
        code: str,
    ) -> None:
        job_id = envelope.get("job_id")
        failure = {
            "schema": RECOVERY_FAILURE_SCHEMA,
            "code": code,
            "backend_reinvoked": False,
            "desired_state_transition_performed": False,
            "backend_mutation_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }
        if isinstance(job_id, str):
            job = self.store.job(job_id)
            if isinstance(job, dict) and job.get("state") == "verifying":
                self.store.transition_action_job(
                    job_id,
                    expected_state="verifying",
                    new_state="failed",
                    evidence=failure,
                )
        failed = dict(envelope)
        failed.update(status="failed", evidence=failure)
        self.store.set_meta(state_key, failed)
