"""Durable read-only Actual State reconciliation runtime for Home Center 0.59.

This layer composes the already-qualified Policy Composer Desired State with the
transport-neutral reconciliation contracts.  It can only observe a deliberately
read-only backend.  Verified evidence is persisted durably before a Job is marked
successful, but this slice intentionally does not flip the protected Desired State
verification flags and grants no backend, infrastructure, or publication authority.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Any, Protocol

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_policy_reconciliation import (
    EVIDENCE_SCHEMA,
    HouseholdPolicyReconciliationError,
    PolicyActualStateObservation,
    PolicyReconciliationRequest,
    build_reconciliation_request,
    observation_from_dict,
    verify_policy_reconciliation,
)
from .household_policy_runtime import DESIRED_KEY_PREFIX
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now

STATE_SCHEMA = "home-center.household-policy-reconciliation-runtime-state.v1"
COMPLETION_SCHEMA = "home-center.household-policy-reconciliation-runtime-completion.v1"
FAILURE_SCHEMA = "home-center.household-policy-reconciliation-runtime-failure.v1"
ACTION = "household.policy.actual-state.reconcile"
STATE_KEY_PREFIX = "cozy.household.policy.reconciliation."
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")


class HouseholdPolicyReconciliationRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class HouseholdPolicyReadBackAdapter(Protocol):
    reconciliation_read_only: bool

    def read_back(self, request: dict[str, object]) -> object: ...


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _key(request_id: object) -> str:
    if (
        not isinstance(request_id, str)
        or not request_id.startswith("hprq-")
        or len(request_id) != 29
        or any(char not in "0123456789abcdef" for char in request_id.removeprefix("hprq-"))
    ):
        raise HouseholdPolicyReconciliationRuntimeError(
            "invalid_household_policy_reconciliation_request_id"
        )
    return STATE_KEY_PREFIX + request_id


class HouseholdPolicyReconciliationRuntimeService:
    """Execute one exact, read-only reconciliation observation durably."""

    def __init__(self, store: StateStore, *, now=utc_now) -> None:
        self.store = store
        self._now = now
        self._lock = threading.RLock()
        self._adapters: dict[str, HouseholdPolicyReadBackAdapter] = {}

    def register_adapter(self, backend_id: str, adapter: object) -> None:
        if (
            not isinstance(backend_id, str)
            or IDENTIFIER.fullmatch(backend_id) is None
            or backend_id in self._adapters
            or getattr(adapter, "reconciliation_read_only", None) is not True
            or not callable(getattr(adapter, "read_back", None))
        ):
            raise HouseholdPolicyReconciliationRuntimeError(
                "invalid_household_policy_reconciliation_adapter_registration"
            )
        self._adapters[backend_id] = adapter  # type: ignore[assignment]

    def _state(self) -> tuple[object, tuple[object, ...]]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyReconciliationRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyReconciliationRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor_member(actor: str, snapshot: object, bindings: tuple[object, ...]) -> str:
        member_id = next(
            (
                item.member_id
                for item in bindings
                if getattr(item, "actor", None) == actor
            ),
            None,
        )
        if member_id is None:
            raise HouseholdPolicyReconciliationRuntimeError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, member_id)  # type: ignore[attr-defined]
        except HomeServiceCatalogError as exc:
            raise HouseholdPolicyReconciliationRuntimeError(exc.code) from exc
        if not policy.administration_allowed or policy.role is not HouseholdRole.PARENT:
            raise HouseholdPolicyReconciliationRuntimeError(
                "household_policy_reconciliation_not_authorized"
            )
        return member_id

    def _desired(
        self,
        *,
        actor: str,
        member_id: str,
        backend_id: str,
        requested_at: str,
        max_observed_age_seconds: int,
    ) -> tuple[dict[str, object], PolicyReconciliationRequest]:
        snapshot, bindings = self._state()
        self._actor_member(actor, snapshot, bindings)
        try:
            snapshot.household.member(member_id)  # type: ignore[attr-defined]
        except HomeServiceCatalogError as exc:
            raise HouseholdPolicyReconciliationRuntimeError(exc.code) from exc
        household_id = snapshot.household_id  # type: ignore[attr-defined]
        desired = self.store.get_meta(DESIRED_KEY_PREFIX + household_id + "." + member_id)
        if not isinstance(desired, dict):
            raise HouseholdPolicyReconciliationRuntimeError(
                "household_policy_desired_state_not_found"
            )
        try:
            request = build_reconciliation_request(
                desired_state=desired,
                backend_id=backend_id,
                requested_at=requested_at,
                max_observed_age_seconds=max_observed_age_seconds,
            )
        except HouseholdPolicyReconciliationError as exc:
            raise HouseholdPolicyReconciliationRuntimeError(exc.code) from exc
        if (
            request.binding.household_id != household_id
            or request.binding.member_id != member_id
        ):
            raise HouseholdPolicyReconciliationRuntimeError(
                "household_policy_reconciliation_binding_mismatch"
            )
        return dict(desired), request

    def _adapter(self, backend_id: str) -> HouseholdPolicyReadBackAdapter:
        adapter = self._adapters.get(backend_id)
        if adapter is None:
            raise HouseholdPolicyReconciliationRuntimeError(
                "household_policy_reconciliation_adapter_unavailable"
            )
        return adapter

    def reconcile(
        self,
        *,
        actor: str,
        member_id: str,
        backend_id: str,
        max_observed_age_seconds: int,
        correlation_id: str,
    ) -> dict[str, object]:
        with self._lock:
            requested_at = self._now()
            original_desired, request = self._desired(
                actor=actor,
                member_id=member_id,
                backend_id=backend_id,
                requested_at=requested_at,
                max_observed_age_seconds=max_observed_age_seconds,
            )
            state_key = _key(request.request_id)
            existing = self.store.get_meta(state_key)
            if isinstance(existing, dict) and existing.get("schema") == STATE_SCHEMA:
                completion = existing.get("completion")
                if existing.get("status") == "completed" and isinstance(completion, dict):
                    return dict(completion)
                if existing.get("request") != request.to_dict():
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_state_invalid"
                    )
                if existing.get("status") in {"running", "verifying", "evidence-persisted"}:
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_in_progress"
                    )
                if existing.get("status") == "failed":
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_previous_attempt_failed"
                    )

            adapter = self._adapter(backend_id)
            request_hash = _digest(
                {
                    "action": ACTION,
                    "actor": actor,
                    "member_id": member_id,
                    "request": request.to_dict(),
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="read-only policy Actual State reconciliation",
                    idempotency_key=request.request_id,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.household-policy-reconciliation-preflight.v1",
                        "request_id": request.request_id,
                        "backend_id": backend_id,
                        "member_id": member_id,
                        "desired_generation": request.binding.desired_generation,
                        "policy_sha256": request.binding.policy_sha256,
                        "backend_read_only_required": True,
                        "backend_mutation_authorized": False,
                        "infrastructure_mutation_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "backend-read-back", "state": "pending"},
                        {"step": "re-read-exact-desired-state", "state": "pending"},
                        {"step": "verify-actual-state", "state": "pending"},
                        {"step": "persist-reconciliation-evidence", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise HouseholdPolicyReconciliationRuntimeError(
                    "household_policy_reconciliation_idempotency_conflict"
                ) from exc

            if not created:
                if isinstance(existing, dict) and existing.get("status") == "completed":
                    completion = existing.get("completion")
                    if isinstance(completion, dict):
                        return dict(completion)
                raise HouseholdPolicyReconciliationRuntimeError(
                    "household_policy_reconciliation_job_state_invalid"
                )

            envelope: dict[str, object] = {
                "schema": STATE_SCHEMA,
                "status": "running",
                "actor": actor,
                "member_id": member_id,
                "request": request.to_dict(),
                "desired_state_sha256": _digest(original_desired),
                "job_id": job["job_id"],
                "observation": None,
                "evidence": None,
                "completion": None,
            }
            self.store.set_meta(state_key, envelope)
            running = self.store.transition_action_job(
                job["job_id"], expected_state="preflight", new_state="running"
            )

            try:
                raw_observation = adapter.read_back(request.to_dict())
                observation = observation_from_dict(raw_observation)
            except HouseholdPolicyReconciliationError as exc:
                self._fail(
                    state_key=state_key,
                    envelope=envelope,
                    job_id=running["job_id"],
                    expected_state="running",
                    code=exc.code,
                )
                raise HouseholdPolicyReconciliationRuntimeError(exc.code) from exc
            except Exception as exc:
                code = "household_policy_reconciliation_backend_read_failed"
                self._fail(
                    state_key=state_key,
                    envelope=envelope,
                    job_id=running["job_id"],
                    expected_state="running",
                    code=code,
                )
                raise HouseholdPolicyReconciliationRuntimeError(code) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result=observation.to_dict(),
                steps=[
                    {"step": "backend-read-back", "state": "succeeded"},
                    {"step": "re-read-exact-desired-state", "state": "running"},
                    {"step": "verify-actual-state", "state": "pending"},
                    {"step": "persist-reconciliation-evidence", "state": "pending"},
                ],
            )
            envelope = dict(envelope)
            envelope.update(status="verifying", observation=observation.to_dict())
            self.store.set_meta(state_key, envelope)

            try:
                fresh_desired, fresh_request = self._desired(
                    actor=actor,
                    member_id=member_id,
                    backend_id=backend_id,
                    requested_at=requested_at,
                    max_observed_age_seconds=max_observed_age_seconds,
                )
                if (
                    fresh_desired != original_desired
                    or fresh_request.to_dict() != request.to_dict()
                    or _digest(fresh_desired) != envelope.get("desired_state_sha256")
                ):
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_desired_state_stale"
                    )
                evidence = verify_policy_reconciliation(
                    request=request,
                    observation=observation,
                    trusted_now=self._now(),
                )
                if evidence.get("schema") != EVIDENCE_SCHEMA:
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_evidence_invalid"
                    )
            except HouseholdPolicyReconciliationRuntimeError as exc:
                self._fail(
                    state_key=state_key,
                    envelope=envelope,
                    job_id=verifying["job_id"],
                    expected_state="verifying",
                    code=exc.code,
                )
                raise
            except HouseholdPolicyReconciliationError as exc:
                self._fail(
                    state_key=state_key,
                    envelope=envelope,
                    job_id=verifying["job_id"],
                    expected_state="verifying",
                    code=exc.code,
                )
                raise HouseholdPolicyReconciliationRuntimeError(exc.code) from exc

            persisted = dict(envelope)
            persisted.update(status="evidence-persisted", evidence=evidence)
            self.store.set_meta(state_key, persisted)
            if self.store.get_meta(state_key) != persisted:
                self._fail(
                    state_key=state_key,
                    envelope=persisted,
                    job_id=verifying["job_id"],
                    expected_state="verifying",
                    code="household_policy_reconciliation_evidence_readback_failed",
                )
                raise HouseholdPolicyReconciliationRuntimeError(
                    "household_policy_reconciliation_evidence_readback_failed"
                )

            completion = {
                "schema": COMPLETION_SCHEMA,
                "state": evidence["status"],
                "request_id": request.request_id,
                "backend_id": backend_id,
                "member_id": member_id,
                "job_id": verifying["job_id"],
                "evidence": evidence,
                "desired_state_transition_performed": False,
                "backend_mutation_performed": False,
                "infrastructure_mutation_performed": False,
                "external_publication_performed": False,
            }
            self.store.transition_action_job(
                verifying["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.household-policy-reconciliation-completion-evidence.v1",
                    "request_id": request.request_id,
                    "reconciliation_evidence": evidence,
                    "desired_state_transition_performed": False,
                    "backend_reinvoked": False,
                },
                steps=[
                    {"step": "backend-read-back", "state": "succeeded"},
                    {"step": "re-read-exact-desired-state", "state": "succeeded"},
                    {"step": "verify-actual-state", "state": "succeeded"},
                    {"step": "persist-reconciliation-evidence", "state": "succeeded"},
                ],
            )
            completed = dict(persisted)
            completed.update(status="completed", completion=completion)
            self.store.set_meta(state_key, completed)
            self.store.audit(
                actor=actor,
                action=ACTION,
                target=member_id,
                outcome=str(evidence["status"]),
                correlation_id=correlation_id,
                details={
                    "request_id": request.request_id,
                    "backend_id": backend_id,
                    "evidence_id": evidence["evidence_id"],
                    "enforcement_verified": evidence["enforcement_verified"],
                    "reconciliation_required": evidence["reconciliation_required"],
                    "desired_state_transition_performed": False,
                    "backend_mutation_performed": False,
                    "infrastructure_mutation_performed": False,
                    "external_publication_performed": False,
                },
            )
            return completion

    def _fail(
        self,
        *,
        state_key: str,
        envelope: dict[str, object],
        job_id: str,
        expected_state: str,
        code: str,
    ) -> None:
        failure = {
            "schema": FAILURE_SCHEMA,
            "code": code,
            "backend_mutation_performed": False,
            "desired_state_transition_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }
        job = self.store.job(job_id)
        if job is not None and job.get("state") == expected_state:
            kwargs: dict[str, object] = {"result": failure} if expected_state == "running" else {"evidence": failure}
            self.store.transition_action_job(
                job_id,
                expected_state=expected_state,
                new_state="failed",
                **kwargs,
            )
        failed = dict(envelope)
        failed.update(status="failed", evidence=failure)
        self.store.set_meta(state_key, failed)
