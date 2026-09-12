"""Fail-closed protected verification-state transition for Home Center 0.59.

This layer consumes only already-persisted, exact-bound reconciliation evidence from
``HouseholdPolicyReconciliationRuntimeService``.  It never invokes a backend and it
never grants backend, infrastructure, or external-publication authority.  The only
allowed product-state mutation is an exact compare-and-set of one existing policy
Desired State from ``unverified/reconciliation-required`` to
``verified/reconciliation-not-required`` for the same generation and policy digest.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_policy_reconciliation import EVIDENCE_SCHEMA, request_from_dict
from .household_policy_reconciliation_runtime import (
    COMPLETION_SCHEMA as RECONCILIATION_COMPLETION_SCHEMA,
    STATE_KEY_PREFIX as RECONCILIATION_STATE_KEY_PREFIX,
    STATE_SCHEMA as RECONCILIATION_STATE_SCHEMA,
)
from .household_policy_runtime import DESIRED_KEY_PREFIX, DESIRED_STATE_SCHEMA
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now

REQUEST_SCHEMA = "home-center.household-policy-verification-transition-request.v1"
RECEIPT_SCHEMA = "home-center.household-policy-verification-transition-receipt.v1"
ACTION = "household.policy.verification-state.transition"
REQUEST_ID = re.compile(r"^hprq-[0-9a-f]{24}$")
EVIDENCE_ID = re.compile(r"^hpev-[0-9a-f]{24}$")
PLAN_ID = re.compile(r"^hpcp-[0-9a-f]{24}$")
POLICY_ID = re.compile(r"^hcpol-[0-9a-f]{24}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class HouseholdPolicyVerificationTransitionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _transition_request(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "request_id", "evidence_id"}
        or value.get("schema") != REQUEST_SCHEMA
        or not isinstance(value.get("request_id"), str)
        or REQUEST_ID.fullmatch(value["request_id"]) is None
        or not isinstance(value.get("evidence_id"), str)
        or EVIDENCE_ID.fullmatch(value["evidence_id"]) is None
    ):
        raise HouseholdPolicyVerificationTransitionError(
            "invalid_household_policy_verification_transition_request"
        )
    return {
        "schema": REQUEST_SCHEMA,
        "request_id": value["request_id"],
        "evidence_id": value["evidence_id"],
    }


def _desired(value: object) -> dict[str, Any]:
    expected = {
        "schema",
        "household_id",
        "member_id",
        "generation",
        "plan_id",
        "policy",
        "policy_sha256",
        "reason",
        "enforcement_verified",
        "reconciliation_required",
        "infrastructure_mutation_authorized",
        "external_publication_authorized",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise HouseholdPolicyVerificationTransitionError(
            "household_policy_verification_desired_state_invalid"
        )
    generation = value.get("generation")
    policy = value.get("policy")
    flags = (value.get("enforcement_verified"), value.get("reconciliation_required"))
    if (
        value.get("schema") != DESIRED_STATE_SCHEMA
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
        or not isinstance(value.get("household_id"), str)
        or not value["household_id"]
        or len(value["household_id"]) > 128
        or not isinstance(value.get("member_id"), str)
        or not value["member_id"]
        or len(value["member_id"]) > 128
        or not isinstance(value.get("plan_id"), str)
        or PLAN_ID.fullmatch(value["plan_id"]) is None
        or not isinstance(policy, dict)
        or not isinstance(value.get("policy_sha256"), str)
        or SHA256.fullmatch(value["policy_sha256"]) is None
        or _digest(policy) != value["policy_sha256"]
        or flags not in {(False, True), (True, False)}
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyVerificationTransitionError(
            "household_policy_verification_desired_state_invalid"
        )
    if (
        policy.get("household_id") != value["household_id"]
        or policy.get("member_id") != value["member_id"]
        or not isinstance(policy.get("policy_id"), str)
        or POLICY_ID.fullmatch(policy["policy_id"]) is None
    ):
        raise HouseholdPolicyVerificationTransitionError(
            "household_policy_verification_desired_state_binding_invalid"
        )
    return dict(value)


def _verified_reconciliation(
    store: StateStore, request_id: str, evidence_id: str
) -> tuple[dict[str, object], dict[str, object]]:
    envelope = store.get_meta(RECONCILIATION_STATE_KEY_PREFIX + request_id)
    if (
        not isinstance(envelope, dict)
        or envelope.get("schema") != RECONCILIATION_STATE_SCHEMA
        or envelope.get("status") != "completed"
        or not isinstance(envelope.get("request"), dict)
        or not isinstance(envelope.get("evidence"), dict)
        or not isinstance(envelope.get("completion"), dict)
    ):
        raise HouseholdPolicyVerificationTransitionError(
            "household_policy_verified_reconciliation_not_found"
        )
    try:
        request = request_from_dict(envelope["request"])
    except Exception as exc:
        raise HouseholdPolicyVerificationTransitionError(
            "household_policy_verified_reconciliation_invalid"
        ) from exc
    evidence = envelope["evidence"]
    completion = envelope["completion"]
    if (
        request.request_id != request_id
        or evidence.get("schema") != EVIDENCE_SCHEMA
        or evidence.get("evidence_id") != evidence_id
        or evidence.get("request_id") != request_id
        or evidence.get("backend_id") != request.backend_id
        or evidence.get("binding") != request.binding.to_dict()
        or evidence.get("status") != "verified"
        or evidence.get("blocker") is not None
        or evidence.get("enforcement_verified") is not True
        or evidence.get("reconciliation_required") is not False
        or evidence.get("backend_mutation_performed") is not False
        or evidence.get("infrastructure_mutation_performed") is not False
        or evidence.get("external_publication_performed") is not False
        or completion.get("schema") != RECONCILIATION_COMPLETION_SCHEMA
        or completion.get("state") != "verified"
        or completion.get("request_id") != request_id
        or completion.get("backend_id") != request.backend_id
        or completion.get("evidence") != evidence
        or completion.get("desired_state_transition_performed") is not False
        or completion.get("backend_mutation_performed") is not False
        or completion.get("infrastructure_mutation_performed") is not False
        or completion.get("external_publication_performed") is not False
    ):
        raise HouseholdPolicyVerificationTransitionError(
            "household_policy_verified_reconciliation_invalid"
        )
    return request.to_dict(), dict(evidence)


def _compare_and_set_meta_exact(
    store: StateStore,
    *,
    key: str,
    expected: dict[str, object],
    replacement: dict[str, object],
) -> bool:
    """Atomically replace one cluster_meta value when its canonical JSON is exact.

    ``StateStore`` does not yet expose a generic metadata CAS.  This bounded internal
    helper deliberately uses the store's own SQLite transaction/lock so a concurrent
    policy commit cannot be overwritten between read and write.  It is kept here rather
    than weakening the product-wide StateStore API before that API has its own review.
    """

    expected_json = canonical_json(expected)
    replacement_json = canonical_json(replacement)
    lock = getattr(store, "_lock", None)
    connection = getattr(store, "_connection", None)
    if lock is None or connection is None:
        raise HouseholdPolicyVerificationTransitionError(
            "household_policy_verification_store_cas_unavailable"
        )
    with lock:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT value_json FROM cluster_meta WHERE key=?", (key,)
            ).fetchone()
            if row is None or row[0] != expected_json:
                connection.rollback()
                return False
            cursor = connection.execute(
                "UPDATE cluster_meta SET value_json=?, updated_at=? WHERE key=? AND value_json=?",
                (replacement_json, utc_now(), key, expected_json),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                return False
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise


class HouseholdPolicyVerificationTransitionService:
    """Promote exact persisted verified evidence into protected Desired State flags."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _authorized_parent(self, actor: str) -> tuple[object, str]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyVerificationTransitionError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyVerificationTransitionError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        actor_member = next(
            (item.member_id for item in bindings if getattr(item, "actor", None) == actor),
            None,
        )
        if actor_member is None:
            raise HouseholdPolicyVerificationTransitionError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, actor_member)  # type: ignore[attr-defined]
        except HomeServiceCatalogError as exc:
            raise HouseholdPolicyVerificationTransitionError(exc.code) from exc
        if not policy.administration_allowed or policy.role is not HouseholdRole.PARENT:
            raise HouseholdPolicyVerificationTransitionError(
                "household_policy_verification_transition_not_authorized"
            )
        return snapshot, actor_member

    @staticmethod
    def _binding_matches_desired(binding: object, desired: dict[str, Any]) -> bool:
        policy = desired.get("policy")
        return (
            isinstance(binding, dict)
            and isinstance(policy, dict)
            and binding
            == {
                "household_id": desired["household_id"],
                "member_id": desired["member_id"],
                "desired_generation": desired["generation"],
                "desired_plan_id": desired["plan_id"],
                "policy_id": policy.get("policy_id"),
                "policy_sha256": desired["policy_sha256"],
            }
        )

    def transition(
        self,
        *,
        actor: str,
        request: dict[str, object],
        correlation_id: str,
    ) -> dict[str, object]:
        transition_request = _transition_request(request)
        with self._lock:
            snapshot, _actor_member = self._authorized_parent(actor)
            reconciliation_request, evidence = _verified_reconciliation(
                self.store,
                transition_request["request_id"],
                transition_request["evidence_id"],
            )
            binding = reconciliation_request.get("binding")
            if not isinstance(binding, dict):
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verified_reconciliation_invalid"
                )
            if getattr(snapshot, "household_id", None) != binding.get("household_id"):
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_household_stale"
                )
            try:
                snapshot.household.member(binding.get("member_id"))  # type: ignore[attr-defined]
            except HomeServiceCatalogError as exc:
                raise HouseholdPolicyVerificationTransitionError(exc.code) from exc

            desired_key = (
                DESIRED_KEY_PREFIX
                + str(binding["household_id"])
                + "."
                + str(binding["member_id"])
            )
            request_hash = _digest(
                {
                    "action": ACTION,
                    "actor": actor,
                    "request": transition_request,
                    "binding": binding,
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="promote exact verified policy reconciliation evidence",
                    idempotency_key=transition_request["evidence_id"],
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.household-policy-verification-transition-preflight.v1",
                        "request_id": transition_request["request_id"],
                        "evidence_id": transition_request["evidence_id"],
                        "binding": binding,
                        "backend_reinvocation_authorized": False,
                        "backend_mutation_authorized": False,
                        "infrastructure_mutation_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-household-parent-authority", "state": "succeeded"},
                        {"step": "validate-persisted-reconciliation-evidence", "state": "succeeded"},
                        {"step": "compare-and-set-protected-desired-state", "state": "pending"},
                        {"step": "read-back-protected-desired-state", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_transition_idempotency_conflict"
                ) from exc

            if not created and job.get("state") == "succeeded":
                prior = job.get("evidence")
                receipt = prior.get("receipt") if isinstance(prior, dict) else None
                if isinstance(receipt, dict) and receipt.get("schema") == RECEIPT_SCHEMA:
                    return dict(receipt)
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_transition_job_invalid"
                )
            if not created and job.get("state") == "failed":
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_transition_previous_attempt_failed"
                )
            if job.get("state") == "preflight":
                job = self.store.transition_action_job(
                    job["job_id"], expected_state="preflight", new_state="running"
                )

            desired = _desired(self.store.get_meta(desired_key))
            if not self._binding_matches_desired(binding, desired):
                if job.get("state") in {"running", "verifying"}:
                    expected = str(job["state"])
                    self.store.transition_action_job(
                        job["job_id"],
                        expected_state=expected,
                        new_state="failed",
                        evidence={
                            "schema": "home-center.household-policy-verification-transition-failure.v1",
                            "code": "household_policy_verification_desired_state_stale",
                        },
                    )
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_desired_state_stale"
                )

            replacement = dict(desired)
            replacement.update(enforcement_verified=True, reconciliation_required=False)
            transitioned = False
            if desired["enforcement_verified"] is False:
                transitioned = _compare_and_set_meta_exact(
                    self.store,
                    key=desired_key,
                    expected=desired,
                    replacement=replacement,
                )
                if not transitioned:
                    current = _desired(self.store.get_meta(desired_key))
                    if current != replacement:
                        if job.get("state") == "running":
                            self.store.transition_action_job(
                                job["job_id"],
                                expected_state="running",
                                new_state="failed",
                                evidence={
                                    "schema": "home-center.household-policy-verification-transition-failure.v1",
                                    "code": "household_policy_verification_desired_state_changed_concurrently",
                                },
                            )
                        raise HouseholdPolicyVerificationTransitionError(
                            "household_policy_verification_desired_state_changed_concurrently"
                        )
            elif desired != replacement:
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_desired_state_invalid"
                )

            if job.get("state") == "running":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="running",
                    new_state="verifying",
                    result={
                        "schema": "home-center.household-policy-verification-transition-write.v1",
                        "request_id": transition_request["request_id"],
                        "evidence_id": transition_request["evidence_id"],
                        "desired_generation": replacement["generation"],
                        "policy_sha256": replacement["policy_sha256"],
                        "enforcement_verified": True,
                        "reconciliation_required": False,
                        "backend_reinvoked": False,
                    },
                    steps=[
                        {"step": "revalidate-household-parent-authority", "state": "succeeded"},
                        {"step": "validate-persisted-reconciliation-evidence", "state": "succeeded"},
                        {"step": "compare-and-set-protected-desired-state", "state": "succeeded"},
                        {"step": "read-back-protected-desired-state", "state": "pending"},
                    ],
                )

            read_back = _desired(self.store.get_meta(desired_key))
            if read_back != replacement:
                if job.get("state") == "verifying":
                    self.store.transition_action_job(
                        job["job_id"],
                        expected_state="verifying",
                        new_state="failed",
                        evidence={
                            "schema": "home-center.household-policy-verification-transition-failure.v1",
                            "code": "household_policy_verification_desired_state_readback_failed",
                        },
                    )
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_desired_state_readback_failed"
                )

            receipt = {
                "schema": RECEIPT_SCHEMA,
                "state": "verification-state-transitioned",
                "job_id": job["job_id"],
                "request_id": transition_request["request_id"],
                "evidence_id": transition_request["evidence_id"],
                "household_id": replacement["household_id"],
                "member_id": replacement["member_id"],
                "desired_generation": replacement["generation"],
                "plan_id": replacement["plan_id"],
                "policy_sha256": replacement["policy_sha256"],
                "enforcement_verified": True,
                "reconciliation_required": False,
                "backend_reinvoked": False,
                "backend_mutation_performed": False,
                "infrastructure_mutation_performed": False,
                "external_publication_performed": False,
            }
            if job.get("state") == "verifying":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="verifying",
                    new_state="succeeded",
                    evidence={
                        "schema": "home-center.household-policy-verification-transition-evidence.v1",
                        "source_reconciliation_evidence": evidence,
                        "desired_state_sha256": _digest(replacement),
                        "receipt": receipt,
                        "backend_reinvoked": False,
                    },
                    steps=[
                        {"step": "revalidate-household-parent-authority", "state": "succeeded"},
                        {"step": "validate-persisted-reconciliation-evidence", "state": "succeeded"},
                        {"step": "compare-and-set-protected-desired-state", "state": "succeeded"},
                        {"step": "read-back-protected-desired-state", "state": "succeeded"},
                    ],
                )
            elif job.get("state") != "succeeded":
                raise HouseholdPolicyVerificationTransitionError(
                    "household_policy_verification_transition_job_invalid"
                )

            self.store.audit(
                actor=actor,
                action=ACTION,
                target=str(replacement["member_id"]),
                outcome="succeeded",
                correlation_id=correlation_id,
                details={
                    "job_id": job["job_id"],
                    "request_id": transition_request["request_id"],
                    "evidence_id": transition_request["evidence_id"],
                    "desired_generation": replacement["generation"],
                    "policy_sha256": replacement["policy_sha256"],
                    "enforcement_verified": True,
                    "reconciliation_required": False,
                    "backend_reinvoked": False,
                    "backend_mutation_performed": False,
                    "infrastructure_mutation_performed": False,
                    "external_publication_performed": False,
                },
            )
            return receipt
