"""Protected verification-state projection for Home Center 0.59 Policy Composer.

This layer consumes only already-durable, exact-bound reconciliation evidence.  It
creates a verified Desired State projection without mutating the original protected
Desired State and without invoking a backend.  The projection is content-bound to the
exact Desired State and reconciliation evidence and is persisted with read-back and
restart-safe transition state before it can be reported as verified.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_policy_reconciliation import (
    EVIDENCE_SCHEMA,
    HouseholdPolicyReconciliationError,
    PolicyReconciliationRequest,
    request_from_dict,
)
from .household_policy_reconciliation_runtime import (
    COMPLETION_SCHEMA,
    STATE_KEY_PREFIX,
    STATE_SCHEMA,
)
from .household_policy_runtime import DESIRED_KEY_PREFIX, DESIRED_STATE_SCHEMA
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

VERIFIED_STATE_SCHEMA = "home-center.household-policy-verified-desired-state.v1"
TRANSITION_STATE_SCHEMA = "home-center.household-policy-verification-transition-state.v1"
RECEIPT_SCHEMA = "home-center.household-policy-verification-transition-receipt.v1"
ACTION = "household.policy.verification-state.commit"
VERIFIED_KEY_PREFIX = "cozy.household.policy.verified."
TRANSITION_KEY_PREFIX = "cozy.household.policy.verification-transition."

REQUEST_ID = re.compile(r"^hprq-[0-9a-f]{24}$")
EVIDENCE_ID = re.compile(r"^hpev-[0-9a-f]{24}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class HouseholdPolicyVerificationStateError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _validated_id(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise HouseholdPolicyVerificationStateError(code)
    return value


def _transition_key(evidence_id: object) -> str:
    return TRANSITION_KEY_PREFIX + _validated_id(
        evidence_id,
        EVIDENCE_ID,
        "invalid_household_policy_verification_evidence_id",
    )


def _verified_key(household_id: str, member_id: str) -> str:
    return VERIFIED_KEY_PREFIX + household_id + "." + member_id


class HouseholdPolicyVerificationStateService:
    """Persist an exact verified Desired State projection from durable evidence."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _state(self) -> tuple[object, tuple[object, ...]]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyVerificationStateError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyVerificationStateError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _authorize(
        actor: str,
        snapshot: object,
        bindings: tuple[object, ...],
        *,
        member_id: str,
    ) -> None:
        actor_member_id = next(
            (
                item.member_id
                for item in bindings
                if getattr(item, "actor", None) == actor
            ),
            None,
        )
        if actor_member_id is None:
            raise HouseholdPolicyVerificationStateError("household_actor_not_bound")
        try:
            actor_policy = effective_policy(snapshot.household, actor_member_id)  # type: ignore[attr-defined]
            snapshot.household.member(member_id)  # type: ignore[attr-defined]
        except HomeServiceCatalogError as exc:
            raise HouseholdPolicyVerificationStateError(exc.code) from exc
        if (
            not actor_policy.administration_allowed
            or actor_policy.role is not HouseholdRole.PARENT
        ):
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_transition_not_authorized"
            )

    @staticmethod
    def _request(value: object) -> PolicyReconciliationRequest:
        try:
            return request_from_dict(value)
        except HouseholdPolicyReconciliationError as exc:
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_reconciliation_request_invalid"
            ) from exc

    @staticmethod
    def _evidence(
        value: object,
        *,
        request: PolicyReconciliationRequest,
        evidence_id: str,
    ) -> dict[str, object]:
        if (
            not isinstance(value, dict)
            or value.get("schema") != EVIDENCE_SCHEMA
            or value.get("evidence_id") != evidence_id
            or value.get("request_id") != request.request_id
            or value.get("backend_id") != request.backend_id
            or value.get("binding") != request.binding.to_dict()
            or value.get("status") != "verified"
            or value.get("blocker") is not None
            or value.get("observed_state") != "enforced"
            or value.get("actual_policy_sha256") != request.binding.policy_sha256
            or value.get("enforcement_verified") is not True
            or value.get("reconciliation_required") is not False
            or value.get("backend_mutation_performed") is not False
            or value.get("infrastructure_mutation_performed") is not False
            or value.get("external_publication_performed") is not False
        ):
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_evidence_not_verified"
            )
        return dict(value)

    def _completed_reconciliation(
        self,
        *,
        request_id: str,
        evidence_id: str,
    ) -> tuple[dict[str, Any], PolicyReconciliationRequest, dict[str, object]]:
        envelope = self.store.get_meta(STATE_KEY_PREFIX + request_id)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != STATE_SCHEMA
            or envelope.get("status") != "completed"
        ):
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_reconciliation_not_completed"
            )
        request = self._request(envelope.get("request"))
        if request.request_id != request_id:
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_reconciliation_request_mismatch"
            )
        completion = envelope.get("completion")
        if (
            not isinstance(completion, dict)
            or completion.get("schema") != COMPLETION_SCHEMA
            or completion.get("state") != "verified"
            or completion.get("request_id") != request_id
            or completion.get("backend_id") != request.backend_id
            or completion.get("member_id") != request.binding.member_id
            or completion.get("desired_state_transition_performed") is not False
            or completion.get("backend_mutation_performed") is not False
            or completion.get("infrastructure_mutation_performed") is not False
            or completion.get("external_publication_performed") is not False
        ):
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_reconciliation_completion_invalid"
            )
        evidence = self._evidence(
            completion.get("evidence"),
            request=request,
            evidence_id=evidence_id,
        )
        return envelope, request, evidence

    @staticmethod
    def _unverified_desired(
        value: object,
        *,
        request: PolicyReconciliationRequest,
        expected_sha256: object,
    ) -> dict[str, object]:
        required = {
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
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value.get("schema") != DESIRED_STATE_SCHEMA
            or value.get("household_id") != request.binding.household_id
            or value.get("member_id") != request.binding.member_id
            or value.get("generation") != request.binding.desired_generation
            or value.get("plan_id") != request.binding.desired_plan_id
            or value.get("policy_sha256") != request.binding.policy_sha256
            or value.get("enforcement_verified") is not False
            or value.get("reconciliation_required") is not True
            or value.get("infrastructure_mutation_authorized") is not False
            or value.get("external_publication_authorized") is not False
            or not isinstance(value.get("policy"), dict)
            or value["policy"].get("policy_id") != request.binding.policy_id
            or _digest(value["policy"]) != request.binding.policy_sha256
            or not isinstance(expected_sha256, str)
            or SHA256.fullmatch(expected_sha256) is None
            or _digest(value) != expected_sha256
        ):
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_desired_state_stale"
            )
        return dict(value)

    @staticmethod
    def _projection(
        *,
        desired: dict[str, object],
        request: PolicyReconciliationRequest,
        evidence: dict[str, object],
        desired_sha256: str,
    ) -> dict[str, object]:
        evidence_sha256 = _digest(evidence)
        return {
            "schema": VERIFIED_STATE_SCHEMA,
            "household_id": request.binding.household_id,
            "member_id": request.binding.member_id,
            "desired_generation": request.binding.desired_generation,
            "desired_plan_id": request.binding.desired_plan_id,
            "policy_id": request.binding.policy_id,
            "policy_sha256": request.binding.policy_sha256,
            "source_desired_state_sha256": desired_sha256,
            "request_id": request.request_id,
            "backend_id": request.backend_id,
            "evidence_id": evidence["evidence_id"],
            "evidence_sha256": evidence_sha256,
            "observed_at": evidence["observed_at"],
            "enforcement_verified": True,
            "reconciliation_required": False,
            "backend_mutation_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
            "desired_state": desired,
        }

    @staticmethod
    def _receipt(
        *,
        projection: dict[str, object],
        job_id: str,
    ) -> dict[str, object]:
        return {
            "schema": RECEIPT_SCHEMA,
            "state": "verified-state-persisted",
            "job_id": job_id,
            "household_id": projection["household_id"],
            "member_id": projection["member_id"],
            "desired_generation": projection["desired_generation"],
            "policy_sha256": projection["policy_sha256"],
            "request_id": projection["request_id"],
            "backend_id": projection["backend_id"],
            "evidence_id": projection["evidence_id"],
            "evidence_sha256": projection["evidence_sha256"],
            "enforcement_verified": True,
            "reconciliation_required": False,
            "backend_reinvoked": False,
            "desired_state_mutated": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }

    @staticmethod
    def _validate_existing_projection(
        value: object,
        *,
        projection: dict[str, object],
    ) -> str:
        if value is None:
            return "missing"
        if not isinstance(value, dict) or value.get("schema") != VERIFIED_STATE_SCHEMA:
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_state_invalid"
            )
        current_generation = value.get("desired_generation")
        next_generation = projection.get("desired_generation")
        if (
            not isinstance(current_generation, int)
            or isinstance(current_generation, bool)
            or not isinstance(next_generation, int)
            or isinstance(next_generation, bool)
        ):
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_state_invalid"
            )
        if current_generation > next_generation:
            raise HouseholdPolicyVerificationStateError(
                "household_policy_verification_state_stale"
            )
        if current_generation == next_generation:
            if value != projection:
                raise HouseholdPolicyVerificationStateError(
                    "household_policy_verification_state_conflict"
                )
            return "exact"
        return "older"

    def transition(
        self,
        *,
        actor: str,
        request_id: str,
        evidence_id: str,
        correlation_id: str,
    ) -> dict[str, object]:
        request_id = _validated_id(
            request_id,
            REQUEST_ID,
            "invalid_household_policy_verification_request_id",
        )
        evidence_id = _validated_id(
            evidence_id,
            EVIDENCE_ID,
            "invalid_household_policy_verification_evidence_id",
        )
        with self._lock:
            envelope, request, evidence = self._completed_reconciliation(
                request_id=request_id,
                evidence_id=evidence_id,
            )
            snapshot, bindings = self._state()
            if getattr(snapshot, "household_id", None) != request.binding.household_id:
                raise HouseholdPolicyVerificationStateError(
                    "household_policy_verification_household_mismatch"
                )
            self._authorize(
                actor,
                snapshot,
                bindings,
                member_id=request.binding.member_id,
            )
            desired_sha256 = envelope.get("desired_state_sha256")
            desired_key = (
                DESIRED_KEY_PREFIX
                + request.binding.household_id
                + "."
                + request.binding.member_id
            )
            desired = self._unverified_desired(
                self.store.get_meta(desired_key),
                request=request,
                expected_sha256=desired_sha256,
            )
            assert isinstance(desired_sha256, str)
            projection = self._projection(
                desired=desired,
                request=request,
                evidence=evidence,
                desired_sha256=desired_sha256,
            )
            projection_key = _verified_key(
                request.binding.household_id,
                request.binding.member_id,
            )
            projection_state = self._validate_existing_projection(
                self.store.get_meta(projection_key),
                projection=projection,
            )
            transition_key = _transition_key(evidence_id)
            transition_state = self.store.get_meta(transition_key)
            if transition_state is not None:
                if (
                    not isinstance(transition_state, dict)
                    or transition_state.get("schema") != TRANSITION_STATE_SCHEMA
                    or transition_state.get("request_id") != request_id
                    or transition_state.get("evidence_id") != evidence_id
                    or transition_state.get("projection") != projection
                    or not isinstance(transition_state.get("job_id"), str)
                ):
                    raise HouseholdPolicyVerificationStateError(
                        "household_policy_verification_transition_state_invalid"
                    )
                if transition_state.get("status") == "completed":
                    receipt = transition_state.get("receipt")
                    if (
                        not isinstance(receipt, dict)
                        or receipt
                        != self._receipt(
                            projection=projection,
                            job_id=transition_state["job_id"],
                        )
                        or projection_state != "exact"
                    ):
                        raise HouseholdPolicyVerificationStateError(
                            "household_policy_verification_transition_state_invalid"
                        )
                    return dict(receipt)
                if transition_state.get("status") not in {"prepared", "verifying"}:
                    raise HouseholdPolicyVerificationStateError(
                        "household_policy_verification_transition_state_invalid"
                    )

            request_hash = _digest(
                {
                    "schema": "home-center.household-policy-verification-transition-request.v1",
                    "request_id": request_id,
                    "evidence_id": evidence_id,
                    "evidence_sha256": projection["evidence_sha256"],
                    "source_desired_state_sha256": desired_sha256,
                }
            )
            if transition_state is None:
                try:
                    job, _created = self.store.create_action_job(
                        action_id=ACTION,
                        actor=actor,
                        reason="persist exact verified policy Desired State projection",
                        idempotency_key=evidence_id,
                        request_hash=request_hash,
                        preflight={
                            "schema": "home-center.household-policy-verification-transition-preflight.v1",
                            "request_id": request_id,
                            "evidence_id": evidence_id,
                            "evidence_sha256": projection["evidence_sha256"],
                            "household_id": request.binding.household_id,
                            "member_id": request.binding.member_id,
                            "desired_generation": request.binding.desired_generation,
                            "policy_sha256": request.binding.policy_sha256,
                            "source_desired_state_sha256": desired_sha256,
                            "backend_reinvocation_authorized": False,
                            "desired_state_mutation_authorized": False,
                            "infrastructure_mutation_authorized": False,
                            "external_publication_authorized": False,
                        },
                        steps=[
                            {"step": "revalidate-household-policy-authority", "state": "succeeded"},
                            {"step": "validate-exact-verified-evidence", "state": "succeeded"},
                            {"step": "persist-verified-state-projection", "state": "pending"},
                            {"step": "read-back-verified-state-projection", "state": "pending"},
                        ],
                    )
                except IdempotencyConflict as exc:
                    raise HouseholdPolicyVerificationStateError(
                        "household_policy_verification_idempotency_conflict"
                    ) from exc
                transition_state = {
                    "schema": TRANSITION_STATE_SCHEMA,
                    "status": "prepared",
                    "request_id": request_id,
                    "evidence_id": evidence_id,
                    "job_id": job["job_id"],
                    "projection": projection,
                    "receipt": None,
                }
                self.store.set_meta(transition_key, transition_state)
            else:
                job = self.store.job(transition_state["job_id"])
                if not isinstance(job, dict):
                    raise HouseholdPolicyVerificationStateError(
                        "household_policy_verification_job_state_invalid"
                    )

            job = self.store.job(transition_state["job_id"])
            if (
                not isinstance(job, dict)
                or job.get("job_type") != ACTION
                or job.get("idempotency_key") != evidence_id
            ):
                raise HouseholdPolicyVerificationStateError(
                    "household_policy_verification_job_state_invalid"
                )
            if job.get("state") == "preflight":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="preflight",
                    new_state="running",
                )

            if job.get("state") == "running":
                current_projection = self.store.get_meta(projection_key)
                current_state = self._validate_existing_projection(
                    current_projection,
                    projection=projection,
                )
                if current_state in {"missing", "older"}:
                    self.store.set_meta(projection_key, projection)
                transition_state = dict(transition_state)
                transition_state["status"] = "verifying"
                self.store.set_meta(transition_key, transition_state)
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="running",
                    new_state="verifying",
                    result={
                        "schema": "home-center.household-policy-verification-state-write.v1",
                        "evidence_id": evidence_id,
                        "evidence_sha256": projection["evidence_sha256"],
                        "projection_sha256": _digest(projection),
                        "backend_reinvoked": False,
                        "desired_state_mutated": False,
                    },
                    steps=[
                        {"step": "revalidate-household-policy-authority", "state": "succeeded"},
                        {"step": "validate-exact-verified-evidence", "state": "succeeded"},
                        {"step": "persist-verified-state-projection", "state": "succeeded"},
                        {"step": "read-back-verified-state-projection", "state": "pending"},
                    ],
                )

            if self.store.get_meta(projection_key) != projection:
                if job.get("state") == "verifying":
                    self.store.transition_action_job(
                        job["job_id"],
                        expected_state="verifying",
                        new_state="failed",
                        evidence={
                            "schema": "home-center.household-policy-verification-transition-failure.v1",
                            "code": "household_policy_verification_state_readback_failed",
                            "evidence_id": evidence_id,
                            "backend_reinvoked": False,
                            "desired_state_mutated": False,
                        },
                    )
                raise HouseholdPolicyVerificationStateError(
                    "household_policy_verification_state_readback_failed"
                )

            receipt = self._receipt(projection=projection, job_id=job["job_id"])
            if job.get("state") == "verifying":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="verifying",
                    new_state="succeeded",
                    evidence={
                        "schema": "home-center.household-policy-verification-transition-evidence.v1",
                        "request_id": request_id,
                        "evidence_id": evidence_id,
                        "evidence_sha256": projection["evidence_sha256"],
                        "projection_sha256": _digest(projection),
                        "receipt": receipt,
                        "backend_reinvoked": False,
                        "desired_state_mutated": False,
                        "infrastructure_mutation_performed": False,
                        "external_publication_performed": False,
                    },
                    steps=[
                        {"step": "revalidate-household-policy-authority", "state": "succeeded"},
                        {"step": "validate-exact-verified-evidence", "state": "succeeded"},
                        {"step": "persist-verified-state-projection", "state": "succeeded"},
                        {"step": "read-back-verified-state-projection", "state": "succeeded"},
                    ],
                )
            elif job.get("state") == "succeeded":
                prior_evidence = job.get("evidence")
                if (
                    not isinstance(prior_evidence, dict)
                    or prior_evidence.get("receipt") != receipt
                    or prior_evidence.get("projection_sha256") != _digest(projection)
                ):
                    raise HouseholdPolicyVerificationStateError(
                        "household_policy_verification_job_evidence_mismatch"
                    )
            else:
                raise HouseholdPolicyVerificationStateError(
                    "household_policy_verification_job_state_invalid"
                )

            completed = dict(transition_state)
            completed.update(status="completed", receipt=receipt)
            self.store.set_meta(transition_key, completed)
            if self.store.get_meta(transition_key) != completed:
                raise HouseholdPolicyVerificationStateError(
                    "household_policy_verification_transition_state_readback_failed"
                )
            self.store.audit(
                actor=actor,
                action=ACTION,
                target=request.binding.member_id,
                outcome="verified-state-persisted",
                correlation_id=correlation_id,
                details={
                    "job_id": job["job_id"],
                    "request_id": request_id,
                    "evidence_id": evidence_id,
                    "evidence_sha256": projection["evidence_sha256"],
                    "desired_generation": request.binding.desired_generation,
                    "policy_sha256": request.binding.policy_sha256,
                    "backend_reinvoked": False,
                    "desired_state_mutated": False,
                    "infrastructure_mutation_performed": False,
                    "external_publication_performed": False,
                },
            )
            return receipt

    def verified_state(
        self,
        *,
        actor: str,
        member_id: str,
    ) -> dict[str, object] | None:
        with self._lock:
            snapshot, bindings = self._state()
            self._authorize(actor, snapshot, bindings, member_id=member_id)
            value = self.store.get_meta(
                _verified_key(snapshot.household_id, member_id)  # type: ignore[attr-defined]
            )
            if value is None:
                return None
            if (
                not isinstance(value, dict)
                or value.get("schema") != VERIFIED_STATE_SCHEMA
                or value.get("household_id") != snapshot.household_id  # type: ignore[attr-defined]
                or value.get("member_id") != member_id
                or value.get("enforcement_verified") is not True
                or value.get("reconciliation_required") is not False
            ):
                raise HouseholdPolicyVerificationStateError(
                    "household_policy_verification_state_invalid"
                )
            return dict(value)
