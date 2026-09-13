"""Protected Desired State runtime for Home Center 0.59 Policy Composer.

The service writes Home Center product Desired State only.  A successful commit means
"saved / waiting for application" and never means that network, device or provider
state has been enforced.  The actual-state reconciliation/enforcement path remains a
separate boundary.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_policy_composer import (
    HouseholdPolicyComposerError,
    build_policy_bundle,
    compose_policy,
    policy_bundle_from_dict,
)
from .household_runtime import HOUSEHOLD_STATE_KEY, _snapshot_from_dict, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

PLAN_REQUEST_SCHEMA = "home-center.household-policy-change-plan-request.v1"
PLAN_SCHEMA = "home-center.household-policy-change-plan.v1"
CONFIRM_REQUEST_SCHEMA = "home-center.household-policy-change-confirm-request.v1"
DESIRED_STATE_SCHEMA = "home-center.household-policy-desired-state.v1"
COMMIT_RECEIPT_SCHEMA = "home-center.household-policy-desired-state-commit-receipt.v1"
PLAN_STATE_SCHEMA = "home-center.household-policy-change-plan-state.v1"
ACTION = "household.policy.desired-state.commit"
PLAN_ID = re.compile(r"^hpcp-[0-9a-f]{24}$")
PLAN_KEY_PREFIX = "cozy.household.policy.plan."
DESIRED_KEY_PREFIX = "cozy.household.policy.desired."


class HouseholdPolicyRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _plan_key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise HouseholdPolicyRuntimeError("invalid_household_policy_plan_id")
    return PLAN_KEY_PREFIX + plan_id


def _desired_key(household_id: str, member_id: str) -> str:
    return DESIRED_KEY_PREFIX + household_id + "." + member_id


def _reason(value: object) -> str:
    if not isinstance(value, str):
        raise HouseholdPolicyRuntimeError("invalid_household_policy_reason")
    text = value.strip()
    if not text or len(text) > 512 or any(ord(char) < 32 for char in text):
        raise HouseholdPolicyRuntimeError("invalid_household_policy_reason")
    return text


class HouseholdPolicyRuntimeService:
    """Plan and explicitly confirm a non-enforcing Household policy Desired State."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor_member(actor: str, snapshot: object, bindings: tuple[object, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise HouseholdPolicyRuntimeError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, member_id)
        except HomeServiceCatalogError as exc:
            raise HouseholdPolicyRuntimeError(exc.code) from exc
        if not policy.administration_allowed or policy.role is not HouseholdRole.PARENT:
            raise HouseholdPolicyRuntimeError("household_policy_change_not_authorized")
        return member_id

    @staticmethod
    def _desired(value: object) -> dict[str, Any] | None:
        if value is None:
            return None
        flags = (
            value.get("enforcement_verified") if isinstance(value, dict) else None,
            value.get("reconciliation_required") if isinstance(value, dict) else None,
        )
        if (
            not isinstance(value, dict)
            or value.get("schema") != DESIRED_STATE_SCHEMA
            or not isinstance(value.get("generation"), int)
            or isinstance(value.get("generation"), bool)
            or value["generation"] < 1
            or flags not in {(False, True), (True, False)}
            or value.get("infrastructure_mutation_authorized") is not False
            or value.get("external_publication_authorized") is not False
            or not isinstance(value.get("policy"), dict)
        ):
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        return dict(value)

    @staticmethod
    def _current_digest(*, desired: dict[str, Any] | None, base_policy: object) -> str:
        if desired is not None:
            return _digest(desired["policy"])
        return _digest(base_policy.to_dict())

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "subject_member_id", "bundle", "reason"}
        if set(request) != required or request.get("schema") != PLAN_REQUEST_SCHEMA:
            raise HouseholdPolicyRuntimeError("invalid_household_policy_plan_request")
        subject_member_id = request.get("subject_member_id")
        if not isinstance(subject_member_id, str):
            raise HouseholdPolicyRuntimeError("invalid_household_policy_subject")
        reason = _reason(request.get("reason"))

        with self._lock:
            snapshot, bindings = self._state()
            actor_member_id = self._actor_member(actor, snapshot, bindings)
            try:
                subject = snapshot.household.member(subject_member_id)
                if not subject.enabled:
                    raise HouseholdPolicyRuntimeError("household_member_disabled")
                base = effective_policy(snapshot.household, subject.member_id)
                bundle = build_policy_bundle(role=subject.role, value=request.get("bundle"))
                proposed = compose_policy(base=base, bundle=bundle)
            except HouseholdPolicyRuntimeError:
                raise
            except (HomeServiceCatalogError, HouseholdPolicyComposerError) as exc:
                raise HouseholdPolicyRuntimeError(getattr(exc, "code", "household_policy_bundle_rejected")) from exc

            desired_key = _desired_key(snapshot.household_id, subject.member_id)
            desired = self._desired(self.store.get_meta(desired_key))
            observed_generation = desired["generation"] if desired is not None else 0
            current_policy_sha256 = self._current_digest(desired=desired, base_policy=base)
            canonical = {
                "household_snapshot_id": snapshot.snapshot_id,
                "household_resource_version": snapshot.resource_version,
                "household_generation": snapshot.generation,
                "actor_member_id": actor_member_id,
                "subject_member_id": subject.member_id,
                "current_policy_sha256": current_policy_sha256,
                "observed_desired_generation": observed_generation,
                "expected_desired_generation": observed_generation + 1,
                "bundle": bundle.to_dict(),
                "proposed_policy": proposed.to_dict(),
                "reason": reason,
            }
            plan_id = "hpcp-" + _digest(canonical)[:24]
            plan = {
                "schema": PLAN_SCHEMA,
                "plan_id": plan_id,
                **canonical,
                "desired_state_write_authorized": False,
                "enforcement_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }
            envelope = {
                "schema": PLAN_STATE_SCHEMA,
                "status": "planned",
                "actor": actor,
                "base_snapshot": snapshot.to_dict(),
                "bindings": [item.to_dict() for item in bindings],
                "plan": plan,
                "commit": None,
            }
            self.store.set_meta(_plan_key(plan_id), envelope)
            self.store.audit(
                actor=actor,
                action="household.policy.plan",
                target=subject.member_id,
                outcome="planned",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan_id,
                    "bundle_id": bundle.bundle_id,
                    "policy_id": proposed.policy_id,
                    "household_snapshot_id": snapshot.snapshot_id,
                    "observed_desired_generation": observed_generation,
                    "expected_desired_generation": observed_generation + 1,
                    "enforcement_verified": False,
                },
            )
            return plan

    def _load(self, plan_id: object) -> tuple[str, dict[str, Any], dict[str, Any]]:
        key = _plan_key(plan_id)
        envelope = self.store.get_meta(key)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != PLAN_STATE_SCHEMA
            or not isinstance(envelope.get("plan"), dict)
            or envelope["plan"].get("plan_id") != plan_id
            or envelope["plan"].get("schema") != PLAN_SCHEMA
        ):
            raise HouseholdPolicyRuntimeError("household_policy_plan_not_found")
        return key, envelope, dict(envelope["plan"])

    def confirm(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        if (
            set(request) != {"schema", "plan_id", "confirmed"}
            or request.get("schema") != CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise HouseholdPolicyRuntimeError("invalid_household_policy_confirm_request")

        with self._lock:
            key, envelope, plan = self._load(request.get("plan_id"))
            if envelope.get("actor") != actor:
                raise HouseholdPolicyRuntimeError("household_policy_actor_mismatch")
            if envelope.get("status") == "committed":
                commit = envelope.get("commit")
                if isinstance(commit, dict) and commit.get("schema") == COMMIT_RECEIPT_SCHEMA:
                    return dict(commit)
                raise HouseholdPolicyRuntimeError("household_policy_plan_state_invalid")
            if envelope.get("status") != "planned":
                raise HouseholdPolicyRuntimeError("household_policy_plan_state_invalid")

            snapshot, bindings = self._state()
            actor_member_id = self._actor_member(actor, snapshot, bindings)
            try:
                base_snapshot = _snapshot_from_dict(envelope.get("base_snapshot"))
            except Exception as exc:
                raise HouseholdPolicyRuntimeError("household_policy_plan_state_invalid") from exc
            if (
                snapshot != base_snapshot
                or [item.to_dict() for item in bindings] != envelope.get("bindings")
                or actor_member_id != plan.get("actor_member_id")
                or snapshot.snapshot_id != plan.get("household_snapshot_id")
                or snapshot.resource_version != plan.get("household_resource_version")
                or snapshot.generation != plan.get("household_generation")
            ):
                raise HouseholdPolicyRuntimeError("household_policy_plan_stale")

            subject_member_id = plan.get("subject_member_id")
            try:
                subject = snapshot.household.member(subject_member_id)
                base = effective_policy(snapshot.household, subject.member_id)
                bundle = policy_bundle_from_dict(plan.get("bundle"))
                proposed = compose_policy(base=base, bundle=bundle)
            except (HomeServiceCatalogError, HouseholdPolicyComposerError, TypeError) as exc:
                raise HouseholdPolicyRuntimeError("household_policy_plan_state_invalid") from exc
            if proposed.to_dict() != plan.get("proposed_policy"):
                raise HouseholdPolicyRuntimeError("household_policy_plan_state_invalid")

            expected_generation = plan.get("expected_desired_generation")
            if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
                raise HouseholdPolicyRuntimeError("household_policy_plan_state_invalid")
            desired_key = _desired_key(snapshot.household_id, subject.member_id)
            desired = {
                "schema": DESIRED_STATE_SCHEMA,
                "household_id": snapshot.household_id,
                "member_id": subject.member_id,
                "generation": expected_generation,
                "plan_id": plan["plan_id"],
                "policy": proposed.to_dict(),
                "policy_sha256": _digest(proposed.to_dict()),
                "reason": plan["reason"],
                "enforcement_verified": False,
                "reconciliation_required": True,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }
            current = self._desired(self.store.get_meta(desired_key))
            recovery_job = next(
                (
                    item
                    for item in self.store.jobs(limit=500)
                    if item.get("job_type") == ACTION
                    and item.get("initiator") == actor
                    and item.get("idempotency_key") == plan["plan_id"]
                ),
                None,
            )
            recovery_preflight = recovery_job.get("preflight") if isinstance(recovery_job, dict) else None
            interrupted_write_recovery = (
                current == desired
                and isinstance(recovery_job, dict)
                and recovery_job.get("state") in {"running", "verifying", "succeeded"}
                and isinstance(recovery_preflight, dict)
                and recovery_preflight.get("schema") == "home-center.household-policy-desired-state-preflight.v1"
                and recovery_preflight.get("plan_id") == plan["plan_id"]
                and recovery_preflight.get("household_snapshot_id") == snapshot.snapshot_id
                and recovery_preflight.get("subject_member_id") == subject.member_id
                and recovery_preflight.get("current_policy_sha256") == plan.get("current_policy_sha256")
                and recovery_preflight.get("expected_desired_generation") == expected_generation
                and recovery_preflight.get("enforcement_authorized") is False
            )
            if not interrupted_write_recovery:
                observed_generation = current["generation"] if current is not None else 0
                if observed_generation != plan.get("observed_desired_generation"):
                    raise HouseholdPolicyRuntimeError("household_policy_desired_generation_stale")
                if self._current_digest(desired=current, base_policy=base) != plan.get("current_policy_sha256"):
                    raise HouseholdPolicyRuntimeError("household_policy_current_digest_stale")

            request_hash = _digest(
                {
                    "schema": CONFIRM_REQUEST_SCHEMA,
                    "plan_id": plan["plan_id"],
                    "confirmed": True,
                }
            )
            try:
                job, _created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason=plan["reason"],
                    idempotency_key=plan["plan_id"],
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.household-policy-desired-state-preflight.v1",
                        "plan_id": plan["plan_id"],
                        "household_snapshot_id": snapshot.snapshot_id,
                        "subject_member_id": subject.member_id,
                        "current_policy_sha256": plan["current_policy_sha256"],
                        "expected_desired_generation": plan["expected_desired_generation"],
                        "enforcement_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-household-policy-authority", "state": "succeeded"},
                        {"step": "commit-protected-desired-state", "state": "pending"},
                        {"step": "read-back-desired-state", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise HouseholdPolicyRuntimeError("household_policy_idempotency_conflict") from exc

            if job.get("state") == "preflight":
                job = self.store.transition_action_job(
                    job["job_id"], expected_state="preflight", new_state="running"
                )

            if job.get("state") == "running":
                if current != desired:
                    self.store.set_meta(desired_key, desired)
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="running",
                    new_state="verifying",
                    result={
                        "schema": "home-center.household-policy-desired-state-write.v1",
                        "plan_id": plan["plan_id"],
                        "generation": expected_generation,
                        "policy_sha256": desired["policy_sha256"],
                        "enforcement_verified": False,
                    },
                    steps=[
                        {"step": "revalidate-household-policy-authority", "state": "succeeded"},
                        {"step": "commit-protected-desired-state", "state": "succeeded"},
                        {"step": "read-back-desired-state", "state": "pending"},
                    ],
                )

            read_back = self._desired(self.store.get_meta(desired_key))
            if read_back != desired:
                if job.get("state") == "verifying":
                    self.store.transition_action_job(
                        job["job_id"],
                        expected_state="verifying",
                        new_state="failed",
                        result={
                            "schema": "home-center.household-policy-desired-state-failure.v1",
                            "code": "household_policy_desired_state_readback_failed",
                            "enforcement_verified": False,
                        },
                    )
                raise HouseholdPolicyRuntimeError("household_policy_desired_state_readback_failed")

            receipt = {
                "schema": COMMIT_RECEIPT_SCHEMA,
                "state": "desired-state-committed",
                "job_id": job["job_id"],
                "plan_id": plan["plan_id"],
                "household_id": snapshot.household_id,
                "member_id": subject.member_id,
                "desired_generation": expected_generation,
                "policy_id": proposed.policy_id,
                "policy_sha256": desired["policy_sha256"],
                "explanation_ru": proposed.explanation_ru,
                "enforcement_verified": False,
                "reconciliation_required": True,
                "infrastructure_mutation_performed": False,
                "external_publication_performed": False,
            }
            if job.get("state") == "verifying":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="verifying",
                    new_state="succeeded",
                    evidence={
                        "schema": "home-center.household-policy-desired-state-evidence.v1",
                        "desired_state_sha256": _digest(desired),
                        "receipt": receipt,
                        "enforcement_verified": False,
                    },
                    steps=[
                        {"step": "revalidate-household-policy-authority", "state": "succeeded"},
                        {"step": "commit-protected-desired-state", "state": "succeeded"},
                        {"step": "read-back-desired-state", "state": "succeeded"},
                    ],
                )
            elif job.get("state") == "succeeded":
                evidence = job.get("evidence")
                prior = evidence.get("receipt") if isinstance(evidence, dict) else None
                if prior != receipt:
                    raise HouseholdPolicyRuntimeError("household_policy_job_evidence_mismatch")
            else:
                raise HouseholdPolicyRuntimeError("household_policy_job_in_progress")

            committed = dict(envelope)
            committed.update(status="committed", commit=receipt)
            self.store.set_meta(key, committed)
            self.store.audit(
                actor=actor,
                action=ACTION,
                target=subject.member_id,
                outcome="succeeded",
                correlation_id=correlation_id,
                details={
                    "job_id": job["job_id"],
                    "plan_id": plan["plan_id"],
                    "desired_generation": expected_generation,
                    "policy_id": proposed.policy_id,
                    "policy_sha256": desired["policy_sha256"],
                    "enforcement_verified": False,
                    "reconciliation_required": True,
                    "infrastructure_mutation_performed": False,
                    "external_publication_performed": False,
                },
            )
            return receipt

    def desired_state(self, *, actor: str, member_id: str) -> dict[str, object] | None:
        with self._lock:
            snapshot, bindings = self._state()
            self._actor_member(actor, snapshot, bindings)
            snapshot.household.member(member_id)
            desired = self._desired(self.store.get_meta(_desired_key(snapshot.household_id, member_id)))
            return dict(desired) if desired is not None else None
