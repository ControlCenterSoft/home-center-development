"""Protected Desired State workflow for Home Center 0.60 parental Internet policy.

A successful commit means only that parental rules were saved. It never means DNS,
proxy, firewall or device enforcement succeeded. The runtime requires an exact verified
0.59 child-policy base before it can plan or commit 0.60 Desired State.
"""
from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_policy_runtime import DESIRED_KEY_PREFIX as BASE_POLICY_DESIRED_KEY_PREFIX
from .household_runtime import HOUSEHOLD_STATE_KEY, _snapshot_from_dict, _state_from_dict
from .household_policy_verification_state import VERIFIED_KEY_PREFIX
from .parental_internet_policy import (
    ParentalInternetPolicyError,
    build_parental_internet_policy,
)
from .parental_internet_policy_validation import parental_internet_policy_from_dict
from .parental_internet_verified_base import (
    ParentalInternetVerifiedBaseError,
    VerifiedParentalPolicyBase,
    verified_parental_policy_base_from_dict,
)
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

PLAN_REQUEST_SCHEMA = "home-center.parental-internet-policy-plan-request.v1"
PLAN_SCHEMA = "home-center.parental-internet-policy-change-plan.v1"
CONFIRM_REQUEST_SCHEMA = "home-center.parental-internet-policy-confirm-request.v1"
DESIRED_STATE_SCHEMA = "home-center.parental-internet-policy-desired-state.v1"
COMMIT_RECEIPT_SCHEMA = "home-center.parental-internet-policy-commit-receipt.v1"
PLAN_STATE_SCHEMA = "home-center.parental-internet-policy-plan-state.v1"
ACTION = "household.parental-internet.desired-state.commit"
PLAN_KEY_PREFIX = "cozy.household.parental-internet.plan."
DESIRED_KEY_PREFIX = "cozy.household.parental-internet.desired."
_PLAN_ID = re.compile(r"hpip-[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

_RULE_FIELDS = {
    "rule_source_id",
    "rule_source_version",
    "rule_source_sha256",
    "allow_domains",
    "deny_domains",
    "allow_categories",
    "deny_categories",
    "schedule",
    "daily_quota_minutes",
    "weekly_quota_minutes",
    "continuous_session_minutes",
    "break_minutes",
    "grace_minutes",
    "bonus_minutes",
}


class ParentalInternetPolicyRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def _plan_key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
        raise ParentalInternetPolicyRuntimeError("invalid_parental_internet_plan_id")
    return PLAN_KEY_PREFIX + plan_id


def _desired_key(household_id: str, member_id: str) -> str:
    return DESIRED_KEY_PREFIX + household_id + "." + member_id


def _verified_key(household_id: str, member_id: str) -> str:
    return VERIFIED_KEY_PREFIX + household_id + "." + member_id


def _base_desired_key(household_id: str, member_id: str) -> str:
    return BASE_POLICY_DESIRED_KEY_PREFIX + household_id + "." + member_id


def _reason(value: object) -> str:
    if not isinstance(value, str):
        raise ParentalInternetPolicyRuntimeError("invalid_parental_internet_reason")
    text = value.strip()
    if not text or len(text) > 512 or any(ord(ch) < 32 for ch in text):
        raise ParentalInternetPolicyRuntimeError("invalid_parental_internet_reason")
    return text


class ParentalInternetPolicyRuntimeService:
    """Plan and explicitly confirm non-enforcing parental Internet Desired State."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise ParentalInternetPolicyRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise ParentalInternetPolicyRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor_parent(actor: str, snapshot: object, bindings: tuple[object, ...]) -> str:
        member_id = next(
            (item.member_id for item in bindings if getattr(item, "actor", None) == actor),
            None,
        )
        if member_id is None:
            raise ParentalInternetPolicyRuntimeError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, member_id)  # type: ignore[attr-defined]
        except HomeServiceCatalogError as exc:
            raise ParentalInternetPolicyRuntimeError(exc.code) from exc
        if not policy.administration_allowed or policy.role is not HouseholdRole.PARENT:
            raise ParentalInternetPolicyRuntimeError("parental_internet_change_not_authorized")
        return member_id

    def _verified_base(self, *, household_id: str, member_id: str) -> VerifiedParentalPolicyBase:
        raw = self.store.get_meta(_verified_key(household_id, member_id))
        if raw is None:
            raise ParentalInternetPolicyRuntimeError("parental_internet_verified_base_missing")
        try:
            verified = verified_parental_policy_base_from_dict(raw)
        except ParentalInternetVerifiedBaseError as exc:
            raise ParentalInternetPolicyRuntimeError(exc.code) from exc
        if verified.household_id != household_id or verified.member_id != member_id:
            raise ParentalInternetPolicyRuntimeError("parental_internet_verified_base_binding_mismatch")
        current_base_desired = self.store.get_meta(_base_desired_key(household_id, member_id))
        if (
            not isinstance(current_base_desired, dict)
            or _digest(current_base_desired) != verified.source_desired_state_sha256
        ):
            raise ParentalInternetPolicyRuntimeError("parental_internet_verified_base_stale")
        return verified

    @staticmethod
    def _require_current_role_base(snapshot: object, verified: VerifiedParentalPolicyBase) -> None:
        try:
            current = effective_policy(snapshot.household, verified.member_id)  # type: ignore[attr-defined]
        except HomeServiceCatalogError as exc:
            raise ParentalInternetPolicyRuntimeError(exc.code) from exc
        if (
            current.role is not HouseholdRole.CHILD
            or current.policy_id != verified.policy.base_policy_id
            or verified.policy.vpn_allowed
            or not verified.policy.managed_device_required
            or verified.policy.smart_home_control_allowed
            or verified.policy.administration_allowed
            or verified.policy.external_publication_allowed
        ):
            raise ParentalInternetPolicyRuntimeError("parental_internet_verified_base_stale")

    @staticmethod
    def _desired(value: object) -> dict[str, Any] | None:
        if value is None:
            return None
        required = {
            "schema", "household_id", "member_id", "generation", "plan_id",
            "verified_base_state_sha256", "base_policy_id", "base_policy_sha256",
            "policy", "policy_sha256", "reason", "enforcement_verified",
            "reconciliation_required", "dns_policy_applied", "proxy_policy_applied",
            "infrastructure_mutation_authorized", "external_publication_authorized",
        }
        if (
            not isinstance(value, dict)
            or set(value) != required
            or value.get("schema") != DESIRED_STATE_SCHEMA
            or type(value.get("generation")) is not int
            or value["generation"] < 1
            or not isinstance(value.get("policy"), dict)
            or not isinstance(value.get("policy_sha256"), str)
            or _SHA256.fullmatch(value["policy_sha256"]) is None
            or _digest(value["policy"]) != value["policy_sha256"]
            or not isinstance(value.get("verified_base_state_sha256"), str)
            or _SHA256.fullmatch(value["verified_base_state_sha256"]) is None
            or not isinstance(value.get("base_policy_sha256"), str)
            or _SHA256.fullmatch(value["base_policy_sha256"]) is None
            or value.get("enforcement_verified") is not False
            or value.get("reconciliation_required") is not True
            or value.get("dns_policy_applied") is not False
            or value.get("proxy_policy_applied") is not False
            or value.get("infrastructure_mutation_authorized") is not False
            or value.get("external_publication_authorized") is not False
        ):
            raise ParentalInternetPolicyRuntimeError("parental_internet_desired_state_invalid")
        return dict(value)

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        expected = {"schema", "subject_member_id", "reason", *_RULE_FIELDS}
        if set(request) != expected or request.get("schema") != PLAN_REQUEST_SCHEMA:
            raise ParentalInternetPolicyRuntimeError("invalid_parental_internet_plan_request")
        subject_member_id = request.get("subject_member_id")
        if not isinstance(subject_member_id, str):
            raise ParentalInternetPolicyRuntimeError("invalid_parental_internet_subject")
        reason = _reason(request.get("reason"))

        with self._lock:
            snapshot, bindings = self._state()
            actor_member_id = self._actor_parent(actor, snapshot, bindings)
            try:
                subject = snapshot.household.member(subject_member_id)
            except HomeServiceCatalogError as exc:
                raise ParentalInternetPolicyRuntimeError(exc.code) from exc
            if not subject.enabled or subject.role is not HouseholdRole.CHILD:
                raise ParentalInternetPolicyRuntimeError("parental_internet_subject_not_eligible")
            verified = self._verified_base(
                household_id=snapshot.household_id,
                member_id=subject.member_id,
            )
            self._require_current_role_base(snapshot, verified)
            try:
                proposed = build_parental_internet_policy(
                    base=verified.policy,
                    **{name: request[name] for name in _RULE_FIELDS},
                )
            except (ParentalInternetPolicyError, TypeError) as exc:
                raise ParentalInternetPolicyRuntimeError(
                    getattr(exc, "code", "parental_internet_policy_rejected")
                ) from exc

            desired_key = _desired_key(snapshot.household_id, subject.member_id)
            current = self._desired(self.store.get_meta(desired_key))
            observed_generation = current["generation"] if current is not None else 0
            current_policy_sha256 = current["policy_sha256"] if current is not None else None
            proposed_dict = proposed.to_dict()
            canonical = {
                "household_snapshot_id": snapshot.snapshot_id,
                "household_resource_version": snapshot.resource_version,
                "household_generation": snapshot.generation,
                "actor_member_id": actor_member_id,
                "subject_member_id": subject.member_id,
                "verified_base_state_sha256": verified.verified_state_sha256,
                "base_policy_id": verified.policy.policy_id,
                "base_policy_sha256": verified.policy_sha256,
                "base_desired_generation": verified.desired_generation,
                "base_evidence_sha256": verified.evidence_sha256,
                "observed_desired_generation": observed_generation,
                "current_parental_policy_sha256": current_policy_sha256,
                "expected_desired_generation": observed_generation + 1,
                "proposed_policy": proposed_dict,
                "proposed_policy_sha256": _digest(proposed_dict),
                "reason": reason,
            }
            plan_id = "hpip-" + _digest(canonical)[:24]
            plan = {
                "schema": PLAN_SCHEMA,
                "plan_id": plan_id,
                **canonical,
                "desired_state_write_authorized": False,
                "enforcement_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }
            self.store.set_meta(
                _plan_key(plan_id),
                {
                    "schema": PLAN_STATE_SCHEMA,
                    "status": "planned",
                    "actor": actor,
                    "base_snapshot": snapshot.to_dict(),
                    "bindings": [item.to_dict() for item in bindings],
                    "plan": plan,
                    "commit": None,
                },
            )
            self.store.audit(
                actor=actor,
                action="household.parental-internet.plan",
                target=subject.member_id,
                outcome="planned",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan_id,
                    "verified_base_state_sha256": verified.verified_state_sha256,
                    "proposed_policy_sha256": plan["proposed_policy_sha256"],
                    "enforcement_authorized": False,
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
            or envelope["plan"].get("schema") != PLAN_SCHEMA
            or envelope["plan"].get("plan_id") != plan_id
        ):
            raise ParentalInternetPolicyRuntimeError("parental_internet_plan_not_found")
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
            raise ParentalInternetPolicyRuntimeError("invalid_parental_internet_confirm_request")

        with self._lock:
            key, envelope, plan = self._load(request.get("plan_id"))
            if envelope.get("actor") != actor:
                raise ParentalInternetPolicyRuntimeError("parental_internet_actor_mismatch")
            if envelope.get("status") == "committed":
                receipt = envelope.get("commit")
                if isinstance(receipt, dict) and receipt.get("schema") == COMMIT_RECEIPT_SCHEMA:
                    return dict(receipt)
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")
            if envelope.get("status") != "planned":
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")

            snapshot, bindings = self._state()
            actor_member_id = self._actor_parent(actor, snapshot, bindings)
            try:
                base_snapshot = _snapshot_from_dict(envelope.get("base_snapshot"))
            except Exception as exc:
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid") from exc
            if (
                snapshot != base_snapshot
                or [item.to_dict() for item in bindings] != envelope.get("bindings")
                or actor_member_id != plan.get("actor_member_id")
                or snapshot.snapshot_id != plan.get("household_snapshot_id")
                or snapshot.resource_version != plan.get("household_resource_version")
                or snapshot.generation != plan.get("household_generation")
            ):
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_stale")

            subject_member_id = plan.get("subject_member_id")
            try:
                subject = snapshot.household.member(subject_member_id)
            except HomeServiceCatalogError as exc:
                raise ParentalInternetPolicyRuntimeError(exc.code) from exc
            if not subject.enabled or subject.role is not HouseholdRole.CHILD:
                raise ParentalInternetPolicyRuntimeError("parental_internet_subject_not_eligible")
            verified = self._verified_base(
                household_id=snapshot.household_id,
                member_id=subject.member_id,
            )
            self._require_current_role_base(snapshot, verified)
            if (
                verified.verified_state_sha256 != plan.get("verified_base_state_sha256")
                or verified.policy.policy_id != plan.get("base_policy_id")
                or verified.policy_sha256 != plan.get("base_policy_sha256")
                or verified.desired_generation != plan.get("base_desired_generation")
                or verified.evidence_sha256 != plan.get("base_evidence_sha256")
            ):
                raise ParentalInternetPolicyRuntimeError("parental_internet_verified_base_stale")
            try:
                proposed = parental_internet_policy_from_dict(
                    value=plan.get("proposed_policy"),
                    base=verified.policy,
                )
            except (ParentalInternetPolicyError, TypeError) as exc:
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid") from exc
            proposed_dict = proposed.to_dict()
            proposed_sha256 = _digest(proposed_dict)
            if proposed_sha256 != plan.get("proposed_policy_sha256"):
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")

            expected_generation = plan.get("expected_desired_generation")
            if type(expected_generation) is not int or expected_generation < 1:
                raise ParentalInternetPolicyRuntimeError("parental_internet_plan_state_invalid")
            desired_key = _desired_key(snapshot.household_id, subject.member_id)
            current = self._desired(self.store.get_meta(desired_key))
            desired = {
                "schema": DESIRED_STATE_SCHEMA,
                "household_id": snapshot.household_id,
                "member_id": subject.member_id,
                "generation": expected_generation,
                "plan_id": plan["plan_id"],
                "verified_base_state_sha256": verified.verified_state_sha256,
                "base_policy_id": verified.policy.policy_id,
                "base_policy_sha256": verified.policy_sha256,
                "policy": proposed_dict,
                "policy_sha256": proposed_sha256,
                "reason": plan["reason"],
                "enforcement_verified": False,
                "reconciliation_required": True,
                "dns_policy_applied": False,
                "proxy_policy_applied": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }

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
                and recovery_preflight.get("schema") == "home-center.parental-internet-preflight.v1"
                and recovery_preflight.get("plan_id") == plan["plan_id"]
                and recovery_preflight.get("verified_base_state_sha256") == verified.verified_state_sha256
                and recovery_preflight.get("expected_desired_generation") == expected_generation
                and recovery_preflight.get("enforcement_authorized") is False
            )
            if not interrupted_write_recovery:
                observed_generation = current["generation"] if current is not None else 0
                current_sha = current["policy_sha256"] if current is not None else None
                if observed_generation != plan.get("observed_desired_generation"):
                    raise ParentalInternetPolicyRuntimeError("parental_internet_desired_generation_stale")
                if current_sha != plan.get("current_parental_policy_sha256"):
                    raise ParentalInternetPolicyRuntimeError("parental_internet_current_policy_stale")

            request_hash = _digest(
                {"schema": CONFIRM_REQUEST_SCHEMA, "plan_id": plan["plan_id"], "confirmed": True}
            )
            try:
                job, _created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason=plan["reason"],
                    idempotency_key=plan["plan_id"],
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.parental-internet-preflight.v1",
                        "plan_id": plan["plan_id"],
                        "household_snapshot_id": snapshot.snapshot_id,
                        "subject_member_id": subject.member_id,
                        "verified_base_state_sha256": verified.verified_state_sha256,
                        "expected_desired_generation": expected_generation,
                        "enforcement_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-parent-authority", "state": "succeeded"},
                        {"step": "revalidate-verified-base", "state": "succeeded"},
                        {"step": "commit-parental-desired-state", "state": "pending"},
                        {"step": "read-back-parental-desired-state", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise ParentalInternetPolicyRuntimeError("parental_internet_idempotency_conflict") from exc

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
                        "schema": "home-center.parental-internet-desired-state-write.v1",
                        "plan_id": plan["plan_id"],
                        "generation": expected_generation,
                        "policy_sha256": proposed_sha256,
                        "enforcement_verified": False,
                        "dns_policy_applied": False,
                        "proxy_policy_applied": False,
                    },
                    steps=[
                        {"step": "revalidate-parent-authority", "state": "succeeded"},
                        {"step": "revalidate-verified-base", "state": "succeeded"},
                        {"step": "commit-parental-desired-state", "state": "succeeded"},
                        {"step": "read-back-parental-desired-state", "state": "pending"},
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
                            "schema": "home-center.parental-internet-desired-state-failure.v1",
                            "code": "parental_internet_desired_state_readback_failed",
                            "enforcement_verified": False,
                        },
                    )
                raise ParentalInternetPolicyRuntimeError("parental_internet_desired_state_readback_failed")

            receipt = {
                "schema": COMMIT_RECEIPT_SCHEMA,
                "state": "desired-state-committed",
                "job_id": job["job_id"],
                "plan_id": plan["plan_id"],
                "household_id": snapshot.household_id,
                "member_id": subject.member_id,
                "desired_generation": expected_generation,
                "verified_base_state_sha256": verified.verified_state_sha256,
                "policy_id": proposed.policy_id,
                "policy_sha256": proposed_sha256,
                "enforcement_verified": False,
                "reconciliation_required": True,
                "dns_policy_applied": False,
                "proxy_policy_applied": False,
                "infrastructure_mutation_performed": False,
                "external_publication_performed": False,
            }
            if job.get("state") == "verifying":
                job = self.store.transition_action_job(
                    job["job_id"],
                    expected_state="verifying",
                    new_state="succeeded",
                    evidence={
                        "schema": "home-center.parental-internet-desired-state-evidence.v1",
                        "desired_state_sha256": _digest(desired),
                        "receipt": receipt,
                        "enforcement_verified": False,
                    },
                    steps=[
                        {"step": "revalidate-parent-authority", "state": "succeeded"},
                        {"step": "revalidate-verified-base", "state": "succeeded"},
                        {"step": "commit-parental-desired-state", "state": "succeeded"},
                        {"step": "read-back-parental-desired-state", "state": "succeeded"},
                    ],
                )
            elif job.get("state") == "succeeded":
                evidence = job.get("evidence")
                prior = evidence.get("receipt") if isinstance(evidence, dict) else None
                if prior != receipt:
                    raise ParentalInternetPolicyRuntimeError("parental_internet_job_evidence_mismatch")
            else:
                raise ParentalInternetPolicyRuntimeError("parental_internet_job_in_progress")

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
                    "verified_base_state_sha256": verified.verified_state_sha256,
                    "policy_sha256": proposed_sha256,
                    "enforcement_verified": False,
                    "reconciliation_required": True,
                    "dns_policy_applied": False,
                    "proxy_policy_applied": False,
                    "infrastructure_mutation_performed": False,
                    "external_publication_performed": False,
                },
            )
            return receipt

    def desired_state(self, *, actor: str, member_id: str) -> dict[str, object] | None:
        with self._lock:
            snapshot, bindings = self._state()
            self._actor_parent(actor, snapshot, bindings)
            try:
                subject = snapshot.household.member(member_id)
            except HomeServiceCatalogError as exc:
                raise ParentalInternetPolicyRuntimeError(exc.code) from exc
            if subject.role is not HouseholdRole.CHILD:
                raise ParentalInternetPolicyRuntimeError("parental_internet_subject_not_eligible")
            desired = self._desired(self.store.get_meta(_desired_key(snapshot.household_id, member_id)))
            return dict(desired) if desired is not None else None
