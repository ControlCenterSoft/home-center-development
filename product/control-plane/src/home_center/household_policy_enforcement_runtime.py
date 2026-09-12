"""Qualification-bound policy enforcement execution boundary for Home Center 0.59.

Backend acceptance is not enforcement success. The service performs one exact,
explicitly confirmed mutation attempt and then requires the existing read-only
reconciliation path. Ambiguous outcomes are never retried automatically.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Any, Protocol

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_policy_runtime import DESIRED_KEY_PREFIX, DESIRED_STATE_SCHEMA
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json

ACTION = "household.policy.enforcement.execute"
PLAN_SCHEMA = "home-center.household-policy-enforcement-plan.v1"
CONFIRMATION_SCHEMA = "home-center.household-policy-enforcement-confirmation.v1"
STATE_SCHEMA = "home-center.household-policy-enforcement-state.v1"
RECEIPT_SCHEMA = "home-center.household-policy-enforcement-receipt.v1"
PLAN_KEY_PREFIX = "cozy.household.policy.enforcement."
IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
PLAN_ID = re.compile(r"^hpep-[0-9a-f]{24}$")
POLICY_ID = re.compile(r"^hcpol-[0-9a-f]{24}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class HouseholdPolicyEnforcementError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class HouseholdPolicyMutationAdapter(Protocol):
    policy_mutation_capable: bool
    policy_backend_qualified: bool
    adapter_id: str
    adapter_version: str
    adapter_artifact_sha256: str
    qualification_evidence_sha256: str

    def apply_policy(self, request: dict[str, object]) -> object: ...


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise HouseholdPolicyEnforcementError(code)
    return value


def _plan_key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise HouseholdPolicyEnforcementError("invalid_household_policy_enforcement_plan_id")
    return PLAN_KEY_PREFIX + plan_id


def _desired(value: object, household_id: str, member_id: str) -> dict[str, Any]:
    required = {
        "schema", "household_id", "member_id", "generation", "plan_id", "policy",
        "policy_sha256", "reason", "enforcement_verified", "reconciliation_required",
        "infrastructure_mutation_authorized", "external_publication_authorized",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema") != DESIRED_STATE_SCHEMA
        or value.get("household_id") != household_id
        or value.get("member_id") != member_id
        or isinstance(value.get("generation"), bool)
        or not isinstance(value.get("generation"), int)
        or value["generation"] < 1
        or not isinstance(value.get("policy"), dict)
        or not isinstance(value.get("policy_sha256"), str)
        or SHA256.fullmatch(value["policy_sha256"]) is None
        or _digest(value["policy"]) != value["policy_sha256"]
        or not isinstance(value["policy"].get("policy_id"), str)
        or POLICY_ID.fullmatch(value["policy"]["policy_id"]) is None
        or value.get("enforcement_verified") is not False
        or value.get("reconciliation_required") is not True
        or value.get("infrastructure_mutation_authorized") is not False
        or value.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyEnforcementError("household_policy_enforcement_desired_state_invalid")
    return dict(value)


class HouseholdPolicyEnforcementRuntimeService:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()
        self._adapters: dict[str, HouseholdPolicyMutationAdapter] = {}

    @staticmethod
    def _adapter_metadata(backend_id: str, adapter: object) -> dict[str, str]:
        values = {
            "adapter_id": getattr(adapter, "adapter_id", None),
            "adapter_version": getattr(adapter, "adapter_version", None),
            "adapter_artifact_sha256": getattr(adapter, "adapter_artifact_sha256", None),
            "qualification_evidence_sha256": getattr(adapter, "qualification_evidence_sha256", None),
        }
        if (
            getattr(adapter, "policy_mutation_capable", None) is not True
            or getattr(adapter, "policy_backend_qualified", None) is not True
            or values["adapter_id"] != backend_id
            or not isinstance(values["adapter_version"], str)
            or not values["adapter_version"]
            or len(values["adapter_version"]) > 128
            or not isinstance(values["adapter_artifact_sha256"], str)
            or SHA256.fullmatch(values["adapter_artifact_sha256"]) is None
            or not isinstance(values["qualification_evidence_sha256"], str)
            or SHA256.fullmatch(values["qualification_evidence_sha256"]) is None
            or not callable(getattr(adapter, "apply_policy", None))
        ):
            raise HouseholdPolicyEnforcementError(
                "invalid_household_policy_enforcement_adapter_registration"
            )
        return values  # type: ignore[return-value]

    def register_adapter(self, backend_id: str, adapter: object) -> None:
        backend_id = _identifier(backend_id, "invalid_household_policy_enforcement_adapter_registration")
        if backend_id in self._adapters:
            raise HouseholdPolicyEnforcementError(
                "invalid_household_policy_enforcement_adapter_registration"
            )
        self._adapter_metadata(backend_id, adapter)
        self._adapters[backend_id] = adapter  # type: ignore[assignment]

    def _context(self, actor: str, member_id: str) -> tuple[dict[str, Any], str]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyEnforcementError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
            actor_member_id = next(
                (item.member_id for item in bindings if getattr(item, "actor", None) == actor),
                None,
            )
            if actor_member_id is None:
                raise HouseholdPolicyEnforcementError("household_actor_not_bound")
            actor_member = snapshot.household.member(actor_member_id)
            target_member = snapshot.household.member(member_id)
            policy = effective_policy(snapshot.household, actor_member_id)
        except HouseholdPolicyEnforcementError:
            raise
        except HomeServiceCatalogError as exc:
            raise HouseholdPolicyEnforcementError(exc.code) from exc
        except Exception as exc:
            raise HouseholdPolicyEnforcementError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        if not actor_member.enabled or not target_member.enabled:
            raise HouseholdPolicyEnforcementError("household_member_disabled")
        if policy.role is not HouseholdRole.PARENT or not policy.administration_allowed:
            raise HouseholdPolicyEnforcementError("household_policy_enforcement_not_authorized")
        household_id = snapshot.household_id
        desired = _desired(
            self.store.get_meta(DESIRED_KEY_PREFIX + household_id + "." + member_id),
            household_id,
            member_id,
        )
        return desired, household_id

    @staticmethod
    def _matches(desired: dict[str, Any], plan: dict[str, Any]) -> bool:
        return (
            desired["generation"] == plan["desired_generation"]
            and desired["plan_id"] == plan["desired_plan_id"]
            and desired["policy"]["policy_id"] == plan["policy_id"]
            and desired["policy_sha256"] == plan["policy_sha256"]
            and _digest(desired) == plan["desired_state_sha256"]
        )

    def plan(self, *, actor: str, member_id: str, backend_id: str, correlation_id: str) -> dict[str, object]:
        member_id = _identifier(member_id, "invalid_household_policy_enforcement_member_id")
        backend_id = _identifier(backend_id, "invalid_household_policy_enforcement_backend_id")
        with self._lock:
            desired, household_id = self._context(actor, member_id)
            binding = {
                "household_id": household_id,
                "member_id": member_id,
                "backend_id": backend_id,
                "desired_generation": desired["generation"],
                "desired_plan_id": desired["plan_id"],
                "policy_id": desired["policy"]["policy_id"],
                "policy_sha256": desired["policy_sha256"],
                "desired_state_sha256": _digest(desired),
            }
            plan_id = "hpep-" + _digest({"actor": actor, **binding})[:24]
            plan = {
                "schema": PLAN_SCHEMA,
                "plan_id": plan_id,
                **binding,
                "backend_mutation_authorized": False,
                "automatic_retry_authorized": False,
                "enforcement_success_claim_authorized": False,
                "infrastructure_mutation_authorized": False,
                "external_publication_authorized": False,
            }
            key = _plan_key(plan_id)
            existing = self.store.get_meta(key)
            if existing is not None:
                if (
                    not isinstance(existing, dict)
                    or existing.get("schema") != STATE_SCHEMA
                    or existing.get("actor") != actor
                    or existing.get("plan") != plan
                ):
                    raise HouseholdPolicyEnforcementError("household_policy_enforcement_plan_conflict")
                return dict(plan)
            self.store.set_meta(key, {
                "schema": STATE_SCHEMA, "status": "planned", "actor": actor, "plan": plan,
                "confirmation": None, "job_id": None, "backend_result": None, "receipt": None,
            })
            self.store.audit(
                actor=actor, action="household.policy.enforcement.plan", target=member_id,
                outcome="planned", correlation_id=correlation_id,
                details={"plan_id": plan_id, "backend_id": backend_id, "policy_sha256": desired["policy_sha256"]},
            )
            return plan

    def _load(self, actor: str, plan_id: str) -> tuple[str, dict[str, Any], dict[str, Any]]:
        key = _plan_key(plan_id)
        state = self.store.get_meta(key)
        if (
            not isinstance(state, dict)
            or state.get("schema") != STATE_SCHEMA
            or state.get("actor") != actor
            or not isinstance(state.get("plan"), dict)
            or state["plan"].get("plan_id") != plan_id
        ):
            raise HouseholdPolicyEnforcementError("household_policy_enforcement_plan_not_found")
        return key, state, dict(state["plan"])

    def _revalidate(self, actor: str, plan: dict[str, Any]) -> dict[str, Any]:
        desired, household_id = self._context(actor, str(plan["member_id"]))
        if household_id != plan["household_id"] or not self._matches(desired, plan):
            raise HouseholdPolicyEnforcementError("household_policy_enforcement_desired_state_stale")
        return desired

    def confirm(
        self, *, actor: str, plan_id: str, confirmed: bool, correlation_id: str
    ) -> dict[str, object]:
        if confirmed is not True:
            raise HouseholdPolicyEnforcementError("household_policy_enforcement_confirmation_required")
        with self._lock:
            key, state, plan = self._load(actor, plan_id)
            if state.get("status") == "confirmed":
                value = state.get("confirmation")
                if isinstance(value, dict) and value.get("schema") == CONFIRMATION_SCHEMA:
                    return dict(value)
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_state_invalid")
            if state.get("status") != "planned":
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_state_invalid")
            self._revalidate(actor, plan)
            confirmation = {
                "schema": CONFIRMATION_SCHEMA, "plan_id": plan_id, "backend_id": plan["backend_id"],
                "member_id": plan["member_id"], "desired_generation": plan["desired_generation"],
                "policy_sha256": plan["policy_sha256"], "backend_mutation_authorized": True,
                "automatic_retry_authorized": False, "enforcement_success_claim_authorized": False,
                "infrastructure_mutation_authorized": False, "external_publication_authorized": False,
            }
            updated = dict(state)
            updated.update(status="confirmed", confirmation=confirmation)
            self.store.set_meta(key, updated)
            self.store.audit(
                actor=actor, action="household.policy.enforcement.confirm", target=str(plan["member_id"]),
                outcome="confirmed", correlation_id=correlation_id,
                details={"plan_id": plan_id, "backend_id": plan["backend_id"], "policy_sha256": plan["policy_sha256"]},
            )
            return confirmation

    def execute(self, *, actor: str, plan_id: str, correlation_id: str) -> dict[str, object]:
        with self._lock:
            key, state, plan = self._load(actor, plan_id)
            if state.get("status") == "completed":
                receipt = state.get("receipt")
                if isinstance(receipt, dict) and receipt.get("schema") == RECEIPT_SCHEMA:
                    return dict(receipt)
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_state_invalid")
            if state.get("status") in {"invoking", "in-doubt"}:
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_reconciliation_required")
            if state.get("status") == "failed":
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_previous_attempt_failed")
            confirmation = state.get("confirmation")
            if (
                state.get("status") != "confirmed"
                or not isinstance(confirmation, dict)
                or confirmation.get("schema") != CONFIRMATION_SCHEMA
                or confirmation.get("plan_id") != plan_id
                or confirmation.get("backend_mutation_authorized") is not True
            ):
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_confirmation_required")
            desired = self._revalidate(actor, plan)
            backend_id = str(plan["backend_id"])
            adapter = self._adapters.get(backend_id)
            if adapter is None:
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_adapter_unavailable")
            adapter_meta = self._adapter_metadata(backend_id, adapter)
            request = {
                "schema": "home-center.household-policy-backend-apply-request.v1",
                "plan_id": plan_id, "household_id": plan["household_id"], "member_id": plan["member_id"],
                "backend_id": backend_id, "desired_generation": plan["desired_generation"],
                "desired_plan_id": plan["desired_plan_id"], "policy_id": plan["policy_id"],
                "policy_sha256": plan["policy_sha256"], "desired_state_sha256": plan["desired_state_sha256"],
                "policy": desired["policy"], **adapter_meta, "secret_values_present": False,
                "backend_mutation_authorized": True, "automatic_retry_authorized": False,
                "infrastructure_mutation_authorized": False, "external_publication_authorized": False,
            }
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION, actor=actor,
                    reason="apply exact protected Household policy through qualified backend",
                    idempotency_key=plan_id,
                    request_hash=_digest({"action": ACTION, "actor": actor, "request": request}),
                    preflight={
                        "schema": "home-center.household-policy-enforcement-preflight.v1",
                        "plan_id": plan_id, "backend_id": backend_id,
                        "policy_sha256": plan["policy_sha256"],
                        "adapter_artifact_sha256": adapter_meta["adapter_artifact_sha256"],
                        "qualification_evidence_sha256": adapter_meta["qualification_evidence_sha256"],
                        "automatic_retry_authorized": False, "enforcement_success_claim_authorized": False,
                    },
                    steps=[
                        {"step": "revalidate-exact-desired-state", "state": "succeeded"},
                        {"step": "invoke-policy-backend-once", "state": "pending"},
                        {"step": "require-read-only-reconciliation", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_idempotency_conflict") from exc
            if not created:
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_job_state_invalid")
            invoking = dict(state)
            invoking.update(status="invoking", job_id=job["job_id"])
            self.store.set_meta(key, invoking)
            self.store.transition_action_job(job["job_id"], expected_state="preflight", new_state="running")
            try:
                raw_result = adapter.apply_policy(request)
            except Exception as exc:
                result = {
                    "schema": "home-center.household-policy-backend-apply-result.v1",
                    "state": "ambiguous", "backend_id": backend_id, "plan_id": plan_id,
                    "policy_sha256": plan["policy_sha256"], "reconciliation_required": True,
                    "automatic_retry_authorized": False,
                }
                indoubt = dict(invoking)
                indoubt.update(status="in-doubt", backend_result=result)
                self.store.set_meta(key, indoubt)
                self.store.transition_action_job(
                    job["job_id"], expected_state="running", new_state="failed",
                    evidence={"schema": "home-center.household-policy-enforcement-failure.v1",
                              "code": "household_policy_enforcement_backend_outcome_ambiguous",
                              "backend_result": result},
                )
                raise HouseholdPolicyEnforcementError(
                    "household_policy_enforcement_backend_outcome_ambiguous"
                ) from exc

            accepted = isinstance(raw_result, dict) and raw_result.get("accepted") is True
            result = {
                "schema": "home-center.household-policy-backend-apply-result.v1",
                "state": "accepted" if accepted else "rejected", "backend_id": backend_id,
                "plan_id": plan_id, "policy_sha256": plan["policy_sha256"],
                "reconciliation_required": True, "automatic_retry_authorized": False,
            }
            receipt = {
                "schema": RECEIPT_SCHEMA,
                "state": "backend-accepted-awaiting-reconciliation" if accepted else "backend-rejected",
                "plan_id": plan_id, "job_id": job["job_id"], "backend_id": backend_id,
                "member_id": plan["member_id"], "desired_generation": plan["desired_generation"],
                "policy_sha256": plan["policy_sha256"], "backend_command_accepted": accepted,
                "enforcement_verified": False, "reconciliation_required": True,
                "automatic_retry_authorized": False, "enforcement_success_claim_authorized": False,
                "infrastructure_mutation_performed": False, "external_publication_performed": False,
            }
            final = dict(invoking)
            final.update(status="completed" if accepted else "failed", backend_result=result, receipt=receipt)
            self.store.set_meta(key, final)
            self.store.transition_action_job(
                job["job_id"], expected_state="running",
                new_state="succeeded" if accepted else "failed",
                evidence={"schema": "home-center.household-policy-enforcement-evidence.v1",
                          "backend_result": result, "receipt": receipt,
                          "enforcement_verified": False, "reconciliation_required": True},
            )
            self.store.audit(
                actor=actor, action=ACTION, target=str(plan["member_id"]),
                outcome="backend-accepted" if accepted else "backend-rejected",
                correlation_id=correlation_id,
                details={"plan_id": plan_id, "backend_id": backend_id,
                         "adapter_artifact_sha256": adapter_meta["adapter_artifact_sha256"],
                         "qualification_evidence_sha256": adapter_meta["qualification_evidence_sha256"],
                         "policy_sha256": plan["policy_sha256"], "enforcement_verified": False,
                         "reconciliation_required": True, "automatic_retry_authorized": False},
            )
            if not accepted:
                raise HouseholdPolicyEnforcementError("household_policy_enforcement_backend_rejected")
            return receipt
