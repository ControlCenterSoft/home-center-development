"""Fail-closed Home Center identity-binding transition for 0.62.

This boundary consumes only an exact verified execution receipt already persisted
in a succeeded durable identity-provisioning Job. It never calls the provider.
After current Household/RBAC and exact-snapshot revalidation it may persist one
separate Home Center member/account binding. The emergency administrator,
privileges, credentials and external-publication state are outside this mutation.
"""
from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .home_services import HomeServiceCatalogError
from .household import HouseholdRole, effective_policy
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .role_identity_provisioning import RoleIdentityProvisioningPlan
from .role_identity_provisioning_runtime import ACTION as EXECUTION_ACTION, RECEIPT_SCHEMA as EXECUTION_RECEIPT_SCHEMA
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now

ACTION = "household.identity.binding.transition"
BINDING_STATE_SCHEMA = "home-center.role-identity-binding-state.v1"
TRANSITION_RECEIPT_SCHEMA = "home-center.role-identity-binding-transition-receipt.v1"
BINDING_KEY_PREFIX = "cozy.household.identity-binding."
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RoleIdentityBindingTransitionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def binding_key(household_id: str, member_id: str) -> str:
    if not isinstance(household_id, str) or not household_id or not isinstance(member_id, str) or not member_id:
        raise RoleIdentityBindingTransitionError("identity_binding_key_invalid")
    return f"{BINDING_KEY_PREFIX}{household_id}.{member_id}"


def _verified_execution_receipt(
    store: StateStore,
    *,
    actor: str,
    plan: RoleIdentityProvisioningPlan,
    receipt: object,
) -> tuple[dict[str, object], dict[str, Any]]:
    expected = {
        "schema", "state", "job_id", "plan_id", "household_id", "member_id",
        "provider_id", "provider_version", "provider_kind", "provider_operation_id",
        "account_name", "account_identity_sha256", "observation_evidence_sha256",
        "account_created_verified", "home_directory_verified", "profile_verified",
        "post_condition_verified", "durable_state_change_authorized",
        "emergency_admin_mutation_authorized", "privilege_grant_authorized",
        "external_publication_authorized",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected:
        raise RoleIdentityBindingTransitionError("identity_binding_execution_receipt_invalid")
    if (
        receipt.get("schema") != EXECUTION_RECEIPT_SCHEMA
        or receipt.get("state") != "verified"
        or receipt.get("plan_id") != plan.plan_id
        or receipt.get("household_id") != plan.household_id
        or receipt.get("member_id") != plan.member_id
        or receipt.get("provider_id") != plan.provider_id
        or receipt.get("provider_version") != plan.provider_version
        or receipt.get("provider_kind") != plan.provider_kind.value
        or receipt.get("account_name") != plan.account_name
        or receipt.get("account_created_verified") is not True
        or receipt.get("home_directory_verified") is not True
        or receipt.get("profile_verified") is not True
        or receipt.get("post_condition_verified") is not True
        or receipt.get("durable_state_change_authorized") is not False
        or receipt.get("emergency_admin_mutation_authorized") is not False
        or receipt.get("privilege_grant_authorized") is not False
        or receipt.get("external_publication_authorized") is not False
        or not isinstance(receipt.get("account_identity_sha256"), str)
        or _SHA256.fullmatch(receipt["account_identity_sha256"]) is None
        or not isinstance(receipt.get("observation_evidence_sha256"), str)
        or _SHA256.fullmatch(receipt["observation_evidence_sha256"]) is None
        or not isinstance(receipt.get("job_id"), str)
        or not receipt["job_id"]
    ):
        raise RoleIdentityBindingTransitionError("identity_binding_execution_receipt_invalid")
    job = store.job(receipt["job_id"])
    if (
        not isinstance(job, dict)
        or job.get("job_type") != EXECUTION_ACTION
        or job.get("state") != "succeeded"
        or job.get("initiator") != actor
        or not isinstance(job.get("result"), dict)
        or job["result"].get("verified") is not True
        or not isinstance(job.get("evidence"), dict)
        or job["evidence"].get("receipt") != receipt
        or job["evidence"].get("durable_state_change_authorized") is not False
    ):
        raise RoleIdentityBindingTransitionError("identity_binding_execution_evidence_invalid")
    return dict(receipt), job


def _binding_state(
    *,
    plan: RoleIdentityProvisioningPlan,
    execution_receipt: dict[str, object],
    transition_job_id: str,
) -> dict[str, object]:
    material = {
        "household_id": plan.household_id,
        "member_id": plan.member_id,
        "plan_id": plan.plan_id,
        "provider_id": plan.provider_id,
        "provider_version": plan.provider_version,
        "provider_kind": plan.provider_kind.value,
        "provider_evidence_sha256": plan.provider_evidence_sha256,
        "account_name": plan.account_name,
        "account_identity_sha256": execution_receipt["account_identity_sha256"],
        "execution_job_id": execution_receipt["job_id"],
        "observation_evidence_sha256": execution_receipt["observation_evidence_sha256"],
        "transition_job_id": transition_job_id,
        "household_snapshot_id": plan.household_snapshot_id,
        "household_resource_version": plan.household_resource_version,
        "household_generation": plan.household_generation,
    }
    return {
        "schema": BINDING_STATE_SCHEMA,
        "binding_id": "hcidb-" + _digest(material)[:24],
        **material,
        "role": plan.role.value,
        "home_directory_mode": plan.home_directory_mode.value,
        "profile_mode": plan.profile_mode.value,
        "verified": True,
        "active": True,
        "credential_material_persisted": False,
        "emergency_admin_isolated": True,
        "privilege_grant_authorized": False,
        "external_publication_authorized": False,
    }


def _persist_binding_exact(
    store: StateStore,
    *,
    expected_household: dict[str, object],
    key: str,
    state: dict[str, object],
) -> str:
    lock = getattr(store, "_lock", None)
    connection = getattr(store, "_connection", None)
    if lock is None or connection is None:
        raise RoleIdentityBindingTransitionError("identity_binding_store_cas_unavailable")
    household_json = canonical_json(expected_household)
    state_json = canonical_json(state)
    with lock:
        connection.execute("BEGIN IMMEDIATE")
        try:
            row = connection.execute(
                "SELECT value_json FROM cluster_meta WHERE key=?", (HOUSEHOLD_STATE_KEY,)
            ).fetchone()
            if row is None or row[0] != household_json:
                connection.rollback()
                raise RoleIdentityBindingTransitionError("identity_binding_household_stale")
            existing = connection.execute(
                "SELECT value_json FROM cluster_meta WHERE key=?", (key,)
            ).fetchone()
            if existing is not None:
                if existing[0] == state_json:
                    connection.commit()
                    return "existing"
                connection.rollback()
                raise RoleIdentityBindingTransitionError("identity_binding_conflict")
            connection.execute(
                "INSERT INTO cluster_meta(key,value_json,updated_at) VALUES(?,?,?)",
                (key, state_json, utc_now()),
            )
            connection.commit()
            return "created"
        except RoleIdentityBindingTransitionError:
            raise
        except Exception:
            connection.rollback()
            raise


class RoleIdentityBindingTransitionService:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _current_authorized_household(
        self,
        *,
        actor: str,
        plan: RoleIdentityProvisioningPlan,
    ) -> tuple[dict[str, object], object]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if not isinstance(raw, dict):
            raise RoleIdentityBindingTransitionError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise RoleIdentityBindingTransitionError(getattr(exc, "code", "household_state_invalid")) from exc
        actor_member = next((item.member_id for item in bindings if item.actor == actor), None)
        if actor_member is None:
            raise RoleIdentityBindingTransitionError("household_actor_not_bound")
        try:
            actor_policy = effective_policy(snapshot.household, actor_member)
            target = snapshot.household.member(plan.member_id)
        except HomeServiceCatalogError as exc:
            raise RoleIdentityBindingTransitionError(exc.code) from exc
        if actor_policy.role is not HouseholdRole.PARENT or not actor_policy.administration_allowed:
            raise RoleIdentityBindingTransitionError("identity_binding_transition_not_authorized")
        if not target.enabled or target.role is not plan.role:
            raise RoleIdentityBindingTransitionError("identity_binding_member_stale")
        if (
            snapshot.household_id != plan.household_id
            or snapshot.snapshot_id != plan.household_snapshot_id
            or snapshot.resource_version != plan.household_resource_version
            or snapshot.generation != plan.household_generation
        ):
            raise RoleIdentityBindingTransitionError("identity_binding_household_stale")
        return raw, snapshot

    def _existing_success_audit(self, job_id: str) -> str | None:
        for event in self.store.audit_events(500):
            if (
                event.get("action") == ACTION
                and event.get("outcome") == "bound"
                and isinstance(event.get("details"), dict)
                and event["details"].get("job_id") == job_id
            ):
                return event.get("event_id") if isinstance(event.get("event_id"), str) else None
        return None

    def transition(
        self,
        *,
        actor: str,
        plan: RoleIdentityProvisioningPlan,
        execution_receipt: object,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, object]:
        if not isinstance(plan, RoleIdentityProvisioningPlan):
            raise RoleIdentityBindingTransitionError("identity_binding_plan_invalid")
        if not isinstance(actor, str) or not actor or not isinstance(correlation_id, str) or not correlation_id:
            raise RoleIdentityBindingTransitionError("identity_binding_actor_or_correlation_invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise RoleIdentityBindingTransitionError("identity_binding_idempotency_key_invalid")

        with self._lock:
            household_raw, _snapshot = self._current_authorized_household(actor=actor, plan=plan)
            receipt, _execution_job = _verified_execution_receipt(
                self.store, actor=actor, plan=plan, receipt=execution_receipt
            )
            request_hash = _digest(
                {
                    "plan_id": plan.plan_id,
                    "execution_job_id": receipt["job_id"],
                    "account_identity_sha256": receipt["account_identity_sha256"],
                    "observation_evidence_sha256": receipt["observation_evidence_sha256"],
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="bind exact verified provider identity to current Household member",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.role-identity-binding-transition-preflight.v1",
                        "plan_id": plan.plan_id,
                        "execution_job_id": receipt["job_id"],
                        "household_id": plan.household_id,
                        "member_id": plan.member_id,
                        "account_name": plan.account_name,
                        "account_identity_sha256": receipt["account_identity_sha256"],
                        "provider_reinvocation_authorized": False,
                        "credential_material_persisted": False,
                        "emergency_admin_mutation_authorized": False,
                        "privilege_grant_authorized": False,
                        "external_publication_authorized": False,
                    },
                    steps=[
                        {"step": "current-household-rbac", "state": "succeeded"},
                        {"step": "verified-execution-evidence", "state": "succeeded"},
                        {"step": "identity-binding-cas", "state": "pending"},
                        {"step": "read-back", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise RoleIdentityBindingTransitionError("identity_binding_idempotency_conflict") from exc

            if not created and job["state"] == "succeeded" and isinstance(job.get("evidence"), dict):
                replay = job["evidence"].get("receipt")
                if isinstance(replay, dict) and replay.get("schema") == TRANSITION_RECEIPT_SCHEMA:
                    return dict(replay)
            if not created and job["state"] == "failed":
                raise RoleIdentityBindingTransitionError("identity_binding_previous_attempt_failed")

            current = job
            if current["state"] == "preflight":
                current = self.store.transition_action_job(
                    current["job_id"], expected_state="preflight", new_state="running"
                )
            if current["state"] == "running":
                current = self.store.transition_action_job(
                    current["job_id"], expected_state="running", new_state="verifying",
                    steps=[
                        {"step": "current-household-rbac", "state": "succeeded"},
                        {"step": "verified-execution-evidence", "state": "succeeded"},
                        {"step": "identity-binding-cas", "state": "running"},
                        {"step": "read-back", "state": "pending"},
                    ],
                )
            if current["state"] != "verifying":
                raise RoleIdentityBindingTransitionError("identity_binding_job_state_invalid")

            state = _binding_state(plan=plan, execution_receipt=receipt, transition_job_id=current["job_id"])
            key = binding_key(plan.household_id, plan.member_id)
            try:
                persistence = _persist_binding_exact(
                    self.store, expected_household=household_raw, key=key, state=state
                )
            except RoleIdentityBindingTransitionError as exc:
                self.store.transition_action_job(
                    current["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result={
                        "schema": "home-center.role-identity-binding-transition-failure.v1",
                        "code": exc.code,
                        "provider_reinvocation_performed": False,
                        "credential_material_persisted": False,
                    },
                )
                self.store.audit(
                    actor=actor,
                    action=ACTION,
                    target=plan.member_id,
                    outcome="failed",
                    correlation_id=correlation_id,
                    details={
                        "job_id": current["job_id"],
                        "plan_id": plan.plan_id,
                        "code": exc.code,
                        "provider_reinvocation_performed": False,
                    },
                )
                raise

            read_back = self.store.get_meta(key)
            if read_back != state:
                self.store.transition_action_job(
                    current["job_id"],
                    expected_state="verifying",
                    new_state="failed",
                    result={
                        "schema": "home-center.role-identity-binding-transition-failure.v1",
                        "code": "identity_binding_readback_mismatch",
                        "provider_reinvocation_performed": False,
                    },
                )
                raise RoleIdentityBindingTransitionError("identity_binding_readback_mismatch")

            audit_event_id = self._existing_success_audit(current["job_id"])
            if audit_event_id is None:
                audit_event_id = self.store.audit(
                    actor=actor,
                    action=ACTION,
                    target=plan.member_id,
                    outcome="bound",
                    correlation_id=correlation_id,
                    details={
                        "job_id": current["job_id"],
                        "plan_id": plan.plan_id,
                        "binding_id": state["binding_id"],
                        "account_name": plan.account_name,
                        "persistence": persistence,
                        "provider_reinvocation_performed": False,
                        "credential_material_persisted": False,
                        "emergency_admin_mutation_authorized": False,
                        "privilege_grant_authorized": False,
                        "external_publication_authorized": False,
                    },
                )
            transition_receipt = {
                "schema": TRANSITION_RECEIPT_SCHEMA,
                "state": "bound",
                "job_id": current["job_id"],
                "execution_job_id": receipt["job_id"],
                "audit_event_id": audit_event_id,
                "binding_id": state["binding_id"],
                "household_id": plan.household_id,
                "member_id": plan.member_id,
                "account_name": plan.account_name,
                "account_identity_sha256": receipt["account_identity_sha256"],
                "identity_binding_committed": True,
                "provider_reinvocation_performed": False,
                "credential_material_persisted": False,
                "emergency_admin_mutation_authorized": False,
                "privilege_grant_authorized": False,
                "external_publication_authorized": False,
            }
            done = self.store.transition_action_job(
                current["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                result={
                    "schema": BINDING_STATE_SCHEMA,
                    "binding_id": state["binding_id"],
                    "state": "bound",
                    "identity_binding_committed": True,
                    "provider_reinvocation_performed": False,
                },
                evidence={
                    "schema": "home-center.role-identity-binding-transition-evidence.v1",
                    "binding": state,
                    "receipt": transition_receipt,
                    "provider_reinvocation_performed": False,
                },
                steps=[
                    {"step": "current-household-rbac", "state": "succeeded"},
                    {"step": "verified-execution-evidence", "state": "succeeded"},
                    {"step": "identity-binding-cas", "state": "succeeded"},
                    {"step": "read-back", "state": "succeeded"},
                ],
            )
            if done["state"] != "succeeded":
                raise RoleIdentityBindingTransitionError("identity_binding_completion_failed")
            return transition_receipt
