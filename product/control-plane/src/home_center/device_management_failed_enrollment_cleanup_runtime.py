"""Durable fail-closed NR2 failed-enrollment cleanup verification runtime.

This boundary consumes only rejected NR1 post-condition evidence. It performs a
read-only provider observation and may authorize a later, bounded cleanup of transient
enrollment state. It never calls a provider mutation, never changes ManagedDevice,
never removes a device or policy, and never exposes credential values.
"""
from __future__ import annotations

import hashlib
import re
import threading
from typing import Any, Protocol

from .device_management_deenrollment import (
    DeviceManagementDeenrollmentError,
    DeviceManagementFailedEnrollmentCleanupPlan,
    authorize_failed_enrollment_cleanup,
    build_failed_enrollment_cleanup_plan,
    cleanup_readback_from_dict,
)
from .device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from .home_services import HomeServiceCatalogError
from .household import effective_policy
from .household_runtime import HOUSEHOLD_STATE_KEY, _snapshot_from_dict, _state_from_dict
from .store import IdempotencyConflict, StateStore
from .util import canonical_json, utc_now

PLAN_REQUEST_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-runtime-plan-request.v1"
VERIFY_REQUEST_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-runtime-verify-request.v1"
READBACK_REQUEST_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-readback-request.v1"
STATE_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-runtime-state.v1"
ACTION = "household.device.management.enrollment.cleanup.verify"
KEY_PREFIX = "cozy.household.device-enrollment-cleanup."
PLAN_ID = re.compile(r"^dmclean-[0-9a-f]{24}$")
PROVIDER_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")


class DeviceManagementFailedEnrollmentCleanupRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceManagementFailedEnrollmentCleanupReadBackAdapter(Protocol):
    verification_read_only: bool

    def read_back(self, request: dict[str, object]) -> object: ...


def _key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
            "invalid_device_management_cleanup_plan_id"
        )
    return KEY_PREFIX + plan_id


def _digest(value: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class DeviceManagementFailedEnrollmentCleanupRuntimeService:
    """Plan and verify bounded cleanup authority without performing cleanup."""

    def __init__(self, store: StateStore, *, now=utc_now) -> None:
        self.store = store
        self._now = now
        self._lock = threading.RLock()
        self._adapters: dict[str, DeviceManagementFailedEnrollmentCleanupReadBackAdapter] = {}

    def register_adapter(self, provider_id: str, adapter: object) -> None:
        if (
            not isinstance(provider_id, str)
            or PROVIDER_ID.fullmatch(provider_id) is None
            or provider_id in self._adapters
            or getattr(adapter, "verification_read_only", None) is not True
            or not callable(getattr(adapter, "read_back", None))
        ):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "invalid_device_management_cleanup_adapter_registration"
            )
        self._adapters[provider_id] = adapter  # type: ignore[assignment]

    def _state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor_member(actor: str, snapshot: object, bindings: tuple[object, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, member_id)
        except HomeServiceCatalogError as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(exc.code) from exc
        if not policy.administration_allowed:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_not_authorized"
            )
        return member_id

    def _rejected_verification(self, verification_id: object) -> dict[str, object]:
        try:
            key = verification_key(verification_id)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_verification_not_found"
            ) from exc
        envelope = self.store.get_meta(key)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != VERIFICATION_STATE_SCHEMA
            or envelope.get("status") != "rejected"
            or not isinstance(envelope.get("receipt"), dict)
        ):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_verification_not_rejected"
            )
        return dict(envelope["receipt"])

    @staticmethod
    def _require_unmanaged_device(snapshot: object, receipt: dict[str, object]) -> None:
        device_id = receipt.get("device_id")
        member_id = receipt.get("member_id")
        device = next((item for item in snapshot.household.devices if item.device_id == device_id), None)
        if device is None:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError("household_device_not_found")
        if device.member_id != member_id:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_binding_mismatch"
            )
        if device.managed:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_device_already_managed"
            )

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "verification_id", "max_observed_age_seconds"}
        if set(request) != required or request.get("schema") != PLAN_REQUEST_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "invalid_device_management_cleanup_plan_request"
            )
        with self._lock:
            snapshot, bindings = self._state()
            actor_member_id = self._actor_member(actor, snapshot, bindings)
            receipt = self._rejected_verification(request.get("verification_id"))
            self._require_unmanaged_device(snapshot, receipt)
            try:
                plan = build_failed_enrollment_cleanup_plan(
                    rejected_verification_receipt=receipt,
                    cleanup_generation=snapshot.generation,
                    created_at=self._now(),
                    max_observed_age_seconds=request.get("max_observed_age_seconds"),
                )
            except DeviceManagementDeenrollmentError as exc:
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(exc.code) from exc

            key = _key(plan.plan_id)
            persisted = {
                "schema": STATE_SCHEMA,
                "status": "planned",
                "plan": plan.to_dict(),
                "verification_id": request["verification_id"],
                "verification_receipt": receipt,
                "base_snapshot": snapshot.to_dict(),
                "bindings": [item.to_dict() for item in bindings],
                "actor_member_id": actor_member_id,
                "job_id": None,
                "readback_result": None,
                "receipt": None,
            }
            old = self.store.get_meta(key)
            if old is None:
                self.store.set_meta(key, persisted)
            elif old != persisted:
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_cleanup_state_invalid"
                )
            self.store.audit(
                actor=actor,
                action="household.device.management.enrollment.cleanup.plan",
                target=plan.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan.plan_id,
                    "verification_id": request["verification_id"],
                    "provider_id": plan.provider_id,
                    "provider_read_required": True,
                    "provider_mutation_authorized": False,
                    "transient_cleanup_authorized": False,
                    "managed_state_change_authorized": False,
                },
            )
            return plan.to_dict()

    def _load(
        self, plan_id: object
    ) -> tuple[str, dict[str, Any], DeviceManagementFailedEnrollmentCleanupPlan]:
        key = _key(plan_id)
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != STATE_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_plan_not_found"
            )
        raw_plan = envelope.get("plan")
        if not isinstance(raw_plan, dict) or raw_plan.get("plan_id") != plan_id:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_state_invalid"
            )
        receipt = envelope.get("verification_receipt")
        if not isinstance(receipt, dict):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_state_invalid"
            )
        try:
            plan = build_failed_enrollment_cleanup_plan(
                rejected_verification_receipt=receipt,
                cleanup_generation=raw_plan.get("cleanup_generation"),
                created_at=raw_plan.get("created_at"),
                max_observed_age_seconds=raw_plan.get("max_observed_age_seconds"),
            )
        except DeviceManagementDeenrollmentError as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(exc.code) from exc
        if plan.to_dict() != raw_plan:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_state_invalid"
            )
        return key, envelope, plan

    def _revalidate(
        self,
        *,
        actor: str,
        envelope: dict[str, Any],
        plan: DeviceManagementFailedEnrollmentCleanupPlan,
    ) -> None:
        snapshot, bindings = self._state()
        actor_member_id = self._actor_member(actor, snapshot, bindings)
        if actor_member_id != envelope.get("actor_member_id"):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_actor_mismatch"
            )
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_state_invalid"
            ) from exc
        if snapshot != base or [item.to_dict() for item in bindings] != envelope.get("bindings"):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_stale"
            )
        receipt = self._rejected_verification(envelope.get("verification_id"))
        if receipt != envelope.get("verification_receipt"):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_binding_mismatch"
            )
        self._require_unmanaged_device(snapshot, receipt)
        if plan.cleanup_generation != snapshot.generation:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_stale"
            )

    def _adapter(self, provider_id: str) -> DeviceManagementFailedEnrollmentCleanupReadBackAdapter:
        adapter = self._adapters.get(provider_id)
        if adapter is None:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_cleanup_adapter_unavailable"
            )
        return adapter

    def verify(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "plan_id", "confirmed", "idempotency_key"}
        if (
            set(request) != required
            or request.get("schema") != VERIFY_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "invalid_device_management_cleanup_verify_request"
            )
        idempotency_key = request.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not 8 <= len(idempotency_key) <= 128:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "invalid_device_management_cleanup_idempotency_key"
            )
        with self._lock:
            key, envelope, plan = self._load(request.get("plan_id"))
            existing = envelope.get("receipt")
            if envelope.get("status") in {"authorized", "blocked"} and isinstance(existing, dict):
                return dict(existing)
            self._revalidate(actor=actor, envelope=envelope, plan=plan)
            adapter = self._adapter(plan.provider_id)
            request_hash = _digest(
                {
                    "plan_id": plan.plan_id,
                    "confirmed": True,
                    "idempotency_key": idempotency_key,
                }
            )
            try:
                job, created = self.store.create_action_job(
                    action_id=ACTION,
                    actor=actor,
                    reason="explicit failed-enrollment cleanup verification",
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    preflight={
                        "schema": "home-center.device-management-failed-enrollment-cleanup-preflight.v1",
                        "plan_id": plan.plan_id,
                        "provider_id": plan.provider_id,
                        "device_id": plan.device_id,
                        "provider_read_required": True,
                        "provider_mutation_authorized": False,
                        "transient_cleanup_authorized": False,
                        "managed_state_change_authorized": False,
                    },
                    steps=[
                        {"step": "provider-read-back", "state": "pending"},
                        {"step": "authorize-transient-cleanup", "state": "pending"},
                    ],
                )
            except IdempotencyConflict as exc:
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_cleanup_idempotency_conflict"
                ) from exc
            if not created:
                if job.get("state") == "succeeded" and isinstance(existing, dict):
                    return dict(existing)
                if job.get("state") in {"preflight", "running", "verifying"}:
                    raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                        "device_management_cleanup_in_progress"
                    )
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_cleanup_previous_attempt_failed"
                )

            running = self.store.transition_action_job(
                job["job_id"], expected_state="preflight", new_state="running"
            )
            read_request = {
                "schema": READBACK_REQUEST_SCHEMA,
                "plan_id": plan.plan_id,
                "provider_id": plan.provider_id,
                "provider_operation_id": plan.provider_operation_id,
                "device_id": plan.device_id,
                "member_id": plan.member_id,
            }
            try:
                result = cleanup_readback_from_dict(adapter.read_back(read_request))
                receipt = authorize_failed_enrollment_cleanup(
                    plan=plan,
                    readback=result.to_dict(),
                    now=self._now(),
                )
            except DeviceManagementDeenrollmentError as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-failed-enrollment-cleanup-read-failure.v1",
                        "state": "failed",
                        "code": exc.code,
                        "provider_mutation_performed": False,
                        "managed_state_changed": False,
                    },
                )
                failed = dict(envelope)
                failed.update(status="verification-failed", job_id=running["job_id"])
                self.store.set_meta(key, failed)
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(exc.code) from exc
            except Exception as exc:
                self.store.transition_action_job(
                    running["job_id"],
                    expected_state="running",
                    new_state="failed",
                    result={
                        "schema": "home-center.device-management-failed-enrollment-cleanup-read-failure.v1",
                        "state": "failed",
                        "code": "device_management_cleanup_provider_error",
                        "provider_mutation_performed": False,
                        "managed_state_changed": False,
                    },
                )
                failed = dict(envelope)
                failed.update(status="verification-failed", job_id=running["job_id"])
                self.store.set_meta(key, failed)
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_cleanup_provider_error"
                ) from exc

            verifying = self.store.transition_action_job(
                running["job_id"],
                expected_state="running",
                new_state="verifying",
                result=result.to_dict(),
                steps=[
                    {"step": "provider-read-back", "state": "succeeded"},
                    {"step": "authorize-transient-cleanup", "state": "running"},
                ],
            )
            receipt_dict = receipt.to_dict()
            done = self.store.transition_action_job(
                verifying["job_id"],
                expected_state="verifying",
                new_state="succeeded",
                evidence={
                    "schema": "home-center.device-management-failed-enrollment-cleanup-verification-evidence.v1",
                    "plan_id": plan.plan_id,
                    "provider_readback": result.to_dict(),
                    "cleanup_receipt": receipt_dict,
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                },
            )
            status = "authorized" if receipt.cleanup_authorized else "blocked"
            completed = dict(envelope)
            completed.update(
                status=status,
                job_id=done["job_id"],
                readback_result=result.to_dict(),
                receipt=receipt_dict,
            )
            self.store.set_meta(key, completed)
            self.store.audit(
                actor=actor,
                action="household.device.management.enrollment.cleanup.verify",
                target=plan.device_id,
                outcome="accepted" if receipt.cleanup_authorized else "denied",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan.plan_id,
                    "job_id": done["job_id"],
                    "provider_id": plan.provider_id,
                    "provider_state": receipt.provider_state,
                    "transient_cleanup_authorized": receipt.cleanup_authorized,
                    "escalation_to_deenrollment_required": receipt.escalation_required,
                    "provider_mutation_performed": False,
                    "managed_state_changed": False,
                },
            )
            return receipt_dict
