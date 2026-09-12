"""Durable provider-neutral failed-enrollment cleanup runtime for Home Center 0.58.

This layer consumes rejected 0.58 post-condition verification evidence and turns it
into a durable, read-only cleanup decision. It deliberately does not call a
provider mutation API and does not alter Household managed state. A later
execution boundary may consume an ``authorized`` receipt to delete only bounded
transient enrollment material.
"""
from __future__ import annotations

import threading
from typing import Any

from .device_management_deenrollment import (
    DeviceManagementDeenrollmentError,
    DeviceManagementFailedEnrollmentCleanupPlan,
    authorize_failed_enrollment_cleanup,
    build_failed_enrollment_cleanup_plan,
    cleanup_readback_from_dict,
)
from .device_management_enrollment_post_condition_runtime import (
    PLAN_SCHEMA as VERIFICATION_PLAN_SCHEMA,
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from .home_services import HomeServiceCatalogError
from .household import ManagedDevice, effective_policy
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .household_store import HouseholdSnapshot
from .store import StateStore
from .util import utc_now


PLAN_REQUEST_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-plan-request.v1"
EVALUATE_REQUEST_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-evaluate-request.v1"
STATE_SCHEMA = "home-center.device-management-failed-enrollment-cleanup-runtime-state.v1"
KEY_PREFIX = "cozy.household.device-failed-enrollment-cleanup."


class DeviceManagementFailedEnrollmentCleanupRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _key(plan_id: object) -> str:
    if (
        not isinstance(plan_id, str)
        or not plan_id.startswith("dmclean-")
        or len(plan_id) != 32
        or any(char not in "0123456789abcdef" for char in plan_id.removeprefix("dmclean-"))
    ):
        raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
            "invalid_device_management_failed_enrollment_cleanup_plan_id"
        )
    return KEY_PREFIX + plan_id


class DeviceManagementFailedEnrollmentCleanupRuntimeService:
    """Persist a fail-closed cleanup decision without provider mutation."""

    def __init__(self, store: StateStore, *, now=utc_now) -> None:
        self.store = store
        self._now = now
        self._lock = threading.RLock()

    def _state(self) -> tuple[HouseholdSnapshot, tuple[ActorBinding, ...]]:
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
    def _actor_member(
        actor: str,
        snapshot: HouseholdSnapshot,
        bindings: tuple[ActorBinding, ...],
    ) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, member_id)
        except HomeServiceCatalogError as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(exc.code) from exc
        if not policy.administration_allowed:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_not_authorized"
            )
        return member_id

    @staticmethod
    def _device(
        snapshot: HouseholdSnapshot,
        *,
        device_id: object,
        member_id: object,
    ) -> ManagedDevice:
        if not isinstance(device_id, str) or not isinstance(member_id, str):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_binding_mismatch"
            )
        device = next((item for item in snapshot.household.devices if item.device_id == device_id), None)
        if device is None:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError("household_device_not_found")
        if device.member_id != member_id:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_binding_mismatch"
            )
        if device.managed:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_device_already_managed"
            )
        return device

    def _verification(self, verification_id: object) -> tuple[dict[str, object], dict[str, object]]:
        try:
            key = verification_key(verification_id)
        except Exception as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_verification_not_found"
            ) from exc
        envelope = self.store.get_meta(key)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != VERIFICATION_STATE_SCHEMA
            or envelope.get("status") != "rejected"
        ):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_verification_not_rejected"
            )
        source_plan = envelope.get("plan")
        receipt = envelope.get("receipt")
        if (
            not isinstance(source_plan, dict)
            or source_plan.get("schema") != VERIFICATION_PLAN_SCHEMA
            or source_plan.get("verification_id") != verification_id
            or not isinstance(receipt, dict)
            or receipt.get("state") != "rejected"
            or receipt.get("cleanup_required") is not True
            or receipt.get("managed_state_change_authorized") is not False
            or source_plan.get("execution_plan_id") != receipt.get("plan_id")
            or source_plan.get("provider_id") != receipt.get("provider_id")
            or source_plan.get("provider_operation_id") != receipt.get("provider_operation_id")
            or source_plan.get("device_id") != receipt.get("device_id")
            or source_plan.get("member_id") != receipt.get("member_id")
        ):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_verification_invalid"
            )
        return dict(source_plan), dict(receipt)

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {
            "schema",
            "verification_id",
            "cleanup_generation",
            "max_observed_age_seconds",
        }
        if set(request) != required or request.get("schema") != PLAN_REQUEST_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "invalid_device_management_failed_enrollment_cleanup_plan_request"
            )
        with self._lock:
            snapshot, bindings = self._state()
            actor_member_id = self._actor_member(actor, snapshot, bindings)
            source_plan, receipt = self._verification(request.get("verification_id"))
            self._device(
                snapshot,
                device_id=receipt.get("device_id"),
                member_id=receipt.get("member_id"),
            )
            try:
                plan = build_failed_enrollment_cleanup_plan(
                    rejected_verification_receipt=receipt,
                    cleanup_generation=request.get("cleanup_generation"),
                    created_at=self._now(),
                    max_observed_age_seconds=request.get("max_observed_age_seconds"),
                )
            except DeviceManagementDeenrollmentError as exc:
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(exc.code) from exc
            key = _key(plan.plan_id)
            envelope = {
                "schema": STATE_SCHEMA,
                "status": "planned",
                "verification_id": request["verification_id"],
                "actor_member_id": actor_member_id,
                "household_id": snapshot.household_id,
                "snapshot_id": snapshot.snapshot_id,
                "resource_version": snapshot.resource_version,
                "generation": snapshot.generation,
                "source_verification_plan": source_plan,
                "source_verification_receipt": receipt,
                "plan": plan.to_dict(),
                "readback_result": None,
                "receipt": None,
            }
            old = self.store.get_meta(key)
            if old is None:
                self.store.set_meta(key, envelope)
            elif old != envelope:
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_failed_enrollment_cleanup_state_conflict"
                )
            self.store.audit(
                actor=actor,
                action="household.device.management.failed-enrollment-cleanup.plan",
                target=str(receipt["device_id"]),
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan.plan_id,
                    "verification_id": request["verification_id"],
                    "provider_id": receipt["provider_id"],
                    "provider_read_required": True,
                    "provider_mutation_authorized": False,
                    "managed_state_change_authorized": False,
                },
            )
            return plan.to_dict()

    def _load(
        self,
        plan_id: object,
    ) -> tuple[str, dict[str, Any], DeviceManagementFailedEnrollmentCleanupPlan]:
        key = _key(plan_id)
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != STATE_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_plan_not_found"
            )
        stored_plan = envelope.get("plan")
        receipt = envelope.get("source_verification_receipt")
        if not isinstance(stored_plan, dict) or not isinstance(receipt, dict):
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_state_invalid"
            )
        try:
            plan = build_failed_enrollment_cleanup_plan(
                rejected_verification_receipt=receipt,
                cleanup_generation=stored_plan.get("cleanup_generation"),
                created_at=stored_plan.get("created_at"),
                max_observed_age_seconds=stored_plan.get("max_observed_age_seconds"),
            )
        except DeviceManagementDeenrollmentError as exc:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_state_invalid"
            ) from exc
        if plan.plan_id != plan_id or plan.to_dict() != stored_plan:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "device_management_failed_enrollment_cleanup_state_invalid"
            )
        return key, envelope, plan

    def evaluate(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "plan_id", "readback"}
        if set(request) != required or request.get("schema") != EVALUATE_REQUEST_SCHEMA:
            raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                "invalid_device_management_failed_enrollment_cleanup_evaluate_request"
            )
        with self._lock:
            key, envelope, plan = self._load(request.get("plan_id"))
            snapshot, bindings = self._state()
            actor_member_id = self._actor_member(actor, snapshot, bindings)
            if actor_member_id != envelope.get("actor_member_id"):
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_failed_enrollment_cleanup_actor_mismatch"
                )
            source_plan, current_receipt = self._verification(envelope.get("verification_id"))
            if (
                source_plan != envelope.get("source_verification_plan")
                or current_receipt != envelope.get("source_verification_receipt")
            ):
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_failed_enrollment_cleanup_verification_changed"
                )
            self._device(
                snapshot,
                device_id=plan.device_id,
                member_id=plan.member_id,
            )
            try:
                readback = cleanup_readback_from_dict(request.get("readback"))
                decision = authorize_failed_enrollment_cleanup(
                    plan=plan,
                    readback=readback.to_dict(),
                    now=self._now(),
                )
            except DeviceManagementDeenrollmentError as exc:
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(exc.code) from exc

            readback_value = readback.to_dict()
            decision_value = decision.to_dict()
            if envelope.get("receipt") is not None:
                if (
                    envelope.get("readback_result") == readback_value
                    and envelope.get("receipt") == decision_value
                ):
                    return decision_value
                raise DeviceManagementFailedEnrollmentCleanupRuntimeError(
                    "device_management_failed_enrollment_cleanup_already_evaluated"
                )

            completed = dict(envelope)
            completed.update(
                status="authorized" if decision.cleanup_authorized else "blocked",
                readback_result=readback_value,
                receipt=decision_value,
            )
            self.store.set_meta(key, completed)
            self.store.audit(
                actor=actor,
                action="household.device.management.failed-enrollment-cleanup.evaluate",
                target=plan.device_id,
                outcome="accepted" if decision.cleanup_authorized else "denied",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan.plan_id,
                    "provider_id": plan.provider_id,
                    "provider_state": decision.provider_state,
                    "transient_cleanup_authorized": decision.cleanup_authorized,
                    "escalation_to_deenrollment_required": decision.escalation_required,
                    "provider_mutation_authorized": False,
                    "managed_state_change_authorized": False,
                },
            )
            return decision_value
