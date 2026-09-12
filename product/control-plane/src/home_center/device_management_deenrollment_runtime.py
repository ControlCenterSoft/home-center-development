"""Durable fail-closed NR2 de-enrollment planning and confirmation runtime.

This boundary deliberately stops before provider mutation. It binds a de-enrollment
plan to a completed NR1 verification receipt and the exact current Household snapshot,
requires an administrator with Household administration authority, and consumes a
single-use step-up grant before emitting provider-mutation authorization.

The emitted confirmation is authority for a future typed provider worker only. This
module never calls a provider, never retries a provider operation, never clears managed
state, never removes a device, and never exposes credential values.
"""
from __future__ import annotations

import re
import threading
from typing import Any

from .device_management_deenrollment import (
    DeviceManagementDeenrollmentError,
    DeviceManagementDeenrollmentPlan,
    build_deenrollment_plan,
    confirm_deenrollment,
)
from .device_management_enrollment_post_condition_runtime import (
    STATE_SCHEMA as VERIFICATION_STATE_SCHEMA,
    _key as verification_key,
)
from .home_services import HomeServiceCatalogError
from .household import effective_policy
from .household_runtime import HOUSEHOLD_STATE_KEY, _snapshot_from_dict, _state_from_dict
from .step_up import StepUpError, StepUpGrantManager
from .store import StateStore
from .util import utc_now

PLAN_REQUEST_SCHEMA = "home-center.device-management-deenrollment-runtime-plan-request.v1"
CONFIRM_REQUEST_SCHEMA = "home-center.device-management-deenrollment-runtime-confirm-request.v1"
STATE_SCHEMA = "home-center.device-management-deenrollment-runtime-state.v1"
KEY_PREFIX = "cozy.household.device-deenrollment."
PLAN_ID = re.compile(r"^dmdel-[0-9a-f]{24}$")


class DeviceManagementDeenrollmentRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _key(plan_id: object) -> str:
    if not isinstance(plan_id, str) or PLAN_ID.fullmatch(plan_id) is None:
        raise DeviceManagementDeenrollmentRuntimeError("invalid_device_management_deenrollment_plan_id")
    return KEY_PREFIX + plan_id


class DeviceManagementDeenrollmentRuntimeService:
    """Persist and revalidate NR2 plan/confirm transitions without provider side effects."""

    def __init__(
        self,
        store: StateStore,
        step_up: StepUpGrantManager,
        *,
        now=utc_now,
    ) -> None:
        self.store = store
        self.step_up = step_up
        self._now = now
        self._lock = threading.RLock()

    @staticmethod
    def step_up_scope(plan_id: str) -> str:
        _key(plan_id)
        return f"household.device.management.deenrollment:{plan_id}"

    def _state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementDeenrollmentRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementDeenrollmentRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc

    @staticmethod
    def _actor_member(actor: str, snapshot: object, bindings: tuple[object, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementDeenrollmentRuntimeError("household_actor_not_bound")
        try:
            policy = effective_policy(snapshot.household, member_id)
        except HomeServiceCatalogError as exc:
            raise DeviceManagementDeenrollmentRuntimeError(exc.code) from exc
        if not policy.administration_allowed:
            raise DeviceManagementDeenrollmentRuntimeError("device_management_deenrollment_not_authorized")
        return member_id

    def _verification_receipt(self, verification_id: object) -> dict[str, object]:
        try:
            key = verification_key(verification_id)
        except Exception as exc:
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_verification_not_found"
            ) from exc
        envelope = self.store.get_meta(key)
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != VERIFICATION_STATE_SCHEMA
            or envelope.get("status") != "applied"
            or not isinstance(envelope.get("receipt"), dict)
        ):
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_verification_not_applied"
            )
        return dict(envelope["receipt"])

    @staticmethod
    def _managed_device(snapshot: object, receipt: dict[str, object]) -> None:
        device_id = receipt.get("device_id")
        member_id = receipt.get("member_id")
        device = next((item for item in snapshot.household.devices if item.device_id == device_id), None)
        if device is None:
            raise DeviceManagementDeenrollmentRuntimeError("household_device_not_found")
        if device.member_id != member_id:
            raise DeviceManagementDeenrollmentRuntimeError("device_management_deenrollment_binding_mismatch")
        if not device.managed:
            raise DeviceManagementDeenrollmentRuntimeError("device_management_deenrollment_device_not_managed")

    def plan(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "verification_id", "max_observed_age_seconds"}
        if set(request) != required or request.get("schema") != PLAN_REQUEST_SCHEMA:
            raise DeviceManagementDeenrollmentRuntimeError(
                "invalid_device_management_deenrollment_plan_request"
            )
        with self._lock:
            snapshot, bindings = self._state()
            actor_member_id = self._actor_member(actor, snapshot, bindings)
            receipt = self._verification_receipt(request.get("verification_id"))
            self._managed_device(snapshot, receipt)
            try:
                plan = build_deenrollment_plan(
                    verification_receipt=receipt,
                    household_id=snapshot.household_id,
                    snapshot_id=snapshot.snapshot_id,
                    resource_version=snapshot.resource_version,
                    generation=snapshot.generation,
                    actor_member_id=actor_member_id,
                    requested_at=self._now(),
                    max_observed_age_seconds=request.get("max_observed_age_seconds"),
                )
            except DeviceManagementDeenrollmentError as exc:
                raise DeviceManagementDeenrollmentRuntimeError(exc.code) from exc

            key = _key(plan.plan_id)
            persisted = {
                "schema": STATE_SCHEMA,
                "status": "planned",
                "plan": plan.to_dict(),
                "verification_id": request["verification_id"],
                "verification_receipt": receipt,
                "base_snapshot": snapshot.to_dict(),
                "bindings": [item.to_dict() for item in bindings],
                "confirmation": None,
            }
            old = self.store.get_meta(key)
            if old is None:
                self.store.set_meta(key, persisted)
            elif old != persisted:
                raise DeviceManagementDeenrollmentRuntimeError(
                    "device_management_deenrollment_state_invalid"
                )
            self.store.audit(
                actor=actor,
                action="household.device.management.deenrollment.plan",
                target=plan.binding.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan.plan_id,
                    "verification_id": request["verification_id"],
                    "provider_id": plan.binding.provider_id,
                    "confirmation_required": True,
                    "provider_mutation_authorized": False,
                    "managed_state_change_authorized": False,
                },
            )
            return plan.to_dict()

    def _load(self, plan_id: object) -> tuple[str, dict[str, Any], dict[str, object]]:
        key = _key(plan_id)
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != STATE_SCHEMA:
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_plan_not_found"
            )
        raw_plan = envelope.get("plan")
        if not isinstance(raw_plan, dict) or raw_plan.get("plan_id") != plan_id:
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_state_invalid"
            )
        return key, envelope, dict(raw_plan)

    @staticmethod
    def _rebuild(envelope: dict[str, Any], raw_plan: dict[str, object]) -> DeviceManagementDeenrollmentPlan:
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
            receipt = envelope.get("verification_receipt")
            if not isinstance(receipt, dict):
                raise ValueError("verification receipt missing")
            plan = build_deenrollment_plan(
                verification_receipt=receipt,
                household_id=base.household_id,
                snapshot_id=base.snapshot_id,
                resource_version=base.resource_version,
                generation=base.generation,
                actor_member_id=raw_plan.get("actor_member_id"),
                requested_at=raw_plan.get("requested_at"),
                max_observed_age_seconds=raw_plan.get("max_observed_age_seconds"),
            )
        except (DeviceManagementDeenrollmentError, TypeError, ValueError) as exc:
            raise DeviceManagementDeenrollmentRuntimeError(
                getattr(exc, "code", "device_management_deenrollment_state_invalid")
            ) from exc
        if plan.to_dict() != raw_plan:
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_state_invalid"
            )
        return plan

    def _revalidate(self, actor: str, envelope: dict[str, Any], plan: DeviceManagementDeenrollmentPlan) -> None:
        snapshot, bindings = self._state()
        actor_member_id = self._actor_member(actor, snapshot, bindings)
        if actor_member_id != plan.actor_member_id:
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_actor_mismatch"
            )
        try:
            base = _snapshot_from_dict(envelope.get("base_snapshot"))
        except Exception as exc:
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_state_invalid"
            ) from exc
        if snapshot != base or [item.to_dict() for item in bindings] != envelope.get("bindings"):
            raise DeviceManagementDeenrollmentRuntimeError("device_management_deenrollment_stale")
        receipt = self._verification_receipt(envelope.get("verification_id"))
        if receipt != envelope.get("verification_receipt"):
            raise DeviceManagementDeenrollmentRuntimeError(
                "device_management_deenrollment_binding_mismatch"
            )
        self._managed_device(snapshot, receipt)

    def confirm(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        step_up_token: object,
        correlation_id: str,
    ) -> dict[str, object]:
        required = {"schema", "plan_id", "confirmed"}
        if (
            set(request) != required
            or request.get("schema") != CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise DeviceManagementDeenrollmentRuntimeError(
                "invalid_device_management_deenrollment_confirm_request"
            )
        with self._lock:
            key, envelope, raw_plan = self._load(request.get("plan_id"))
            existing = envelope.get("confirmation")
            if envelope.get("status") == "confirmed" and isinstance(existing, dict):
                return dict(existing)
            plan = self._rebuild(envelope, raw_plan)
            self._revalidate(actor, envelope, plan)
            try:
                self.step_up.consume(
                    actor=actor,
                    scope=self.step_up_scope(plan.plan_id),
                    token=step_up_token,
                )
            except StepUpError as exc:
                raise DeviceManagementDeenrollmentRuntimeError(exc.code) from exc
            try:
                confirmation = confirm_deenrollment(
                    plan=plan,
                    actor_member_id=plan.actor_member_id,
                    confirmed_at=self._now(),
                )
            except DeviceManagementDeenrollmentError as exc:
                raise DeviceManagementDeenrollmentRuntimeError(exc.code) from exc
            updated = dict(envelope)
            updated.update(status="confirmed", confirmation=confirmation.to_dict())
            self.store.set_meta(key, updated)
            self.store.audit(
                actor=actor,
                action="household.device.management.deenrollment.confirm",
                target=plan.binding.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "plan_id": plan.plan_id,
                    "provider_id": plan.binding.provider_id,
                    "provider_mutation_authorized": True,
                    "automatic_retry_authorized": False,
                    "managed_state_change_authorized": False,
                    "provider_invoked": False,
                },
            )
            return confirmation.to_dict()
