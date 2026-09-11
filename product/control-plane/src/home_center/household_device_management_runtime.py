"""Audited runtime facade for provider-neutral device management planning."""

from __future__ import annotations

from typing import Any

from .household_device_management import HouseholdDeviceManagementError, plan_device_management
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore


DEVICE_MANAGEMENT_REQUEST_SCHEMA = "home-center.household-device-management-plan-request.v1"


class HouseholdDeviceManagementRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class HouseholdDeviceManagementRuntimeService:
    def __init__(self, store: StateStore) -> None:
        self.store = store

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if set(request) != {"schema", "device_id"} or request.get("schema") != DEVICE_MANAGEMENT_REQUEST_SCHEMA:
            raise HouseholdDeviceManagementRuntimeError("invalid_household_device_management_request")
        device_id = request.get("device_id")
        if not isinstance(device_id, str):
            raise HouseholdDeviceManagementRuntimeError("invalid_household_device_management_request")

        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdDeviceManagementRuntimeError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdDeviceManagementRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc
        actor_member_id = next((binding.member_id for binding in bindings if binding.actor == actor), None)
        if actor_member_id is None:
            raise HouseholdDeviceManagementRuntimeError("household_actor_not_bound")
        try:
            plan = plan_device_management(snapshot, actor_member_id=actor_member_id, device_id=device_id)
        except HouseholdDeviceManagementError as exc:
            raise HouseholdDeviceManagementRuntimeError(exc.code) from exc

        self.store.audit(
            actor=actor,
            action="household.device.management.plan",
            target=plan.device_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={
                "plan_id": plan.plan_id,
                "snapshot_id": plan.snapshot_id,
                "resource_version": plan.resource_version,
                "state": plan.state.value,
                "management_required": plan.management_required,
                "managed": plan.managed,
            },
        )
        return plan.to_dict()
