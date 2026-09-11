"""Audited confirmation runtime for provider-neutral device enrollment intent."""

from __future__ import annotations

import re
import threading
from typing import Any

from .household_device_enrollment import (
    HouseholdDeviceEnrollmentConfirmation,
    HouseholdDeviceEnrollmentError,
    build_device_enrollment_proposal,
    device_enrollment_proposal_from_dict,
    revalidate_device_enrollment_proposal,
)
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore


DEVICE_ENROLLMENT_PLAN_REQUEST_SCHEMA = "home-center.household-device-enrollment-plan-request.v1"
DEVICE_ENROLLMENT_CONFIRM_REQUEST_SCHEMA = "home-center.household-device-enrollment-confirm-request.v1"
DEVICE_ENROLLMENT_STATE_SCHEMA = "home-center.household-device-enrollment-state.v1"
DEVICE_ENROLLMENT_KEY_PREFIX = "cozy.household.device-enrollment."
DEVICE_ENROLLMENT_ID = re.compile(r"^hdenroll-[a-f0-9]{24}$")


class HouseholdDeviceEnrollmentRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _proposal_key(proposal_id: object) -> str:
    if not isinstance(proposal_id, str) or DEVICE_ENROLLMENT_ID.fullmatch(proposal_id) is None:
        raise HouseholdDeviceEnrollmentRuntimeError("invalid_household_device_enrollment_proposal_id")
    return DEVICE_ENROLLMENT_KEY_PREFIX + proposal_id


class HouseholdDeviceEnrollmentRuntimeService:
    """Persist enrollment consent evidence only; never mutate Household/provider state."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _read_state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdDeviceEnrollmentRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdDeviceEnrollmentRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc

    @staticmethod
    def _actor_member(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise HouseholdDeviceEnrollmentRuntimeError("household_actor_not_bound")
        return member_id

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "device_id"}
            or request.get("schema") != DEVICE_ENROLLMENT_PLAN_REQUEST_SCHEMA
            or not isinstance(request.get("device_id"), str)
        ):
            raise HouseholdDeviceEnrollmentRuntimeError("invalid_household_device_enrollment_plan_request")

        with self._lock:
            snapshot, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            try:
                proposal = build_device_enrollment_proposal(snapshot, actor_member_id=actor_member_id, device_id=request["device_id"])
            except HouseholdDeviceEnrollmentError as exc:
                raise HouseholdDeviceEnrollmentRuntimeError(exc.code) from exc
            key = _proposal_key(proposal.proposal_id)
            existing = self.store.get_meta(key)
            if existing is None:
                self.store.set_meta(
                    key,
                    {
                        "schema": DEVICE_ENROLLMENT_STATE_SCHEMA,
                        "status": "pending",
                        "proposal": proposal.to_dict(),
                        "receipt": None,
                    },
                )
            elif (
                not isinstance(existing, dict)
                or existing.get("schema") != DEVICE_ENROLLMENT_STATE_SCHEMA
                or existing.get("proposal") != proposal.to_dict()
                or existing.get("status") not in {"pending", "confirmed"}
            ):
                raise HouseholdDeviceEnrollmentRuntimeError("household_device_enrollment_state_invalid")

            self.store.audit(
                actor=actor,
                action="household.device.enrollment.plan",
                target=proposal.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "management_plan_id": proposal.management_plan_id,
                    "snapshot_id": proposal.snapshot_id,
                    "resource_version": proposal.resource_version,
                    "provider_selected": False,
                    "managed_state_change_authorized": False,
                },
            )
            return proposal.to_dict()

    def confirm(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "proposal_id", "confirmed"}
            or request.get("schema") != DEVICE_ENROLLMENT_CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise HouseholdDeviceEnrollmentRuntimeError("invalid_household_device_enrollment_confirm_request")
        key = _proposal_key(request.get("proposal_id"))

        with self._lock:
            envelope = self.store.get_meta(key)
            if not isinstance(envelope, dict) or envelope.get("schema") != DEVICE_ENROLLMENT_STATE_SCHEMA:
                raise HouseholdDeviceEnrollmentRuntimeError("household_device_enrollment_proposal_not_found")
            if envelope.get("status") not in {"pending", "confirmed"}:
                raise HouseholdDeviceEnrollmentRuntimeError("household_device_enrollment_state_invalid")
            try:
                proposal = device_enrollment_proposal_from_dict(envelope.get("proposal"))
            except HouseholdDeviceEnrollmentError as exc:
                raise HouseholdDeviceEnrollmentRuntimeError(exc.code) from exc

            snapshot, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            try:
                revalidate_device_enrollment_proposal(snapshot, proposal, actor_member_id=actor_member_id)
            except HouseholdDeviceEnrollmentError as exc:
                raise HouseholdDeviceEnrollmentRuntimeError(exc.code) from exc

            if envelope.get("status") == "confirmed":
                receipt = envelope.get("receipt")
                if not isinstance(receipt, dict) or receipt.get("proposal_id") != proposal.proposal_id:
                    raise HouseholdDeviceEnrollmentRuntimeError("household_device_enrollment_receipt_invalid")
                replay = dict(receipt)
                replay["outcome"] = "already-confirmed"
                return replay

            audit_event_id = self.store.audit(
                actor=actor,
                action="household.device.enrollment.confirm",
                target=proposal.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "management_plan_id": proposal.management_plan_id,
                    "snapshot_id": proposal.snapshot_id,
                    "resource_version": proposal.resource_version,
                    "provider_resolution_required": True,
                    "provider_selected": False,
                    "provider_execution_authorized": False,
                    "managed_state_change_authorized": False,
                },
            )
            receipt = HouseholdDeviceEnrollmentConfirmation(
                proposal_id=proposal.proposal_id,
                management_plan_id=proposal.management_plan_id,
                device_id=proposal.device_id,
                member_id=proposal.member_id,
                outcome="confirmed-for-provider-resolution",
                snapshot_id=proposal.snapshot_id,
                resource_version=proposal.resource_version,
                generation=proposal.generation,
                audit_event_id=audit_event_id,
            ).to_dict()
            self.store.set_meta(
                key,
                {
                    "schema": DEVICE_ENROLLMENT_STATE_SCHEMA,
                    "status": "confirmed",
                    "proposal": proposal.to_dict(),
                    "receipt": receipt,
                },
            )
            return receipt
