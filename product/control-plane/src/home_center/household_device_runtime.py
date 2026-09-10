"""Audited runtime facade for confirmation-gated Household device registration."""

from __future__ import annotations

import re
import threading
import uuid
from typing import Any

from .household_device_change import (
    HouseholdDeviceAddReceipt,
    HouseholdDeviceChangeError,
    apply_device_add_proposal,
    build_device_add_proposal,
    device_add_proposal_from_dict,
)
from .household_runtime import (
    ActorBinding,
    HOUSEHOLD_STATE_KEY,
    _persisted,
    _state_from_dict,
    _snapshot_from_dict,
)
from .store import StateStore


HOUSEHOLD_DEVICE_PLAN_SCHEMA = "home-center.household-device-add-plan.v1"
HOUSEHOLD_DEVICE_CONFIRM_SCHEMA = "home-center.household-device-add-confirm.v1"
HOUSEHOLD_DEVICE_PROPOSAL_STATE_SCHEMA = "home-center.household-device-proposal-state.v1"
DEVICE_PROPOSAL_KEY_PREFIX = "cozy.household.device-proposal."
DEVICE_PROPOSAL_ID = re.compile(r"^hdadd-[a-f0-9]{24}$")


class HouseholdDeviceRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _proposal_key(proposal_id: object) -> str:
    if not isinstance(proposal_id, str) or DEVICE_PROPOSAL_ID.fullmatch(proposal_id) is None:
        raise HouseholdDeviceRuntimeError("invalid_household_device_proposal_id")
    return DEVICE_PROPOSAL_KEY_PREFIX + proposal_id


class HouseholdDeviceRuntimeService:
    """Persist only Household product state; never execute device providers."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _read_state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdDeviceRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            code = getattr(exc, "code", "household_state_invalid")
            raise HouseholdDeviceRuntimeError(code) from exc

    @staticmethod
    def _actor_member(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise HouseholdDeviceRuntimeError("household_actor_not_bound")
        return member_id

    def plan_device_add(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "subject_member_id", "display_name"}
            or request.get("schema") != HOUSEHOLD_DEVICE_PLAN_SCHEMA
        ):
            raise HouseholdDeviceRuntimeError("invalid_household_device_plan_request")
        subject_member_id = request.get("subject_member_id")
        display_name = request.get("display_name")
        if not isinstance(subject_member_id, str) or not isinstance(display_name, str):
            raise HouseholdDeviceRuntimeError("invalid_household_device_plan_request")

        with self._lock:
            snapshot, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            for _attempt in range(4):
                device_id = "device-" + uuid.uuid4().hex[:16]
                try:
                    proposal = build_device_add_proposal(
                        snapshot,
                        actor_member_id=actor_member_id,
                        device_id=device_id,
                        subject_member_id=subject_member_id,
                        display_name=display_name,
                    )
                except HouseholdDeviceChangeError as exc:
                    raise HouseholdDeviceRuntimeError(exc.code) from exc
                key = _proposal_key(proposal.proposal_id)
                if self.store.get_meta(key) is None:
                    break
            else:
                raise HouseholdDeviceRuntimeError("household_device_proposal_collision")

            self.store.set_meta(
                key,
                {
                    "schema": HOUSEHOLD_DEVICE_PROPOSAL_STATE_SCHEMA,
                    "status": "pending",
                    "proposal": proposal.to_dict(),
                    "base_snapshot": snapshot.to_dict(),
                    "pre_audit_event_id": None,
                    "receipt": None,
                },
            )
            self.store.audit(
                actor=actor,
                action="household.device.plan",
                target=proposal.proposal_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "snapshot_id": proposal.snapshot_id,
                    "resource_version": proposal.resource_version,
                    "device_id": proposal.device.device_id,
                    "subject_member_id": proposal.device.member_id,
                    "management_required": proposal.management_required,
                    "managed_after_registration": False,
                },
            )
            return proposal.to_dict()

    def confirm_device_add(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "proposal_id", "confirmed"}
            or request.get("schema") != HOUSEHOLD_DEVICE_CONFIRM_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise HouseholdDeviceRuntimeError("invalid_household_device_confirm_request")
        key = _proposal_key(request.get("proposal_id"))

        with self._lock:
            raw = self.store.get_meta(key)
            if not isinstance(raw, dict) or raw.get("schema") != HOUSEHOLD_DEVICE_PROPOSAL_STATE_SCHEMA:
                raise HouseholdDeviceRuntimeError("household_device_proposal_not_found")
            status = raw.get("status")
            if status not in {"pending", "applying", "applied"}:
                raise HouseholdDeviceRuntimeError("household_device_proposal_state_invalid")
            try:
                proposal = device_add_proposal_from_dict(raw.get("proposal"))
                base_snapshot = _snapshot_from_dict(raw.get("base_snapshot"))
            except Exception as exc:
                code = getattr(exc, "code", "household_device_proposal_state_invalid")
                raise HouseholdDeviceRuntimeError(code) from exc
            if (
                base_snapshot.household_id != proposal.household_id
                or base_snapshot.snapshot_id != proposal.snapshot_id
                or base_snapshot.resource_version != proposal.resource_version
                or base_snapshot.generation != proposal.generation
            ):
                raise HouseholdDeviceRuntimeError("household_device_proposal_evidence_mismatch")
            try:
                rebuilt = build_device_add_proposal(
                    base_snapshot,
                    actor_member_id=proposal.actor_member_id,
                    device_id=proposal.device.device_id,
                    subject_member_id=proposal.device.member_id,
                    display_name=proposal.device.display_name,
                )
            except HouseholdDeviceChangeError as exc:
                raise HouseholdDeviceRuntimeError(exc.code) from exc
            if rebuilt != proposal:
                raise HouseholdDeviceRuntimeError("household_device_proposal_evidence_mismatch")

            current, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            if actor_member_id != proposal.actor_member_id:
                raise HouseholdDeviceRuntimeError("household_device_change_actor_mismatch")

            if status == "applied":
                receipt = raw.get("receipt")
                if not isinstance(receipt, dict) or receipt.get("proposal_id") != proposal.proposal_id:
                    raise HouseholdDeviceRuntimeError("household_device_receipt_invalid")
                device = next(
                    (item for item in current.household.devices if item.device_id == proposal.device.device_id),
                    None,
                )
                if device != proposal.device:
                    raise HouseholdDeviceRuntimeError("household_device_receipt_state_mismatch")
                result = dict(receipt)
                result["outcome"] = "already-applied"
                return result

            try:
                expected_snapshot, commit = apply_device_add_proposal(
                    base_snapshot,
                    proposal,
                    actor_member_id=actor_member_id,
                )
            except HouseholdDeviceChangeError as exc:
                raise HouseholdDeviceRuntimeError(exc.code) from exc

            current_is_base = (
                current.snapshot_id == base_snapshot.snapshot_id
                and current.resource_version == base_snapshot.resource_version
                and current.generation == base_snapshot.generation
                and current.household == base_snapshot.household
            )
            current_is_expected = current == expected_snapshot
            if not current_is_base and not current_is_expected:
                raise HouseholdDeviceRuntimeError("household_device_change_stale")

            pre_audit_event_id = raw.get("pre_audit_event_id")
            if status == "pending" or not isinstance(pre_audit_event_id, str):
                pre_audit_event_id = self.store.audit(
                    actor=actor,
                    action="household.device.register.requested",
                    target=proposal.device.device_id,
                    outcome="accepted",
                    correlation_id=correlation_id,
                    details={
                        "proposal_id": proposal.proposal_id,
                        "snapshot_id": proposal.snapshot_id,
                        "resource_version": proposal.resource_version,
                        "subject_member_id": proposal.device.member_id,
                        "management_required": proposal.management_required,
                    },
                )
                raw = {
                    "schema": HOUSEHOLD_DEVICE_PROPOSAL_STATE_SCHEMA,
                    "status": "applying",
                    "proposal": proposal.to_dict(),
                    "base_snapshot": base_snapshot.to_dict(),
                    "pre_audit_event_id": pre_audit_event_id,
                    "receipt": None,
                }
                self.store.set_meta(key, raw)

            if current_is_base:
                self.store.set_meta(HOUSEHOLD_STATE_KEY, _persisted(expected_snapshot, bindings))

            completion_audit_event_id = self.store.audit(
                actor=actor,
                action="household.device.register",
                target=proposal.device.device_id,
                outcome="succeeded" if current_is_base else "recovered",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "pre_audit_event_id": pre_audit_event_id,
                    "commit_id": commit.commit_id,
                    "previous_snapshot_id": base_snapshot.snapshot_id,
                    "snapshot_id": expected_snapshot.snapshot_id,
                    "resource_version": expected_snapshot.resource_version,
                    "subject_member_id": proposal.device.member_id,
                    "management_required": proposal.management_required,
                    "managed": False,
                },
            )
            receipt = HouseholdDeviceAddReceipt(
                proposal_id=proposal.proposal_id,
                outcome="applied" if current_is_base else "already-applied",
                device=proposal.device,
                management_required=proposal.management_required,
                previous_snapshot_id=base_snapshot.snapshot_id,
                previous_resource_version=base_snapshot.resource_version,
                snapshot_id=expected_snapshot.snapshot_id,
                resource_version=expected_snapshot.resource_version,
                generation=expected_snapshot.generation,
                commit_id=commit.commit_id,
                audit_event_id=completion_audit_event_id,
            )
            result = receipt.to_dict()
            self.store.set_meta(
                key,
                {
                    "schema": HOUSEHOLD_DEVICE_PROPOSAL_STATE_SCHEMA,
                    "status": "applied",
                    "proposal": proposal.to_dict(),
                    "base_snapshot": base_snapshot.to_dict(),
                    "pre_audit_event_id": pre_audit_event_id,
                    "receipt": result,
                },
            )
            return result
