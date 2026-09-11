"""Durable plan/confirm runtime for explicit provider selection; never executes enrollment."""

from __future__ import annotations

import re
import threading
from typing import Any

from .device_management_provider import (
    DeviceManagementProviderError,
    DevicePlatform,
    empty_provider_catalog,
    normalize_provider_catalog,
)
from .device_management_provider_runtime import PROVIDER_CATALOG_STATE_KEY
from .device_management_provider_selection import (
    DeviceManagementProviderSelectionConfirmation,
    DeviceManagementProviderSelectionError,
    DeviceManagementProviderSelectionProposal,
    build_provider_selection_proposal,
    provider_selection_proposal_from_dict,
    revalidate_provider_selection_proposal,
)
from .household_device_enrollment import device_enrollment_proposal_from_dict
from .household_device_enrollment_runtime import (
    DEVICE_ENROLLMENT_STATE_SCHEMA,
    HouseholdDeviceEnrollmentRuntimeError,
    _proposal_key as enrollment_proposal_key,
)
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore


PROVIDER_SELECTION_PLAN_REQUEST_SCHEMA = "home-center.device-management-provider-selection-plan-request.v1"
PROVIDER_SELECTION_CONFIRM_REQUEST_SCHEMA = "home-center.device-management-provider-selection-confirm-request.v1"
PROVIDER_SELECTION_STATE_SCHEMA = "home-center.device-management-provider-selection-state.v1"
PROVIDER_SELECTION_KEY_PREFIX = "cozy.household.device-provider-selection."
PROVIDER_SELECTION_ID = re.compile(r"^dmpsel-[0-9a-f]{24}$")


class DeviceManagementProviderSelectionRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _selection_key(proposal_id: object) -> str:
    if not isinstance(proposal_id, str) or PROVIDER_SELECTION_ID.fullmatch(proposal_id) is None:
        raise DeviceManagementProviderSelectionRuntimeError("invalid_device_management_provider_selection_proposal_id")
    return PROVIDER_SELECTION_KEY_PREFIX + proposal_id


class DeviceManagementProviderSelectionRuntimeService:
    """Persist explicit provider choice evidence without credentials or execution authority."""

    def __init__(self, store: StateStore) -> None:
        self.store = store
        self._lock = threading.RLock()

    def _read_state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementProviderSelectionRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementProviderSelectionRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc

    @staticmethod
    def _actor_member(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementProviderSelectionRuntimeError("household_actor_not_bound")
        return member_id

    def _catalog(self):
        raw = self.store.get_meta(PROVIDER_CATALOG_STATE_KEY)
        try:
            return empty_provider_catalog() if raw is None else normalize_provider_catalog(raw)
        except DeviceManagementProviderError as exc:
            raise DeviceManagementProviderSelectionRuntimeError(exc.code) from exc

    def _confirmed_enrollment(self, proposal_id: object):
        try:
            key = enrollment_proposal_key(proposal_id)
        except HouseholdDeviceEnrollmentRuntimeError as exc:
            raise DeviceManagementProviderSelectionRuntimeError(exc.code) from exc
        envelope = self.store.get_meta(key)
        if not isinstance(envelope, dict) or envelope.get("schema") != DEVICE_ENROLLMENT_STATE_SCHEMA:
            raise DeviceManagementProviderSelectionRuntimeError("household_device_enrollment_proposal_not_found")
        if envelope.get("status") != "confirmed":
            raise DeviceManagementProviderSelectionRuntimeError("household_device_enrollment_not_confirmed")
        try:
            proposal = device_enrollment_proposal_from_dict(envelope.get("proposal"))
        except Exception as exc:
            raise DeviceManagementProviderSelectionRuntimeError(
                getattr(exc, "code", "household_device_enrollment_state_invalid")
            ) from exc
        receipt = envelope.get("receipt")
        if (
            not isinstance(receipt, dict)
            or receipt.get("schema") != "home-center.household-device-enrollment-confirmation.v1"
            or receipt.get("proposal_id") != proposal.proposal_id
            or receipt.get("management_plan_id") != proposal.management_plan_id
            or receipt.get("device_id") != proposal.device_id
            or receipt.get("member_id") != proposal.member_id
            or receipt.get("snapshot_id") != proposal.snapshot_id
            or receipt.get("resource_version") != proposal.resource_version
            or receipt.get("generation") != proposal.generation
            or receipt.get("outcome") not in {"confirmed-for-provider-resolution", "already-confirmed"}
            or receipt.get("provider_resolution_required") is not True
            or receipt.get("provider_selected") is not False
            or receipt.get("provider_execution_authorized") is not False
            or receipt.get("policy_application_authorized") is not False
            or receipt.get("managed_state_change_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
        ):
            raise DeviceManagementProviderSelectionRuntimeError("household_device_enrollment_receipt_invalid")
        return proposal

    @staticmethod
    def _snapshot_identity(snapshot) -> tuple[str, str, str, int]:
        return (
            snapshot.household_id,
            snapshot.snapshot_id,
            snapshot.resource_version,
            snapshot.generation,
        )

    @staticmethod
    def _confirmed_receipt(
        envelope: dict[str, object],
        proposal: DeviceManagementProviderSelectionProposal,
    ) -> dict[str, object]:
        receipt = envelope.get("receipt")
        if not isinstance(receipt, dict):
            raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_receipt_invalid")
        audit_event_id = receipt.get("audit_event_id")
        if not isinstance(audit_event_id, str) or not audit_event_id:
            raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_receipt_invalid")
        expected = DeviceManagementProviderSelectionConfirmation(
            proposal_id=proposal.proposal_id,
            resolution_plan_id=proposal.resolution_plan_id,
            enrollment_proposal_id=proposal.enrollment_proposal_id,
            device_id=proposal.device_id,
            member_id=proposal.member_id,
            selected_provider_id=proposal.proposed_provider_id,
            snapshot_id=proposal.snapshot_id,
            resource_version=proposal.resource_version,
            generation=proposal.generation,
            catalog_id=proposal.catalog_id,
            audit_event_id=audit_event_id,
            outcome="provider-selected",
        ).to_dict()
        if receipt != expected:
            raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_receipt_invalid")
        replay = dict(receipt)
        replay["outcome"] = "already-confirmed"
        return replay

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if set(request) != {
            "schema",
            "resolution_plan_id",
            "enrollment_proposal_id",
            "device_platform",
            "provider_id",
        } or request.get("schema") != PROVIDER_SELECTION_PLAN_REQUEST_SCHEMA:
            raise DeviceManagementProviderSelectionRuntimeError("invalid_device_management_provider_selection_plan_request")
        try:
            platform = DevicePlatform(request.get("device_platform"))
        except (TypeError, ValueError) as exc:
            raise DeviceManagementProviderSelectionRuntimeError("invalid_device_platform") from exc

        with self._lock:
            snapshot, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            enrollment = self._confirmed_enrollment(request.get("enrollment_proposal_id"))
            catalog = self._catalog()
            try:
                proposal = build_provider_selection_proposal(
                    snapshot,
                    enrollment,
                    catalog,
                    actor_member_id=actor_member_id,
                    resolution_plan_id=request.get("resolution_plan_id"),
                    device_platform=platform,
                    provider_id=request.get("provider_id"),
                )
            except DeviceManagementProviderSelectionError as exc:
                raise DeviceManagementProviderSelectionRuntimeError(exc.code) from exc

            latest_snapshot, latest_bindings = self._read_state()
            latest_actor_member = self._actor_member(actor, latest_bindings)
            latest_catalog = self._catalog()
            latest_enrollment = self._confirmed_enrollment(request.get("enrollment_proposal_id"))
            if (
                latest_actor_member != actor_member_id
                or self._snapshot_identity(latest_snapshot) != self._snapshot_identity(snapshot)
                or latest_catalog.catalog_id != catalog.catalog_id
                or latest_enrollment.to_dict() != enrollment.to_dict()
            ):
                raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_stale")

            key = _selection_key(proposal.proposal_id)
            existing = self.store.get_meta(key)
            if existing is None:
                self.store.set_meta(
                    key,
                    {
                        "schema": PROVIDER_SELECTION_STATE_SCHEMA,
                        "status": "pending",
                        "proposal": proposal.to_dict(),
                        "receipt": None,
                    },
                )
            elif (
                not isinstance(existing, dict)
                or existing.get("schema") != PROVIDER_SELECTION_STATE_SCHEMA
                or existing.get("proposal") != proposal.to_dict()
                or existing.get("status") not in {"pending", "confirmed"}
            ):
                raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_state_invalid")

            self.store.audit(
                actor=actor,
                action="household.device.management.provider-selection.plan",
                target=proposal.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "resolution_plan_id": proposal.resolution_plan_id,
                    "catalog_id": proposal.catalog_id,
                    "proposed_provider_id": proposal.proposed_provider_id,
                    "provider_selected": False,
                    "provider_execution_authorized": False,
                    "credential_access_authorized": False,
                    "enrollment_authorized": False,
                },
            )
            return proposal.to_dict()

    def confirm(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "proposal_id", "confirmed"}
            or request.get("schema") != PROVIDER_SELECTION_CONFIRM_REQUEST_SCHEMA
            or request.get("confirmed") is not True
        ):
            raise DeviceManagementProviderSelectionRuntimeError("invalid_device_management_provider_selection_confirm_request")
        key = _selection_key(request.get("proposal_id"))

        with self._lock:
            envelope = self.store.get_meta(key)
            if not isinstance(envelope, dict) or envelope.get("schema") != PROVIDER_SELECTION_STATE_SCHEMA:
                raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_proposal_not_found")
            if envelope.get("status") not in {"pending", "confirmed"}:
                raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_state_invalid")
            try:
                proposal = provider_selection_proposal_from_dict(envelope.get("proposal"))
            except DeviceManagementProviderSelectionError as exc:
                raise DeviceManagementProviderSelectionRuntimeError(exc.code) from exc

            snapshot, bindings = self._read_state()
            actor_member_id = self._actor_member(actor, bindings)
            if proposal.actor_member_id != actor_member_id:
                raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_actor_mismatch")
            if envelope.get("status") == "confirmed":
                return self._confirmed_receipt(envelope, proposal)

            enrollment = self._confirmed_enrollment(proposal.enrollment_proposal_id)
            catalog = self._catalog()
            try:
                revalidate_provider_selection_proposal(
                    snapshot,
                    enrollment,
                    catalog,
                    proposal,
                    actor_member_id=actor_member_id,
                )
            except DeviceManagementProviderSelectionError as exc:
                raise DeviceManagementProviderSelectionRuntimeError(exc.code) from exc

            latest_snapshot, latest_bindings = self._read_state()
            latest_actor_member = self._actor_member(actor, latest_bindings)
            latest_catalog = self._catalog()
            latest_enrollment = self._confirmed_enrollment(proposal.enrollment_proposal_id)
            if (
                latest_actor_member != actor_member_id
                or self._snapshot_identity(latest_snapshot) != self._snapshot_identity(snapshot)
                or latest_catalog.catalog_id != catalog.catalog_id
                or latest_enrollment.to_dict() != enrollment.to_dict()
            ):
                raise DeviceManagementProviderSelectionRuntimeError("device_management_provider_selection_stale")

            audit_event_id = self.store.audit(
                actor=actor,
                action="household.device.management.provider-selection.confirm",
                target=proposal.device_id,
                outcome="accepted",
                correlation_id=correlation_id,
                details={
                    "proposal_id": proposal.proposal_id,
                    "resolution_plan_id": proposal.resolution_plan_id,
                    "catalog_id": proposal.catalog_id,
                    "selected_provider_id": proposal.proposed_provider_id,
                    "provider_selected": True,
                    "provider_execution_authorized": False,
                    "credential_access_authorized": False,
                    "enrollment_authorized": False,
                },
            )
            receipt = DeviceManagementProviderSelectionConfirmation(
                proposal_id=proposal.proposal_id,
                resolution_plan_id=proposal.resolution_plan_id,
                enrollment_proposal_id=proposal.enrollment_proposal_id,
                device_id=proposal.device_id,
                member_id=proposal.member_id,
                selected_provider_id=proposal.proposed_provider_id,
                snapshot_id=proposal.snapshot_id,
                resource_version=proposal.resource_version,
                generation=proposal.generation,
                catalog_id=proposal.catalog_id,
                audit_event_id=audit_event_id,
                outcome="provider-selected",
            ).to_dict()
            self.store.set_meta(
                key,
                {
                    "schema": PROVIDER_SELECTION_STATE_SCHEMA,
                    "status": "confirmed",
                    "proposal": proposal.to_dict(),
                    "receipt": receipt,
                },
            )
            return receipt
