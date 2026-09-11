"""Read-only provider-resolution runtime for confirmed Cozy enrollment intent."""

from __future__ import annotations

from typing import Any

from .device_management_provider import (
    DeviceManagementProviderError,
    DevicePlatform,
    empty_provider_catalog,
    normalize_provider_catalog,
    plan_provider_resolution,
)
from .household_device_enrollment import device_enrollment_proposal_from_dict
from .household_device_enrollment_runtime import (
    DEVICE_ENROLLMENT_STATE_SCHEMA,
    HouseholdDeviceEnrollmentRuntimeError,
    _proposal_key,
)
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore


PROVIDER_CATALOG_STATE_KEY = "device-management.provider-catalog.v1"
PROVIDER_RESOLUTION_REQUEST_SCHEMA = "home-center.device-management-provider-resolution-request.v1"


class DeviceManagementProviderRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DeviceManagementProviderRuntimeService:
    """Resolve only registered trusted providers; never select or execute one."""

    def __init__(self, store: StateStore) -> None:
        self.store = store

    def _read_state(self):
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise DeviceManagementProviderRuntimeError("household_not_configured")
        try:
            return _state_from_dict(raw)
        except Exception as exc:
            raise DeviceManagementProviderRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc

    @staticmethod
    def _actor_member(actor: str, bindings: tuple[ActorBinding, ...]) -> str:
        member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if member_id is None:
            raise DeviceManagementProviderRuntimeError("household_actor_not_bound")
        return member_id

    @staticmethod
    def _snapshot_identity(snapshot) -> tuple[str, str, str, int]:
        return (
            snapshot.household_id,
            snapshot.snapshot_id,
            snapshot.resource_version,
            snapshot.generation,
        )

    def catalog(self) -> dict[str, object]:
        raw = self.store.get_meta(PROVIDER_CATALOG_STATE_KEY)
        if raw is None:
            return empty_provider_catalog().to_dict()
        try:
            return normalize_provider_catalog(raw).to_dict()
        except DeviceManagementProviderError as exc:
            raise DeviceManagementProviderRuntimeError(exc.code) from exc

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        if (
            set(request) != {"schema", "enrollment_proposal_id", "device_platform"}
            or request.get("schema") != PROVIDER_RESOLUTION_REQUEST_SCHEMA
            or not isinstance(request.get("enrollment_proposal_id"), str)
        ):
            raise DeviceManagementProviderRuntimeError("invalid_device_management_provider_resolution_request")
        try:
            platform = DevicePlatform(request.get("device_platform"))
        except (TypeError, ValueError) as exc:
            raise DeviceManagementProviderRuntimeError("invalid_device_platform") from exc

        snapshot, bindings = self._read_state()
        actor_member_id = self._actor_member(actor, bindings)
        try:
            proposal_key = _proposal_key(request["enrollment_proposal_id"])
        except HouseholdDeviceEnrollmentRuntimeError as exc:
            raise DeviceManagementProviderRuntimeError(exc.code) from exc
        envelope = self.store.get_meta(proposal_key)
        if not isinstance(envelope, dict) or envelope.get("schema") != DEVICE_ENROLLMENT_STATE_SCHEMA:
            raise DeviceManagementProviderRuntimeError("household_device_enrollment_proposal_not_found")
        if envelope.get("status") != "confirmed":
            raise DeviceManagementProviderRuntimeError("household_device_enrollment_not_confirmed")
        try:
            proposal = device_enrollment_proposal_from_dict(envelope.get("proposal"))
        except Exception as exc:
            raise DeviceManagementProviderRuntimeError(
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
            raise DeviceManagementProviderRuntimeError("household_device_enrollment_receipt_invalid")

        raw_catalog = self.store.get_meta(PROVIDER_CATALOG_STATE_KEY)
        try:
            catalog = empty_provider_catalog() if raw_catalog is None else normalize_provider_catalog(raw_catalog)
            plan = plan_provider_resolution(
                snapshot,
                proposal,
                catalog,
                actor_member_id=actor_member_id,
                device_platform=platform,
            )
        except DeviceManagementProviderError as exc:
            raise DeviceManagementProviderRuntimeError(exc.code) from exc

        latest_snapshot, latest_bindings = self._read_state()
        latest_actor_member_id = self._actor_member(actor, latest_bindings)
        if (
            latest_actor_member_id != actor_member_id
            or self._snapshot_identity(latest_snapshot) != self._snapshot_identity(snapshot)
        ):
            raise DeviceManagementProviderRuntimeError("household_device_enrollment_stale")

        self.store.audit(
            actor=actor,
            action="household.device.management.provider-resolution.plan",
            target=proposal.device_id,
            outcome="accepted",
            correlation_id=correlation_id,
            details={
                "plan_id": plan.plan_id,
                "enrollment_proposal_id": proposal.proposal_id,
                "catalog_id": plan.catalog_id,
                "device_platform": plan.device_platform.value,
                "platform_verified": False,
                "state": plan.state.value,
                "candidate_count": len(plan.candidates),
                "selected_provider_id": None,
                "provider_execution_authorized": False,
            },
        )
        return plan.to_dict()
