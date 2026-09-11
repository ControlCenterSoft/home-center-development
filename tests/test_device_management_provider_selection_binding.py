from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_provider_runtime import (
    PROVIDER_CATALOG_STATE_KEY,
    DeviceManagementProviderRuntimeService,
)
from home_center.device_management_provider_selection_runtime import (
    PROVIDER_SELECTION_BINDING_SCHEMA,
    PROVIDER_SELECTION_STATE_SCHEMA,
    DeviceManagementProviderSelectionRuntimeError,
    DeviceManagementProviderSelectionRuntimeService,
    _binding_key,
    _selection_key,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_enrollment_runtime import HouseholdDeviceEnrollmentRuntimeService
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore
from home_center.store import StateStore


ACTOR = "local-admin:admin"


def _snapshot():
    household = Household(
        household_id="home",
        members=(
            FamilyMember(member_id="member-parent", display_name="Parent", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member-child", display_name="Child", role=HouseholdRole.CHILD),
        ),
        devices=(
            ManagedDevice(
                device_id="device-phone",
                member_id="member-child",
                display_name="Phone",
                managed=False,
            ),
        ),
    )
    reference = HouseholdStore()
    reference.create(household)
    return reference.read("home")


def _catalog() -> dict[str, object]:
    return {
        "schema": "home-center.device-management-provider-catalog.v1",
        "source": "local-trusted-registry",
        "providers": [
            {
                "provider_id": "android-mdm-primary",
                "display_name": "Android MDM Primary",
                "supported_platforms": ["android"],
                "enrollment_modes": ["qr"],
                "ready": True,
            },
            {
                "provider_id": "android-mdm-secondary",
                "display_name": "Android MDM Secondary",
                "supported_platforms": ["android"],
                "enrollment_modes": ["manual"],
                "ready": True,
            },
        ],
    }


def _store(tmp_path: Path) -> StateStore:
    store = StateStore(tmp_path / "state.db", b"r" * 32, "cluster-test")
    snapshot = _snapshot()
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor=ACTOR, member_id="member-parent"),)),
    )
    store.set_meta(PROVIDER_CATALOG_STATE_KEY, _catalog())
    return store


def _confirmed_enrollment(store: StateStore) -> dict[str, object]:
    enrollment = HouseholdDeviceEnrollmentRuntimeService(store)
    proposal = enrollment.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.household-device-enrollment-plan-request.v1",
            "device_id": "device-phone",
        },
        correlation_id="corr-enrollment-plan",
    )
    enrollment.confirm(
        actor=ACTOR,
        request={
            "schema": "home-center.household-device-enrollment-confirm-request.v1",
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id="corr-enrollment-confirm",
    )
    return proposal


def _resolution(store: StateStore, enrollment_proposal_id: str) -> dict[str, object]:
    return DeviceManagementProviderRuntimeService(store).plan(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-provider-resolution-request.v1",
            "enrollment_proposal_id": enrollment_proposal_id,
            "device_platform": "android",
        },
        correlation_id="corr-resolution",
    )


def _selection_plan(
    service: DeviceManagementProviderSelectionRuntimeService,
    *,
    resolution: dict[str, object],
    enrollment_proposal_id: str,
    provider_id: str,
) -> dict[str, object]:
    return service.plan(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-provider-selection-plan-request.v1",
            "resolution_plan_id": resolution["plan_id"],
            "enrollment_proposal_id": enrollment_proposal_id,
            "device_platform": "android",
            "provider_id": provider_id,
        },
        correlation_id=f"corr-selection-plan-{provider_id}",
    )


def _confirm(
    service: DeviceManagementProviderSelectionRuntimeService,
    proposal_id: str,
) -> dict[str, object]:
    return service.confirm(
        actor=ACTOR,
        request={
            "schema": "home-center.device-management-provider-selection-confirm-request.v1",
            "proposal_id": proposal_id,
            "confirmed": True,
        },
        correlation_id="corr-selection-confirm",
    )


def test_only_one_canonical_provider_can_be_selected_per_enrollment(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        enrollment = _confirmed_enrollment(store)
        resolution = _resolution(store, enrollment["proposal_id"])
        assert resolution["state"] == "choice-required"
        service = DeviceManagementProviderSelectionRuntimeService(store)

        first = _selection_plan(
            service,
            resolution=resolution,
            enrollment_proposal_id=enrollment["proposal_id"],
            provider_id="android-mdm-primary",
        )
        receipt = _confirm(service, first["proposal_id"])
        assert receipt["selected_provider_id"] == "android-mdm-primary"
        assert receipt["provider_selected"] is True
        assert receipt["provider_execution_authorized"] is False
        assert receipt["credential_access_authorized"] is False
        assert receipt["enrollment_authorized"] is False

        binding = store.get_meta(_binding_key(enrollment["proposal_id"]))
        assert binding["schema"] == PROVIDER_SELECTION_BINDING_SCHEMA
        assert binding["proposal"]["proposal_id"] == first["proposal_id"]
        assert binding["receipt"]["selected_provider_id"] == "android-mdm-primary"

        with pytest.raises(
            DeviceManagementProviderSelectionRuntimeError,
            match="device_management_provider_already_selected",
        ):
            _selection_plan(
                service,
                resolution=resolution,
                enrollment_proposal_id=enrollment["proposal_id"],
                provider_id="android-mdm-secondary",
            )
    finally:
        store.close()


def test_confirmation_replay_is_idempotent_without_fresh_provider_execution_authority(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        enrollment = _confirmed_enrollment(store)
        resolution = _resolution(store, enrollment["proposal_id"])
        service = DeviceManagementProviderSelectionRuntimeService(store)
        proposal = _selection_plan(
            service,
            resolution=resolution,
            enrollment_proposal_id=enrollment["proposal_id"],
            provider_id="android-mdm-primary",
        )
        first = _confirm(service, proposal["proposal_id"])
        replay = _confirm(service, proposal["proposal_id"])

        assert first["outcome"] == "provider-selected"
        assert replay["outcome"] == "already-confirmed"
        assert replay["audit_event_id"] == first["audit_event_id"]
        assert replay["selected_provider_id"] == first["selected_provider_id"]
        assert replay["provider_execution_authorized"] is False
        assert replay["credential_access_authorized"] is False
        assert replay["enrollment_authorized"] is False
        assert replay["policy_application_authorized"] is False
        assert replay["managed_state_change_authorized"] is False
        assert replay["infrastructure_mutation_authorized"] is False
        assert replay["external_publication_authorized"] is False
    finally:
        store.close()


def test_binding_recovers_interrupted_selection_envelope_completion(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        enrollment = _confirmed_enrollment(store)
        resolution = _resolution(store, enrollment["proposal_id"])
        service = DeviceManagementProviderSelectionRuntimeService(store)
        proposal = _selection_plan(
            service,
            resolution=resolution,
            enrollment_proposal_id=enrollment["proposal_id"],
            provider_id="android-mdm-primary",
        )
        first = _confirm(service, proposal["proposal_id"])

        store.set_meta(
            _selection_key(proposal["proposal_id"]),
            {
                "schema": PROVIDER_SELECTION_STATE_SCHEMA,
                "status": "pending",
                "proposal": proposal,
                "receipt": None,
            },
        )

        replay = _confirm(service, proposal["proposal_id"])
        repaired = store.get_meta(_selection_key(proposal["proposal_id"]))
        assert replay["outcome"] == "already-confirmed"
        assert replay["audit_event_id"] == first["audit_event_id"]
        assert repaired["status"] == "confirmed"
        assert repaired["receipt"]["outcome"] == "provider-selected"
        assert repaired["receipt"]["selected_provider_id"] == "android-mdm-primary"
    finally:
        store.close()


def test_corrupted_canonical_binding_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        enrollment = _confirmed_enrollment(store)
        resolution = _resolution(store, enrollment["proposal_id"])
        service = DeviceManagementProviderSelectionRuntimeService(store)
        proposal = _selection_plan(
            service,
            resolution=resolution,
            enrollment_proposal_id=enrollment["proposal_id"],
            provider_id="android-mdm-primary",
        )
        _confirm(service, proposal["proposal_id"])

        binding_key = _binding_key(enrollment["proposal_id"])
        corrupted = store.get_meta(binding_key)
        corrupted["receipt"]["provider_execution_authorized"] = True
        store.set_meta(binding_key, corrupted)

        with pytest.raises(
            DeviceManagementProviderSelectionRuntimeError,
            match="device_management_provider_selection_receipt_invalid",
        ):
            _confirm(service, proposal["proposal_id"])
    finally:
        store.close()
