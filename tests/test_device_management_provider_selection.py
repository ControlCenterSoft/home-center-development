from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_provider import (
    DevicePlatform,
    normalize_provider_catalog,
    plan_provider_resolution,
)
from home_center.device_management_provider_runtime import (
    PROVIDER_CATALOG_STATE_KEY,
    DeviceManagementProviderRuntimeService,
)
from home_center.device_management_provider_selection import (
    DeviceManagementProviderSelectionError,
    build_provider_selection_proposal,
    provider_selection_proposal_from_dict,
    revalidate_provider_selection_proposal,
)
from home_center.device_management_provider_selection_runtime import (
    PROVIDER_SELECTION_STATE_SCHEMA,
    DeviceManagementProviderSelectionRuntimeError,
    DeviceManagementProviderSelectionRuntimeService,
    _selection_key,
)
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.household_device_enrollment import build_device_enrollment_proposal
from home_center.household_device_enrollment_runtime import HouseholdDeviceEnrollmentRuntimeService
from home_center.household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _persisted
from home_center.household_store import HouseholdStore, build_household_replacement
from home_center.store import StateStore


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
    ref = HouseholdStore()
    ref.create(household)
    return ref.read("home")


def _catalog(*, ready: bool = True):
    return normalize_provider_catalog(
        {
            "schema": "home-center.device-management-provider-catalog.v1",
            "source": "local-trusted-registry",
            "providers": [
                {
                    "provider_id": "android-mdm-primary",
                    "display_name": "Android MDM Primary",
                    "supported_platforms": ["android"],
                    "enrollment_modes": ["qr"],
                    "ready": ready,
                },
                {
                    "provider_id": "windows-mdm-primary",
                    "display_name": "Windows MDM Primary",
                    "supported_platforms": ["windows"],
                    "enrollment_modes": ["manual"],
                    "ready": True,
                },
            ],
        }
    )


def _state_store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"q" * 32, "cluster-test")


def _seed_household(store: StateStore, snapshot) -> None:
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(snapshot, (ActorBinding(actor="local-admin:admin", member_id="member-parent"),)),
    )


def _confirmed_enrollment(store: StateStore) -> dict[str, object]:
    service = HouseholdDeviceEnrollmentRuntimeService(store)
    proposal = service.plan(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-device-enrollment-plan-request.v1",
            "device_id": "device-phone",
        },
        correlation_id="corr-enrollment-plan",
    )
    service.confirm(
        actor="local-admin:admin",
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
        actor="local-admin:admin",
        request={
            "schema": "home-center.device-management-provider-resolution-request.v1",
            "enrollment_proposal_id": enrollment_proposal_id,
            "device_platform": "android",
        },
        correlation_id="corr-resolution",
    )


def test_selection_proposal_requires_exact_resolution_and_never_authorizes_execution() -> None:
    snapshot = _snapshot()
    enrollment = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    catalog = _catalog()
    resolution = plan_provider_resolution(
        snapshot,
        enrollment,
        catalog,
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    proposal = build_provider_selection_proposal(
        snapshot,
        enrollment,
        catalog,
        actor_member_id="member-parent",
        resolution_plan_id=resolution.plan_id,
        device_platform=DevicePlatform.ANDROID,
        provider_id="android-mdm-primary",
    )
    value = proposal.to_dict()
    assert value["proposed_provider_id"] == "android-mdm-primary"
    assert value["provider_ready"] is True
    assert value["platform_supported"] is True
    assert value["confirmation_required"] is True
    assert value["provider_selected"] is False
    assert value["provider_execution_authorized"] is False
    assert value["credential_access_authorized"] is False
    assert value["enrollment_authorized"] is False
    assert value["policy_application_authorized"] is False
    assert value["managed_state_change_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False
    assert provider_selection_proposal_from_dict(value) == proposal


def test_selection_rejects_stale_resolution_or_non_candidate_provider() -> None:
    snapshot = _snapshot()
    enrollment = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    catalog = _catalog()
    resolution = plan_provider_resolution(
        snapshot,
        enrollment,
        catalog,
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    with pytest.raises(DeviceManagementProviderSelectionError, match="device_management_provider_resolution_stale"):
        build_provider_selection_proposal(
            snapshot,
            enrollment,
            catalog,
            actor_member_id="member-parent",
            resolution_plan_id="dmpr-" + "0" * 24,
            device_platform=DevicePlatform.ANDROID,
            provider_id="android-mdm-primary",
        )
    with pytest.raises(DeviceManagementProviderSelectionError, match="device_management_provider_not_available"):
        build_provider_selection_proposal(
            snapshot,
            enrollment,
            catalog,
            actor_member_id="member-parent",
            resolution_plan_id=resolution.plan_id,
            device_platform=DevicePlatform.ANDROID,
            provider_id="windows-mdm-primary",
        )


def test_selection_revalidation_rejects_household_or_catalog_drift() -> None:
    snapshot = _snapshot()
    enrollment = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    catalog = _catalog()
    resolution = plan_provider_resolution(
        snapshot,
        enrollment,
        catalog,
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    proposal = build_provider_selection_proposal(
        snapshot,
        enrollment,
        catalog,
        actor_member_id="member-parent",
        resolution_plan_id=resolution.plan_id,
        device_platform=DevicePlatform.ANDROID,
        provider_id="android-mdm-primary",
    )

    changed = Household(
        household_id="home",
        members=snapshot.household.members,
        devices=(
            *snapshot.household.devices,
            ManagedDevice(
                device_id="device-extra",
                member_id="member-parent",
                display_name="Extra",
                managed=False,
            ),
        ),
    )
    newer, _ = build_household_replacement(
        snapshot,
        changed,
        expected_resource_version=snapshot.resource_version,
    )
    with pytest.raises(DeviceManagementProviderSelectionError):
        revalidate_provider_selection_proposal(
            newer,
            enrollment,
            catalog,
            proposal,
            actor_member_id="member-parent",
        )
    with pytest.raises(DeviceManagementProviderSelectionError):
        revalidate_provider_selection_proposal(
            snapshot,
            enrollment,
            _catalog(ready=False),
            proposal,
            actor_member_id="member-parent",
        )


def test_serialized_selection_proposal_rejects_authority_tampering() -> None:
    snapshot = _snapshot()
    enrollment = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    catalog = _catalog()
    resolution = plan_provider_resolution(
        snapshot,
        enrollment,
        catalog,
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    payload = build_provider_selection_proposal(
        snapshot,
        enrollment,
        catalog,
        actor_member_id="member-parent",
        resolution_plan_id=resolution.plan_id,
        device_platform=DevicePlatform.ANDROID,
        provider_id="android-mdm-primary",
    ).to_dict()
    payload["enrollment_authorized"] = True
    with pytest.raises(DeviceManagementProviderSelectionError, match="evidence_rejected"):
        provider_selection_proposal_from_dict(payload)


def test_runtime_plan_and_confirm_preserve_household_and_catalog(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        snapshot = _snapshot()
        _seed_household(store, snapshot)
        enrollment = _confirmed_enrollment(store)
        store.set_meta(
            PROVIDER_CATALOG_STATE_KEY,
            {
                "schema": "home-center.device-management-provider-catalog.v1",
                "source": "local-trusted-registry",
                "providers": [
                    {
                        "provider_id": "android-mdm-primary",
                        "display_name": "Android MDM Primary",
                        "supported_platforms": ["android"],
                        "enrollment_modes": ["qr"],
                        "ready": True,
                    }
                ],
            },
        )
        resolution = _resolution(store, enrollment["proposal_id"])
        before_household = store.get_meta(HOUSEHOLD_STATE_KEY)
        before_catalog = store.get_meta(PROVIDER_CATALOG_STATE_KEY)
        service = DeviceManagementProviderSelectionRuntimeService(store)
        proposal = service.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.device-management-provider-selection-plan-request.v1",
                "resolution_plan_id": resolution["plan_id"],
                "enrollment_proposal_id": enrollment["proposal_id"],
                "device_platform": "android",
                "provider_id": "android-mdm-primary",
            },
            correlation_id="corr-selection-plan",
        )
        assert proposal["provider_selected"] is False
        assert proposal["credential_access_authorized"] is False
        envelope = store.get_meta(_selection_key(proposal["proposal_id"]))
        assert envelope["schema"] == PROVIDER_SELECTION_STATE_SCHEMA
        assert envelope["status"] == "pending"

        receipt = service.confirm(
            actor="local-admin:admin",
            request={
                "schema": "home-center.device-management-provider-selection-confirm-request.v1",
                "proposal_id": proposal["proposal_id"],
                "confirmed": True,
            },
            correlation_id="corr-selection-confirm",
        )
        assert receipt["provider_selected"] is True
        assert receipt["selected_provider_id"] == "android-mdm-primary"
        assert receipt["provider_execution_authorized"] is False
        assert receipt["credential_access_authorized"] is False
        assert receipt["enrollment_authorized"] is False
        assert receipt["managed_state_change_authorized"] is False
        assert store.get_meta(HOUSEHOLD_STATE_KEY) == before_household
        assert store.get_meta(PROVIDER_CATALOG_STATE_KEY) == before_catalog
    finally:
        store.close()


def test_runtime_rejects_credentials_and_catalog_drift(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed_household(store, _snapshot())
        enrollment = _confirmed_enrollment(store)
        catalog = {
            "schema": "home-center.device-management-provider-catalog.v1",
            "source": "local-trusted-registry",
            "providers": [
                {
                    "provider_id": "android-mdm-primary",
                    "display_name": "Android MDM Primary",
                    "supported_platforms": ["android"],
                    "enrollment_modes": ["qr"],
                    "ready": True,
                }
            ],
        }
        store.set_meta(PROVIDER_CATALOG_STATE_KEY, catalog)
        resolution = _resolution(store, enrollment["proposal_id"])
        service = DeviceManagementProviderSelectionRuntimeService(store)
        invalid_request = {
            "schema": "home-center.device-management-provider-selection-plan-request.v1",
            "resolution_plan_id": resolution["plan_id"],
            "enrollment_proposal_id": enrollment["proposal_id"],
            "device_platform": "android",
            "provider_id": "android-mdm-primary",
            "credential": "must-not-be-accepted",
        }
        with pytest.raises(
            DeviceManagementProviderSelectionRuntimeError,
            match="invalid_device_management_provider_selection_plan_request",
        ):
            service.plan(actor="local-admin:admin", request=invalid_request, correlation_id="corr-invalid")

        proposal = service.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.device-management-provider-selection-plan-request.v1",
                "resolution_plan_id": resolution["plan_id"],
                "enrollment_proposal_id": enrollment["proposal_id"],
                "device_platform": "android",
                "provider_id": "android-mdm-primary",
            },
            correlation_id="corr-plan",
        )
        catalog["providers"][0]["ready"] = False
        store.set_meta(PROVIDER_CATALOG_STATE_KEY, catalog)
        with pytest.raises(DeviceManagementProviderSelectionRuntimeError):
            service.confirm(
                actor="local-admin:admin",
                request={
                    "schema": "home-center.device-management-provider-selection-confirm-request.v1",
                    "proposal_id": proposal["proposal_id"],
                    "confirmed": True,
                },
                correlation_id="corr-confirm",
            )
    finally:
        store.close()
