from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_provider import (
    DeviceManagementProviderError,
    DevicePlatform,
    ProviderResolutionState,
    empty_provider_catalog,
    normalize_provider_catalog,
    plan_provider_resolution,
)
from home_center.device_management_provider_runtime import (
    PROVIDER_CATALOG_STATE_KEY,
    DeviceManagementProviderRuntimeError,
    DeviceManagementProviderRuntimeService,
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


def _catalog(*, second: bool = False, first_ready: bool = True):
    providers = [
        {
            "provider_id": "android-mdm-primary",
            "display_name": "Android MDM Primary",
            "supported_platforms": ["android"],
            "enrollment_modes": ["qr"],
            "ready": first_ready,
        }
    ]
    if second:
        providers.append(
            {
                "provider_id": "android-mdm-secondary",
                "display_name": "Android MDM Secondary",
                "supported_platforms": ["android", "windows"],
                "enrollment_modes": ["qr", "manual"],
                "ready": True,
            }
        )
    return {
        "schema": "home-center.device-management-provider-catalog.v1",
        "source": "local-trusted-registry",
        "providers": providers,
    }


def _state_store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"p" * 32, "cluster-test")


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


def test_empty_catalog_is_explicit_and_non_mutating() -> None:
    value = empty_provider_catalog().to_dict()
    assert value["source"] == "local-trusted-registry"
    assert value["providers"] == []
    assert value["production_mutation_enabled"] is False
    assert value["catalog_id"].startswith("dmpcat-")


def test_catalog_normalization_is_deterministic_and_never_authorizes_execution() -> None:
    catalog = normalize_provider_catalog(_catalog(second=True))
    value = catalog.to_dict()
    assert [item["provider_id"] for item in value["providers"]] == [
        "android-mdm-primary",
        "android-mdm-secondary",
    ]
    assert all(item["execution_authorized"] is False for item in value["providers"])
    assert value["production_mutation_enabled"] is False
    assert normalize_provider_catalog(_catalog(second=True)).catalog_id == catalog.catalog_id


def test_catalog_rejects_unknown_fields_duplicates_and_duplicate_platforms() -> None:
    with pytest.raises(DeviceManagementProviderError, match="invalid_device_management_provider_profile"):
        bad = _catalog()
        bad["providers"][0]["credential"] = "secret"
        normalize_provider_catalog(bad)

    duplicate = _catalog(second=True)
    duplicate["providers"][1]["provider_id"] = "android-mdm-primary"
    with pytest.raises(DeviceManagementProviderError, match="duplicate_device_management_provider_id"):
        normalize_provider_catalog(duplicate)

    duplicate_platform = _catalog()
    duplicate_platform["providers"][0]["supported_platforms"] = ["android", "android"]
    with pytest.raises(DeviceManagementProviderError, match="duplicate_device_management_provider_platform"):
        normalize_provider_catalog(duplicate_platform)


def test_resolution_states_never_select_or_authorize_provider() -> None:
    snapshot = _snapshot()
    proposal = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )

    unavailable = plan_provider_resolution(
        snapshot,
        proposal,
        empty_provider_catalog(),
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    assert unavailable.state is ProviderResolutionState.UNAVAILABLE
    assert unavailable.candidates == ()

    single = plan_provider_resolution(
        snapshot,
        proposal,
        normalize_provider_catalog(_catalog()),
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    assert single.state is ProviderResolutionState.SINGLE_CANDIDATE
    assert len(single.candidates) == 1

    multiple = plan_provider_resolution(
        snapshot,
        proposal,
        normalize_provider_catalog(_catalog(second=True)),
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    assert multiple.state is ProviderResolutionState.CHOICE_REQUIRED
    assert len(multiple.candidates) == 2

    for plan in (unavailable, single, multiple):
        value = plan.to_dict()
        assert value["platform_claim_source"] == "user"
        assert value["platform_verified"] is False
        assert value["provider_selection_required"] is True
        assert value["selected_provider_id"] is None
        assert value["provider_execution_authorized"] is False
        assert value["policy_application_authorized"] is False
        assert value["managed_state_change_authorized"] is False
        assert value["infrastructure_mutation_authorized"] is False
        assert value["external_publication_authorized"] is False


def test_not_ready_provider_is_not_a_candidate() -> None:
    snapshot = _snapshot()
    proposal = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    plan = plan_provider_resolution(
        snapshot,
        proposal,
        normalize_provider_catalog(_catalog(first_ready=False)),
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    assert plan.state is ProviderResolutionState.UNAVAILABLE
    assert plan.candidates == ()


def test_resolution_rejects_stale_household_state() -> None:
    snapshot = _snapshot()
    proposal = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
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
    with pytest.raises(DeviceManagementProviderError, match="household_device_enrollment_stale"):
        plan_provider_resolution(
            newer,
            proposal,
            empty_provider_catalog(),
            actor_member_id="member-parent",
            device_platform=DevicePlatform.ANDROID,
        )


def test_runtime_requires_confirmed_enrollment_and_exact_request_shape(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        snapshot = _snapshot()
        _seed_household(store, snapshot)
        enrollment = HouseholdDeviceEnrollmentRuntimeService(store)
        proposal = enrollment.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.household-device-enrollment-plan-request.v1",
                "device_id": "device-phone",
            },
            correlation_id="corr-enrollment-plan",
        )
        providers = DeviceManagementProviderRuntimeService(store)
        request = {
            "schema": "home-center.device-management-provider-resolution-request.v1",
            "enrollment_proposal_id": proposal["proposal_id"],
            "device_platform": "android",
        }
        with pytest.raises(DeviceManagementProviderRuntimeError, match="household_device_enrollment_not_confirmed"):
            providers.plan(actor="local-admin:admin", request=request, correlation_id="corr-provider")

        request["selected_provider_id"] = "android-mdm-primary"
        with pytest.raises(
            DeviceManagementProviderRuntimeError,
            match="invalid_device_management_provider_resolution_request",
        ):
            providers.plan(actor="local-admin:admin", request=request, correlation_id="corr-provider")
    finally:
        store.close()


def test_runtime_resolution_is_read_only_and_defaults_to_empty_catalog(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        snapshot = _snapshot()
        _seed_household(store, snapshot)
        proposal = _confirmed_enrollment(store)
        before_household = store.get_meta(HOUSEHOLD_STATE_KEY)
        providers = DeviceManagementProviderRuntimeService(store)
        plan = providers.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.device-management-provider-resolution-request.v1",
                "enrollment_proposal_id": proposal["proposal_id"],
                "device_platform": "android",
            },
            correlation_id="corr-provider",
        )
        assert plan["state"] == "unavailable"
        assert plan["candidates"] == []
        assert plan["selected_provider_id"] is None
        assert plan["provider_execution_authorized"] is False
        assert store.get_meta(HOUSEHOLD_STATE_KEY) == before_household
        assert store.get_meta(PROVIDER_CATALOG_STATE_KEY) is None
    finally:
        store.close()


def test_runtime_uses_only_ready_trusted_catalog_entries(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed_household(store, _snapshot())
        proposal = _confirmed_enrollment(store)
        store.set_meta(PROVIDER_CATALOG_STATE_KEY, _catalog(second=True, first_ready=False))
        providers = DeviceManagementProviderRuntimeService(store)
        plan = providers.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.device-management-provider-resolution-request.v1",
                "enrollment_proposal_id": proposal["proposal_id"],
                "device_platform": "android",
            },
            correlation_id="corr-provider",
        )
        assert plan["state"] == "single-candidate"
        assert [item["provider_id"] for item in plan["candidates"]] == ["android-mdm-secondary"]
        assert plan["provider_selection_required"] is True
        assert plan["selected_provider_id"] is None
    finally:
        store.close()


def test_runtime_fails_closed_on_malformed_persisted_catalog(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed_household(store, _snapshot())
        proposal = _confirmed_enrollment(store)
        store.set_meta(
            PROVIDER_CATALOG_STATE_KEY,
            {
                "schema": "home-center.device-management-provider-catalog.v1",
                "source": "local-trusted-registry",
                "providers": [{"provider_id": "broken"}],
            },
        )
        providers = DeviceManagementProviderRuntimeService(store)
        with pytest.raises(DeviceManagementProviderRuntimeError, match="invalid_device_management_provider_profile"):
            providers.plan(
                actor="local-admin:admin",
                request={
                    "schema": "home-center.device-management-provider-resolution-request.v1",
                    "enrollment_proposal_id": proposal["proposal_id"],
                    "device_platform": "android",
                },
                correlation_id="corr-provider",
            )
    finally:
        store.close()
