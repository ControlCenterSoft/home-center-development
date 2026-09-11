from __future__ import annotations

from pathlib import Path

import pytest

from home_center.device_management_provider import (
    DeviceManagementProviderError,
    DevicePlatform,
    ProviderResolutionState,
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
from home_center.household_store import HouseholdStore
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
    store = HouseholdStore()
    store.create(household)
    return store.read("home")


def _catalog(*providers: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "home-center.device-management-provider-catalog.v1",
        "source": "local-trusted-registry",
        "providers": list(providers),
    }


def _provider(
    provider_id: str,
    *,
    platforms: list[str] | None = None,
    ready: bool = True,
) -> dict[str, object]:
    return {
        "provider_id": provider_id,
        "display_name": provider_id.replace("-", " ").title(),
        "supported_platforms": platforms or ["android"],
        "enrollment_modes": ["work-profile"],
        "ready": ready,
    }


def _state_store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"p" * 32, "cluster-test")


def _seed_household(store: StateStore) -> None:
    store.set_meta(
        HOUSEHOLD_STATE_KEY,
        _persisted(
            _snapshot(),
            (ActorBinding(actor="local-admin:admin", member_id="member-parent"),),
        ),
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
    return service.confirm(
        actor="local-admin:admin",
        request={
            "schema": "home-center.household-device-enrollment-confirm-request.v1",
            "proposal_id": proposal["proposal_id"],
            "confirmed": True,
        },
        correlation_id="corr-enrollment-confirm",
    )


def test_catalog_normalization_is_strict_and_non_authorizing() -> None:
    catalog = normalize_provider_catalog(_catalog(_provider("android-local")))
    value = catalog.to_dict()
    assert value["source"] == "local-trusted-registry"
    assert value["production_mutation_enabled"] is False
    assert value["providers"][0]["execution_authorized"] is False


def test_catalog_rejects_duplicate_provider_and_platform() -> None:
    with pytest.raises(DeviceManagementProviderError, match="duplicate_device_management_provider_id"):
        normalize_provider_catalog(_catalog(_provider("provider-a"), _provider("provider-a")))

    duplicate_platform = _provider("provider-a", platforms=["android", "android"])
    with pytest.raises(DeviceManagementProviderError, match="duplicate_device_management_provider_platform"):
        normalize_provider_catalog(_catalog(duplicate_platform))


def test_resolution_with_no_ready_candidate_is_unavailable_and_never_selects() -> None:
    snapshot = _snapshot()
    proposal = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    catalog = normalize_provider_catalog(_catalog(_provider("android-local", ready=False)))
    plan = plan_provider_resolution(
        snapshot,
        proposal,
        catalog,
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    )
    assert plan.state is ProviderResolutionState.UNAVAILABLE
    assert plan.candidates == ()
    value = plan.to_dict()
    assert value["platform_claim_source"] == "user"
    assert value["platform_verified"] is False
    assert value["selected_provider_id"] is None
    assert value["provider_execution_authorized"] is False
    assert value["policy_application_authorized"] is False
    assert value["managed_state_change_authorized"] is False
    assert value["infrastructure_mutation_authorized"] is False
    assert value["external_publication_authorized"] is False


def test_single_candidate_is_not_implicitly_selected() -> None:
    snapshot = _snapshot()
    proposal = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    catalog = normalize_provider_catalog(_catalog(_provider("android-local")))
    value = plan_provider_resolution(
        snapshot,
        proposal,
        catalog,
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    ).to_dict()
    assert value["state"] == "single-candidate"
    assert [item["provider_id"] for item in value["candidates"]] == ["android-local"]
    assert value["provider_selection_required"] is True
    assert value["selected_provider_id"] is None
    assert value["provider_execution_authorized"] is False


def test_multiple_candidates_require_choice_and_are_deterministically_ordered() -> None:
    snapshot = _snapshot()
    proposal = build_device_enrollment_proposal(
        snapshot,
        actor_member_id="member-parent",
        device_id="device-phone",
    )
    catalog = normalize_provider_catalog(
        _catalog(
            _provider("provider-z"),
            _provider("provider-a"),
        )
    )
    value = plan_provider_resolution(
        snapshot,
        proposal,
        catalog,
        actor_member_id="member-parent",
        device_platform=DevicePlatform.ANDROID,
    ).to_dict()
    assert value["state"] == "choice-required"
    assert [item["provider_id"] for item in value["candidates"]] == ["provider-a", "provider-z"]
    assert value["selected_provider_id"] is None


def test_runtime_refuses_provider_resolution_before_enrollment_consent(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed_household(store)
        enrollment = HouseholdDeviceEnrollmentRuntimeService(store)
        proposal = enrollment.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.household-device-enrollment-plan-request.v1",
                "device_id": "device-phone",
            },
            correlation_id="corr-plan",
        )
        service = DeviceManagementProviderRuntimeService(store)
        with pytest.raises(DeviceManagementProviderRuntimeError, match="household_device_enrollment_not_confirmed"):
            service.plan(
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


def test_runtime_resolves_only_after_exact_confirmed_receipt_without_household_mutation(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed_household(store)
        receipt = _confirmed_enrollment(store)
        store.set_meta(PROVIDER_CATALOG_STATE_KEY, _catalog(_provider("android-local")))
        before = store.get_meta(HOUSEHOLD_STATE_KEY)

        service = DeviceManagementProviderRuntimeService(store)
        value = service.plan(
            actor="local-admin:admin",
            request={
                "schema": "home-center.device-management-provider-resolution-request.v1",
                "enrollment_proposal_id": receipt["proposal_id"],
                "device_platform": "android",
            },
            correlation_id="corr-provider",
        )
        after = store.get_meta(HOUSEHOLD_STATE_KEY)

        assert before == after
        assert value["state"] == "single-candidate"
        assert value["platform_verified"] is False
        assert value["selected_provider_id"] is None
        assert value["provider_execution_authorized"] is False
        events = store.audit_events(50)
        event = next(
            item
            for item in events
            if item["action"] == "household.device.management.provider-resolution.plan"
        )
        assert event["target"] == "device-phone"
        assert event["outcome"] == "accepted"
    finally:
        store.close()


def test_runtime_rejects_tampered_confirmation_receipt(tmp_path: Path) -> None:
    store = _state_store(tmp_path)
    try:
        _seed_household(store)
        receipt = _confirmed_enrollment(store)
        key = "cozy.household.device-enrollment." + str(receipt["proposal_id"])
        envelope = store.get_meta(key)
        assert isinstance(envelope, dict)
        tampered = dict(envelope)
        bad_receipt = dict(tampered["receipt"])
        bad_receipt["provider_execution_authorized"] = True
        tampered["receipt"] = bad_receipt
        store.set_meta(key, tampered)

        service = DeviceManagementProviderRuntimeService(store)
        with pytest.raises(DeviceManagementProviderRuntimeError, match="household_device_enrollment_receipt_invalid"):
            service.plan(
                actor="local-admin:admin",
                request={
                    "schema": "home-center.device-management-provider-resolution-request.v1",
                    "enrollment_proposal_id": receipt["proposal_id"],
                    "device_platform": "android",
                },
                correlation_id="corr-tampered",
            )
    finally:
        store.close()
