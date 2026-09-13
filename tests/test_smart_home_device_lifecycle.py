from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.smart_home_device_lifecycle import (
    DeviceChangeKind,
    DeviceDriftState,
    DeviceLifecycleHealth,
    SmartHomeDeviceDesiredState,
    SmartHomeDeviceLifecycleError,
    build_device_change_plan,
    build_lifecycle_view,
)
from home_center.zigbee_mqtt import (
    CoordinatorKind,
    CoordinatorObservation,
    CoordinatorTransport,
    EvidenceState,
    SmartHomeDeviceObservation,
    build_inventory_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]


def snapshot(*, state: EvidenceState = EvidenceState.CURRENT, room_id: str = "room-kitchen"):
    unavailable = state is EvidenceState.UNAVAILABLE
    coordinator = CoordinatorObservation(
        coordinator_id="zigbee-main", kind=CoordinatorKind.ZIGBEE,
        transport=CoordinatorTransport.USB, observed_at_epoch=995,
        firmware_version=None if unavailable else "1.2.3",
        endpoint_fingerprint_sha256=None if unavailable else "a" * 64,
        evidence_state=state,
    )
    device = SmartHomeDeviceObservation(
        device_id="sensor-1", coordinator_id="zigbee-main", observed_at_epoch=996,
        capabilities=("battery", "temperature"), room_id=None if unavailable else room_id,
        battery_percent=None if unavailable else 91,
        link_quality=None if unavailable else 201,
        evidence_state=state,
    )
    return build_inventory_snapshot(
        coordinator=coordinator, devices=(device,), now_epoch=1_000, freshness_seconds=60,
    )


def desired(*, room_id: str = "room-kitchen", configuration_sha256: str | None = None):
    return SmartHomeDeviceDesiredState(
        device_id="sensor-1", generation=7, display_name="Датчик кухни", room_id=room_id,
        expected_capabilities=("battery", "temperature"), configuration_sha256=configuration_sha256,
    )


def test_current_matching_observation_is_in_sync_without_mutation_authority() -> None:
    view = build_lifecycle_view(snapshot=snapshot(), desired=desired())
    assert view.health is DeviceLifecycleHealth.CURRENT
    assert view.drift_state is DeviceDriftState.IN_SYNC
    assert view.drift_reasons == ()
    payload = view.to_dict()
    assert payload["lifecycle_mutation_authorized"] is False
    assert payload["configuration_restore_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False


def test_room_drift_is_explicit_and_does_not_authorize_repair() -> None:
    view = build_lifecycle_view(snapshot=snapshot(room_id="room-living"), desired=desired())
    assert view.drift_state is DeviceDriftState.DRIFTED
    assert view.drift_reasons == ("room_mismatch",)
    assert view.to_dict()["lifecycle_mutation_authorized"] is False


def test_configuration_digest_never_claims_verified_without_provider_readback() -> None:
    view = build_lifecycle_view(snapshot=snapshot(), desired=desired(configuration_sha256="c" * 64))
    assert view.drift_state is DeviceDriftState.DRIFTED
    assert "configuration_verification_unavailable" in view.drift_reasons
    assert view.configuration_verification_available is False
    assert view.configuration_restore_authorized is False


def test_stale_or_unavailable_actual_state_makes_drift_unknown() -> None:
    for state, expected_health in (
        (EvidenceState.STALE, DeviceLifecycleHealth.STALE),
        (EvidenceState.UNAVAILABLE, DeviceLifecycleHealth.UNAVAILABLE),
    ):
        view = build_lifecycle_view(snapshot=snapshot(state=state), desired=desired())
        assert view.health is expected_health
        assert view.drift_state is DeviceDriftState.UNKNOWN
        assert view.drift_reasons


def test_room_assignment_plan_is_exact_bound_and_plan_only() -> None:
    current = snapshot()
    plan = build_device_change_plan(
        snapshot=current, desired=desired(), change_kind=DeviceChangeKind.ASSIGN_ROOM,
        proposed_room_id="room-living",
    )
    assert plan.inventory_sha256 == current.inventory_sha256
    assert plan.desired_generation == 7
    assert plan.expected_observed_room_id == "room-kitchen"
    assert plan.explicit_confirmation_required is True
    assert plan.execution_authorized is False
    assert plan.provider_execution_authorized is False
    assert plan.infrastructure_mutation_authorized is False
    assert plan.external_publication_authorized is False


def test_noop_room_assignment_and_stale_inventory_fail_closed() -> None:
    with pytest.raises(SmartHomeDeviceLifecycleError, match="device_change_room_already_current"):
        build_device_change_plan(
            snapshot=snapshot(), desired=desired(), change_kind=DeviceChangeKind.ASSIGN_ROOM,
            proposed_room_id="room-kitchen",
        )
    with pytest.raises(SmartHomeDeviceLifecycleError, match="device_change_inventory_not_current"):
        build_device_change_plan(
            snapshot=snapshot(state=EvidenceState.STALE), desired=desired(),
            change_kind=DeviceChangeKind.RENAME, proposed_display_name="Новый датчик",
        )


def test_rename_plan_rejects_control_characters() -> None:
    with pytest.raises(SmartHomeDeviceLifecycleError, match="device_display_name_invalid"):
        build_device_change_plan(
            snapshot=snapshot(), desired=desired(), change_kind=DeviceChangeKind.RENAME,
            proposed_display_name="bad\nname",
        )


def test_change_plan_id_is_deterministic() -> None:
    current = snapshot()
    first = build_device_change_plan(
        snapshot=current, desired=desired(), change_kind=DeviceChangeKind.RENAME,
        proposed_display_name="Датчик температуры",
    )
    second = build_device_change_plan(
        snapshot=current, desired=desired(), change_kind=DeviceChangeKind.RENAME,
        proposed_display_name="Датчик температуры",
    )
    assert first == second
    assert first.plan_id.startswith("hc66-change-")


def test_public_contracts_accept_generated_payloads() -> None:
    current = snapshot()
    desired_state = desired()
    view = build_lifecycle_view(snapshot=current, desired=desired_state)
    plan = build_device_change_plan(
        snapshot=current, desired=desired_state, change_kind=DeviceChangeKind.ASSIGN_ROOM,
        proposed_room_id="room-living",
    )
    cases = (
        ("smart-home-device-desired-state.v1.schema.json", desired_state.to_dict()),
        ("smart-home-device-lifecycle-view.v1.schema.json", view.to_dict()),
        ("smart-home-device-change-plan.v1.schema.json", plan.to_dict()),
    )
    for name, payload in cases:
        schema = json.loads((ROOT / "contracts/smart-home" / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(payload)


def test_lifecycle_schema_rejects_false_in_sync_for_stale_evidence() -> None:
    payload = build_lifecycle_view(snapshot=snapshot(state=EvidenceState.STALE), desired=desired()).to_dict()
    payload["drift_state"] = "in-sync"
    schema = json.loads(
        (ROOT / "contracts/smart-home/smart-home-device-lifecycle-view.v1.schema.json").read_text(encoding="utf-8")
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(payload)
