from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.smart_home_device_lifecycle import (
    DeviceChangeKind,
    DeviceHealth,
    SmartHomeLifecycleError,
    SmartHomeLocalProfile,
    build_change_plan,
    build_device_state,
    project_cozy,
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


def snapshot(*, room_id="room-kitchen", battery=80, link=180, stale=False):
    coordinator = CoordinatorObservation(
        coordinator_id="zigbee-main",
        kind=CoordinatorKind.ZIGBEE,
        transport=CoordinatorTransport.USB,
        observed_at_epoch=100,
        firmware_version="1.2.3",
        endpoint_fingerprint_sha256="a" * 64,
        evidence_state=EvidenceState.STALE if stale else EvidenceState.CURRENT,
    )
    device = SmartHomeDeviceObservation(
        device_id="lamp-1",
        coordinator_id="zigbee-main",
        observed_at_epoch=100,
        capabilities=("light.brightness", "light.onoff", "sensor.power"),
        room_id=room_id,
        battery_percent=battery,
        link_quality=link,
        evidence_state=EvidenceState.STALE if stale else EvidenceState.CURRENT,
    )
    return build_inventory_snapshot(
        coordinator=coordinator,
        devices=(device,),
        now_epoch=110,
        freshness_seconds=60,
    )


def profile(*, room_id="room-kitchen", name="Лампа кухни"):
    return SmartHomeLocalProfile(
        device_id="lamp-1",
        generation=4,
        display_name=name,
        room_id=room_id,
    )


def test_current_device_projects_healthy_cozy_state_without_provider_details() -> None:
    state = build_device_state(snapshot=snapshot(), profile=profile())
    assert state.health is DeviceHealth.HEALTHY
    assert state.drift_detected is False
    assert state.capability_families == ("lighting", "sensor")
    cozy = project_cozy(state)
    assert cozy["status"] == "healthy"
    assert cozy["attention_required"] is False
    assert cozy["mutation_authorized"] is False
    serialized = json.dumps(cozy, ensure_ascii=False)
    assert "zigbee-main" not in serialized
    assert "usb" not in serialized.lower()


def test_room_drift_is_visible_and_never_presented_as_healthy() -> None:
    state = build_device_state(snapshot=snapshot(room_id="room-hall"), profile=profile())
    assert state.health is DeviceHealth.DEGRADED
    assert state.drift_detected is True
    assert "room-drift" in state.diagnostics
    assert project_cozy(state)["attention_required"] is True


def test_stale_evidence_does_not_invent_room_drift_or_allow_change_plan() -> None:
    stale = snapshot(room_id="room-hall", stale=True)
    state = build_device_state(snapshot=stale, profile=profile())
    assert state.health is DeviceHealth.STALE
    assert state.drift_detected is False
    with pytest.raises(SmartHomeLifecycleError, match="smart_home_change_inventory_not_current"):
        build_change_plan(
            snapshot=stale,
            profile=profile(),
            change=DeviceChangeKind.RENAME,
            target_display_name="Новая лампа",
        )


def test_low_battery_and_weak_link_are_bounded_diagnostics() -> None:
    state = build_device_state(snapshot=snapshot(battery=5, link=20), profile=profile())
    assert state.health is DeviceHealth.DEGRADED
    assert state.diagnostics == ("low-battery", "weak-link")


def test_rename_plan_is_exact_bound_non_authorizing_and_recoverable() -> None:
    current = snapshot()
    plan = build_change_plan(
        snapshot=current,
        profile=profile(),
        change=DeviceChangeKind.RENAME,
        target_display_name="Лампа над столом",
    )
    assert plan.inventory_sha256 == current.inventory_sha256
    assert plan.expected_profile_generation == 4
    assert plan.to_dict()["before"] == {"display_name": "Лампа кухни", "room_id": "room-kitchen"}
    assert plan.to_dict()["target"] == {"display_name": "Лампа над столом", "room_id": "room-kitchen"}
    assert plan.explicit_confirmation_required is True
    assert plan.recovery_snapshot_required is True
    assert plan.execution_authorized is False
    assert plan.device_state_mutation_authorized is False
    assert plan.provider_execution_authorized is False


def test_move_room_plan_rejects_noop_and_name_smuggling() -> None:
    current = snapshot()
    with pytest.raises(SmartHomeLifecycleError, match="smart_home_change_noop"):
        build_change_plan(
            snapshot=current,
            profile=profile(),
            change=DeviceChangeKind.MOVE_ROOM,
            target_room_id="room-kitchen",
        )
    with pytest.raises(SmartHomeLifecycleError, match="smart_home_move_name_forbidden"):
        build_change_plan(
            snapshot=current,
            profile=profile(),
            change=DeviceChangeKind.MOVE_ROOM,
            target_display_name="forged",
            target_room_id="room-hall",
        )


def test_state_and_change_plan_match_closed_contracts() -> None:
    current = snapshot()
    state = build_device_state(snapshot=current, profile=profile())
    plan = build_change_plan(
        snapshot=current,
        profile=profile(),
        change=DeviceChangeKind.MOVE_ROOM,
        target_room_id="room-hall",
    )
    state_schema = json.loads(
        (ROOT / "contracts/smart-home/smart-home-device-state.v1.schema.json").read_text(encoding="utf-8")
    )
    plan_schema = json.loads(
        (ROOT / "contracts/smart-home/smart-home-device-change-plan.v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(state_schema).validate(state.to_dict())
    jsonschema.Draft202012Validator(plan_schema).validate(plan.to_dict())
