from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.zigbee_mqtt import (
    CoordinatorKind,
    CoordinatorObservation,
    CoordinatorTransport,
    EvidenceState,
    PairingOperation,
    SmartHomeDeviceObservation,
    ZigbeeMqttFoundationError,
    build_backup_plan,
    build_inventory_snapshot,
    build_operation_plan,
    project_cozy,
    project_full,
)

ROOT = Path(__file__).resolve().parents[1]


def _snapshot(now: int = 1000):
    coordinator = CoordinatorObservation(
        coordinator_id="zb-1",
        kind=CoordinatorKind.ZIGBEE,
        transport=CoordinatorTransport.USB,
        observed_at_epoch=990,
        firmware_version="1.2.3",
        endpoint_fingerprint_sha256="a" * 64,
    )
    device = SmartHomeDeviceObservation(
        device_id="dev-1",
        coordinator_id="zb-1",
        observed_at_epoch=995,
        capabilities=("battery", "switch.on_off"),
        room_id="kitchen",
        battery_percent=80,
        link_quality=200,
    )
    return build_inventory_snapshot(
        coordinator=coordinator,
        devices=(device,),
        now_epoch=now,
        freshness_seconds=30,
    )


def _schema(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/smart-home" / name).read_text(encoding="utf-8"))


def test_snapshot_is_content_addressed_and_non_authorizing():
    snapshot = _snapshot()
    assert snapshot.state is EvidenceState.CURRENT
    assert len(snapshot.inventory_sha256) == 64
    body = snapshot.to_dict()
    assert body["mutation_authorized"] is False
    assert body["pairing_authorized"] is False
    assert body["provider_execution_authorized"] is False
    assert body["external_publication_authorized"] is False
    assert body["coordinator"]["ha_supported"] is False
    assert body["coordinator"]["physical_single_coordinator"] is True


def test_stale_or_unavailable_evidence_blocks_operation_planning():
    stale = _snapshot(now=2000)
    assert stale.state is EvidenceState.STALE
    with pytest.raises(ZigbeeMqttFoundationError, match="operation_inventory_not_current"):
        build_operation_plan(
            snapshot=stale,
            operation=PairingOperation.PAIR,
            pairing_window_seconds=60,
        )


def test_pair_and_unpair_plans_remain_non_executing_and_require_backup():
    snapshot = _snapshot()
    pair = build_operation_plan(
        snapshot=snapshot,
        operation=PairingOperation.PAIR,
        pairing_window_seconds=60,
    )
    assert pair.physical_confirmation_required is True
    assert pair.backup_required_before_execution is True
    assert pair.execution_authorized is False

    unpair = build_operation_plan(
        snapshot=snapshot,
        operation=PairingOperation.UNPAIR,
        expected_device_id="dev-1",
    )
    assert unpair.pairing_window_seconds is None
    assert unpair.device_state_mutation_authorized is False
    with pytest.raises(ZigbeeMqttFoundationError, match="unpair_device_not_observed"):
        build_operation_plan(
            snapshot=snapshot,
            operation=PairingOperation.UNPAIR,
            expected_device_id="missing",
        )


def test_backup_plan_is_plan_only():
    snapshot = _snapshot()
    plan = build_backup_plan(snapshot=snapshot, reason="pre-unpair")
    assert plan.backup_execution_authorized is False
    assert plan.restore_execution_authorized is False
    assert plan.external_publication_authorized is False


def test_cozy_hides_provider_details_and_tells_ha_limitation():
    snapshot = _snapshot()
    cozy = project_cozy(snapshot)
    assert cozy["title"] == "Умный дом"
    assert cozy["ha_limitation"] == "Один физический координатор"
    assert "coordinator" not in cozy
    full = project_full(snapshot)
    assert full["coordinator"]["coordinator_id"] == "zb-1"
    assert full["ha_supported"] is False


def test_canonical_capabilities_and_future_evidence_fail_closed():
    with pytest.raises(ZigbeeMqttFoundationError, match="device_capabilities_not_canonical"):
        SmartHomeDeviceObservation(
            device_id="dev-1",
            coordinator_id="zb-1",
            observed_at_epoch=1,
            capabilities=("switch.on_off", "battery"),
        )
    coordinator = CoordinatorObservation(
        coordinator_id="zb-1",
        kind=CoordinatorKind.ZIGBEE,
        transport=CoordinatorTransport.USB,
        observed_at_epoch=101,
    )
    with pytest.raises(ZigbeeMqttFoundationError, match="inventory_future_evidence"):
        build_inventory_snapshot(
            coordinator=coordinator,
            devices=(),
            now_epoch=100,
            freshness_seconds=10,
        )


def test_unavailable_evidence_cannot_smuggle_telemetry():
    with pytest.raises(ZigbeeMqttFoundationError, match="device_unavailable_contains_telemetry"):
        SmartHomeDeviceObservation(
            device_id="dev-1",
            coordinator_id="zb-1",
            observed_at_epoch=1,
            capabilities=("battery",),
            battery_percent=80,
            evidence_state=EvidenceState.UNAVAILABLE,
        )


def test_domain_outputs_match_closed_public_schemas():
    snapshot = _snapshot()
    pair = build_operation_plan(
        snapshot=snapshot,
        operation=PairingOperation.PAIR,
        pairing_window_seconds=60,
    )
    backup = build_backup_plan(snapshot=snapshot, reason="pre-pair")
    cases = (
        (snapshot.to_dict(), "zigbee-mqtt-inventory-snapshot.v1.schema.json"),
        (pair.to_dict(), "zigbee-mqtt-operation-plan.v1.schema.json"),
        (backup.to_dict(), "zigbee-mqtt-backup-plan.v1.schema.json"),
    )
    for value, name in cases:
        schema = _schema(name)
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(value)
