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
    build_inventory_snapshot,
    build_operation_plan,
)
from home_center.zigbee_mqtt_recovery import (
    BackupVerification,
    ZigbeeMqttBackupEvidence,
    ZigbeeMqttRecoveryError,
    bind_recovery_to_operation,
    build_backup_evidence,
)

ROOT = Path(__file__).resolve().parents[1]


def current_snapshot(*, generation_time: int = 1_000):
    coordinator = CoordinatorObservation(
        coordinator_id="zigbee-main",
        kind=CoordinatorKind.ZIGBEE,
        transport=CoordinatorTransport.USB,
        observed_at_epoch=generation_time - 5,
        firmware_version="1.2.3",
        endpoint_fingerprint_sha256="a" * 64,
    )
    device = SmartHomeDeviceObservation(
        device_id="sensor-1",
        coordinator_id="zigbee-main",
        observed_at_epoch=generation_time - 4,
        capabilities=("battery", "temperature"),
        room_id="room-kitchen",
        battery_percent=90,
        link_quality=200,
    )
    return build_inventory_snapshot(
        coordinator=coordinator,
        devices=(device,),
        now_epoch=generation_time,
        freshness_seconds=60,
    )


def verified_backup(snapshot) -> ZigbeeMqttBackupEvidence:
    return build_backup_evidence(
        snapshot=snapshot,
        backup_id="backup-before-pair-1",
        configuration_sha256="b" * 64,
        artifact_sha256="c" * 64,
        created_at_epoch=1_001,
        verified_at_epoch=1_002,
        verification=BackupVerification.VERIFIED,
        now_epoch=1_003,
    )


def pair_plan(snapshot):
    return build_operation_plan(
        snapshot=snapshot,
        operation=PairingOperation.PAIR,
        pairing_window_seconds=120,
    )


def test_verified_backup_is_hash_only_and_restore_eligible() -> None:
    backup = verified_backup(current_snapshot())
    payload = backup.to_dict()
    assert payload["verification"] == "verified"
    assert payload["restore_eligible"] is True
    assert payload["contains_secret_values"] is False
    assert payload["restore_execution_authorized"] is False
    assert payload["external_publication_authorized"] is False
    assert "configuration" not in payload
    assert "credential" not in payload


def test_failed_or_unknown_backup_cannot_be_bound_as_recovery() -> None:
    snapshot = current_snapshot()
    plan = pair_plan(snapshot)
    for verification in (BackupVerification.FAILED, BackupVerification.UNKNOWN):
        backup = build_backup_evidence(
            snapshot=snapshot,
            backup_id=f"backup-{verification.value}",
            configuration_sha256=None,
            artifact_sha256=None,
            created_at_epoch=1_001,
            verified_at_epoch=None,
            verification=verification,
            now_epoch=1_003,
        )
        assert backup.restore_eligible is False
        with pytest.raises(ZigbeeMqttRecoveryError, match="recovery_backup_not_verified"):
            bind_recovery_to_operation(operation_plan=plan, backup=backup)


def test_recovery_binding_requires_exact_inventory_and_coordinator() -> None:
    snapshot = current_snapshot()
    plan = pair_plan(snapshot)
    backup = verified_backup(snapshot)
    binding = bind_recovery_to_operation(operation_plan=plan, backup=backup)
    assert binding.operation_plan_id == plan.plan_id
    assert binding.inventory_sha256 == snapshot.inventory_sha256
    assert binding.backup_verified is True
    assert binding.recovery_available is True
    assert binding.execution_authorized is False
    assert binding.restore_execution_authorized is False
    assert binding.device_state_mutation_authorized is False
    assert binding.infrastructure_mutation_authorized is False
    assert binding.external_publication_authorized is False

    other_snapshot = current_snapshot(generation_time=1_010)
    other_backup = verified_backup(other_snapshot)
    with pytest.raises(ZigbeeMqttRecoveryError, match="recovery_inventory_binding_mismatch"):
        bind_recovery_to_operation(operation_plan=plan, backup=other_backup)


def test_stale_inventory_cannot_produce_backup_evidence() -> None:
    coordinator = CoordinatorObservation(
        coordinator_id="zigbee-main",
        kind=CoordinatorKind.ZIGBEE,
        transport=CoordinatorTransport.USB,
        observed_at_epoch=100,
        evidence_state=EvidenceState.STALE,
    )
    snapshot = build_inventory_snapshot(
        coordinator=coordinator,
        devices=(),
        now_epoch=1_000,
        freshness_seconds=60,
    )
    with pytest.raises(ZigbeeMqttRecoveryError, match="backup_inventory_not_current"):
        build_backup_evidence(
            snapshot=snapshot,
            backup_id="backup-stale",
            configuration_sha256="b" * 64,
            artifact_sha256="c" * 64,
            created_at_epoch=1_000,
            verified_at_epoch=1_000,
            verification=BackupVerification.VERIFIED,
            now_epoch=1_000,
        )


def test_recovery_binding_identity_is_deterministic() -> None:
    snapshot = current_snapshot()
    plan = pair_plan(snapshot)
    backup = verified_backup(snapshot)
    first = bind_recovery_to_operation(operation_plan=plan, backup=backup)
    second = bind_recovery_to_operation(operation_plan=plan, backup=backup)
    assert first == second
    assert first.recovery_binding_id.startswith("hc65-recovery-")


def test_public_recovery_contracts_accept_generated_evidence() -> None:
    snapshot = current_snapshot()
    plan = pair_plan(snapshot)
    backup = verified_backup(snapshot)
    binding = bind_recovery_to_operation(operation_plan=plan, backup=backup)

    backup_schema = json.loads(
        (ROOT / "contracts/smart-home/zigbee-mqtt-backup-evidence.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    recovery_schema = json.loads(
        (ROOT / "contracts/smart-home/zigbee-mqtt-recovery-binding.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(backup_schema).validate(backup.to_dict())
    jsonschema.Draft202012Validator(recovery_schema).validate(binding.to_dict())


def test_failed_backup_schema_cannot_claim_restore_eligible() -> None:
    snapshot = current_snapshot()
    backup = build_backup_evidence(
        snapshot=snapshot,
        backup_id="backup-failed",
        configuration_sha256=None,
        artifact_sha256=None,
        created_at_epoch=1_001,
        verified_at_epoch=None,
        verification=BackupVerification.FAILED,
        now_epoch=1_003,
    ).to_dict()
    backup["restore_eligible"] = True
    schema = json.loads(
        (ROOT / "contracts/smart-home/zigbee-mqtt-backup-evidence.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(backup)
