"""Verified ZigBee/MQTT configuration-backup evidence for Home Center 0.65.

This module remains plan/evidence only. It never reads or writes coordinator
configuration, invokes a provider, opens a pairing window, mutates a device, or
restores a backup. It binds a future pair/unpair operation to a verified,
content-addressed pre-operation backup so later execution code has a fail-closed
recovery precondition.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import hashlib
import re

from .util import canonical_json
from .zigbee_mqtt import EvidenceState, ZigbeeMqttInventorySnapshot, ZigbeeMqttOperationPlan

SCHEMA_BACKUP_EVIDENCE = "home-center.zigbee-mqtt-backup-evidence.v1"
SCHEMA_RECOVERY_BINDING = "home-center.zigbee-mqtt-recovery-binding.v1"

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class ZigbeeMqttRecoveryError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class BackupVerification(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ZigbeeMqttBackupEvidence:
    backup_id: str
    coordinator_id: str
    inventory_sha256: str
    configuration_sha256: str | None
    artifact_sha256: str | None
    created_at_epoch: int
    verified_at_epoch: int | None
    verification: BackupVerification
    schema: str = field(default=SCHEMA_BACKUP_EVIDENCE, init=False)
    contains_secret_values: bool = field(default=False, init=False)
    restore_execution_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    @property
    def restore_eligible(self) -> bool:
        return (
            self.verification is BackupVerification.VERIFIED
            and self.configuration_sha256 is not None
            and self.artifact_sha256 is not None
            and self.verified_at_epoch is not None
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "backup_id": self.backup_id,
            "coordinator_id": self.coordinator_id,
            "inventory_sha256": self.inventory_sha256,
            "configuration_sha256": self.configuration_sha256,
            "artifact_sha256": self.artifact_sha256,
            "created_at_epoch": self.created_at_epoch,
            "verified_at_epoch": self.verified_at_epoch,
            "verification": self.verification.value,
            "restore_eligible": self.restore_eligible,
            "contains_secret_values": False,
            "restore_execution_authorized": False,
            "external_publication_authorized": False,
        }


@dataclass(frozen=True, slots=True)
class ZigbeeMqttRecoveryBinding:
    recovery_binding_id: str
    operation_plan_id: str
    coordinator_id: str
    inventory_sha256: str
    backup_id: str
    backup_configuration_sha256: str
    backup_artifact_sha256: str
    schema: str = field(default=SCHEMA_RECOVERY_BINDING, init=False)
    backup_verified: bool = field(default=True, init=False)
    recovery_available: bool = field(default=True, init=False)
    execution_authorized: bool = field(default=False, init=False)
    restore_execution_authorized: bool = field(default=False, init=False)
    device_state_mutation_authorized: bool = field(default=False, init=False)
    infrastructure_mutation_authorized: bool = field(default=False, init=False)
    external_publication_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "recovery_binding_id": self.recovery_binding_id,
            "operation_plan_id": self.operation_plan_id,
            "coordinator_id": self.coordinator_id,
            "inventory_sha256": self.inventory_sha256,
            "backup_id": self.backup_id,
            "backup_configuration_sha256": self.backup_configuration_sha256,
            "backup_artifact_sha256": self.backup_artifact_sha256,
            "backup_verified": True,
            "recovery_available": True,
            "execution_authorized": False,
            "restore_execution_authorized": False,
            "device_state_mutation_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def _require_id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ZigbeeMqttRecoveryError(f"{field_name}_invalid")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ZigbeeMqttRecoveryError(f"{field_name}_invalid")
    return value


def _content_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def build_backup_evidence(
    *,
    snapshot: ZigbeeMqttInventorySnapshot,
    backup_id: str,
    configuration_sha256: str | None,
    artifact_sha256: str | None,
    created_at_epoch: int,
    verified_at_epoch: int | None,
    verification: BackupVerification,
    now_epoch: int,
) -> ZigbeeMqttBackupEvidence:
    if not isinstance(snapshot, ZigbeeMqttInventorySnapshot):
        raise ZigbeeMqttRecoveryError("backup_snapshot_invalid")
    if snapshot.state is not EvidenceState.CURRENT:
        raise ZigbeeMqttRecoveryError("backup_inventory_not_current")
    _require_id(backup_id, "backup_id")
    if not isinstance(verification, BackupVerification):
        raise ZigbeeMqttRecoveryError("backup_verification_invalid")
    if type(now_epoch) is not int or now_epoch < 0:
        raise ZigbeeMqttRecoveryError("backup_now_invalid")
    if type(created_at_epoch) is not int or created_at_epoch < 0 or created_at_epoch > now_epoch:
        raise ZigbeeMqttRecoveryError("backup_created_at_invalid")

    if verification is BackupVerification.VERIFIED:
        configuration_sha256 = _require_sha256(configuration_sha256, "backup_configuration_sha256")
        artifact_sha256 = _require_sha256(artifact_sha256, "backup_artifact_sha256")
        if (
            type(verified_at_epoch) is not int
            or verified_at_epoch < created_at_epoch
            or verified_at_epoch > now_epoch
        ):
            raise ZigbeeMqttRecoveryError("backup_verified_at_invalid")
    else:
        if configuration_sha256 is not None:
            _require_sha256(configuration_sha256, "backup_configuration_sha256")
        if artifact_sha256 is not None:
            _require_sha256(artifact_sha256, "backup_artifact_sha256")
        if verified_at_epoch is not None and (
            type(verified_at_epoch) is not int
            or verified_at_epoch < created_at_epoch
            or verified_at_epoch > now_epoch
        ):
            raise ZigbeeMqttRecoveryError("backup_verified_at_invalid")

    return ZigbeeMqttBackupEvidence(
        backup_id=backup_id,
        coordinator_id=snapshot.coordinator.coordinator_id,
        inventory_sha256=snapshot.inventory_sha256,
        configuration_sha256=configuration_sha256,
        artifact_sha256=artifact_sha256,
        created_at_epoch=created_at_epoch,
        verified_at_epoch=verified_at_epoch,
        verification=verification,
    )


def bind_recovery_to_operation(
    *,
    operation_plan: ZigbeeMqttOperationPlan,
    backup: ZigbeeMqttBackupEvidence,
) -> ZigbeeMqttRecoveryBinding:
    if not isinstance(operation_plan, ZigbeeMqttOperationPlan):
        raise ZigbeeMqttRecoveryError("recovery_operation_plan_invalid")
    if not isinstance(backup, ZigbeeMqttBackupEvidence):
        raise ZigbeeMqttRecoveryError("recovery_backup_invalid")
    if not backup.restore_eligible:
        raise ZigbeeMqttRecoveryError("recovery_backup_not_verified")
    if backup.coordinator_id != operation_plan.coordinator_id:
        raise ZigbeeMqttRecoveryError("recovery_coordinator_binding_mismatch")
    if backup.inventory_sha256 != operation_plan.inventory_sha256:
        raise ZigbeeMqttRecoveryError("recovery_inventory_binding_mismatch")
    if backup.configuration_sha256 is None or backup.artifact_sha256 is None:
        raise ZigbeeMqttRecoveryError("recovery_backup_digest_missing")

    payload = {
        "operation_plan_id": operation_plan.plan_id,
        "coordinator_id": operation_plan.coordinator_id,
        "inventory_sha256": operation_plan.inventory_sha256,
        "backup_id": backup.backup_id,
        "backup_configuration_sha256": backup.configuration_sha256,
        "backup_artifact_sha256": backup.artifact_sha256,
    }
    return ZigbeeMqttRecoveryBinding(
        recovery_binding_id=f"hc65-recovery-{_content_sha256(payload)[:24]}",
        operation_plan_id=operation_plan.plan_id,
        coordinator_id=operation_plan.coordinator_id,
        inventory_sha256=operation_plan.inventory_sha256,
        backup_id=backup.backup_id,
        backup_configuration_sha256=backup.configuration_sha256,
        backup_artifact_sha256=backup.artifact_sha256,
    )
