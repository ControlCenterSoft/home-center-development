"""Валидация по принципу fail-closed для неактивных в production манифестов модулей Home Center."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any


MAX_MANIFEST_BYTES = 64 * 1024
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
MODULE_ID = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,126}[a-z0-9])?$")
SYMBOLIC_ID = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$")
PERMISSION = re.compile(r"^[a-z][a-z0-9.-]*\.[a-z][a-z0-9.-]*$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class ModuleManifestError(ValueError):
    """Ограниченная ошибка валидации, которая никогда не включает недоверенные входные данные."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ModuleManifestIdentity:
    module_id: str
    version: str
    artifact_sha256: str
    artifact_size_bytes: int
    permissions: tuple[str, ...]
    actions: tuple[str, ...]


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ModuleManifestError("manifest_duplicate_key")
        value[key] = item
    return value


def _reject_float(_: str) -> None:
    raise ModuleManifestError("manifest_float_rejected")


def _reject_constant(_: str) -> None:
    raise ModuleManifestError("manifest_constant_rejected")


def load_manifest(payload: bytes) -> dict[str, Any]:
    """Декодирует ограниченный JSON-манифест, отклоняя повторяющиеся ключи объектов."""

    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_MANIFEST_BYTES:
        raise ModuleManifestError("manifest_size_rejected")
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ModuleManifestError("manifest_bom_rejected")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ModuleManifestError("manifest_encoding_rejected") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ModuleManifestError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ModuleManifestError("manifest_json_rejected") from exc
    if not isinstance(value, dict):
        raise ModuleManifestError("manifest_root_rejected")
    return value


def _object(value: Any, keys: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ModuleManifestError(code)
    return value


def _array(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list):
        raise ModuleManifestError(code)
    return value


def _string(value: Any, pattern: re.Pattern[str], code: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or pattern.fullmatch(value) is None:
        raise ModuleManifestError(code)
    return value


def _plain_string(value: Any, code: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ModuleManifestError(code)
    return value


def _integer(value: Any, code: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ModuleManifestError(code)
    return value


def _semver(value: Any, code: str) -> tuple[int, int, int]:
    text = _string(value, SEMVER, code, maximum=64)
    return tuple(int(part) for part in text.split("."))  # type: ignore[return-value]


def _unique_strings(value: Any, pattern: re.Pattern[str], code: str, *, maximum_items: int = 128) -> list[str]:
    items = _array(value, code)
    if len(items) > maximum_items:
        raise ModuleManifestError(code)
    result = [_string(item, pattern, code) for item in items]
    if len(result) != len(set(result)):
        raise ModuleManifestError(code)
    return result


def validate_manifest(value: dict[str, Any]) -> ModuleManifestIdentity:
    """Проверяет форму схемы и межполевую семантику без выполнения модуля."""

    root = _object(
        value,
        {
            "schema",
            "module",
            "compatibility",
            "dependencies",
            "conflicts",
            "capabilities",
            "permissions",
            "actions",
            "network",
            "storage",
            "health",
            "backup",
            "lifecycle",
            "artifact",
        },
        "manifest_fields_rejected",
    )
    if root["schema"] != "home-center.module-manifest.v2":
        raise ModuleManifestError("manifest_schema_rejected")

    module = _object(root["module"], {"id", "version", "name", "publisher"}, "module_identity_rejected")
    module_id = _string(module["id"], MODULE_ID, "module_id_rejected")
    version = _string(module["version"], SEMVER, "module_version_rejected", maximum=64)
    _plain_string(module["name"], "module_name_rejected")
    _string(module["publisher"], MODULE_ID, "module_publisher_rejected")

    compatibility = _object(
        root["compatibility"],
        {"home_center", "architectures", "operating_systems"},
        "compatibility_rejected",
    )
    home_center = _object(
        compatibility["home_center"], {"minimum", "maximum_exclusive"}, "home_center_compatibility_rejected"
    )
    minimum = _semver(home_center["minimum"], "home_center_minimum_rejected")
    maximum = _semver(home_center["maximum_exclusive"], "home_center_maximum_rejected")
    if minimum >= maximum:
        raise ModuleManifestError("home_center_compatibility_interval_rejected")
    architectures = _unique_strings(compatibility["architectures"], SYMBOLIC_ID, "architectures_rejected", maximum_items=8)
    operating_systems = _unique_strings(
        compatibility["operating_systems"], SYMBOLIC_ID, "operating_systems_rejected", maximum_items=8
    )
    if not architectures or not operating_systems:
        raise ModuleManifestError("compatibility_empty")

    dependencies = _array(root["dependencies"], "dependencies_rejected")
    if len(dependencies) > 128:
        raise ModuleManifestError("dependencies_rejected")
    dependency_ids: list[str] = []
    for item in dependencies:
        dependency = _object(
            item, {"id", "minimum_version", "maximum_version_exclusive", "optional"}, "dependency_rejected"
        )
        dependency_id = _string(dependency["id"], MODULE_ID, "dependency_id_rejected")
        if dependency_id == module_id:
            raise ModuleManifestError("dependency_self_rejected")
        dependency_minimum = _semver(dependency["minimum_version"], "dependency_minimum_rejected")
        dependency_maximum = _semver(
            dependency["maximum_version_exclusive"], "dependency_maximum_rejected"
        )
        if dependency_minimum >= dependency_maximum:
            raise ModuleManifestError("dependency_interval_rejected")
        if not isinstance(dependency["optional"], bool):
            raise ModuleManifestError("dependency_optional_rejected")
        dependency_ids.append(dependency_id)
    if len(dependency_ids) != len(set(dependency_ids)):
        raise ModuleManifestError("dependency_duplicate_rejected")

    conflicts = _unique_strings(root["conflicts"], MODULE_ID, "conflicts_rejected")
    if module_id in conflicts or set(conflicts).intersection(dependency_ids):
        raise ModuleManifestError("conflict_relationship_rejected")
    _unique_strings(root["capabilities"], SYMBOLIC_ID, "capabilities_rejected")
    permissions = _unique_strings(root["permissions"], PERMISSION, "permissions_rejected")

    actions = _array(root["actions"], "actions_rejected")
    if not 5 <= len(actions) <= 128:
        raise ModuleManifestError("actions_rejected")
    action_ids: list[str] = []
    action_risks: dict[str, str] = {}
    for item in actions:
        action = _object(
            item,
            {"id", "permission", "risk", "timeout_seconds", "idempotent"},
            "action_rejected",
        )
        action_id = _string(action["id"], SYMBOLIC_ID, "action_id_rejected")
        permission = _string(action["permission"], PERMISSION, "action_permission_rejected")
        if permission not in permissions:
            raise ModuleManifestError("action_permission_undeclared")
        if action["risk"] not in {"read-only", "mutation", "destructive"}:
            raise ModuleManifestError("action_risk_rejected")
        _integer(action["timeout_seconds"], "action_timeout_rejected", minimum=1, maximum=3600)
        if not isinstance(action["idempotent"], bool):
            raise ModuleManifestError("action_idempotency_rejected")
        if action["risk"] != "read-only" and action["idempotent"] is not True:
            raise ModuleManifestError("mutation_action_not_idempotent")
        action_ids.append(action_id)
        action_risks[action_id] = action["risk"]
    if len(action_ids) != len(set(action_ids)):
        raise ModuleManifestError("action_duplicate_rejected")

    network = _object(root["network"], {"inbound", "outbound"}, "network_rejected")
    endpoint_keys: set[tuple[str, int, str]] = set()
    for direction in ("inbound", "outbound"):
        endpoints = _array(network[direction], "network_endpoint_rejected")
        if len(endpoints) > 64:
            raise ModuleManifestError("network_endpoint_rejected")
        for item in endpoints:
            endpoint = _object(item, {"protocol", "port", "scope", "purpose"}, "network_endpoint_rejected")
            if endpoint["protocol"] not in {"tcp", "udp"} or endpoint["scope"] not in {
                "loopback",
                "node",
                "cluster",
            }:
                raise ModuleManifestError("network_endpoint_rejected")
            port = _integer(endpoint["port"], "network_port_rejected", minimum=1, maximum=65535)
            _plain_string(endpoint["purpose"], "network_purpose_rejected", maximum=128)
            key = (endpoint["protocol"], port, endpoint["scope"])
            if key in endpoint_keys:
                raise ModuleManifestError("network_endpoint_duplicate_rejected")
            endpoint_keys.add(key)

    storage = _array(root["storage"], "storage_rejected")
    if len(storage) > 128:
        raise ModuleManifestError("storage_rejected")
    storage_ids: list[str] = []
    persistent_ids: set[str] = set()
    for item in storage:
        resource = _object(item, {"id", "kind", "minimum_bytes", "backup_required"}, "storage_resource_rejected")
        resource_id = _string(resource["id"], SYMBOLIC_ID, "storage_id_rejected")
        if resource["kind"] not in {"persistent", "cache"} or not isinstance(resource["backup_required"], bool):
            raise ModuleManifestError("storage_resource_rejected")
        _integer(resource["minimum_bytes"], "storage_size_rejected", minimum=0, maximum=2**63 - 1)
        if resource["kind"] == "cache" and resource["backup_required"]:
            raise ModuleManifestError("cache_backup_rejected")
        if resource["kind"] == "persistent" and resource["backup_required"]:
            persistent_ids.add(resource_id)
        storage_ids.append(resource_id)
    if len(storage_ids) != len(set(storage_ids)):
        raise ModuleManifestError("storage_duplicate_rejected")

    health = _array(root["health"], "health_rejected")
    if not 1 <= len(health) <= 64:
        raise ModuleManifestError("health_rejected")
    health_ids: list[str] = []
    for item in health:
        probe = _object(item, {"id", "kind", "interval_seconds", "timeout_seconds"}, "health_probe_rejected")
        probe_id = _string(probe["id"], SYMBOLIC_ID, "health_id_rejected")
        if probe["kind"] not in {"readiness", "liveness"}:
            raise ModuleManifestError("health_kind_rejected")
        interval = _integer(probe["interval_seconds"], "health_interval_rejected", minimum=5, maximum=3600)
        timeout = _integer(probe["timeout_seconds"], "health_timeout_rejected", minimum=1, maximum=300)
        if timeout >= interval:
            raise ModuleManifestError("health_budget_rejected")
        health_ids.append(probe_id)
    if len(health_ids) != len(set(health_ids)):
        raise ModuleManifestError("health_duplicate_rejected")

    backup = _object(root["backup"], {"mode", "data_ids", "restore_required"}, "backup_rejected")
    if backup["mode"] not in {"required", "not-required"} or not isinstance(backup["restore_required"], bool):
        raise ModuleManifestError("backup_rejected")
    backup_ids = _unique_strings(backup["data_ids"], SYMBOLIC_ID, "backup_data_rejected")
    if not set(backup_ids).issubset(storage_ids):
        raise ModuleManifestError("backup_data_unknown")
    if backup["mode"] == "required":
        if set(backup_ids) != persistent_ids or backup["restore_required"] is not True:
            raise ModuleManifestError("backup_coverage_rejected")
    elif backup_ids or backup["restore_required"] or persistent_ids:
        raise ModuleManifestError("backup_not_required_rejected")

    lifecycle = _object(root["lifecycle"], {"install", "upgrade", "remove"}, "lifecycle_rejected")
    for phase in ("install", "upgrade"):
        step = _object(lifecycle[phase], {"action", "rollback_action"}, "lifecycle_step_rejected")
        if step["action"] not in action_ids or step["rollback_action"] not in action_ids:
            raise ModuleManifestError("lifecycle_action_unknown")
        if step["action"] == step["rollback_action"]:
            raise ModuleManifestError("lifecycle_rollback_rejected")
        if action_risks[step["action"]] != "mutation" or action_risks[step["rollback_action"]] != "mutation":
            raise ModuleManifestError("lifecycle_action_risk_rejected")
    remove = _object(lifecycle["remove"], {"action", "data_policy"}, "lifecycle_remove_rejected")
    if remove["action"] not in action_ids or remove["data_policy"] != "preserve":
        raise ModuleManifestError("lifecycle_remove_rejected")
    if action_risks[remove["action"]] != "mutation":
        raise ModuleManifestError("lifecycle_action_risk_rejected")

    artifact = _object(
        root["artifact"], {"sha256", "size_bytes", "media_type", "provenance"}, "artifact_rejected"
    )
    artifact_sha256 = _string(artifact["sha256"], DIGEST, "artifact_digest_rejected")
    artifact_size = _integer(artifact["size_bytes"], "artifact_size_rejected", minimum=1, maximum=2**63 - 1)
    if artifact["media_type"] != "application/vnd.home-center.module.v1+tar+gzip":
        raise ModuleManifestError("artifact_media_type_rejected")
    provenance = _object(
        artifact["provenance"], {"statement_sha256", "signer_key_ids", "threshold"}, "provenance_rejected"
    )
    _string(provenance["statement_sha256"], DIGEST, "provenance_digest_rejected")
    signer_ids = _unique_strings(provenance["signer_key_ids"], KEY_ID, "provenance_signers_rejected", maximum_items=16)
    threshold = _integer(provenance["threshold"], "provenance_threshold_rejected", minimum=1, maximum=16)
    if threshold > len(signer_ids):
        raise ModuleManifestError("provenance_threshold_rejected")

    return ModuleManifestIdentity(
        module_id=module_id,
        version=version,
        artifact_sha256=artifact_sha256,
        artifact_size_bytes=artifact_size,
        permissions=tuple(permissions),
        actions=tuple(action_ids),
    )


def load_and_validate_manifest(payload: bytes) -> ModuleManifestIdentity:
    return validate_manifest(load_manifest(payload))
