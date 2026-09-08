"""Typed, closed inputs for the five admitted 0.10 Core planning actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .configuration_engine import CONFIG_KEY
from .contracts import ACTION, IDENTIFIER, CoreCommand, CoreContractError, CoreModule
from .policy_engine import AccessMode
from .service_manager import SERVICE_ID
from .upgrade_engine import ReleaseIdentity


@dataclass(frozen=True, slots=True)
class NodeDrainPlanInput:
    quorum_safe: bool
    mandatory_services_safe: bool


@dataclass(frozen=True, slots=True)
class UpgradeReleasePlanInput:
    current: ReleaseIdentity
    target: ReleaseIdentity


@dataclass(frozen=True, slots=True)
class ConfigurationChangePlanInput:
    key: str


@dataclass(frozen=True, slots=True)
class ServiceStartPlanInput:
    service_id: str


@dataclass(frozen=True, slots=True)
class PolicyAuthorizePlanInput:
    requested_module: CoreModule
    requested_action: str
    requested_mode: AccessMode
    permissions: tuple[str, ...]


ActionInput = (
    NodeDrainPlanInput
    | UpgradeReleasePlanInput
    | ConfigurationChangePlanInput
    | ServiceStartPlanInput
    | PolicyAuthorizePlanInput
)


def _closed(value: Mapping[str, Any], *, schema: str, fields: set[str]) -> None:
    if set(value) != fields | {"schema"} or value.get("schema") != schema:
        raise CoreContractError("invalid_action_input")


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise CoreContractError("invalid_action_input")
    return value


def _identity(value: object) -> ReleaseIdentity:
    if not isinstance(value, Mapping) or set(value) != {"version", "revision", "artifact_sha256"}:
        raise CoreContractError("invalid_release_identity")
    if any(not isinstance(value[key], str) for key in value):
        raise CoreContractError("invalid_release_identity")
    identity = ReleaseIdentity(
        version=value["version"],
        revision=value["revision"],
        artifact_sha256=value["artifact_sha256"],
    )
    try:
        identity.validate()
    except ValueError as exc:
        raise CoreContractError("invalid_release_identity") from exc
    return identity


def parse_action_input(command: CoreCommand) -> ActionInput:
    value = command.input
    key = (command.module, command.action)
    if key == (CoreModule.NODE_MANAGER, "node.drain.plan.v1"):
        _closed(
            value,
            schema="home-center.node-drain-plan-input.v1",
            fields={"quorum_safe", "mandatory_services_safe"},
        )
        return NodeDrainPlanInput(
            quorum_safe=_boolean(value["quorum_safe"]),
            mandatory_services_safe=_boolean(value["mandatory_services_safe"]),
        )
    if key == (CoreModule.UPGRADE_ENGINE, "upgrade.release.plan.v1"):
        _closed(
            value,
            schema="home-center.upgrade-release-plan-input.v1",
            fields={"current", "target"},
        )
        return UpgradeReleasePlanInput(
            current=_identity(value["current"]),
            target=_identity(value["target"]),
        )
    if key == (CoreModule.CONFIGURATION_ENGINE, "configuration.change.plan.v1"):
        _closed(
            value,
            schema="home-center.configuration-change-plan-input.v1",
            fields={"key"},
        )
        config_key = value["key"]
        if not isinstance(config_key, str) or CONFIG_KEY.fullmatch(config_key) is None:
            raise CoreContractError("invalid_configuration_key")
        return ConfigurationChangePlanInput(config_key)
    if key == (CoreModule.SERVICE_MANAGER, "service.start.plan.v1"):
        _closed(
            value,
            schema="home-center.service-start-plan-input.v1",
            fields={"service_id"},
        )
        service_id = value["service_id"]
        if not isinstance(service_id, str) or SERVICE_ID.fullmatch(service_id) is None:
            raise CoreContractError("invalid_service_id")
        return ServiceStartPlanInput(service_id)
    if key == (CoreModule.POLICY_ENGINE, "policy.authorize.plan.v1"):
        _closed(
            value,
            schema="home-center.policy-authorize-plan-input.v1",
            fields={"requested_module", "requested_action", "requested_mode", "permissions"},
        )
        try:
            requested_module = CoreModule(value["requested_module"])
            requested_mode = AccessMode(value["requested_mode"])
        except (TypeError, ValueError) as exc:
            raise CoreContractError("invalid_policy_query") from exc
        requested_action = value["requested_action"]
        permissions = value["permissions"]
        if not isinstance(requested_action, str) or ACTION.fullmatch(requested_action) is None:
            raise CoreContractError("invalid_policy_query")
        if not isinstance(permissions, tuple) or not 1 <= len(permissions) <= 32:
            raise CoreContractError("invalid_policy_query")
        if any(not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None for item in permissions):
            raise CoreContractError("invalid_policy_query")
        return PolicyAuthorizePlanInput(
            requested_module=requested_module,
            requested_action=requested_action,
            requested_mode=requested_mode,
            permissions=tuple(sorted(set(permissions))),
        )
    raise CoreContractError("unsupported_action")
