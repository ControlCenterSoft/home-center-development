"""Deterministic, plan-only automation boundary for device capabilities."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
MAX_ACTIONS = 64
MAX_CAPABILITIES = 128
MAX_PARAMETERS = 32
MAX_PARAMETER_BYTES = 16 * 1024
MAX_TARGETS = 4096
FORBIDDEN_PARAMETER_NAMES = {
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


class AutomationError(ValueError):
    """Stable public rejection for malformed or unsafe automation input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TriggerKind(StrEnum):
    DEVICE_EVENT = "device-event"
    SCHEDULE = "schedule"
    STATE_CHANGE = "state-change"
    MANUAL = "manual"


def _identifier(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AutomationError(code)
    return value


def _validate_parameter_tree(value: object) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    item_count = 0
    while pending:
        current, depth = pending.pop()
        if depth > 8:
            raise AutomationError("invalid_parameters")
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen_containers:
                raise AutomationError("invalid_parameters")
            seen_containers.add(identity)
            for key, item in current.items():
                item_count += 1
                if item_count > 1024:
                    raise AutomationError("invalid_parameters")
                if (
                    isinstance(key, str)
                    and key.lower() in FORBIDDEN_PARAMETER_NAMES
                ):
                    raise AutomationError("secret_parameter_rejected")
                pending.append((item, depth + 1))
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen_containers:
                raise AutomationError("invalid_parameters")
            seen_containers.add(identity)
            item_count += len(current)
            if item_count > 1024:
                raise AutomationError("invalid_parameters")
            pending.extend((item, depth + 1) for item in current)


def _parameters(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or len(value) > MAX_PARAMETERS:
        raise AutomationError("invalid_parameters")
    if any(not isinstance(key, str) or ID.fullmatch(key) is None for key in value):
        raise AutomationError("invalid_parameter_name")
    _validate_parameter_tree(value)
    try:
        encoded = json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(encoded.encode("utf-8")) > MAX_PARAMETER_BYTES:
            raise AutomationError("parameters_too_large")
        normalized = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, AutomationError):
            raise
        raise AutomationError("invalid_parameters") from exc
    return MappingProxyType(normalized)


def _capability_set(value: object, code: str) -> frozenset[str]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) > MAX_CAPABILITIES
        or any(
            not isinstance(item, str) or CAPABILITY.fullmatch(item) is None
            for item in value
        )
        or len(value) != len(set(value))
    ):
        raise AutomationError(code)
    return frozenset(value)


@dataclass(frozen=True, slots=True)
class Trigger:
    kind: TriggerKind
    source_id: str
    event: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, TriggerKind):
            raise AutomationError("invalid_trigger_kind")
        _identifier(self.source_id, ID, "invalid_trigger")
        _identifier(self.event, ID, "invalid_trigger")


@dataclass(frozen=True, slots=True)
class PlannedAction:
    target_id: str
    capability: str
    command: str
    parameters: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _identifier(self.target_id, ID, "invalid_action")
        _identifier(self.capability, CAPABILITY, "invalid_action")
        _identifier(self.command, ID, "invalid_action")
        object.__setattr__(self, "parameters", _parameters(self.parameters))


@dataclass(frozen=True, slots=True)
class AutomationRule:
    rule_id: str
    enabled: bool
    trigger: Trigger
    actions: tuple[PlannedAction, ...]
    required_permissions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.rule_id, ID, "invalid_rule")
        if not isinstance(self.enabled, bool) or not isinstance(self.trigger, Trigger):
            raise AutomationError("invalid_rule")
        if (
            not isinstance(self.actions, tuple)
            or not 1 <= len(self.actions) <= MAX_ACTIONS
            or any(not isinstance(action, PlannedAction) for action in self.actions)
        ):
            raise AutomationError("invalid_rule")
        if (
            not isinstance(self.required_permissions, tuple)
            or len(self.required_permissions) > MAX_CAPABILITIES
            or any(
                not isinstance(permission, str) or ID.fullmatch(permission) is None
                for permission in self.required_permissions
            )
            or len(self.required_permissions) != len(set(self.required_permissions))
        ):
            raise AutomationError("invalid_permission")
        object.__setattr__(
            self,
            "required_permissions",
            tuple(sorted(self.required_permissions)),
        )


@dataclass(frozen=True, slots=True)
class AutomationPlan:
    rule_id: str
    state: str
    steps: tuple[dict[str, object], ...]
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = field(default=False, init=False)
    execution_authorized: bool = field(default=False, init=False)
    schema: str = field(default="home-center.automation-plan.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "rule_id": self.rule_id,
            "state": self.state,
            "steps": [dict(step) for step in self.steps],
            "blockers": list(self.blockers),
            "production_mutation_enabled": False,
            "execution_authorized": False,
        }


class AutomationPlanner:
    """Validate trusted facts and return a plan that cannot execute actions."""

    def plan(
        self,
        rule: AutomationRule,
        *,
        trigger: Trigger,
        permissions: tuple[str, ...],
        available_capabilities: Mapping[str, tuple[str, ...]],
    ) -> AutomationPlan:
        if not isinstance(rule, AutomationRule) or not isinstance(trigger, Trigger):
            raise AutomationError("invalid_planning_input")
        if (
            not isinstance(permissions, tuple)
            or len(permissions) > MAX_CAPABILITIES
            or any(
                not isinstance(permission, str) or ID.fullmatch(permission) is None
                for permission in permissions
            )
            or len(permissions) != len(set(permissions))
        ):
            raise AutomationError("invalid_permissions")
        if not isinstance(available_capabilities, Mapping) or len(available_capabilities) > MAX_TARGETS:
            raise AutomationError("invalid_capability_inventory")

        normalized_capabilities: dict[str, frozenset[str]] = {}
        for target_id, capabilities in available_capabilities.items():
            normalized_id = _identifier(
                target_id, ID, "invalid_capability_inventory"
            )
            normalized_capabilities[normalized_id] = _capability_set(
                capabilities, "invalid_capability_inventory"
            )

        blockers: list[str] = []
        if not rule.enabled:
            blockers.append("rule_disabled")
        if trigger != rule.trigger:
            blockers.append("trigger_not_matched")
        if not set(rule.required_permissions).issubset(permissions):
            blockers.append("permission_denied")

        steps: list[dict[str, object]] = []
        for sequence, action in enumerate(rule.actions, start=1):
            capabilities = normalized_capabilities.get(action.target_id, frozenset())
            if action.capability not in capabilities:
                blockers.append(f"capability_unavailable:{action.target_id}")
            steps.append(
                {
                    "sequence": sequence,
                    "target_id": action.target_id,
                    "capability": action.capability,
                    "command": action.command,
                    "parameters": dict(action.parameters),
                    "requires_execution_authority": True,
                }
            )

        return AutomationPlan(
            rule.rule_id,
            "blocked" if blockers else "planned",
            tuple(steps) if not blockers else (),
            tuple(blockers),
        )
