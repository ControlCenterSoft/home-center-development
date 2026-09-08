"""Closed runtime representations for the Home Center Core API v1 boundary."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Mapping


IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
ACTION = re.compile(r"^[a-z][a-z0-9.-]{1,95}\.v[1-9][0-9]*$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


class CoreContractError(ValueError):
    """A bounded public rejection code, never an internal exception string."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class CoreModule(StrEnum):
    NODE_MANAGER = "node-manager"
    UPGRADE_ENGINE = "upgrade-engine"
    CONFIGURATION_ENGINE = "configuration-engine"
    SERVICE_MANAGER = "service-manager"
    POLICY_ENGINE = "policy-engine"


class ResultState(StrEnum):
    PLANNED = "planned"
    BLOCKED = "blocked"
    REJECTED = "rejected"


def _bounded(value: object, *, minimum: int, maximum: int, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise CoreContractError("invalid_string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise CoreContractError("invalid_string")
    return value


def _operation_id(value: object) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise CoreContractError("invalid_operation_id") from exc


def _freeze_json(value: object, *, depth: int = 0) -> Any:
    if depth > 5:
        raise CoreContractError("input_too_deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**53) < value < 2**53:
            raise CoreContractError("input_integer_out_of_range")
        return value
    if isinstance(value, str):
        return _bounded(value, minimum=0, maximum=500)
    if isinstance(value, Mapping):
        if len(value) > 32:
            raise CoreContractError("input_too_many_properties")
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = _bounded(key, minimum=1, maximum=128, pattern=IDENTIFIER)
            frozen[normalized_key] = _freeze_json(item, depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        if len(value) > 64:
            raise CoreContractError("input_too_many_items")
        return tuple(_freeze_json(item, depth=depth + 1) for item in value)
    raise CoreContractError("input_value_rejected")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class CoreCommand:
    """Validated plan-only command envelope for the stable ``/api/v1`` surface."""

    operation_id: str
    idempotency_key: str
    correlation_id: str
    actor: str
    reason: str
    module: CoreModule
    action: str
    target_id: str
    input: Mapping[str, Any]
    mode: str = "plan"
    schema: str = field(default="home-center.core-command.v1", init=False)

    def __post_init__(self) -> None:
        canonical_operation_id = _operation_id(self.operation_id)
        if not isinstance(self.module, CoreModule):
            raise CoreContractError("unsupported_module")
        if self.mode != "plan":
            raise CoreContractError("execution_not_certified")
        object.__setattr__(self, "operation_id", canonical_operation_id)
        _bounded(self.idempotency_key, minimum=8, maximum=128, pattern=IDEMPOTENCY_KEY)
        _bounded(self.correlation_id, minimum=2, maximum=128, pattern=IDENTIFIER)
        _bounded(self.actor, minimum=3, maximum=128)
        _bounded(self.reason, minimum=3, maximum=500)
        _bounded(self.action, minimum=4, maximum=96, pattern=ACTION)
        _bounded(self.target_id, minimum=2, maximum=128, pattern=IDENTIFIER)
        if not isinstance(self.input, Mapping):
            raise CoreContractError("invalid_action_input")
        object.__setattr__(self, "input", _freeze_json(self.input))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CoreCommand":
        required = {
            "schema",
            "operation_id",
            "idempotency_key",
            "correlation_id",
            "actor",
            "reason",
            "module",
            "action",
            "target_id",
            "input",
            "mode",
        }
        if set(value) != required or value.get("schema") != "home-center.core-command.v1":
            raise CoreContractError("invalid_command_envelope")
        operation_id = _operation_id(value["operation_id"])
        try:
            module = CoreModule(value["module"])
        except (TypeError, ValueError) as exc:
            raise CoreContractError("unsupported_module") from exc
        if value.get("mode") != "plan":
            raise CoreContractError("execution_not_certified")
        return cls(
            operation_id=operation_id,
            idempotency_key=_bounded(value["idempotency_key"], minimum=8, maximum=128, pattern=IDEMPOTENCY_KEY),
            correlation_id=_bounded(value["correlation_id"], minimum=2, maximum=128, pattern=IDENTIFIER),
            actor=_bounded(value["actor"], minimum=3, maximum=128),
            reason=_bounded(value["reason"], minimum=3, maximum=500),
            module=module,
            action=_bounded(value["action"], minimum=4, maximum=96, pattern=ACTION),
            target_id=_bounded(value["target_id"], minimum=2, maximum=128, pattern=IDENTIFIER),
            input=value["input"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "operation_id": self.operation_id,
            "idempotency_key": self.idempotency_key,
            "correlation_id": self.correlation_id,
            "actor": self.actor,
            "reason": self.reason,
            "module": self.module.value,
            "action": self.action,
            "target_id": self.target_id,
            "input": _thaw_json(self.input),
            "mode": self.mode,
        }


@dataclass(frozen=True, slots=True)
class CoreResult:
    operation_id: str
    module: CoreModule
    target_id: str
    state: ResultState
    code: str
    idempotent_replay: bool = False
    schema: str = field(default="home-center.core-result.v1", init=False)

    def __post_init__(self) -> None:
        canonical_operation_id = _operation_id(self.operation_id)
        if not isinstance(self.module, CoreModule) or not isinstance(self.state, ResultState):
            raise CoreContractError("invalid_result_envelope")
        if not isinstance(self.idempotent_replay, bool):
            raise CoreContractError("invalid_result_envelope")
        object.__setattr__(self, "operation_id", canonical_operation_id)
        _bounded(self.target_id, minimum=2, maximum=128, pattern=IDENTIFIER)
        _bounded(self.code, minimum=2, maximum=128, pattern=IDENTIFIER)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "operation_id": self.operation_id,
            "module": self.module.value,
            "target_id": self.target_id,
            "state": self.state.value,
            "code": self.code,
            "idempotent_replay": self.idempotent_replay,
        }


@dataclass(frozen=True, slots=True)
class CoreError:
    code: str
    message: str
    correlation_id: str
    retryable: bool = False
    schema: str = field(default="home-center.error.v1", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.retryable, bool):
            raise CoreContractError("invalid_error_envelope")
        _bounded(self.code, minimum=2, maximum=128, pattern=IDENTIFIER)
        _bounded(self.message, minimum=1, maximum=500)
        _bounded(self.correlation_id, minimum=2, maximum=128, pattern=IDENTIFIER)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "code": self.code,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "retryable": self.retryable,
        }
