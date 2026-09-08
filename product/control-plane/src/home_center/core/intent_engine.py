"""Детерминированное планирование intents для Home Center 0.13 без побочных эффектов."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .policy_engine import AccessMode, PolicyEngine


PRODUCTION_EXECUTION_ENABLED = False

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
ACTION = re.compile(r"^[a-z][a-z0-9.-]{1,95}\.v[1-9][0-9]*$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?$")
FORBIDDEN_PARAMETER_KEYS = frozenset(
    {
        "credential",
        "credentials",
        "password",
        "private_key",
        "secret",
        "token",
    }
)


class IntentEngineError(ValueError):
    """Стабильный ограниченный код отказа для ошибок планирования intents."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class IntentKind(StrEnum):
    NODE_DRAIN = "node.drain"
    STORAGE_SHARE_CREATE = "storage.share.create"
    VIRTUALIZATION_WORKLOAD_CREATE = "virtualization.workload.create"
    MODULE_INSTALL = "module.install"


class IntentModule(StrEnum):
    NODE_MANAGER = "node-manager"
    STORAGE_MANAGER = "storage-manager"
    VIRTUALIZATION_MANAGER = "virtualization-manager"
    MODULE_MANAGER = "module-manager"
    BACKUP_MANAGER = "backup-manager"


class IntentPlanState(StrEnum):
    PLANNED = "planned"
    BLOCKED = "blocked"


def _bounded(
    value: object,
    *,
    minimum: int,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
    code: str = "invalid_string",
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise IntentEngineError(code)
    if pattern is not None and pattern.fullmatch(value) is None:
        raise IntentEngineError(code)
    return value


def _canonical_uuid(value: object) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise IntentEngineError("invalid_intent_id") from exc


def _freeze_parameters(value: object, *, depth: int = 0) -> Any:
    if depth > 4:
        raise IntentEngineError("parameters_too_deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**53) < value < 2**53:
            raise IntentEngineError("parameter_integer_out_of_range")
        return value
    if isinstance(value, str):
        return _bounded(value, minimum=0, maximum=500, code="parameter_string_out_of_range")
    if isinstance(value, Mapping):
        if len(value) > 32:
            raise IntentEngineError("too_many_parameters")
        frozen: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = _bounded(raw_key, minimum=1, maximum=128, pattern=IDENTIFIER, code="invalid_parameter_key")
            if key in FORBIDDEN_PARAMETER_KEYS:
                raise IntentEngineError("secret_parameter_rejected")
            frozen[key] = _freeze_parameters(item, depth=depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        if len(value) > 32:
            raise IntentEngineError("too_many_parameter_items")
        return tuple(_freeze_parameters(item, depth=depth + 1) for item in value)
    raise IntentEngineError("unsupported_parameter_value")


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _exact_parameters(parameters: Mapping[str, Any], required: set[str]) -> None:
    if set(parameters) != required:
        raise IntentEngineError("invalid_intent_parameters")


def _positive_int(value: object, *, minimum: int, maximum: int, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise IntentEngineError(code)
    return value


def _boolean(value: object, *, code: str) -> bool:
    if not isinstance(value, bool):
        raise IntentEngineError(code)
    return value


@dataclass(frozen=True, slots=True)
class IntentRequest:
    intent_id: str
    idempotency_key: str
    correlation_id: str
    actor: str
    reason: str
    kind: IntentKind
    target_id: str
    parameters: Mapping[str, Any]
    mode: str = "plan"
    schema: str = field(default="home-center.intent-request.v1", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, IntentKind):
            raise IntentEngineError("unsupported_intent_kind")
        if self.mode != "plan" or PRODUCTION_EXECUTION_ENABLED:
            raise IntentEngineError("execution_not_certified")
        object.__setattr__(self, "intent_id", _canonical_uuid(self.intent_id))
        _bounded(
            self.idempotency_key,
            minimum=8,
            maximum=128,
            pattern=IDEMPOTENCY_KEY,
            code="invalid_idempotency_key",
        )
        _bounded(self.correlation_id, minimum=2, maximum=128, pattern=IDENTIFIER, code="invalid_correlation_id")
        _bounded(self.actor, minimum=3, maximum=128, code="invalid_actor")
        _bounded(self.reason, minimum=3, maximum=500, code="invalid_reason")
        _bounded(self.target_id, minimum=2, maximum=128, pattern=IDENTIFIER, code="invalid_target_id")
        if not isinstance(self.parameters, Mapping):
            raise IntentEngineError("invalid_intent_parameters")
        object.__setattr__(self, "parameters", _freeze_parameters(self.parameters))

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "IntentRequest":
        required = {
            "schema",
            "intent_id",
            "idempotency_key",
            "correlation_id",
            "actor",
            "reason",
            "kind",
            "target_id",
            "parameters",
            "mode",
        }
        if set(value) != required or value.get("schema") != "home-center.intent-request.v1":
            raise IntentEngineError("invalid_intent_envelope")
        try:
            kind = IntentKind(value["kind"])
        except (TypeError, ValueError) as exc:
            raise IntentEngineError("unsupported_intent_kind") from exc
        return cls(
            intent_id=value["intent_id"],
            idempotency_key=value["idempotency_key"],
            correlation_id=value["correlation_id"],
            actor=value["actor"],
            reason=value["reason"],
            kind=kind,
            target_id=value["target_id"],
            parameters=value["parameters"],
            mode=value["mode"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "intent_id": self.intent_id,
            "idempotency_key": self.idempotency_key,
            "correlation_id": self.correlation_id,
            "actor": self.actor,
            "reason": self.reason,
            "kind": self.kind.value,
            "target_id": self.target_id,
            "parameters": _thaw(self.parameters),
            "mode": self.mode,
        }


@dataclass(frozen=True, slots=True)
class IntentStep:
    sequence: int
    module: IntentModule
    action: str
    target_id: str
    input: Mapping[str, Any]
    execution_requires_approval: bool
    schema: str = field(default="home-center.intent-step.v1", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or not 1 <= self.sequence <= 32:
            raise IntentEngineError("invalid_step_sequence")
        if not isinstance(self.module, IntentModule):
            raise IntentEngineError("invalid_step_module")
        _bounded(self.action, minimum=4, maximum=96, pattern=ACTION, code="invalid_step_action")
        _bounded(self.target_id, minimum=2, maximum=128, pattern=IDENTIFIER, code="invalid_step_target")
        if not isinstance(self.input, Mapping):
            raise IntentEngineError("invalid_step_input")
        if not isinstance(self.execution_requires_approval, bool):
            raise IntentEngineError("invalid_approval_flag")
        object.__setattr__(self, "input", _freeze_parameters(self.input))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "sequence": self.sequence,
            "module": self.module.value,
            "action": self.action,
            "target_id": self.target_id,
            "input": _thaw(self.input),
            "execution_requires_approval": self.execution_requires_approval,
        }


@dataclass(frozen=True, slots=True)
class IntentPlan:
    intent_id: str
    kind: IntentKind
    target_id: str
    state: IntentPlanState
    code: str
    steps: tuple[IntentStep, ...]
    blockers: tuple[str, ...] = ()
    production_execution_enabled: bool = False
    schema: str = field(default="home-center.intent-plan.v1", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "intent_id", _canonical_uuid(self.intent_id))
        if not isinstance(self.kind, IntentKind) or not isinstance(self.state, IntentPlanState):
            raise IntentEngineError("invalid_plan_envelope")
        _bounded(self.target_id, minimum=2, maximum=128, pattern=IDENTIFIER, code="invalid_target_id")
        _bounded(self.code, minimum=2, maximum=128, pattern=IDENTIFIER, code="invalid_plan_code")
        if self.production_execution_enabled:
            raise IntentEngineError("execution_not_certified")
        if len(self.steps) > 32 or len(self.blockers) > 16:
            raise IntentEngineError("plan_too_large")
        expected = tuple(range(1, len(self.steps) + 1))
        if tuple(step.sequence for step in self.steps) != expected:
            raise IntentEngineError("non_deterministic_step_sequence")
        for blocker in self.blockers:
            _bounded(blocker, minimum=2, maximum=128, pattern=IDENTIFIER, code="invalid_blocker")
        if self.state is IntentPlanState.PLANNED and self.blockers:
            raise IntentEngineError("planned_intent_has_blockers")
        if self.state is IntentPlanState.BLOCKED and self.steps:
            raise IntentEngineError("blocked_intent_has_steps")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "intent_id": self.intent_id,
            "kind": self.kind.value,
            "target_id": self.target_id,
            "state": self.state.value,
            "code": self.code,
            "steps": [step.to_dict() for step in self.steps],
            "blockers": list(self.blockers),
            "production_execution_enabled": self.production_execution_enabled,
        }


class IntentEngine:
    """Компилирует ограниченные инфраструктурные цели в детерминированные plan-only шаги."""

    def __init__(self, policy_engine: PolicyEngine) -> None:
        self._policy_engine = policy_engine

    def compile(self, request: IntentRequest, *, permissions: Iterable[str]) -> IntentPlan:
        decision = self._policy_engine.authorize(
            module="intent-engine",
            action=f"intent.{request.kind.value}.plan.v1",
            mode=AccessMode.PLAN,
            permissions=permissions,
        )
        if not decision.allowed:
            return self._blocked(request, decision.code)

        if request.kind is IntentKind.NODE_DRAIN:
            return self._plan_node_drain(request)
        if request.kind is IntentKind.STORAGE_SHARE_CREATE:
            return self._plan_storage_share(request)
        if request.kind is IntentKind.VIRTUALIZATION_WORKLOAD_CREATE:
            return self._plan_virtualization_workload(request)
        if request.kind is IntentKind.MODULE_INSTALL:
            return self._plan_module_install(request)
        raise IntentEngineError("unsupported_intent_kind")

    @staticmethod
    def _blocked(request: IntentRequest, *blockers: str) -> IntentPlan:
        return IntentPlan(
            intent_id=request.intent_id,
            kind=request.kind,
            target_id=request.target_id,
            state=IntentPlanState.BLOCKED,
            code="intent_blocked",
            steps=(),
            blockers=tuple(blockers),
        )

    def _plan_node_drain(self, request: IntentRequest) -> IntentPlan:
        parameters = request.parameters
        _exact_parameters(parameters, {"quorum_safe", "mandatory_services_safe"})
        quorum_safe = _boolean(parameters["quorum_safe"], code="invalid_quorum_safety")
        services_safe = _boolean(parameters["mandatory_services_safe"], code="invalid_service_safety")
        blockers: list[str] = []
        if not quorum_safe:
            blockers.append("quorum_not_safe")
        if not services_safe:
            blockers.append("mandatory_services_not_safe")
        if blockers:
            return self._blocked(request, *blockers)
        step = IntentStep(
            sequence=1,
            module=IntentModule.NODE_MANAGER,
            action="node.drain.plan.v1",
            target_id=request.target_id,
            input={
                "schema": "home-center.node-drain-plan-input.v1",
                "quorum_safe": quorum_safe,
                "mandatory_services_safe": services_safe,
            },
            execution_requires_approval=True,
        )
        return self._planned(request, (step,))

    def _plan_storage_share(self, request: IntentRequest) -> IntentPlan:
        parameters = request.parameters
        _exact_parameters(parameters, {"capacity_gib", "protocol", "high_availability", "backup_enabled"})
        capacity_gib = _positive_int(
            parameters["capacity_gib"], minimum=1, maximum=1_048_576, code="invalid_storage_capacity"
        )
        protocol = _bounded(parameters["protocol"], minimum=3, maximum=3, code="invalid_storage_protocol").lower()
        if protocol not in {"smb", "nfs"}:
            raise IntentEngineError("invalid_storage_protocol")
        high_availability = _boolean(parameters["high_availability"], code="invalid_high_availability")
        backup_enabled = _boolean(parameters["backup_enabled"], code="invalid_backup_flag")
        steps = [
            IntentStep(
                sequence=1,
                module=IntentModule.STORAGE_MANAGER,
                action="storage.capacity.check.plan.v1",
                target_id=request.target_id,
                input={"capacity_gib": capacity_gib, "high_availability": high_availability},
                execution_requires_approval=False,
            ),
            IntentStep(
                sequence=2,
                module=IntentModule.STORAGE_MANAGER,
                action="storage.share.create.plan.v1",
                target_id=request.target_id,
                input={
                    "capacity_gib": capacity_gib,
                    "protocol": protocol,
                    "high_availability": high_availability,
                },
                execution_requires_approval=True,
            ),
        ]
        if backup_enabled:
            steps.append(
                IntentStep(
                    sequence=3,
                    module=IntentModule.BACKUP_MANAGER,
                    action="backup.policy.attach.plan.v1",
                    target_id=request.target_id,
                    input={"policy": "default-daily"},
                    execution_requires_approval=False,
                )
            )
        return self._planned(request, tuple(steps))

    def _plan_virtualization_workload(self, request: IntentRequest) -> IntentPlan:
        parameters = request.parameters
        _exact_parameters(parameters, {"runtime", "vcpu", "memory_mib", "disk_gib", "high_availability"})
        runtime = _bounded(
            parameters["runtime"], minimum=2, maximum=3, code="invalid_virtualization_runtime"
        ).lower()
        if runtime not in {"vm", "lxc"}:
            raise IntentEngineError("invalid_virtualization_runtime")
        vcpu = _positive_int(parameters["vcpu"], minimum=1, maximum=256, code="invalid_vcpu")
        memory_mib = _positive_int(
            parameters["memory_mib"], minimum=256, maximum=4_194_304, code="invalid_memory"
        )
        disk_gib = _positive_int(parameters["disk_gib"], minimum=1, maximum=1_048_576, code="invalid_disk_size")
        high_availability = _boolean(parameters["high_availability"], code="invalid_high_availability")
        steps = (
            IntentStep(
                sequence=1,
                module=IntentModule.VIRTUALIZATION_MANAGER,
                action="virtualization.capacity.check.plan.v1",
                target_id=request.target_id,
                input={
                    "runtime": runtime,
                    "vcpu": vcpu,
                    "memory_mib": memory_mib,
                    "disk_gib": disk_gib,
                    "high_availability": high_availability,
                },
                execution_requires_approval=False,
            ),
            IntentStep(
                sequence=2,
                module=IntentModule.VIRTUALIZATION_MANAGER,
                action="virtualization.workload.create.plan.v1",
                target_id=request.target_id,
                input={
                    "runtime": runtime,
                    "vcpu": vcpu,
                    "memory_mib": memory_mib,
                    "disk_gib": disk_gib,
                    "high_availability": high_availability,
                },
                execution_requires_approval=True,
            ),
        )
        return self._planned(request, steps)

    def _plan_module_install(self, request: IntentRequest) -> IntentPlan:
        parameters = request.parameters
        _exact_parameters(parameters, {"module_id", "version", "permissions_acknowledged"})
        module_id = _bounded(
            parameters["module_id"], minimum=2, maximum=128, pattern=IDENTIFIER, code="invalid_module_id"
        )
        version = _bounded(
            parameters["version"], minimum=5, maximum=64, pattern=SEMVER, code="invalid_module_version"
        )
        acknowledged = _boolean(
            parameters["permissions_acknowledged"], code="invalid_permissions_acknowledgement"
        )
        if not acknowledged:
            return self._blocked(request, "module_permissions_not_acknowledged")
        step = IntentStep(
            sequence=1,
            module=IntentModule.MODULE_MANAGER,
            action="module.install.plan.v1",
            target_id=request.target_id,
            input={"module_id": module_id, "version": version, "permissions_acknowledged": True},
            execution_requires_approval=True,
        )
        return self._planned(request, (step,))

    @staticmethod
    def _planned(request: IntentRequest, steps: tuple[IntentStep, ...]) -> IntentPlan:
        return IntentPlan(
            intent_id=request.intent_id,
            kind=request.kind,
            target_id=request.target_id,
            state=IntentPlanState.PLANNED,
            code="intent_planned",
            steps=steps,
        )
