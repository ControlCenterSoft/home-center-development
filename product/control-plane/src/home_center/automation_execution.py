"""Fail-closed planning boundary for typed automation runbooks."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping

from .automation_runbook import RunbookStep, plan_runbook
from .util import canonical_json


RUNBOOK_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
STEP_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
NODE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{1,127}$")
CAPABILITY_ID = re.compile(r"^[a-z0-9][a-z0-9.-]+\.v[0-9]+$")
MAX_STEPS = 64
MAX_DEPENDENCIES = 16


class AutomationPlanningError(ValueError):
    """A stable public rejection code for an unsafe or malformed request."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ActionDefinition:
    action_id: str
    required_capability: str
    risk: str
    input_kind: str = "empty"


@dataclass(frozen=True, slots=True)
class _NormalizedStep:
    step_id: str
    action: ActionDefinition
    target_node_id: str
    depends_on: tuple[str, ...]
    action_input: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _TargetFacts:
    status: str
    capabilities: frozenset[str] | None


# This registry contains semantic operations, never process names, executable
# paths, shell fragments, or user-provided commands. Execution remains disabled
# at this planning boundary.
ACTION_REGISTRY: Mapping[str, ActionDefinition] = MappingProxyType(
    {
        definition.action_id: definition
        for definition in (
            ActionDefinition("inventory.refresh.v1", "inventory.v1", "read-only"),
            ActionDefinition("health.verify.v1", "health.v1", "read-only"),
            ActionDefinition("backup.verify.v1", "backup.sqlite.v1", "read-only"),
            ActionDefinition(
                "backup.create.v1",
                "backup.sqlite.v1",
                "bounded-change",
                "retention-class",
            ),
        )
    }
)


NodeSource = Callable[[], Iterable[Mapping[str, Any]]]


class AutomationPlanningService:
    """Plan every request against a fresh snapshot of trusted stored node facts."""

    def __init__(self, node_source: NodeSource) -> None:
        self._node_source = node_source

    def plan(self, request: object) -> dict[str, Any]:
        return plan_automation_runbook(request, nodes=self._node_source())


def action_catalog() -> dict[str, Any]:
    """Return the immutable public vocabulary accepted by the planner."""

    return {
        "schema": "home-center.automation-action-catalog.v1",
        "actions": [
            {
                "action_id": definition.action_id,
                "required_capability": definition.required_capability,
                "risk": definition.risk,
            }
            for definition in sorted(ACTION_REGISTRY.values(), key=lambda item: item.action_id)
        ],
        "arbitrary_commands_allowed": False,
    }


def _required_mapping(value: object, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AutomationPlanningError(code)
    return value


def _identifier(value: object, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AutomationPlanningError(code)
    return value


def _normalize_action_input(definition: ActionDefinition, value: object) -> Mapping[str, object]:
    action_input = _required_mapping(value, "invalid_action_input")
    if definition.input_kind == "empty":
        if action_input:
            raise AutomationPlanningError("invalid_action_input")
        return {}
    if definition.input_kind == "retention-class":
        if set(action_input) != {"retention_class"}:
            raise AutomationPlanningError("invalid_action_input")
        retention_class = action_input.get("retention_class")
        if retention_class not in {"default", "protected"}:
            raise AutomationPlanningError("invalid_action_input")
        return {"retention_class": retention_class}
    raise AutomationPlanningError("action_not_registered")


def _normalize_request(value: object) -> tuple[str, tuple[_NormalizedStep, ...]]:
    root = _required_mapping(value, "invalid_runbook_request")
    if set(root) != {"schema", "runbook_id", "steps"}:
        raise AutomationPlanningError("invalid_runbook_request")
    if root.get("schema") != "home-center.automation-runbook-plan-request.v1":
        raise AutomationPlanningError("unsupported_runbook_schema")
    runbook_id = _identifier(root.get("runbook_id"), RUNBOOK_ID, "invalid_runbook_id")
    raw_steps = root.get("steps")
    if not isinstance(raw_steps, list) or not 1 <= len(raw_steps) <= MAX_STEPS:
        raise AutomationPlanningError("invalid_runbook_steps")

    normalized: list[_NormalizedStep] = []
    seen_ids: set[str] = set()
    for raw_step in raw_steps:
        step = _required_mapping(raw_step, "invalid_runbook_step")
        if set(step) != {"step_id", "action_id", "target_node_id", "depends_on", "input"}:
            raise AutomationPlanningError("invalid_runbook_step")
        step_id = _identifier(step.get("step_id"), STEP_ID, "invalid_step_id")
        if step_id in seen_ids:
            raise AutomationPlanningError("duplicate_step_id")
        seen_ids.add(step_id)
        action_id = step.get("action_id")
        if not isinstance(action_id, str) or action_id not in ACTION_REGISTRY:
            raise AutomationPlanningError("action_not_registered")
        target_node_id = _identifier(
            step.get("target_node_id"), NODE_ID, "invalid_target_node_id"
        )
        raw_dependencies = step.get("depends_on")
        if not isinstance(raw_dependencies, list) or len(raw_dependencies) > MAX_DEPENDENCIES:
            raise AutomationPlanningError("invalid_step_dependencies")
        dependencies: list[str] = []
        for dependency in raw_dependencies:
            dependencies.append(_identifier(dependency, STEP_ID, "invalid_step_dependency"))
        if len(set(dependencies)) != len(dependencies):
            raise AutomationPlanningError("duplicate_step_dependency")
        definition = ACTION_REGISTRY[action_id]
        normalized.append(
            _NormalizedStep(
                step_id=step_id,
                action=definition,
                target_node_id=target_node_id,
                depends_on=tuple(sorted(dependencies)),
                action_input=_normalize_action_input(definition, step.get("input")),
            )
        )
    return runbook_id, tuple(normalized)


def _target_inventory(nodes: Iterable[Mapping[str, Any]]) -> dict[str, _TargetFacts]:
    result: dict[str, _TargetFacts] = {}
    count = 0
    for raw_node in nodes:
        count += 1
        if count > 64 or not isinstance(raw_node, Mapping):
            raise AutomationPlanningError("invalid_target_inventory")
        node_id = raw_node.get("node_id")
        if not isinstance(node_id, str) or NODE_ID.fullmatch(node_id) is None or node_id in result:
            raise AutomationPlanningError("invalid_target_inventory")
        status = raw_node.get("status")
        if not isinstance(status, str):
            raise AutomationPlanningError("invalid_target_inventory")
        envelope = raw_node.get("capabilities")
        capabilities: frozenset[str] | None = None
        if (
            isinstance(envelope, Mapping)
            and envelope.get("schema") == "home-center.node-capability.v1"
            and isinstance(envelope.get("capabilities"), list)
        ):
            raw_capabilities = envelope["capabilities"]
            if (
                len(raw_capabilities) <= 128
                and all(isinstance(item, str) and CAPABILITY_ID.fullmatch(item) for item in raw_capabilities)
                and len(set(raw_capabilities)) == len(raw_capabilities)
            ):
                capabilities = frozenset(raw_capabilities)
        result[node_id] = _TargetFacts(status=status, capabilities=capabilities)
    return result


def plan_automation_runbook(
    request: object,
    *,
    nodes: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Validate and deterministically plan a typed, dependency-aware runbook."""

    runbook_id, steps = _normalize_request(request)
    try:
        dependency_plan = plan_runbook(
            RunbookStep(step.step_id, step.action.action_id, step.depends_on) for step in steps
        )
    except ValueError as exc:
        message = str(exc)
        if "unknown step" in message:
            raise AutomationPlanningError("unknown_step_dependency") from exc
        if "cycle" in message:
            raise AutomationPlanningError("runbook_dependency_cycle") from exc
        raise AutomationPlanningError("invalid_runbook_dependencies") from exc

    targets = _target_inventory(nodes)
    by_id = {step.step_id: step for step in steps}
    planned_steps: list[dict[str, Any]] = []
    blockers: list[dict[str, str]] = []
    for sequence, dependency_step in enumerate(dependency_plan.ordered_steps, start=1):
        step = by_id[dependency_step.step_id]
        facts = targets.get(step.target_node_id)
        target_check = "pass"
        if facts is None:
            blocker_code = "target_not_found"
        elif facts.status != "ready":
            blocker_code = "target_not_ready"
        elif facts.capabilities is None:
            blocker_code = "target_capabilities_unknown"
        elif step.action.required_capability not in facts.capabilities:
            blocker_code = "target_capability_unavailable"
        else:
            blocker_code = None
        if blocker_code is not None:
            target_check = "fail"
            blockers.append(
                {
                    "code": blocker_code,
                    "step_id": step.step_id,
                    "target_node_id": step.target_node_id,
                    "required_capability": step.action.required_capability,
                }
            )
        planned_steps.append(
            {
                "sequence": sequence,
                "step_id": step.step_id,
                "action_id": step.action.action_id,
                "target_node_id": step.target_node_id,
                "depends_on": list(step.depends_on),
                "input": dict(step.action_input),
                "required_capability": step.action.required_capability,
                "risk": step.action.risk,
                "target_check": target_check,
            }
        )

    blockers.sort(
        key=lambda item: (
            item["step_id"],
            item["code"],
            item["target_node_id"],
            item["required_capability"],
        )
    )
    plan_material = {
        "runbook_id": runbook_id,
        "steps": planned_steps,
        "blockers": blockers,
    }
    return {
        "schema": "home-center.automation-runbook-plan.v1",
        "runbook_id": runbook_id,
        "state": "blocked" if blockers else "planned",
        "planning_ready": not blockers,
        "production_mutation_enabled": False,
        "execution_authorized": False,
        "arbitrary_commands_allowed": False,
        "plan_sha256": hashlib.sha256(canonical_json(plan_material).encode("utf-8")).hexdigest(),
        "blockers": blockers,
        "steps": planned_steps,
    }
