"""Deterministic runbook planning for Home Center automation."""

from __future__ import annotations

from dataclasses import dataclass
from heapq import heappop, heappush
from typing import Iterable


@dataclass(frozen=True, slots=True)
class RunbookStep:
    step_id: str
    action: str
    depends_on: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.step_id.strip():
            raise ValueError("step_id must not be empty")
        if not self.action.strip():
            raise ValueError("action must not be empty")


@dataclass(frozen=True, slots=True)
class RunbookPlan:
    ordered_steps: tuple[RunbookStep, ...]


def plan_runbook(steps: Iterable[RunbookStep]) -> RunbookPlan:
    by_id: dict[str, RunbookStep] = {}
    for step in steps:
        if step.step_id in by_id:
            raise ValueError(f"duplicate step_id: {step.step_id}")
        by_id[step.step_id] = step

    indegree = {step_id: 0 for step_id in by_id}
    dependents: dict[str, list[str]] = {step_id: [] for step_id in by_id}

    for step in by_id.values():
        for dependency in step.depends_on:
            if dependency not in by_id:
                raise ValueError(
                    f"step {step.step_id} depends on unknown step {dependency}"
                )
            indegree[step.step_id] += 1
            dependents[dependency].append(step.step_id)

    ready: list[str] = []
    for step_id, count in indegree.items():
        if count == 0:
            heappush(ready, step_id)

    ordered: list[RunbookStep] = []
    while ready:
        step_id = heappop(ready)
        ordered.append(by_id[step_id])
        for dependent in sorted(dependents[step_id]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heappush(ready, dependent)

    if len(ordered) != len(by_id):
        raise ValueError("runbook dependency cycle detected")

    return RunbookPlan(tuple(ordered))
