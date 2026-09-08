"""Execution-state evaluation for Home Center automation runbooks."""

from __future__ import annotations

from dataclasses import dataclass


TERMINAL_SUCCESS = "succeeded"
TERMINAL_FAILURE = "failed"
WAITING = "pending"
RUNNING = "running"


@dataclass(frozen=True)
class StepState:
    step_id: str
    dependencies: tuple[str, ...] = ()
    status: str = WAITING


@dataclass(frozen=True)
class RunbookEvaluation:
    ready: tuple[str, ...]
    blocked: tuple[str, ...]
    complete: bool
    failed: bool


def evaluate_runbook(states: list[StepState]) -> RunbookEvaluation:
    """Determine runnable and blocked steps from current execution state."""

    by_id: dict[str, StepState] = {}
    for state in states:
        if not state.step_id.strip():
            raise ValueError("step_id is required")
        if state.step_id in by_id:
            raise ValueError(f"duplicate step_id: {state.step_id}")
        if state.status not in {WAITING, RUNNING, TERMINAL_SUCCESS, TERMINAL_FAILURE}:
            raise ValueError(f"unsupported status: {state.status}")
        by_id[state.step_id] = state

    for state in states:
        missing = [dep for dep in state.dependencies if dep not in by_id]
        if missing:
            raise ValueError(f"missing dependency for {state.step_id}: {missing[0]}")

    ready: list[str] = []
    blocked: list[str] = []
    for state in states:
        if state.status != WAITING:
            continue
        dependency_states = [by_id[dep].status for dep in state.dependencies]
        if any(status == TERMINAL_FAILURE for status in dependency_states):
            blocked.append(state.step_id)
        elif all(status == TERMINAL_SUCCESS for status in dependency_states):
            ready.append(state.step_id)

    ready.sort()
    blocked.sort()
    complete = all(state.status in {TERMINAL_SUCCESS, TERMINAL_FAILURE} for state in states)
    failed = any(state.status == TERMINAL_FAILURE for state in states)
    return RunbookEvaluation(tuple(ready), tuple(blocked), complete, failed)
