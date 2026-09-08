"""Deterministic node health aggregation for Home Center."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class HealthSignal:
    source: str
    state: HealthState
    message: str = ""

    def __post_init__(self) -> None:
        if not self.source.strip():
            raise ValueError("health signal source must not be empty")


@dataclass(frozen=True, slots=True)
class NodeHealth:
    state: HealthState
    signals: tuple[HealthSignal, ...]

    @property
    def ready(self) -> bool:
        return self.state in {HealthState.HEALTHY, HealthState.DEGRADED}


_SEVERITY = {
    HealthState.HEALTHY: 0,
    HealthState.UNKNOWN: 1,
    HealthState.DEGRADED: 2,
    HealthState.UNHEALTHY: 3,
}


def aggregate_node_health(signals: Iterable[HealthSignal]) -> NodeHealth:
    """Aggregate component signals into a single node health state.

    Empty input is intentionally ``unknown``. Signals are sorted by source so
    callers receive a stable representation regardless of discovery order.
    """

    normalized = tuple(sorted(signals, key=lambda signal: signal.source))
    if not normalized:
        return NodeHealth(state=HealthState.UNKNOWN, signals=())

    state = max(normalized, key=lambda signal: _SEVERITY[signal.state]).state
    return NodeHealth(state=state, signals=normalized)
