"""Safety preflight for draining a Home Center node."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DrainState:
    node_id: str
    healthy_voters: int
    required_voters: int
    hosts_critical_service: bool = False
    critical_service_movable: bool = True
    failover_target_ready: bool = True


@dataclass(frozen=True)
class DrainDecision:
    allowed: bool
    blockers: tuple[str, ...]


def evaluate_drain(state: DrainState) -> DrainDecision:
    """Return a deterministic drain decision for a node.

    The node being drained is assumed to be one of the currently healthy
    voters. A drain is rejected when it would break quorum or strand a
    critical service without a migration/failover path.
    """

    if not state.node_id.strip():
        raise ValueError("node_id is required")
    if state.healthy_voters < 0:
        raise ValueError("healthy_voters must be non-negative")
    if state.required_voters < 1:
        raise ValueError("required_voters must be at least one")

    blockers: list[str] = []
    remaining_voters = max(0, state.healthy_voters - 1)
    if remaining_voters < state.required_voters:
        blockers.append("quorum")

    if state.hosts_critical_service:
        if not state.critical_service_movable:
            blockers.append("critical-service-immovable")
        elif not state.failover_target_ready:
            blockers.append("failover-target-not-ready")

    return DrainDecision(allowed=not blockers, blockers=tuple(blockers))
