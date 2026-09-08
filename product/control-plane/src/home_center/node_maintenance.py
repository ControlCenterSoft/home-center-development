"""Node maintenance planning primitives for Home Center 0.15."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MaintenanceDecision:
    node_id: str
    allowed: bool
    blockers: tuple[str, ...]


def plan_node_maintenance(
    node_id: str,
    *,
    healthy_peers: int,
    required_services: tuple[str, ...] = (),
    movable_services: tuple[str, ...] = (),
) -> MaintenanceDecision:
    """Return a deterministic drain decision for a node."""
    normalized = node_id.strip()
    if not normalized:
        raise ValueError("node_id must not be empty")
    if healthy_peers < 0:
        raise ValueError("healthy_peers must be non-negative")

    blockers: set[str] = set()
    if healthy_peers == 0:
        blockers.add("no-healthy-peer")

    movable = {value.strip() for value in movable_services if value.strip()}
    for service in required_services:
        name = service.strip()
        if name and name not in movable:
            blockers.add(f"service-not-movable:{name}")

    ordered = tuple(sorted(blockers))
    return MaintenanceDecision(node_id=normalized, allowed=not ordered, blockers=ordered)
