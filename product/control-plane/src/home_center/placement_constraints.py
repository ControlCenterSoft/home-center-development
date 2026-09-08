"""Placement constraints for Home Center compute workloads."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PlacementRequest:
    workload_id: str
    required_labels: tuple[str, ...] = ()
    forbidden_failure_domains: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlacementCandidate:
    node_id: str
    labels: tuple[str, ...] = ()
    failure_domain: str = "default"
    schedulable: bool = True
    free_cpu: int = 0
    free_memory_mb: int = 0


@dataclass(frozen=True)
class PlacementDecision:
    node_id: str
    score: tuple[int, int, str]


def rank_candidates(request: PlacementRequest, candidates: list[PlacementCandidate]) -> list[PlacementDecision]:
    """Filter and rank placement candidates deterministically."""

    if not request.workload_id.strip():
        raise ValueError("workload_id is required")

    required = set(request.required_labels)
    forbidden_domains = set(request.forbidden_failure_domains)
    decisions: list[PlacementDecision] = []

    for candidate in candidates:
        if not candidate.node_id.strip():
            raise ValueError("candidate node_id is required")
        if candidate.free_cpu < 0 or candidate.free_memory_mb < 0:
            raise ValueError("free resources must be non-negative")
        if not candidate.schedulable:
            continue
        if candidate.failure_domain in forbidden_domains:
            continue
        if not required.issubset(set(candidate.labels)):
            continue

        decisions.append(
            PlacementDecision(
                node_id=candidate.node_id,
                score=(-candidate.free_cpu, -candidate.free_memory_mb, candidate.node_id),
            )
        )

    decisions.sort(key=lambda decision: decision.score)
    return decisions
