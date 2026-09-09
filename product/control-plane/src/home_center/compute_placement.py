"""Infrastructure-neutral compute placement for Home Center 0.16."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ComputeNode:
    node_id: str
    free_cpu: int
    free_memory_mb: int
    free_disk_gb: int


@dataclass(frozen=True, slots=True)
class PlacementCandidate:
    node_id: str
    score: int


def rank_placement_candidates(
    nodes: tuple[ComputeNode, ...],
    *,
    cpu: int,
    memory_mb: int,
    disk_gb: int,
) -> tuple[PlacementCandidate, ...]:
    if min(cpu, memory_mb, disk_gb) < 0:
        raise ValueError("resource requirements must be non-negative")

    candidates: list[PlacementCandidate] = []
    for node in nodes:
        if not node.node_id.strip():
            raise ValueError("node_id must not be empty")
        if node.free_cpu < cpu or node.free_memory_mb < memory_mb or node.free_disk_gb < disk_gb:
            continue
        score = (
            (node.free_cpu - cpu) * 1_000_000
            + (node.free_memory_mb - memory_mb) * 1_000
            + (node.free_disk_gb - disk_gb)
        )
        candidates.append(PlacementCandidate(node_id=node.node_id.strip(), score=score))

    return tuple(sorted(candidates, key=lambda item: (-item.score, item.node_id)))
