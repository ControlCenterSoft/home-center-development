"""Infrastructure-neutral compute capacity planning primitives."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Capacity:
    cpu_millicores: int
    memory_mib: int
    storage_gib: int

    def __post_init__(self) -> None:
        if min(self.cpu_millicores, self.memory_mib, self.storage_gib) < 0:
            raise ValueError("capacity values must be non-negative")

    def subtract(self, other: "Capacity") -> "Capacity":
        return Capacity(
            cpu_millicores=self.cpu_millicores - other.cpu_millicores,
            memory_mib=self.memory_mib - other.memory_mib,
            storage_gib=self.storage_gib - other.storage_gib,
        )


@dataclass(frozen=True, slots=True)
class CapacityDecision:
    fits: bool
    remaining: Capacity | None
    limiting_resources: tuple[str, ...]


def evaluate_capacity(available: Capacity, requested: Capacity) -> CapacityDecision:
    limiting: list[str] = []
    if requested.cpu_millicores > available.cpu_millicores:
        limiting.append("cpu")
    if requested.memory_mib > available.memory_mib:
        limiting.append("memory")
    if requested.storage_gib > available.storage_gib:
        limiting.append("storage")

    if limiting:
        return CapacityDecision(False, None, tuple(limiting))

    return CapacityDecision(True, available.subtract(requested), ())
