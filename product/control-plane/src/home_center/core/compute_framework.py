"""Side-effect-free compute provider planning for Home Center."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import islice
from typing import Iterable

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
BLOCKER = re.compile(r"^[a-z0-9_:-]+$")
MAX_CAPABILITIES = 128

class ComputeFrameworkError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

class ComputeProviderKind(StrEnum):
    PHYSICAL = "physical"
    PROXMOX = "proxmox"

class ComputeResourceKind(StrEnum):
    PHYSICAL = "physical"
    VM = "vm"
    LXC = "lxc"

class ComputePlanState(StrEnum):
    PLANNED = "planned"
    BLOCKED = "blocked"


def _normalize_capabilities(capabilities: Iterable[str]) -> tuple[str, ...]:
    if isinstance(capabilities, (str, bytes)):
        raise ComputeFrameworkError("invalid_provider_capability")
    try:
        values = tuple(islice(iter(capabilities), MAX_CAPABILITIES + 1))
    except (TypeError, ValueError) as exc:
        raise ComputeFrameworkError("invalid_provider_capability") from exc
    if len(values) > MAX_CAPABILITIES or any(
        not isinstance(item, str) or CAPABILITY.fullmatch(item) is None for item in values
    ):
        raise ComputeFrameworkError("invalid_provider_capability")
    return tuple(sorted(set(values)))

@dataclass(frozen=True, slots=True)
class ComputeProviderDescriptor:
    provider_id: str
    kind: ComputeProviderKind
    healthy: bool
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or IDENTIFIER.fullmatch(self.provider_id) is None:
            raise ComputeFrameworkError("invalid_provider_id")
        if not isinstance(self.kind, ComputeProviderKind) or type(self.healthy) is not bool:
            raise ComputeFrameworkError("invalid_provider")
        object.__setattr__(self, "capabilities", _normalize_capabilities(self.capabilities))

    @classmethod
    def create(cls, *, provider_id: str, kind: ComputeProviderKind, healthy: bool, capabilities: Iterable[str]) -> "ComputeProviderDescriptor":
        return cls(
            provider_id=provider_id,
            kind=kind,
            healthy=healthy,
            capabilities=_normalize_capabilities(capabilities),
        )

@dataclass(frozen=True, slots=True)
class ComputeResourceRequest:
    resource_id: str
    kind: ComputeResourceKind
    vcpu: int
    memory_mib: int
    disk_gib: int
    high_availability: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.resource_id, str)
            or IDENTIFIER.fullmatch(self.resource_id) is None
            or not isinstance(self.kind, ComputeResourceKind)
        ):
            raise ComputeFrameworkError("invalid_compute_request")
        if not isinstance(self.vcpu, int) or isinstance(self.vcpu, bool) or not 1 <= self.vcpu <= 256:
            raise ComputeFrameworkError("invalid_vcpu")
        if not isinstance(self.memory_mib, int) or isinstance(self.memory_mib, bool) or not 256 <= self.memory_mib <= 4_194_304:
            raise ComputeFrameworkError("invalid_memory")
        if not isinstance(self.disk_gib, int) or isinstance(self.disk_gib, bool) or not 1 <= self.disk_gib <= 1_048_576:
            raise ComputeFrameworkError("invalid_disk_size")
        if not isinstance(self.high_availability, bool):
            raise ComputeFrameworkError("invalid_high_availability")

    def to_dict(self) -> dict[str, object]:
        return {"resource_id": self.resource_id, "kind": self.kind.value, "vcpu": self.vcpu, "memory_mib": self.memory_mib, "disk_gib": self.disk_gib, "high_availability": self.high_availability}

@dataclass(frozen=True, slots=True)
class ComputePlan:
    provider_id: str
    request: ComputeResourceRequest
    state: ComputePlanState
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.compute-plan.v1", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or IDENTIFIER.fullmatch(self.provider_id) is None:
            raise ComputeFrameworkError("invalid_provider_id")
        if not isinstance(self.request, ComputeResourceRequest):
            raise ComputeFrameworkError("invalid_compute_request")
        if not isinstance(self.state, ComputePlanState):
            raise ComputeFrameworkError("invalid_compute_plan_state")
        if (
            not isinstance(self.blockers, tuple)
            or len(self.blockers) > 16
            or len(self.blockers) != len(set(self.blockers))
            or any(
                not isinstance(item, str) or BLOCKER.fullmatch(item) is None
                for item in self.blockers
            )
        ):
            raise ComputeFrameworkError("invalid_compute_plan_blockers")
        if (
            self.state is ComputePlanState.PLANNED and self.blockers
        ) or (
            self.state is ComputePlanState.BLOCKED and not self.blockers
        ):
            raise ComputeFrameworkError("inconsistent_compute_plan")
        if self.production_mutation_enabled is not False:
            raise ComputeFrameworkError("production_mutation_forbidden")

    def to_dict(self) -> dict[str, object]:
        return {"schema": self.schema, "provider_id": self.provider_id, "request": self.request.to_dict(), "state": self.state.value, "blockers": list(self.blockers), "production_mutation_enabled": self.production_mutation_enabled}

class ComputePlanner:
    _RUNTIME_CAPABILITY = {
        ComputeResourceKind.VM: "compute.vm.v1",
        ComputeResourceKind.LXC: "compute.lxc.v1",
        ComputeResourceKind.PHYSICAL: "compute.physical.v1",
    }

    def plan_create(self, provider: ComputeProviderDescriptor, request: ComputeResourceRequest, *, available_cpu: int, available_memory_mib: int, available_storage_gib: int) -> ComputePlan:
        if not isinstance(provider, ComputeProviderDescriptor):
            raise ComputeFrameworkError("invalid_provider")
        if not isinstance(request, ComputeResourceRequest):
            raise ComputeFrameworkError("invalid_compute_request")
        for value, code in ((available_cpu, "invalid_available_cpu"), (available_memory_mib, "invalid_available_memory"), (available_storage_gib, "invalid_available_storage")):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ComputeFrameworkError(code)
        blockers: list[str] = []
        if not provider.healthy:
            blockers.append("provider_not_healthy")
        required = self._RUNTIME_CAPABILITY[request.kind]
        if required not in provider.capabilities:
            blockers.append("provider_runtime_unsupported")
        if request.high_availability and "compute.ha.v1" not in provider.capabilities:
            blockers.append("provider_ha_unsupported")
        if available_cpu < request.vcpu:
            blockers.append("insufficient_cpu_capacity")
        if available_memory_mib < request.memory_mib:
            blockers.append("insufficient_memory_capacity")
        if available_storage_gib < request.disk_gib:
            blockers.append("insufficient_storage_capacity")
        return ComputePlan(provider_id=provider.provider_id, request=request, state=ComputePlanState.BLOCKED if blockers else ComputePlanState.PLANNED, blockers=tuple(blockers))
