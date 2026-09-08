"""Typed, side-effect-free compute provider and capacity planning.

The planner consumes provider profiles and observed capacity. It deliberately
does not know provider endpoints, credentials, cluster names, or hypervisor
APIs. A provider adapter translates its inventory into these public types and
executes an independently authorized plan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Iterable, Mapping


IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
CAPABILITY = re.compile(r"^[a-z][a-z0-9.-]{1,126}\.v[1-9][0-9]*$")
MAX_PROVIDERS = 64


class ComputeFrameworkError(ValueError):
    """A stable rejection code suitable for an API response."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ComputeProviderKind(StrEnum):
    """Legacy adapter classification.

    New API consumers use ``profile_id`` and capabilities. The older values
    remain available so the 0.14 Home Lab plan boundary stays compatible.
    """

    PHYSICAL = "physical"
    PROXMOX = "proxmox"
    PROFILE = "profile"


class ComputeResourceKind(StrEnum):
    PHYSICAL = "physical"
    VM = "vm"
    CONTAINER = "container"
    LXC = "lxc"


class ComputePlanState(StrEnum):
    PLANNED = "planned"
    BLOCKED = "blocked"


def _closed_mapping(value: object, required: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != required:
        raise ComputeFrameworkError(code)
    return value


def _bounded_integer(
    value: object,
    *,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ComputeFrameworkError(code)
    return value


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ComputeFrameworkError(code)
    return value


def _normalize_capabilities(capabilities: Iterable[str]) -> tuple[str, ...]:
    if isinstance(capabilities, (str, bytes)):
        raise ComputeFrameworkError("invalid_provider_capability")
    try:
        normalized = tuple(sorted(set(capabilities)))
    except (TypeError, ValueError) as exc:
        raise ComputeFrameworkError("invalid_provider_capability") from exc
    if len(normalized) > 128 or any(
        not isinstance(item, str) or CAPABILITY.fullmatch(item) is None for item in normalized
    ):
        raise ComputeFrameworkError("invalid_provider_capability")
    return normalized


@dataclass(frozen=True, slots=True)
class ComputeProviderDescriptor:
    provider_id: str
    kind: ComputeProviderKind
    healthy: bool
    capabilities: tuple[str, ...]
    profile_id: str = "generic.virtualization.v1"

    def __post_init__(self) -> None:
        _identifier(self.provider_id, "invalid_provider_id")
        if not isinstance(self.kind, ComputeProviderKind) or not isinstance(self.healthy, bool):
            raise ComputeFrameworkError("invalid_provider")
        if not isinstance(self.profile_id, str) or CAPABILITY.fullmatch(self.profile_id) is None:
            raise ComputeFrameworkError("invalid_provider_profile_id")
        object.__setattr__(self, "capabilities", _normalize_capabilities(self.capabilities))

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        healthy: bool,
        capabilities: Iterable[str],
        kind: ComputeProviderKind = ComputeProviderKind.PROFILE,
        profile_id: str | None = None,
    ) -> "ComputeProviderDescriptor":
        _identifier(provider_id, "invalid_provider_id")
        if not isinstance(kind, ComputeProviderKind) or not isinstance(healthy, bool):
            raise ComputeFrameworkError("invalid_provider")
        if profile_id is None:
            profile_id = {
                ComputeProviderKind.PHYSICAL: "generic.physical.v1",
                ComputeProviderKind.PROXMOX: "proxmox.virtualization.v1",
                ComputeProviderKind.PROFILE: "generic.virtualization.v1",
            }[kind]
        if not isinstance(profile_id, str) or CAPABILITY.fullmatch(profile_id) is None:
            raise ComputeFrameworkError("invalid_provider_profile_id")
        normalized = _normalize_capabilities(capabilities)
        return cls(
            provider_id=provider_id,
            kind=kind,
            healthy=healthy,
            capabilities=normalized,
            profile_id=profile_id,
        )

    @classmethod
    def from_mapping(cls, value: object) -> "ComputeProviderDescriptor":
        item = _closed_mapping(
            value,
            {"provider_id", "profile_id", "healthy", "capabilities"},
            "invalid_provider_descriptor",
        )
        capabilities = item["capabilities"]
        if not isinstance(capabilities, list):
            raise ComputeFrameworkError("invalid_provider_capability")
        normalized = _normalize_capabilities(capabilities)
        if len(normalized) != len(capabilities):
            raise ComputeFrameworkError("invalid_provider_capability")
        return cls.create(
            provider_id=item["provider_id"],
            profile_id=item["profile_id"],
            healthy=item["healthy"],
            capabilities=normalized,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "profile_id": self.profile_id,
            "healthy": self.healthy,
            "capabilities": list(self.capabilities),
        }


@dataclass(frozen=True, slots=True)
class ComputeProviderProfile:
    """Portable description of an adapter's supported compute surface."""

    profile_id: str
    resource_kinds: tuple[ComputeResourceKind, ...]
    capabilities: tuple[str, ...]
    schema: str = field(default="home-center.compute-provider-profile.v1", init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.profile_id, str) or CAPABILITY.fullmatch(self.profile_id) is None:
            raise ComputeFrameworkError("invalid_provider_profile_id")
        try:
            kinds = tuple(sorted(set(self.resource_kinds), key=lambda item: item.value))
        except (AttributeError, TypeError) as exc:
            raise ComputeFrameworkError("invalid_provider_resource_kind") from exc
        if not kinds or len(kinds) > len(ComputeResourceKind) or any(
            not isinstance(item, ComputeResourceKind) for item in kinds
        ):
            raise ComputeFrameworkError("invalid_provider_resource_kind")
        capabilities = _normalize_capabilities(self.capabilities)
        for kind in kinds:
            if ComputePlanner.runtime_capability(kind) not in capabilities:
                raise ComputeFrameworkError("provider_profile_capability_missing")
        object.__setattr__(self, "resource_kinds", kinds)
        object.__setattr__(self, "capabilities", capabilities)

    @classmethod
    def create(
        cls,
        *,
        profile_id: str,
        resource_kinds: Iterable[ComputeResourceKind],
        capabilities: Iterable[str],
    ) -> "ComputeProviderProfile":
        if not isinstance(profile_id, str) or CAPABILITY.fullmatch(profile_id) is None:
            raise ComputeFrameworkError("invalid_provider_profile_id")
        try:
            kinds = tuple(sorted(set(resource_kinds), key=lambda item: item.value))
        except (AttributeError, TypeError) as exc:
            raise ComputeFrameworkError("invalid_provider_resource_kind") from exc
        if not kinds or len(kinds) > len(ComputeResourceKind) or any(
            not isinstance(item, ComputeResourceKind) for item in kinds
        ):
            raise ComputeFrameworkError("invalid_provider_resource_kind")
        normalized = _normalize_capabilities(capabilities)
        return cls(profile_id=profile_id, resource_kinds=kinds, capabilities=normalized)

    def describe(
        self,
        *,
        provider_id: str,
        healthy: bool,
        enabled_capabilities: Iterable[str] | None = None,
    ) -> ComputeProviderDescriptor:
        capabilities = self.capabilities if enabled_capabilities is None else _normalize_capabilities(enabled_capabilities)
        if not set(capabilities).issubset(self.capabilities):
            raise ComputeFrameworkError("provider_capability_not_in_profile")
        return ComputeProviderDescriptor.create(
            provider_id=provider_id,
            healthy=healthy,
            capabilities=capabilities,
            profile_id=self.profile_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "profile_id": self.profile_id,
            "resource_kinds": [item.value for item in self.resource_kinds],
            "capabilities": list(self.capabilities),
        }


def proxmox_compute_profile() -> ComputeProviderProfile:
    """Return the built-in Proxmox adapter profile without runtime bindings."""

    return ComputeProviderProfile.create(
        profile_id="proxmox.virtualization.v1",
        resource_kinds=(ComputeResourceKind.VM, ComputeResourceKind.CONTAINER, ComputeResourceKind.LXC),
        capabilities=(
            "compute.capacity.v1",
            "compute.container.v1",
            "compute.ha.v1",
            "compute.lxc.v1",
            "compute.vm.v1",
        ),
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
        _identifier(self.resource_id, "invalid_compute_request")
        if not isinstance(self.kind, ComputeResourceKind):
            raise ComputeFrameworkError("invalid_compute_request")
        _bounded_integer(self.vcpu, minimum=1, maximum=256, code="invalid_vcpu")
        _bounded_integer(self.memory_mib, minimum=256, maximum=4_194_304, code="invalid_memory")
        _bounded_integer(self.disk_gib, minimum=1, maximum=1_048_576, code="invalid_disk_size")
        if not isinstance(self.high_availability, bool):
            raise ComputeFrameworkError("invalid_high_availability")

    @classmethod
    def from_mapping(cls, value: object) -> "ComputeResourceRequest":
        item = _closed_mapping(
            value,
            {"resource_id", "kind", "vcpu", "memory_mib", "disk_gib", "high_availability"},
            "invalid_compute_request",
        )
        try:
            kind = ComputeResourceKind(item["kind"])
        except (TypeError, ValueError) as exc:
            raise ComputeFrameworkError("invalid_compute_request") from exc
        return cls(
            resource_id=item["resource_id"],
            kind=kind,
            vcpu=item["vcpu"],
            memory_mib=item["memory_mib"],
            disk_gib=item["disk_gib"],
            high_availability=item["high_availability"],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "resource_id": self.resource_id,
            "kind": self.kind.value,
            "vcpu": self.vcpu,
            "memory_mib": self.memory_mib,
            "disk_gib": self.disk_gib,
            "high_availability": self.high_availability,
        }


@dataclass(frozen=True, slots=True)
class ComputeCapacity:
    vcpu: int
    memory_mib: int
    storage_gib: int

    def __post_init__(self) -> None:
        _bounded_integer(self.vcpu, minimum=0, maximum=65_536, code="invalid_capacity_vcpu")
        _bounded_integer(
            self.memory_mib,
            minimum=0,
            maximum=16_777_216,
            code="invalid_capacity_memory",
        )
        _bounded_integer(
            self.storage_gib,
            minimum=0,
            maximum=16_777_216,
            code="invalid_capacity_storage",
        )

    @classmethod
    def from_mapping(cls, value: object) -> "ComputeCapacity":
        item = _closed_mapping(value, {"vcpu", "memory_mib", "storage_gib"}, "invalid_capacity")
        return cls(vcpu=item["vcpu"], memory_mib=item["memory_mib"], storage_gib=item["storage_gib"])

    def to_dict(self) -> dict[str, int]:
        return {"vcpu": self.vcpu, "memory_mib": self.memory_mib, "storage_gib": self.storage_gib}


@dataclass(frozen=True, slots=True)
class ComputeCapacitySnapshot:
    provider_id: str
    sequence: int
    total: ComputeCapacity
    allocated: ComputeCapacity
    reserved: ComputeCapacity
    schema: str = field(default="home-center.compute-capacity-snapshot.v1", init=False)

    def __post_init__(self) -> None:
        _identifier(self.provider_id, "invalid_provider_id")
        _bounded_integer(self.sequence, minimum=0, maximum=2**63 - 1, code="invalid_capacity_sequence")
        if not all(isinstance(value, ComputeCapacity) for value in (self.total, self.allocated, self.reserved)):
            raise ComputeFrameworkError("invalid_capacity")

    @classmethod
    def from_mapping(cls, value: object) -> "ComputeCapacitySnapshot":
        item = _closed_mapping(
            value,
            {"schema", "provider_id", "sequence", "total", "allocated", "reserved"},
            "invalid_capacity_snapshot",
        )
        if item["schema"] != "home-center.compute-capacity-snapshot.v1":
            raise ComputeFrameworkError("invalid_capacity_snapshot")
        return cls(
            provider_id=item["provider_id"],
            sequence=item["sequence"],
            total=ComputeCapacity.from_mapping(item["total"]),
            allocated=ComputeCapacity.from_mapping(item["allocated"]),
            reserved=ComputeCapacity.from_mapping(item["reserved"]),
        )

    @property
    def accounting_consistent(self) -> bool:
        return (
            self.allocated.vcpu + self.reserved.vcpu <= self.total.vcpu
            and self.allocated.memory_mib + self.reserved.memory_mib <= self.total.memory_mib
            and self.allocated.storage_gib + self.reserved.storage_gib <= self.total.storage_gib
        )

    @property
    def available(self) -> ComputeCapacity:
        return ComputeCapacity(
            vcpu=max(self.total.vcpu - self.allocated.vcpu - self.reserved.vcpu, 0),
            memory_mib=max(self.total.memory_mib - self.allocated.memory_mib - self.reserved.memory_mib, 0),
            storage_gib=max(self.total.storage_gib - self.allocated.storage_gib - self.reserved.storage_gib, 0),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "sequence": self.sequence,
            "total": self.total.to_dict(),
            "allocated": self.allocated.to_dict(),
            "reserved": self.reserved.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class ComputeProviderState:
    provider: ComputeProviderDescriptor
    capacity: ComputeCapacitySnapshot

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ComputeProviderDescriptor) or not isinstance(
            self.capacity, ComputeCapacitySnapshot
        ):
            raise ComputeFrameworkError("invalid_provider_state")
        if self.provider.provider_id != self.capacity.provider_id:
            raise ComputeFrameworkError("provider_capacity_identity_mismatch")

    @classmethod
    def from_mapping(cls, value: object) -> "ComputeProviderState":
        item = _closed_mapping(value, {"provider", "capacity"}, "invalid_provider_state")
        return cls(
            provider=ComputeProviderDescriptor.from_mapping(item["provider"]),
            capacity=ComputeCapacitySnapshot.from_mapping(item["capacity"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {"provider": self.provider.to_dict(), "capacity": self.capacity.to_dict()}


@dataclass(frozen=True, slots=True)
class ComputeCapacityPlanningRequest:
    request_id: str
    resource: ComputeResourceRequest
    providers: tuple[ComputeProviderState, ...]
    schema: str = field(default="home-center.compute-capacity-request.v1", init=False)

    def __post_init__(self) -> None:
        _identifier(self.request_id, "invalid_compute_request_id")
        if not isinstance(self.resource, ComputeResourceRequest):
            raise ComputeFrameworkError("invalid_compute_request")
        if self.resource.kind is ComputeResourceKind.PHYSICAL:
            raise ComputeFrameworkError("unsupported_resource_kind")
        if not isinstance(self.providers, tuple) or len(self.providers) > MAX_PROVIDERS or any(
            not isinstance(item, ComputeProviderState) for item in self.providers
        ):
            raise ComputeFrameworkError("invalid_provider_states")
        provider_ids = [item.provider.provider_id for item in self.providers]
        if len(provider_ids) != len(set(provider_ids)):
            raise ComputeFrameworkError("duplicate_provider_id")

    @classmethod
    def from_mapping(cls, value: object) -> "ComputeCapacityPlanningRequest":
        item = _closed_mapping(
            value,
            {"schema", "request_id", "resource", "providers"},
            "invalid_compute_capacity_request",
        )
        if item["schema"] != "home-center.compute-capacity-request.v1" or not isinstance(item["providers"], list):
            raise ComputeFrameworkError("invalid_compute_capacity_request")
        if len(item["providers"]) > MAX_PROVIDERS:
            raise ComputeFrameworkError("invalid_provider_states")
        return cls(
            request_id=item["request_id"],
            resource=ComputeResourceRequest.from_mapping(item["resource"]),
            providers=tuple(ComputeProviderState.from_mapping(provider) for provider in item["providers"]),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "resource": self.resource.to_dict(),
            "providers": [item.to_dict() for item in sorted(self.providers, key=lambda item: item.provider.provider_id)],
        }


@dataclass(frozen=True, slots=True)
class ComputeProviderEvaluation:
    provider_id: str
    profile_id: str
    state: ComputePlanState
    blockers: tuple[str, ...]
    available_before: ComputeCapacity
    available_after: ComputeCapacity | None
    maximum_utilization_bps_after: int | None
    capacity_sequence: int

    def to_dict(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "profile_id": self.profile_id,
            "state": self.state.value,
            "blockers": list(self.blockers),
            "available_before": self.available_before.to_dict(),
            "available_after": None if self.available_after is None else self.available_after.to_dict(),
            "maximum_utilization_bps_after": self.maximum_utilization_bps_after,
            "capacity_sequence": self.capacity_sequence,
        }


@dataclass(frozen=True, slots=True)
class ComputeCapacityPlan:
    request_id: str
    resource: ComputeResourceRequest
    state: ComputePlanState
    selected_provider_id: str | None
    blockers: tuple[str, ...]
    evaluations: tuple[ComputeProviderEvaluation, ...]
    selection_policy: str = "least-utilized-then-provider-id.v1"
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.compute-capacity-plan.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "resource": self.resource.to_dict(),
            "state": self.state.value,
            "selected_provider_id": self.selected_provider_id,
            "blockers": list(self.blockers),
            "evaluations": [item.to_dict() for item in self.evaluations],
            "selection_policy": self.selection_policy,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


@dataclass(frozen=True, slots=True)
class ComputePlan:
    """Compatibility result for the original single-provider plan boundary."""

    provider_id: str
    request: ComputeResourceRequest
    state: ComputePlanState
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.compute-plan.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "provider_id": self.provider_id,
            "request": self.request.to_dict(),
            "state": self.state.value,
            "blockers": list(self.blockers),
            "production_mutation_enabled": self.production_mutation_enabled,
        }


class ComputePlanner:
    _RUNTIME_CAPABILITY = {
        ComputeResourceKind.VM: "compute.vm.v1",
        ComputeResourceKind.CONTAINER: "compute.container.v1",
        ComputeResourceKind.LXC: "compute.lxc.v1",
        ComputeResourceKind.PHYSICAL: "compute.physical.v1",
    }

    @classmethod
    def runtime_capability(cls, kind: ComputeResourceKind) -> str:
        if not isinstance(kind, ComputeResourceKind):
            raise ComputeFrameworkError("invalid_compute_request")
        return cls._RUNTIME_CAPABILITY[kind]

    @staticmethod
    def _legacy_available(value: object, code: str) -> int:
        return _bounded_integer(value, minimum=0, maximum=16_777_216, code=code)

    def plan_create(
        self,
        provider: ComputeProviderDescriptor,
        request: ComputeResourceRequest,
        *,
        available_cpu: int,
        available_memory_mib: int,
        available_storage_gib: int,
    ) -> ComputePlan:
        """Plan against caller-supplied free capacity for 0.14 compatibility."""

        if not isinstance(provider, ComputeProviderDescriptor) or not isinstance(request, ComputeResourceRequest):
            raise ComputeFrameworkError("invalid_compute_plan_input")
        available_cpu = self._legacy_available(available_cpu, "invalid_available_cpu")
        available_memory_mib = self._legacy_available(available_memory_mib, "invalid_available_memory")
        available_storage_gib = self._legacy_available(available_storage_gib, "invalid_available_storage")
        blockers = self._provider_blockers(provider, request)
        if available_cpu < request.vcpu:
            blockers.append("insufficient_cpu_capacity")
        if available_memory_mib < request.memory_mib:
            blockers.append("insufficient_memory_capacity")
        if available_storage_gib < request.disk_gib:
            blockers.append("insufficient_storage_capacity")
        return ComputePlan(
            provider_id=provider.provider_id,
            request=request,
            state=ComputePlanState.BLOCKED if blockers else ComputePlanState.PLANNED,
            blockers=tuple(blockers),
        )

    def plan_capacity(self, request: ComputeCapacityPlanningRequest) -> ComputeCapacityPlan:
        if not isinstance(request, ComputeCapacityPlanningRequest):
            raise ComputeFrameworkError("invalid_compute_capacity_request")
        evaluations = tuple(
            self._evaluate_provider(state, request.resource)
            for state in sorted(request.providers, key=lambda item: item.provider.provider_id)
        )
        eligible = [item for item in evaluations if item.state is ComputePlanState.PLANNED]
        if not eligible:
            return ComputeCapacityPlan(
                request_id=request.request_id,
                resource=request.resource,
                state=ComputePlanState.BLOCKED,
                selected_provider_id=None,
                blockers=("no_eligible_provider",),
                evaluations=evaluations,
            )
        selected = min(
            eligible,
            key=lambda item: (
                item.maximum_utilization_bps_after if item.maximum_utilization_bps_after is not None else 10_001,
                item.provider_id,
            ),
        )
        return ComputeCapacityPlan(
            request_id=request.request_id,
            resource=request.resource,
            state=ComputePlanState.PLANNED,
            selected_provider_id=selected.provider_id,
            blockers=(),
            evaluations=evaluations,
        )

    def _evaluate_provider(
        self,
        state: ComputeProviderState,
        request: ComputeResourceRequest,
    ) -> ComputeProviderEvaluation:
        provider = state.provider
        snapshot = state.capacity
        available = snapshot.available
        blockers = self._provider_blockers(provider, request, require_capacity=True)
        if not snapshot.accounting_consistent:
            blockers.append("capacity_accounting_exceeds_total")
        if available.vcpu < request.vcpu:
            blockers.append("insufficient_cpu_capacity")
        if available.memory_mib < request.memory_mib:
            blockers.append("insufficient_memory_capacity")
        if available.storage_gib < request.disk_gib:
            blockers.append("insufficient_storage_capacity")
        if blockers:
            return ComputeProviderEvaluation(
                provider_id=provider.provider_id,
                profile_id=provider.profile_id,
                state=ComputePlanState.BLOCKED,
                blockers=tuple(blockers),
                available_before=available,
                available_after=None,
                maximum_utilization_bps_after=None,
                capacity_sequence=snapshot.sequence,
            )
        remaining = ComputeCapacity(
            vcpu=available.vcpu - request.vcpu,
            memory_mib=available.memory_mib - request.memory_mib,
            storage_gib=available.storage_gib - request.disk_gib,
        )
        maximum_utilization = max(
            self._utilization_bps(
                snapshot.total.vcpu,
                snapshot.allocated.vcpu + snapshot.reserved.vcpu + request.vcpu,
            ),
            self._utilization_bps(
                snapshot.total.memory_mib,
                snapshot.allocated.memory_mib + snapshot.reserved.memory_mib + request.memory_mib,
            ),
            self._utilization_bps(
                snapshot.total.storage_gib,
                snapshot.allocated.storage_gib + snapshot.reserved.storage_gib + request.disk_gib,
            ),
        )
        return ComputeProviderEvaluation(
            provider_id=provider.provider_id,
            profile_id=provider.profile_id,
            state=ComputePlanState.PLANNED,
            blockers=(),
            available_before=available,
            available_after=remaining,
            maximum_utilization_bps_after=maximum_utilization,
            capacity_sequence=snapshot.sequence,
        )

    def _provider_blockers(
        self,
        provider: ComputeProviderDescriptor,
        request: ComputeResourceRequest,
        *,
        require_capacity: bool = False,
    ) -> list[str]:
        blockers: list[str] = []
        if not provider.healthy:
            blockers.append("provider_not_healthy")
        if require_capacity and "compute.capacity.v1" not in provider.capabilities:
            blockers.append("provider_capacity_unsupported")
        required = self.runtime_capability(request.kind)
        if required not in provider.capabilities:
            blockers.append("provider_runtime_unsupported")
        if request.high_availability and "compute.ha.v1" not in provider.capabilities:
            blockers.append("provider_ha_unsupported")
        return blockers

    @staticmethod
    def _utilization_bps(total: int, used: int) -> int:
        if total == 0:
            return 10_000
        return (used * 10_000 + total - 1) // total
