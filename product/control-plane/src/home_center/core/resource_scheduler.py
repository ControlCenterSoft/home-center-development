"""Deterministic, fail-closed resource placement across compute providers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import islice
from typing import Iterable

from .compute_framework import (
    ComputeProviderDescriptor,
    ComputeResourceKind,
    ComputeResourceRequest,
)


ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
BLOCKER = re.compile(r"^[a-z0-9_:-]+$")
MAX_PROVIDERS = 64
MAX_METADATA_ITEMS = 64


class ResourceSchedulerError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise ResourceSchedulerError(code)
    return value


def _identifiers(
    values: object,
    *,
    code: str,
    preserve_order: bool = False,
) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > MAX_METADATA_ITEMS:
        raise ResourceSchedulerError(code)
    normalized = tuple(_identifier(value, code) for value in values)
    if len(normalized) != len(set(normalized)):
        raise ResourceSchedulerError(code)
    return normalized if preserve_order else tuple(sorted(normalized))


def _capacity(value: object, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ResourceSchedulerError(code)
    return value


@dataclass(frozen=True, slots=True)
class ProviderCapacity:
    provider: ComputeProviderDescriptor
    cpu: int
    memory_mib: int
    storage_gib: int
    failure_domain: str | None = None
    labels: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.provider, ComputeProviderDescriptor):
            raise ResourceSchedulerError("invalid_provider")
        _capacity(self.cpu, "invalid_available_cpu")
        _capacity(self.memory_mib, "invalid_available_memory")
        _capacity(self.storage_gib, "invalid_available_storage")
        if self.failure_domain is not None:
            _identifier(self.failure_domain, "invalid_failure_domain")
        object.__setattr__(self, "labels", _identifiers(self.labels, code="invalid_labels"))


@dataclass(frozen=True, slots=True)
class PlacementRequest:
    request_id: str
    resource: ComputeResourceRequest
    preferred_providers: tuple[str, ...] = ()
    required_labels: tuple[str, ...] = ()
    avoid_failure_domains: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.request_id, "invalid_request_id")
        if not isinstance(self.resource, ComputeResourceRequest):
            raise ResourceSchedulerError("invalid_resource_request")
        object.__setattr__(
            self,
            "preferred_providers",
            _identifiers(
                self.preferred_providers,
                code="invalid_preferred_providers",
                preserve_order=True,
            ),
        )
        object.__setattr__(
            self,
            "required_labels",
            _identifiers(self.required_labels, code="invalid_required_labels"),
        )
        object.__setattr__(
            self,
            "avoid_failure_domains",
            _identifiers(self.avoid_failure_domains, code="invalid_failure_domains"),
        )


@dataclass(frozen=True, slots=True)
class PlacementPlan:
    request_id: str
    state: str
    provider_id: str | None
    score: int | None
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.resource-placement-plan.v1", init=False)

    def __post_init__(self) -> None:
        _identifier(self.request_id, "invalid_plan_request_id")
        if not isinstance(self.state, str) or self.state not in {"planned", "blocked"}:
            raise ResourceSchedulerError("invalid_plan_state")
        if self.provider_id is not None:
            _identifier(self.provider_id, "invalid_plan_provider_id")
        if self.score is not None and (
            not isinstance(self.score, int) or isinstance(self.score, bool)
        ):
            raise ResourceSchedulerError("invalid_plan_score")
        if (
            not isinstance(self.blockers, tuple)
            or len(self.blockers) > 16
            or len(self.blockers) != len(set(self.blockers))
            or any(not isinstance(item, str) or BLOCKER.fullmatch(item) is None for item in self.blockers)
        ):
            raise ResourceSchedulerError("invalid_plan_blockers")
        if self.state == "planned" and (
            self.provider_id is None or self.score is None or self.blockers
        ):
            raise ResourceSchedulerError("inconsistent_plan")
        if self.state == "blocked" and (
            self.provider_id is not None or self.score is not None or not self.blockers
        ):
            raise ResourceSchedulerError("inconsistent_plan")
        if self.production_mutation_enabled is not False:
            raise ResourceSchedulerError("production_mutation_forbidden")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "state": self.state,
            "provider_id": self.provider_id,
            "score": self.score,
            "blockers": list(self.blockers),
            "production_mutation_enabled": False,
        }


class ResourceScheduler:
    _RUNTIME_CAPABILITY = {
        ComputeResourceKind.VM: "compute.vm.v1",
        ComputeResourceKind.LXC: "compute.lxc.v1",
        ComputeResourceKind.PHYSICAL: "compute.physical.v1",
    }

    def plan(
        self,
        request: PlacementRequest,
        providers: Iterable[ProviderCapacity],
    ) -> PlacementPlan:
        if not isinstance(request, PlacementRequest):
            raise ResourceSchedulerError("invalid_placement_request")
        if isinstance(providers, (str, bytes)):
            raise ResourceSchedulerError("invalid_providers")
        try:
            candidates = tuple(islice(iter(providers), MAX_PROVIDERS + 1))
        except TypeError as exc:
            raise ResourceSchedulerError("invalid_providers") from exc
        if len(candidates) > MAX_PROVIDERS or any(
            not isinstance(item, ProviderCapacity) for item in candidates
        ):
            raise ResourceSchedulerError("invalid_providers")
        provider_ids = tuple(item.provider.provider_id for item in candidates)
        if len(provider_ids) != len(set(provider_ids)):
            raise ResourceSchedulerError("duplicate_provider_id")

        preferred_rank = {
            provider_id: index for index, provider_id in enumerate(request.preferred_providers)
        }
        ranked: list[tuple[int, str]] = []
        for item in candidates:
            provider = item.provider
            if not provider.healthy:
                continue
            required = self._RUNTIME_CAPABILITY[request.resource.kind]
            if required not in provider.capabilities:
                continue
            if request.resource.high_availability and "compute.ha.v1" not in provider.capabilities:
                continue
            if (
                item.cpu < request.resource.vcpu
                or item.memory_mib < request.resource.memory_mib
                or item.storage_gib < request.resource.disk_gib
            ):
                continue
            if not set(request.required_labels).issubset(item.labels):
                continue
            if item.failure_domain and item.failure_domain in request.avoid_failure_domains:
                continue

            score = 0
            if provider.provider_id in preferred_rank:
                score += 1000 - preferred_rank[provider.provider_id] * 5
            score += min(item.cpu - request.resource.vcpu, 100)
            score += min((item.memory_mib - request.resource.memory_mib) // 256, 100)
            score += min(item.storage_gib - request.resource.disk_gib, 100)
            ranked.append((score, provider.provider_id))

        if not ranked:
            return PlacementPlan(
                request.request_id,
                "blocked",
                None,
                None,
                ("no_eligible_provider",),
            )
        ranked.sort(key=lambda row: (-row[0], row[1]))
        score, provider_id = ranked[0]
        return PlacementPlan(request.request_id, "planned", provider_id, score, ())
