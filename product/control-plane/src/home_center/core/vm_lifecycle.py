"""Fail-closed, plan-only virtual-machine lifecycle."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from .compute_framework import (
    ComputePlanner,
    ComputeProviderDescriptor,
    ComputeResourceKind,
    ComputeResourceRequest,
)


ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
STEP = re.compile(r"^[a-z0-9-]+$")
BLOCKER = re.compile(r"^[a-z0-9_:-]+$")


class VmLifecycleError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class VmState(StrEnum):
    STOPPED = "stopped"
    RUNNING = "running"
    SUSPENDED = "suspended"
    ABSENT = "absent"


class VmAction(StrEnum):
    CREATE = "create"
    START = "start"
    STOP = "stop"
    SUSPEND = "suspend"
    DELETE = "delete"


def _identity(value: object, code: str) -> str:
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise VmLifecycleError(code)
    return value


def _resources(vcpu: object, memory_mib: object, disk_gib: object, code: str) -> None:
    if (
        not isinstance(vcpu, int)
        or isinstance(vcpu, bool)
        or not 1 <= vcpu <= 256
        or not isinstance(memory_mib, int)
        or isinstance(memory_mib, bool)
        or not 256 <= memory_mib <= 4_194_304
        or not isinstance(disk_gib, int)
        or isinstance(disk_gib, bool)
        or not 1 <= disk_gib <= 1_048_576
    ):
        raise VmLifecycleError(code)


@dataclass(frozen=True, slots=True)
class VmSnapshot:
    vm_id: str
    provider_id: str
    state: VmState
    vcpu: int
    memory_mib: int
    disk_gib: int

    def __post_init__(self) -> None:
        _identity(self.vm_id, "invalid_vm_identity")
        _identity(self.provider_id, "invalid_vm_identity")
        if not isinstance(self.state, VmState):
            raise VmLifecycleError("invalid_vm_state")
        _resources(self.vcpu, self.memory_mib, self.disk_gib, "invalid_vm_resources")


@dataclass(frozen=True, slots=True)
class VmLifecycleRequest:
    operation_id: str
    vm_id: str
    action: VmAction
    vcpu: int | None = None
    memory_mib: int | None = None
    disk_gib: int | None = None
    high_availability: bool = False

    def __post_init__(self) -> None:
        _identity(self.operation_id, "invalid_request_identity")
        _identity(self.vm_id, "invalid_request_identity")
        if not isinstance(self.action, VmAction):
            raise VmLifecycleError("invalid_vm_action")
        if type(self.high_availability) is not bool:
            raise VmLifecycleError("invalid_high_availability")
        sizing = (self.vcpu, self.memory_mib, self.disk_gib)
        if self.action is VmAction.CREATE:
            if None in sizing:
                raise VmLifecycleError("create_resources_required")
            _resources(*sizing, "invalid_create_resources")
        elif any(value is not None for value in sizing) or self.high_availability:
            raise VmLifecycleError("non_create_resources_forbidden")


@dataclass(frozen=True, slots=True)
class VmLifecyclePlan:
    operation_id: str
    vm_id: str
    action: VmAction
    state: str
    provider_id: str | None
    steps: tuple[str, ...]
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.vm-lifecycle-plan.v1", init=False)

    def __post_init__(self) -> None:
        _identity(self.operation_id, "invalid_plan_identity")
        _identity(self.vm_id, "invalid_plan_identity")
        if (
            not isinstance(self.action, VmAction)
            or not isinstance(self.state, str)
            or self.state not in {"planned", "blocked"}
        ):
            raise VmLifecycleError("invalid_plan_state")
        if self.provider_id is not None:
            _identity(self.provider_id, "invalid_plan_provider")
        if (
            not isinstance(self.steps, tuple)
            or not 1 <= len(self.steps) <= 8
            or len(self.steps) != len(set(self.steps))
            or any(not isinstance(item, str) or STEP.fullmatch(item) is None for item in self.steps)
        ):
            raise VmLifecycleError("invalid_plan_steps")
        if (
            not isinstance(self.blockers, tuple)
            or len(self.blockers) > 16
            or len(self.blockers) != len(set(self.blockers))
            or any(not isinstance(item, str) or BLOCKER.fullmatch(item) is None for item in self.blockers)
        ):
            raise VmLifecycleError("invalid_plan_blockers")
        if (
            self.state == "planned" and (self.blockers or self.provider_id is None)
        ) or (
            self.state == "blocked" and not self.blockers
        ):
            raise VmLifecycleError("inconsistent_plan")
        if self.production_mutation_enabled is not False:
            raise VmLifecycleError("production_mutation_forbidden")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "operation_id": self.operation_id,
            "vm_id": self.vm_id,
            "action": self.action.value,
            "state": self.state,
            "provider_id": self.provider_id,
            "steps": list(self.steps),
            "blockers": list(self.blockers),
            "production_mutation_enabled": False,
        }


class VmLifecyclePlanner:
    _RUNTIME_CAPABILITY = "compute.vm.v1"
    _ALLOWED = {
        VmAction.START: {VmState.STOPPED},
        VmAction.STOP: {VmState.RUNNING, VmState.SUSPENDED},
        VmAction.SUSPEND: {VmState.RUNNING},
        VmAction.DELETE: {VmState.STOPPED},
    }

    def plan(
        self,
        request: VmLifecycleRequest,
        *,
        provider: ComputeProviderDescriptor,
        snapshot: VmSnapshot | None = None,
        available_cpu: int = 0,
        available_memory_mib: int = 0,
        available_storage_gib: int = 0,
    ) -> VmLifecyclePlan:
        if not isinstance(request, VmLifecycleRequest):
            raise VmLifecycleError("invalid_request")
        if not isinstance(provider, ComputeProviderDescriptor):
            raise VmLifecycleError("invalid_provider")
        if snapshot is not None and not isinstance(snapshot, VmSnapshot):
            raise VmLifecycleError("invalid_snapshot")

        blockers: list[str] = []
        if snapshot is not None:
            if snapshot.vm_id != request.vm_id:
                blockers.append("snapshot_identity_mismatch")
            if snapshot.provider_id != provider.provider_id:
                blockers.append("provider_identity_mismatch")

        if request.action is VmAction.CREATE:
            if snapshot is not None and snapshot.state is not VmState.ABSENT:
                blockers.append("vm_already_exists")
            resource = ComputeResourceRequest(
                request.vm_id,
                ComputeResourceKind.VM,
                request.vcpu,
                request.memory_mib,
                request.disk_gib,
                request.high_availability,
            )
            compute = ComputePlanner().plan_create(
                provider,
                resource,
                available_cpu=available_cpu,
                available_memory_mib=available_memory_mib,
                available_storage_gib=available_storage_gib,
            )
            blockers.extend(compute.blockers)
            steps = ("validate-provider", "reserve-capacity", "create-vm", "verify-state")
        else:
            if not provider.healthy:
                blockers.append("provider_not_healthy")
            if self._RUNTIME_CAPABILITY not in provider.capabilities:
                blockers.append("provider_runtime_unsupported")
            if snapshot is None or snapshot.state is VmState.ABSENT:
                blockers.append("vm_not_found")
            elif snapshot.vm_id == request.vm_id and snapshot.provider_id == provider.provider_id:
                if snapshot.state not in self._ALLOWED[request.action]:
                    blockers.append("invalid_state_transition")
            steps = ("validate-current-state", f"{request.action.value}-vm", "verify-state")

        blockers = list(dict.fromkeys(blockers))
        return VmLifecyclePlan(
            request.operation_id,
            request.vm_id,
            request.action,
            "blocked" if blockers else "planned",
            provider.provider_id,
            tuple(steps),
            tuple(blockers),
        )
