"""Secret-free, side-effect-free lifecycle operation plans for home services."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping

from home_center.home_services import (
    HOME_SERVICE_BY_ID,
    BackupPolicy,
    HomeServiceCatalogError,
    HomeServiceProfile,
    _identifier,
)


SCHEMA = "home-center.home-service-operation-plan.v1"
MAX_SECRET_REFERENCES = 32


class HomeServiceInstanceState(StrEnum):
    PLANNED = "planned"
    INSTALLED = "installed"
    CONFIGURED = "configured"
    READY = "ready"
    DEGRADED = "degraded"
    REMOVED = "removed"


class HomeServiceOperation(StrEnum):
    INSTALL = "install"
    CONFIGURE = "configure"
    HEALTH = "health"
    UPDATE = "update"
    BACKUP = "backup"
    RESTORE = "restore"
    REMOVE = "remove"


@dataclass(frozen=True, slots=True)
class HomeServiceInstanceSnapshot:
    instance_id: str
    service_id: str
    target_node_id: str
    state: HomeServiceInstanceState
    generation: int
    resource_version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "instance_id", _identifier(self.instance_id, "invalid_instance_id"))
        object.__setattr__(self, "service_id", _identifier(self.service_id, "invalid_service_id"))
        object.__setattr__(
            self,
            "target_node_id",
            _identifier(self.target_node_id, "invalid_node_id"),
        )
        if not isinstance(self.state, HomeServiceInstanceState):
            raise HomeServiceCatalogError("invalid_instance_state")
        if (
            not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < 1
        ):
            raise HomeServiceCatalogError("invalid_instance_generation")
        _identifier(self.resource_version, "invalid_resource_version")


@dataclass(frozen=True, slots=True)
class HomeServiceOperationRequest:
    operation: HomeServiceOperation
    expected_generation: int
    expected_resource_version: str
    idempotency_key: str
    configuration_revision_id: str | None = None
    secret_references: tuple[str, ...] = ()
    restore_point_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.operation, HomeServiceOperation):
            raise HomeServiceCatalogError("invalid_service_operation")
        if (
            not isinstance(self.expected_generation, int)
            or isinstance(self.expected_generation, bool)
            or self.expected_generation < 1
        ):
            raise HomeServiceCatalogError("invalid_expected_generation")
        object.__setattr__(
            self,
            "expected_resource_version",
            _identifier(self.expected_resource_version, "invalid_expected_resource_version"),
        )
        object.__setattr__(
            self,
            "idempotency_key",
            _identifier(self.idempotency_key, "invalid_idempotency_key"),
        )
        if self.configuration_revision_id is not None:
            object.__setattr__(
                self,
                "configuration_revision_id",
                _identifier(
                    self.configuration_revision_id,
                    "invalid_configuration_revision",
                ),
            )
        if self.restore_point_id is not None:
            object.__setattr__(
                self,
                "restore_point_id",
                _identifier(self.restore_point_id, "invalid_restore_point"),
            )
        if (
            not isinstance(self.secret_references, tuple)
            or len(self.secret_references) > MAX_SECRET_REFERENCES
        ):
            raise HomeServiceCatalogError("invalid_secret_references")
        canonical = tuple(
            sorted(
                _identifier(reference, "invalid_secret_reference")
                for reference in self.secret_references
            )
        )
        if len(canonical) != len(set(canonical)):
            raise HomeServiceCatalogError("duplicate_secret_reference")
        object.__setattr__(self, "secret_references", canonical)


@dataclass(frozen=True, slots=True)
class HomeServiceOperationPlan:
    plan_id: str
    instance_id: str
    service_id: str
    target_node_id: str
    operation: HomeServiceOperation
    from_state: HomeServiceInstanceState
    target_state: HomeServiceInstanceState
    based_on_generation: int
    based_on_resource_version: str
    idempotency_key: str
    steps: tuple[str, ...]
    secret_references: tuple[str, ...]
    schema: str = field(default=SCHEMA, init=False)
    approval_required: bool = field(default=True, init=False)
    durable_job_required: bool = field(default=True, init=False)
    audit_required: bool = field(default=True, init=False)
    plan_only: bool = field(default=True, init=False)
    execution_authorized: bool = field(default=False, init=False)
    production_mutation_enabled: bool = field(default=False, init=False)
    accepts_secret_values: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "plan_id": self.plan_id,
            "instance_id": self.instance_id,
            "service_id": self.service_id,
            "target_node_id": self.target_node_id,
            "operation": self.operation.value,
            "from_state": self.from_state.value,
            "target_state": self.target_state.value,
            "based_on_generation": self.based_on_generation,
            "based_on_resource_version": self.based_on_resource_version,
            "idempotency_key": self.idempotency_key,
            "steps": list(self.steps),
            "secret_references": list(self.secret_references),
            "approval_required": True,
            "durable_job_required": True,
            "audit_required": True,
            "plan_only": True,
            "execution_authorized": False,
            "production_mutation_enabled": False,
            "accepts_secret_values": False,
        }


class HomeServiceOperationPlanner:
    """Validate lifecycle/CAS boundaries and return an inert operation plan."""

    def __init__(self, profiles: Mapping[str, HomeServiceProfile] = HOME_SERVICE_BY_ID) -> None:
        self._profiles = dict(profiles)

    def plan(
        self,
        snapshot: HomeServiceInstanceSnapshot,
        request: HomeServiceOperationRequest,
    ) -> HomeServiceOperationPlan:
        if not isinstance(snapshot, HomeServiceInstanceSnapshot):
            raise HomeServiceCatalogError("invalid_instance_snapshot")
        if not isinstance(request, HomeServiceOperationRequest):
            raise HomeServiceCatalogError("invalid_operation_request")
        profile = self._profiles.get(snapshot.service_id)
        if profile is None:
            raise HomeServiceCatalogError("unknown_service")
        if (
            request.expected_generation != snapshot.generation
            or request.expected_resource_version != snapshot.resource_version
        ):
            raise HomeServiceCatalogError("operation_precondition_failed")

        target_state, steps = _operation_shape(profile, snapshot.state, request)
        fingerprint = {
            "instance_id": snapshot.instance_id,
            "service_id": snapshot.service_id,
            "target_node_id": snapshot.target_node_id,
            "state": snapshot.state.value,
            "generation": snapshot.generation,
            "resource_version": snapshot.resource_version,
            "operation": request.operation.value,
            "idempotency_key": request.idempotency_key,
            "configuration_revision_id": request.configuration_revision_id,
            "secret_references": request.secret_references,
            "restore_point_id": request.restore_point_id,
        }
        digest = hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return HomeServiceOperationPlan(
            plan_id=f"hsop-{digest[:24]}",
            instance_id=snapshot.instance_id,
            service_id=snapshot.service_id,
            target_node_id=snapshot.target_node_id,
            operation=request.operation,
            from_state=snapshot.state,
            target_state=target_state,
            based_on_generation=snapshot.generation,
            based_on_resource_version=snapshot.resource_version,
            idempotency_key=request.idempotency_key,
            steps=steps,
            secret_references=request.secret_references,
        )


def _operation_shape(
    profile: HomeServiceProfile,
    state: HomeServiceInstanceState,
    request: HomeServiceOperationRequest,
) -> tuple[HomeServiceInstanceState, tuple[str, ...]]:
    operation = request.operation
    if state is HomeServiceInstanceState.REMOVED:
        raise HomeServiceCatalogError("instance_removed")
    if operation is HomeServiceOperation.INSTALL:
        if state is not HomeServiceInstanceState.PLANNED:
            raise HomeServiceCatalogError("invalid_operation_state")
        return HomeServiceInstanceState.INSTALLED, (
            "artifact.verify",
            "storage.reserve",
            "runtime.provision",
            "service.install",
            "result.verify",
        )
    if operation is HomeServiceOperation.CONFIGURE:
        if state is not HomeServiceInstanceState.INSTALLED:
            raise HomeServiceCatalogError("invalid_operation_state")
        if request.configuration_revision_id is None:
            raise HomeServiceCatalogError("configuration_revision_required")
        return HomeServiceInstanceState.CONFIGURED, (
            "configuration.resolve",
            "secret-references.resolve-at-execution",
            "service.configure",
            "result.verify",
        )
    if operation is HomeServiceOperation.HEALTH:
        if state not in {
            HomeServiceInstanceState.CONFIGURED,
            HomeServiceInstanceState.READY,
            HomeServiceInstanceState.DEGRADED,
        }:
            raise HomeServiceCatalogError("invalid_operation_state")
        return HomeServiceInstanceState.READY, ("service.health", "health.record")
    if operation is HomeServiceOperation.UPDATE:
        if state not in {HomeServiceInstanceState.READY, HomeServiceInstanceState.DEGRADED}:
            raise HomeServiceCatalogError("invalid_operation_state")
        steps = ["artifact.verify", "service.update", "service.health", "rollback.verify"]
        if profile.backup_policy is not BackupPolicy.NONE:
            steps.insert(0, "backup.pre-update")
        return HomeServiceInstanceState.READY, tuple(steps)
    if operation in {HomeServiceOperation.BACKUP, HomeServiceOperation.RESTORE}:
        if profile.backup_policy is BackupPolicy.NONE:
            raise HomeServiceCatalogError("backup_not_supported")
        if state not in {
            HomeServiceInstanceState.CONFIGURED,
            HomeServiceInstanceState.READY,
            HomeServiceInstanceState.DEGRADED,
        }:
            raise HomeServiceCatalogError("invalid_operation_state")
        if operation is HomeServiceOperation.BACKUP:
            return state, ("backup.prepare", "backup.capture", "backup.verify")
        if request.restore_point_id is None:
            raise HomeServiceCatalogError("restore_point_required")
        return state, (
            "restore-point.verify",
            "service.quiesce",
            "backup.restore",
            "service.health",
        )
    if operation is HomeServiceOperation.REMOVE:
        steps = ["external-publication.disable"]
        if profile.backup_policy is not BackupPolicy.NONE:
            steps.append("backup.final")
        steps.extend(("service.remove", "result.verify"))
        return HomeServiceInstanceState.REMOVED, tuple(steps)
    raise HomeServiceCatalogError("invalid_service_operation")
