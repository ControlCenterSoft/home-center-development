"""Deterministic service dependency planning with no process-control surface."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


SERVICE_ID = re.compile(r"^[a-z][a-z0-9_.@-]{1,127}$")


class ServiceManagerError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ServiceDefinition:
    service_id: str
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ServicePlan:
    service_id: str
    action: str
    ordered_services: tuple[str, ...]
    production_activation_enabled: bool = False
    schema: str = field(default="home-center.service-plan.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "service_id": self.service_id,
            "action": self.action,
            "ordered_services": list(self.ordered_services),
            "production_activation_enabled": self.production_activation_enabled,
        }


class ServiceManager:
    def __init__(self, definitions: Iterable[ServiceDefinition] = ()) -> None:
        self._definitions: dict[str, ServiceDefinition] = {}
        for definition in definitions:
            self.register(definition)

    def register(self, definition: ServiceDefinition) -> None:
        if SERVICE_ID.fullmatch(definition.service_id) is None:
            raise ServiceManagerError("invalid_service_id")
        if any(SERVICE_ID.fullmatch(item) is None for item in definition.dependencies):
            raise ServiceManagerError("invalid_dependency")
        current = self._definitions.get(definition.service_id)
        if current is not None and current != definition:
            raise ServiceManagerError("service_definition_conflict")
        self._definitions[definition.service_id] = definition

    def plan_start(self, service_id: str) -> ServicePlan:
        if service_id not in self._definitions:
            raise ServiceManagerError("service_not_found")
        ordered: list[str] = []
        visiting: set[str] = set()
        complete: set[str] = set()

        def visit(item: str) -> None:
            if item in complete:
                return
            if item in visiting:
                raise ServiceManagerError("dependency_cycle")
            definition = self._definitions.get(item)
            if definition is None:
                raise ServiceManagerError("dependency_not_found")
            visiting.add(item)
            for dependency in sorted(definition.dependencies):
                visit(dependency)
            visiting.remove(item)
            complete.add(item)
            ordered.append(item)

        visit(service_id)
        return ServicePlan(service_id=service_id, action="start", ordered_services=tuple(ordered))
