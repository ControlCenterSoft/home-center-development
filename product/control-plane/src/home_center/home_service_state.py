"""Durable, compare-and-swap state for Home Center service instances."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from home_center.home_service_operations import HomeServiceInstanceState
from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.store import StateStore
from home_center.util import canonical_json, utc_now


@dataclass(frozen=True, slots=True)
class InstanceTransition:
    instance_id: str
    expected_generation: int
    expected_resource_version: str
    idempotency_key: str
    target_state: HomeServiceInstanceState
    configuration_revision_id: str | None = None
    external_publication_enabled: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "instance_id", _identifier(self.instance_id, "invalid_instance_id"))
        object.__setattr__(self, "expected_resource_version", _identifier(self.expected_resource_version, "invalid_resource_version"))
        object.__setattr__(self, "idempotency_key", _identifier(self.idempotency_key, "invalid_idempotency_key"))
        if not isinstance(self.expected_generation, int) or isinstance(self.expected_generation, bool) or self.expected_generation < 1:
            raise HomeServiceCatalogError("invalid_instance_generation")
        if not isinstance(self.target_state, HomeServiceInstanceState):
            raise HomeServiceCatalogError("invalid_instance_state")
        if self.configuration_revision_id is not None:
            object.__setattr__(self, "configuration_revision_id", _identifier(self.configuration_revision_id, "invalid_configuration_revision"))
        if not isinstance(self.external_publication_enabled, bool):
            raise HomeServiceCatalogError("invalid_publication_state")


class HomeServiceInstanceStateStore:
    def __init__(self, store: StateStore) -> None:
        if not isinstance(store, StateStore):
            raise TypeError("invalid_state_store")
        self._store = store

    def create(self, *, instance_id: str, service_id: str, target_node_id: str) -> dict[str, object]:
        identity = {
            "instance_id": _identifier(instance_id, "invalid_instance_id"),
            "service_id": _identifier(service_id, "invalid_service_id"),
            "target_node_id": _identifier(target_node_id, "invalid_node_id"),
        }
        digest = hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()[:24]
        return self._store.create_home_service_instance({
            **identity,
            "state": HomeServiceInstanceState.PLANNED.value,
            "generation": 1,
            "resource_version": f"rv:instance:{digest}",
            "configuration_revision_id": None,
            "external_publication_enabled": False,
            "updated_at": utc_now(),
        })

    def get(self, instance_id: str) -> dict[str, object] | None:
        return self._store.home_service_instance(_identifier(instance_id, "invalid_instance_id"))

    def transition(self, request: InstanceTransition) -> tuple[dict[str, object], bool]:
        if not isinstance(request, InstanceTransition):
            raise TypeError("invalid_instance_transition")
        material = {
            "instance_id": request.instance_id,
            "expected_generation": request.expected_generation,
            "expected_resource_version": request.expected_resource_version,
            "target_state": request.target_state.value,
            "configuration_revision_id": request.configuration_revision_id,
            "external_publication_enabled": request.external_publication_enabled,
        }
        request_hash = hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
        next_generation = request.expected_generation + 1
        next_version = "rv:instance:" + hashlib.sha256(
            canonical_json({**material, "generation": next_generation}).encode("utf-8")
        ).hexdigest()[:24]
        return self._store.transition_home_service_instance(
            instance_id=request.instance_id,
            expected_generation=request.expected_generation,
            expected_resource_version=request.expected_resource_version,
            idempotency_key=request.idempotency_key,
            request_hash=request_hash,
            target_state=request.target_state.value,
            generation=next_generation,
            resource_version=next_version,
            configuration_revision_id=request.configuration_revision_id,
            external_publication_enabled=request.external_publication_enabled,
            updated_at=utc_now(),
        )
