"""Authorized durable commit boundary for home-service execution results.

This module is the first state-mutating step after the inert 0.22 decision and
commit envelopes.  It requires a separately bound authorization and applies the
exact prepared generation/resource-version through the durable CAS store.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from home_center.home_service_state import HomeServiceInstanceStateStore, PreparedInstanceTransition
from home_center.home_service_state_transition import HomeServiceTransitionCommit
from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.util import canonical_json


AUTHORIZATION_SCHEMA = "home-center.home-service-transition-authorization.v1"
RECEIPT_SCHEMA = "home-center.home-service-transition-apply-receipt.v1"


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionAuthorization:
    authorization_id: str
    commit_id: str
    decision_id: str
    instance_id: str
    expected_generation: int
    expected_resource_version: str
    allow_durable_commit: bool
    production_mutation_enabled: bool
    schema: str = field(default=AUTHORIZATION_SCHEMA, init=False)

    def __post_init__(self) -> None:
        for name in (
            "authorization_id",
            "commit_id",
            "decision_id",
            "instance_id",
            "expected_resource_version",
        ):
            object.__setattr__(self, name, _identifier(getattr(self, name), f"invalid_{name}"))
        if (
            not isinstance(self.expected_generation, int)
            or isinstance(self.expected_generation, bool)
            or self.expected_generation < 1
        ):
            raise HomeServiceCatalogError("invalid_transition_generation")
        if self.allow_durable_commit is not True or self.production_mutation_enabled is not True:
            raise HomeServiceCatalogError("durable_transition_not_authorized")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "authorization_id": self.authorization_id,
            "commit_id": self.commit_id,
            "decision_id": self.decision_id,
            "instance_id": self.instance_id,
            "expected_generation": self.expected_generation,
            "expected_resource_version": self.expected_resource_version,
            "allow_durable_commit": True,
            "production_mutation_enabled": True,
        }


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionApplyReceipt:
    receipt_id: str
    authorization_id: str
    commit_id: str
    decision_id: str
    instance_id: str
    target_state: str
    generation: int
    resource_version: str
    applied: bool
    idempotent_replay: bool
    schema: str = field(default=RECEIPT_SCHEMA, init=False)
    further_mutation_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "authorization_id": self.authorization_id,
            "commit_id": self.commit_id,
            "decision_id": self.decision_id,
            "instance_id": self.instance_id,
            "target_state": self.target_state,
            "generation": self.generation,
            "resource_version": self.resource_version,
            "applied": self.applied,
            "idempotent_replay": self.idempotent_replay,
            "further_mutation_authorized": False,
        }


def apply_transition_commit(
    commit: HomeServiceTransitionCommit,
    authorization: HomeServiceTransitionAuthorization,
    instances: HomeServiceInstanceStateStore,
) -> HomeServiceTransitionApplyReceipt:
    """Apply one exact, explicitly authorized transition with CAS and replay safety."""

    if not isinstance(commit, HomeServiceTransitionCommit):
        raise TypeError("invalid_transition_commit")
    if not isinstance(authorization, HomeServiceTransitionAuthorization):
        raise TypeError("invalid_transition_authorization")
    if not isinstance(instances, HomeServiceInstanceStateStore):
        raise TypeError("invalid_instance_state_store")
    if (
        commit.compare_and_swap_required is not True
        or commit.idempotent is not True
        or commit.committed is not False
        or commit.production_mutation_enabled is not False
    ):
        raise HomeServiceCatalogError("unsafe_transition_commit")
    if (
        authorization.commit_id != commit.commit_id
        or authorization.decision_id != commit.decision_id
        or authorization.instance_id != commit.instance_id
        or authorization.expected_generation != commit.expected_generation
        or authorization.expected_resource_version != commit.expected_resource_version
    ):
        raise HomeServiceCatalogError("transition_authorization_binding_mismatch")

    current = instances.get(commit.instance_id)
    if current is None:
        raise HomeServiceCatalogError("transition_instance_not_found")
    current_generation = int(current["generation"])
    current_version = str(current["resource_version"])
    current_state = str(current["state"])
    is_source = (
        current_generation == commit.expected_generation
        and current_version == commit.expected_resource_version
        and current_state == commit.source_state.value
    )
    is_exact_replay_state = (
        current_generation == commit.next_generation
        and current_version == commit.next_resource_version
        and current_state == commit.target_state.value
    )
    if not is_source and not is_exact_replay_state:
        raise HomeServiceCatalogError("transition_state_precondition_failed")

    request = PreparedInstanceTransition(
        instance_id=commit.instance_id,
        expected_generation=commit.expected_generation,
        expected_resource_version=commit.expected_resource_version,
        idempotency_key=commit.idempotency_key,
        target_state=commit.target_state,
        next_generation=commit.next_generation,
        next_resource_version=commit.next_resource_version,
        configuration_revision_id=current.get("configuration_revision_id"),
        external_publication_enabled=bool(current.get("external_publication_enabled", False)),
    )
    result, created = instances.commit_prepared(request)
    if (
        int(result["generation"]) != commit.next_generation
        or str(result["resource_version"]) != commit.next_resource_version
        or str(result["state"]) != commit.target_state.value
    ):
        raise RuntimeError("durable transition result does not match prepared commit")

    receipt_material = {
        "authorization_id": authorization.authorization_id,
        "commit_id": commit.commit_id,
        "decision_id": commit.decision_id,
        "instance_id": commit.instance_id,
        "target_state": commit.target_state.value,
        "generation": commit.next_generation,
        "resource_version": commit.next_resource_version,
    }
    digest = hashlib.sha256(canonical_json(receipt_material).encode("utf-8")).hexdigest()
    return HomeServiceTransitionApplyReceipt(
        receipt_id=f"hstr-{digest[:24]}",
        authorization_id=authorization.authorization_id,
        commit_id=commit.commit_id,
        decision_id=commit.decision_id,
        instance_id=commit.instance_id,
        target_state=commit.target_state.value,
        generation=commit.next_generation,
        resource_version=commit.next_resource_version,
        applied=created,
        idempotent_replay=not created,
    )
