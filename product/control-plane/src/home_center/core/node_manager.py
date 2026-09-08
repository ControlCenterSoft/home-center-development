"""Инфраструктурно-нейтральная идентичность узлов и планирование их жизненного цикла."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable

NODE_ID = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
HOSTNAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$", re.IGNORECASE)

class NodeManagerError(ValueError):
    pass

class NodeState(StrEnum):
    DISCOVERED = "discovered"
    PREFLIGHTED = "preflighted"
    TRUSTED = "trusted"
    ENROLLED = "enrolled"
    CONFIGURING = "configuring"
    READY = "ready"
    DEGRADED = "degraded"
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    DRAINING = "draining"
    DECOMMISSIONED = "decommissioned"

_ALLOWED_TRANSITIONS = {
    NodeState.DISCOVERED: frozenset({NodeState.PREFLIGHTED}),
    NodeState.PREFLIGHTED: frozenset({NodeState.TRUSTED}),
    NodeState.TRUSTED: frozenset({NodeState.ENROLLED}),
    NodeState.ENROLLED: frozenset({NodeState.CONFIGURING}),
    NodeState.CONFIGURING: frozenset({NodeState.READY}),
    NodeState.READY: frozenset({NodeState.MAINTENANCE, NodeState.DEGRADED}),
    NodeState.DEGRADED: frozenset({NodeState.READY, NodeState.MAINTENANCE}),
    NodeState.ACTIVE: frozenset({NodeState.READY, NodeState.MAINTENANCE, NodeState.DEGRADED}),
    NodeState.MAINTENANCE: frozenset({NodeState.READY, NodeState.DRAINING}),
    NodeState.DRAINING: frozenset({NodeState.MAINTENANCE, NodeState.DECOMMISSIONED}),
    NodeState.DECOMMISSIONED: frozenset(),
}

@dataclass(frozen=True, slots=True)
class NodeDescriptor:
    node_id: str
    hostname: str
    state: NodeState
    capabilities: tuple[str, ...]

    @classmethod
    def create(cls, *, node_id: str, hostname: str, state: NodeState, capabilities: Iterable[str]) -> "NodeDescriptor":
        if NODE_ID.fullmatch(node_id) is None or HOSTNAME.fullmatch(hostname) is None:
            raise NodeManagerError("invalid_node_identity")
        if not isinstance(state, NodeState):
            raise NodeManagerError("invalid_node_state")
        normalized = tuple(sorted(set(capabilities)))
        if any(NODE_ID.fullmatch(item) is None for item in normalized):
            raise NodeManagerError("invalid_capability")
        return cls(node_id=node_id, hostname=hostname, state=state, capabilities=normalized)

@dataclass(frozen=True, slots=True)
class NodeTransitionPlan:
    node_id: str
    from_state: NodeState
    to_state: NodeState
    state: str
    blockers: tuple[str, ...]
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.node-transition-plan.v2", init=False)

class NodeManager:
    def __init__(self, nodes: Iterable[NodeDescriptor] = ()) -> None:
        self._nodes: dict[str, NodeDescriptor] = {}
        for node in nodes:
            self.register(node)

    def register(self, node: NodeDescriptor) -> NodeDescriptor:
        current = self._nodes.get(node.node_id)
        if current is not None and current != node:
            raise NodeManagerError("node_identity_conflict")
        self._nodes[node.node_id] = node
        return node

    def list_nodes(self) -> tuple[NodeDescriptor, ...]:
        return tuple(self._nodes[key] for key in sorted(self._nodes))

    def plan_transition(self, node_id: str, target_state: NodeState, *, trust_valid: bool = True, capabilities_known: bool = True, health_ok: bool = True, quorum_safe: bool = True, mandatory_services_safe: bool = True) -> NodeTransitionPlan:
        node = self._nodes.get(node_id)
        if node is None:
            raise NodeManagerError("node_not_found")
        blockers: list[str] = []
        if target_state not in _ALLOWED_TRANSITIONS[node.state]:
            blockers.append("transition_not_allowed")
        if target_state is NodeState.TRUSTED and not trust_valid:
            blockers.append("trust_not_valid")
        if target_state in {NodeState.CONFIGURING, NodeState.READY} and not capabilities_known:
            blockers.append("capabilities_not_known")
        if target_state is NodeState.READY and not health_ok:
            blockers.append("health_not_ready")
        if target_state in {NodeState.DRAINING, NodeState.DECOMMISSIONED}:
            if not quorum_safe:
                blockers.append("quorum_not_safe")
            if not mandatory_services_safe:
                blockers.append("mandatory_services_not_safe")
        return NodeTransitionPlan(node_id=node_id, from_state=node.state, to_state=target_state, state="blocked" if blockers else "planned", blockers=tuple(blockers))
