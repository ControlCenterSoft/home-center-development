"""Deterministic, side-effect-free rolling HA safety planning."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")


class HASafetyError(ValueError):
    """Stable validation error for rolling-safety inputs."""


class NodeRole(StrEnum):
    WRITER = "writer"
    STANDBY = "standby"


class NodeState(StrEnum):
    READY = "ready"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"


@dataclass(frozen=True, slots=True)
class NodeObservation:
    node_id: str
    role: NodeRole
    state: NodeState
    revision: str

    def __post_init__(self) -> None:
        if IDENTIFIER.fullmatch(self.node_id) is None:
            raise HASafetyError("invalid_node_id")
        if not isinstance(self.role, NodeRole):
            raise HASafetyError("invalid_node_role")
        if not isinstance(self.state, NodeState):
            raise HASafetyError("invalid_node_state")
        if REVISION.fullmatch(self.revision) is None:
            raise HASafetyError("invalid_revision")

    def to_dict(self) -> dict[str, str]:
        return {
            "node_id": self.node_id,
            "role": self.role.value,
            "state": self.state.value,
            "revision": self.revision,
        }


@dataclass(frozen=True, slots=True)
class RollingSafetyRequest:
    cluster_id: str
    target_node_id: str
    observations: tuple[NodeObservation, ...]
    minimum_ready_nodes: int
    expected_transition_seq: int
    observed_transition_seq: int
    required_predecessor_node_id: str | None = None
    required_predecessor_revision: str | None = None
    single_node_downtime_acknowledged: bool = False
    schema: str = field(default="home-center.ha-rolling-safety-request.v1", init=False)

    def __post_init__(self) -> None:
        if IDENTIFIER.fullmatch(self.cluster_id) is None:
            raise HASafetyError("invalid_cluster_id")
        if IDENTIFIER.fullmatch(self.target_node_id) is None:
            raise HASafetyError("invalid_target_node_id")
        if not 1 <= len(self.observations) <= 31:
            raise HASafetyError("invalid_cluster_size")
        node_ids = tuple(item.node_id for item in self.observations)
        if len(node_ids) != len(set(node_ids)):
            raise HASafetyError("duplicate_node_id")
        if self.target_node_id not in node_ids:
            raise HASafetyError("target_node_missing")
        if not isinstance(self.minimum_ready_nodes, int) or isinstance(self.minimum_ready_nodes, bool):
            raise HASafetyError("invalid_minimum_ready_nodes")
        if not 0 <= self.minimum_ready_nodes < len(self.observations):
            raise HASafetyError("invalid_minimum_ready_nodes")
        for name, value in (
            ("expected_transition_seq", self.expected_transition_seq),
            ("observed_transition_seq", self.observed_transition_seq),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise HASafetyError(f"invalid_{name}")
        if not isinstance(self.single_node_downtime_acknowledged, bool):
            raise HASafetyError("invalid_single_node_downtime_acknowledgement")
        if self.required_predecessor_node_id is None:
            if self.required_predecessor_revision is not None:
                raise HASafetyError("predecessor_revision_without_node")
        else:
            if IDENTIFIER.fullmatch(self.required_predecessor_node_id) is None:
                raise HASafetyError("invalid_predecessor_node_id")
            if self.required_predecessor_node_id == self.target_node_id:
                raise HASafetyError("target_cannot_be_predecessor")
            if self.required_predecessor_revision is None or REVISION.fullmatch(self.required_predecessor_revision) is None:
                raise HASafetyError("invalid_predecessor_revision")
        if len(self.observations) == 1:
            if self.minimum_ready_nodes != 0:
                raise HASafetyError("single_node_minimum_ready_must_be_zero")
        elif self.minimum_ready_nodes < 1:
            raise HASafetyError("ha_minimum_ready_must_be_positive")


@dataclass(frozen=True, slots=True)
class RollingSafetyDecision:
    safe: bool
    plan_id: str
    blockers: tuple[str, ...]
    ready_before: int
    ready_after_target_stops: int
    writer_node_id: str | None
    rollback_state: str = "ready"
    rollback_required_on_failure: bool = True
    production_mutation_enabled: bool = False
    schema: str = field(default="home-center.ha-rolling-safety-decision.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "safe": self.safe,
            "plan_id": self.plan_id,
            "blockers": list(self.blockers),
            "ready_before": self.ready_before,
            "ready_after_target_stops": self.ready_after_target_stops,
            "writer_node_id": self.writer_node_id,
            "rollback_state": self.rollback_state,
            "rollback_required_on_failure": self.rollback_required_on_failure,
            "production_mutation_enabled": self.production_mutation_enabled,
        }


def _canonical_plan_id(request: RollingSafetyRequest) -> str:
    payload = {
        "schema": request.schema,
        "cluster_id": request.cluster_id,
        "target_node_id": request.target_node_id,
        "observations": [
            item.to_dict() for item in sorted(request.observations, key=lambda observation: observation.node_id)
        ],
        "minimum_ready_nodes": request.minimum_ready_nodes,
        "expected_transition_seq": request.expected_transition_seq,
        "observed_transition_seq": request.observed_transition_seq,
        "required_predecessor_node_id": request.required_predecessor_node_id,
        "required_predecessor_revision": request.required_predecessor_revision,
        "single_node_downtime_acknowledged": request.single_node_downtime_acknowledged,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f"ha-roll-{digest}"


def evaluate_rolling_safety(request: RollingSafetyRequest) -> RollingSafetyDecision:
    """Evaluate whether the target may enter maintenance without unsafe HA transitions.

    The result is planning evidence only. It never transfers the writer role, changes
    node state, executes an update, or authorizes production mutation.
    """

    observations = {item.node_id: item for item in request.observations}
    target = observations[request.target_node_id]
    ready_nodes = tuple(item for item in request.observations if item.state is NodeState.READY)
    ready_after = tuple(item for item in ready_nodes if item.node_id != target.node_id)
    writers = tuple(item for item in ready_nodes if item.role is NodeRole.WRITER)
    blockers: list[str] = []

    if request.expected_transition_seq != request.observed_transition_seq:
        blockers.append("transition_journal_stale")

    if len(writers) > 1:
        blockers.append("split_brain_detected")
    writer_node_id = writers[0].node_id if len(writers) == 1 else None

    if target.state is not NodeState.READY:
        blockers.append("target_not_ready")

    if len(request.observations) == 1:
        if target.role is not NodeRole.WRITER:
            blockers.append("single_node_writer_missing")
        if not request.single_node_downtime_acknowledged:
            blockers.append("single_node_downtime_not_acknowledged")
    else:
        if len(writers) != 1:
            blockers.append("writer_not_unique")
        elif writer_node_id == target.node_id:
            blockers.append("writer_handoff_required")
        if len(ready_after) < request.minimum_ready_nodes:
            blockers.append("minimum_ready_nodes_not_met")

    if request.required_predecessor_node_id is not None:
        predecessor = observations.get(request.required_predecessor_node_id)
        if predecessor is None:
            blockers.append("predecessor_missing")
        else:
            if predecessor.state is not NodeState.READY:
                blockers.append("predecessor_not_ready")
            if predecessor.revision != request.required_predecessor_revision:
                blockers.append("predecessor_revision_mismatch")

    return RollingSafetyDecision(
        safe=not blockers,
        plan_id=_canonical_plan_id(request),
        blockers=tuple(dict.fromkeys(blockers)),
        ready_before=len(ready_nodes),
        ready_after_target_stops=len(ready_after),
        writer_node_id=writer_node_id,
    )


def observations(*items: NodeObservation) -> tuple[NodeObservation, ...]:
    """Small helper for callers that construct immutable observations."""

    return tuple(items)
