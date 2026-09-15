"""Deterministic cluster health aggregation for Home Center HA."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .node_health import HealthState, NodeHealth


@dataclass(frozen=True, slots=True)
class ClusterMember:
    """Runtime-neutral member snapshot used to evaluate cluster health."""

    node_id: str
    health: NodeHealth
    version: str | None = None
    revision: str | None = None

    def __post_init__(self) -> None:
        if not self.node_id.strip():
            raise ValueError("cluster member node_id must not be empty")


@dataclass(frozen=True, slots=True)
class ClusterHealth:
    """Aggregate HA health without changing the local health of any node."""

    state: HealthState
    members: tuple[ClusterMember, ...]
    reasons: tuple[str, ...]

    @property
    def ready(self) -> bool:
        """Whether at least one member can still serve traffic."""

        return any(member.health.ready for member in self.members)

    @property
    def release_consistent(self) -> bool:
        """Whether the known multi-node release identities agree."""

        return not any(reason.startswith("release-") for reason in self.reasons)


def _normalized_identity(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _release_consistency_reasons(members: tuple[ClusterMember, ...]) -> list[str]:
    """Return stable release-drift reasons for a multi-node cluster."""

    if len(members) < 2:
        return []

    reasons: list[str] = []
    versions = [(_normalized_identity(member.version), member.node_id) for member in members]
    revisions = [(_normalized_identity(member.revision), member.node_id) for member in members]

    unknown_versions = [node_id for version, node_id in versions if version is None]
    if unknown_versions:
        reasons.extend(f"release-version-unknown:{node_id}" for node_id in unknown_versions)
    elif len({version for version, _ in versions}) > 1:
        reasons.append("release-version-mismatch")

    unknown_revisions = [node_id for revision, node_id in revisions if revision is None]
    if unknown_revisions:
        reasons.extend(f"release-revision-unknown:{node_id}" for node_id in unknown_revisions)
    elif len({revision for revision, _ in revisions}) > 1:
        reasons.append("release-revision-mismatch")

    return reasons


def aggregate_cluster_health(members: Iterable[ClusterMember]) -> ClusterHealth:
    """Aggregate node health and release parity into a cluster-level state.

    Node health remains local and immutable. A version/revision drift between
    otherwise healthy HA members degrades the cluster instead of marking the
    nodes unhealthy. Loss of one member also degrades a still-serving cluster;
    the cluster becomes unhealthy only when no member is ready and at least one
    member is explicitly unhealthy. Empty/all-unknown membership is unknown.
    """

    normalized = tuple(sorted(members, key=lambda member: member.node_id))
    node_ids = [member.node_id for member in normalized]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("cluster member node_id values must be unique")

    if not normalized:
        return ClusterHealth(
            state=HealthState.UNKNOWN,
            members=(),
            reasons=("no-members",),
        )

    reasons: list[str] = []
    for member in normalized:
        if member.health.state is HealthState.UNHEALTHY:
            reasons.append(f"member-unhealthy:{member.node_id}")
        elif member.health.state is HealthState.UNKNOWN:
            reasons.append(f"member-unknown:{member.node_id}")
        elif member.health.state is HealthState.DEGRADED:
            reasons.append(f"member-degraded:{member.node_id}")

    reasons.extend(_release_consistency_reasons(normalized))

    ready_members = [member for member in normalized if member.health.ready]
    if not ready_members:
        state = (
            HealthState.UNHEALTHY
            if any(member.health.state is HealthState.UNHEALTHY for member in normalized)
            else HealthState.UNKNOWN
        )
    elif reasons:
        state = HealthState.DEGRADED
    else:
        state = HealthState.HEALTHY

    return ClusterHealth(
        state=state,
        members=normalized,
        reasons=tuple(reasons),
    )
