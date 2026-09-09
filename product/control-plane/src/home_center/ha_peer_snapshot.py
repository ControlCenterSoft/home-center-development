"""Immutable HA peer-state snapshots derived from reconciler-owned state."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence

IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$")
_ALLOWED_AUDIT_ACTION = "peer.health.transition"


class HAPeerSnapshotError(ValueError):
    """Stable validation error for observed HA peer-state snapshots."""


class PeerHealthState(StrEnum):
    UNKNOWN = "unknown"
    READY = "ready"
    DEGRADED = "degraded"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"


@dataclass(frozen=True, slots=True)
class ObservedPeerState:
    node_id: str
    role: str
    state: PeerHealthState
    state_revision: str

    def to_dict(self) -> dict[str, str]:
        return {
            "node_id": self.node_id,
            "role": self.role,
            "state": self.state.value,
            "state_revision": self.state_revision,
        }


@dataclass(frozen=True, slots=True)
class HAPeerStateSnapshot:
    cluster_id: str
    journal_seq: int
    members: tuple[ObservedPeerState, ...]
    snapshot_id: str
    schema: str = "home-center.ha-peer-state-snapshot.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "cluster_id": self.cluster_id,
            "journal_seq": self.journal_seq,
            "members": [member.to_dict() for member in self.members],
            "snapshot_id": self.snapshot_id,
        }

    def require_exact(self, *, expected_snapshot_id: str, expected_journal_seq: int) -> None:
        if expected_snapshot_id != self.snapshot_id:
            raise HAPeerSnapshotError("ha_snapshot_stale")
        if expected_journal_seq != self.journal_seq:
            raise HAPeerSnapshotError("ha_transition_journal_stale")


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise HAPeerSnapshotError(code)
    return value


def _stable_capability(value: object) -> object:
    if not isinstance(value, dict):
        return {}
    result = dict(value)
    result.pop("observed_at", None)
    return result


def _state_revision(row: Mapping[str, Any], *, state: PeerHealthState) -> str:
    material = {
        "node_id": row.get("node_id"),
        "name": row.get("name"),
        "role": row.get("role"),
        "address": row.get("address"),
        "state": state.value,
        "capabilities": _stable_capability(row.get("capabilities")),
    }
    payload = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "state-" + hashlib.sha256(payload).hexdigest()


def _journal_seq(events: Iterable[Mapping[str, Any]]) -> int:
    maximum = 0
    for event in events:
        if event.get("action") != _ALLOWED_AUDIT_ACTION:
            continue
        seq = event.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
            raise HAPeerSnapshotError("invalid_peer_transition_seq")
        maximum = max(maximum, seq)
    return maximum


def build_peer_state_snapshot(
    *,
    cluster_id: str,
    configured_node_ids: Sequence[str],
    node_rows: Sequence[Mapping[str, Any]],
    audit_events: Sequence[Mapping[str, Any]],
) -> HAPeerStateSnapshot:
    """Build a deterministic snapshot from reconciler-owned state.

    Configured nodes that have never produced inventory are represented as UNKNOWN.
    Extra stored nodes fail closed so stale membership cannot silently participate.
    """

    cluster_id = _identifier(cluster_id, "invalid_cluster_id")
    if not 1 <= len(configured_node_ids) <= 64:
        raise HAPeerSnapshotError("invalid_configured_node_count")
    configured = tuple(
        _identifier(value, "invalid_configured_node_id") for value in configured_node_ids
    )
    if len(configured) != len(set(configured)):
        raise HAPeerSnapshotError("duplicate_configured_node_id")

    indexed: dict[str, Mapping[str, Any]] = {}
    for row in node_rows:
        node_id = _identifier(row.get("node_id"), "invalid_observed_node_id")
        if node_id in indexed:
            raise HAPeerSnapshotError("duplicate_observed_node_id")
        if node_id not in configured:
            raise HAPeerSnapshotError("unexpected_observed_node")
        indexed[node_id] = row

    members: list[ObservedPeerState] = []
    for node_id in sorted(configured):
        row = indexed.get(node_id)
        if row is None:
            members.append(
                ObservedPeerState(
                    node_id=node_id,
                    role="unknown",
                    state=PeerHealthState.UNKNOWN,
                    state_revision="state-unobserved",
                )
            )
            continue

        role = _identifier(row.get("role"), "invalid_observed_role")
        raw_state = row.get("status")
        try:
            state = PeerHealthState(raw_state)
        except (TypeError, ValueError) as exc:
            raise HAPeerSnapshotError("invalid_observed_state") from exc
        members.append(
            ObservedPeerState(
                node_id=node_id,
                role=role,
                state=state,
                state_revision=_state_revision(row, state=state),
            )
        )

    journal_seq = _journal_seq(audit_events)
    canonical = {
        "schema": "home-center.ha-peer-state-snapshot.v1",
        "cluster_id": cluster_id,
        "journal_seq": journal_seq,
        "members": [member.to_dict() for member in members],
    }
    snapshot_id = "ha-state-" + hashlib.sha256(
        json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return HAPeerStateSnapshot(
        cluster_id=cluster_id,
        journal_seq=journal_seq,
        members=tuple(members),
        snapshot_id=snapshot_id,
    )
