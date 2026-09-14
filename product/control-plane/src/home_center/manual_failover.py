"""Fail-closed state machine for qualified two-node manual failover.

This module deliberately contains no systemd, firewall or SSH side effects.  It
models the evidence gates an executor must satisfy before the durable writer
membership may advance.  Keeping the planner pure makes interruption/replay
qualification deterministic.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from typing import Any

from .util import utc_now

TRANSITION_SCHEMA = "home-center.manual-failover-transition.v1"
MANUAL_MODE = "single-writer-manual-failover"
PHASES = (
    "planned",
    "source_quiesced",
    "final_sync_verified",
    "source_fenced",
    "target_promoted",
    "target_verified",
    "completed",
)
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


class ManualFailoverRejected(RuntimeError):
    """A required failover safety invariant was not proven."""


@dataclass(frozen=True, slots=True)
class NodeEvidence:
    node_id: str
    version: str
    revision: str
    ready: bool
    service_active: bool
    fenced: bool
    authoritative_sha256: str
    source_sequence: int

    def validate(self) -> None:
        if not self.node_id:
            raise ManualFailoverRejected("node_identity_missing")
        if _VERSION.fullmatch(self.version) is None:
            raise ManualFailoverRejected("node_version_invalid")
        if _HEX40.fullmatch(self.revision) is None:
            raise ManualFailoverRejected("node_revision_invalid")
        if _HEX64.fullmatch(self.authoritative_sha256) is None:
            raise ManualFailoverRejected("authoritative_digest_invalid")
        if isinstance(self.source_sequence, bool) or not isinstance(self.source_sequence, int) or self.source_sequence < 0:
            raise ManualFailoverRejected("source_sequence_invalid")


@dataclass(frozen=True, slots=True)
class ManualFailoverTransition:
    transition_id: str
    cluster_id: str
    source_writer: str
    target_writer: str
    from_generation: int
    to_generation: int
    phase: str
    version: str
    revision: str
    authoritative_sha256: str
    final_source_sequence: int | None
    started_at: str
    updated_at: str
    failure_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": TRANSITION_SCHEMA,
            "transition_id": self.transition_id,
            "cluster_id": self.cluster_id,
            "source_writer": self.source_writer,
            "target_writer": self.target_writer,
            "from_generation": self.from_generation,
            "to_generation": self.to_generation,
            "phase": self.phase,
            "version": self.version,
            "revision": self.revision,
            "authoritative_sha256": self.authoritative_sha256,
            "final_source_sequence": self.final_source_sequence,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "failure_reason": self.failure_reason,
        }


def _validate_membership(membership: dict[str, Any]) -> tuple[str, int, str, set[str]]:
    if not isinstance(membership, dict) or membership.get("schema") != "home-center.cluster-membership.v1":
        raise ManualFailoverRejected("membership_schema_rejected")
    cluster_id = membership.get("cluster_id")
    generation = membership.get("generation")
    writer = membership.get("writer")
    members = membership.get("members")
    quorum = membership.get("quorum")
    if not isinstance(cluster_id, str) or not cluster_id:
        raise ManualFailoverRejected("membership_cluster_rejected")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise ManualFailoverRejected("membership_generation_rejected")
    if not isinstance(writer, str) or not writer:
        raise ManualFailoverRejected("membership_writer_rejected")
    if not isinstance(members, list) or len(members) != 2:
        raise ManualFailoverRejected("manual_failover_requires_two_members")
    member_ids: set[str] = set()
    for member in members:
        if not isinstance(member, dict) or not isinstance(member.get("node_id"), str):
            raise ManualFailoverRejected("membership_member_rejected")
        member_ids.add(member["node_id"])
    if len(member_ids) != 2 or writer not in member_ids:
        raise ManualFailoverRejected("membership_identity_rejected")
    if not isinstance(quorum, dict):
        raise ManualFailoverRejected("membership_quorum_rejected")
    if quorum.get("mode") != MANUAL_MODE or quorum.get("automatic_failover") is not False:
        raise ManualFailoverRejected("automatic_or_nonmanual_failover_rejected")
    return cluster_id, generation, writer, member_ids


def begin_manual_failover(
    membership: dict[str, Any],
    *,
    target_node_id: str,
    source: NodeEvidence,
    target: NodeEvidence,
    transition_id: str | None = None,
) -> ManualFailoverTransition:
    cluster_id, generation, writer, member_ids = _validate_membership(membership)
    source.validate()
    target.validate()
    if source.node_id != writer:
        raise ManualFailoverRejected("source_is_not_current_writer")
    if target_node_id == writer or target_node_id not in member_ids or target.node_id != target_node_id:
        raise ManualFailoverRejected("target_identity_rejected")
    if not source.ready or not source.service_active:
        raise ManualFailoverRejected("source_not_healthy_for_planned_handoff")
    if not target.ready or not target.service_active:
        raise ManualFailoverRejected("target_not_healthy_for_planned_handoff")
    if target.fenced is not True:
        raise ManualFailoverRejected("standby_must_be_fenced_before_handoff")
    if source.version != target.version or source.revision != target.revision:
        raise ManualFailoverRejected("release_drift")
    if source.authoritative_sha256 != target.authoritative_sha256:
        raise ManualFailoverRejected("authoritative_state_drift")
    if target.source_sequence < source.source_sequence:
        raise ManualFailoverRejected("standby_sequence_behind_source")
    now = utc_now()
    return ManualFailoverTransition(
        transition_id=transition_id or str(uuid.uuid4()),
        cluster_id=cluster_id,
        source_writer=writer,
        target_writer=target_node_id,
        from_generation=generation,
        to_generation=generation + 1,
        phase="planned",
        version=source.version,
        revision=source.revision,
        authoritative_sha256=source.authoritative_sha256,
        final_source_sequence=None,
        started_at=now,
        updated_at=now,
    )


def record_source_quiesced(
    transition: ManualFailoverTransition,
    source: NodeEvidence,
) -> ManualFailoverTransition:
    if transition.phase != "planned":
        raise ManualFailoverRejected("source_quiesce_phase_rejected")
    source.validate()
    if source.node_id != transition.source_writer or source.service_active:
        raise ManualFailoverRejected("source_not_quiesced")
    if source.version != transition.version or source.revision != transition.revision:
        raise ManualFailoverRejected("source_release_changed")
    return replace(transition, phase="source_quiesced", updated_at=utc_now())


def record_final_sync_verified(
    transition: ManualFailoverTransition,
    *,
    source: NodeEvidence,
    target: NodeEvidence,
) -> ManualFailoverTransition:
    if transition.phase != "source_quiesced":
        raise ManualFailoverRejected("final_sync_phase_rejected")
    source.validate()
    target.validate()
    if source.node_id != transition.source_writer or target.node_id != transition.target_writer:
        raise ManualFailoverRejected("final_sync_identity_rejected")
    if source.service_active:
        raise ManualFailoverRejected("source_must_remain_quiesced")
    if source.version != target.version or source.revision != target.revision:
        raise ManualFailoverRejected("release_drift")
    if source.authoritative_sha256 != target.authoritative_sha256:
        raise ManualFailoverRejected("final_sync_digest_mismatch")
    if target.source_sequence < source.source_sequence:
        raise ManualFailoverRejected("final_sync_sequence_not_applied")
    return replace(
        transition,
        phase="final_sync_verified",
        authoritative_sha256=source.authoritative_sha256,
        final_source_sequence=source.source_sequence,
        updated_at=utc_now(),
    )


def record_source_fenced(
    transition: ManualFailoverTransition,
    source: NodeEvidence,
) -> ManualFailoverTransition:
    if transition.phase != "final_sync_verified":
        raise ManualFailoverRejected("source_fence_phase_rejected")
    source.validate()
    if source.node_id != transition.source_writer or source.service_active or not source.fenced:
        raise ManualFailoverRejected("source_fence_not_proven")
    return replace(transition, phase="source_fenced", updated_at=utc_now())


def promote_membership(
    transition: ManualFailoverTransition,
    membership: dict[str, Any],
) -> tuple[ManualFailoverTransition, dict[str, Any]]:
    if transition.phase != "source_fenced":
        raise ManualFailoverRejected("promotion_phase_rejected")
    cluster_id, generation, writer, member_ids = _validate_membership(membership)
    if cluster_id != transition.cluster_id or generation != transition.from_generation:
        raise ManualFailoverRejected("membership_generation_changed")
    if writer != transition.source_writer or transition.target_writer not in member_ids:
        raise ManualFailoverRejected("membership_writer_changed")
    updated = dict(membership)
    updated["generation"] = transition.to_generation
    updated["writer"] = transition.target_writer
    updated["observed_at"] = utc_now()
    return replace(transition, phase="target_promoted", updated_at=utc_now()), updated


def record_target_verified(
    transition: ManualFailoverTransition,
    *,
    source: NodeEvidence,
    target: NodeEvidence,
    write_readback_verified: bool,
    source_write_rejected: bool,
) -> ManualFailoverTransition:
    if transition.phase != "target_promoted":
        raise ManualFailoverRejected("target_verification_phase_rejected")
    source.validate()
    target.validate()
    if source.node_id != transition.source_writer or source.service_active or not source.fenced:
        raise ManualFailoverRejected("old_writer_not_safely_fenced")
    if target.node_id != transition.target_writer or not target.ready or not target.service_active or target.fenced:
        raise ManualFailoverRejected("promoted_writer_not_serving")
    if target.version != transition.version or target.revision != transition.revision:
        raise ManualFailoverRejected("promoted_writer_release_changed")
    if not write_readback_verified:
        raise ManualFailoverRejected("promoted_writer_readback_unverified")
    if not source_write_rejected:
        raise ManualFailoverRejected("old_writer_write_rejection_unverified")
    return replace(transition, phase="target_verified", updated_at=utc_now())


def complete_manual_failover(transition: ManualFailoverTransition) -> ManualFailoverTransition:
    if transition.phase != "target_verified":
        raise ManualFailoverRejected("completion_phase_rejected")
    return replace(transition, phase="completed", updated_at=utc_now())


def fail_manual_failover(transition: ManualFailoverTransition, reason: str) -> ManualFailoverTransition:
    if transition.phase == "completed":
        raise ManualFailoverRejected("completed_transition_is_immutable")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 256:
        raise ManualFailoverRejected("failure_reason_rejected")
    return replace(transition, phase="failed", failure_reason=reason.strip(), updated_at=utc_now())
