"""Crash-safe orchestration for bounded two-node manual HA promotion.

The state machine in :mod:`home_center.manual_failover` deliberately has no
side effects.  This module binds that state machine to a small, injected
privileged backend while keeping every irreversible boundary fail closed.

The executor never performs automatic failover.  Its backend is expected to
implement idempotent operations so a durable transition can be resumed after a
process/node interruption.  A shared updater interlock is held for the entire
uninterrupted execution attempt; after a crash a new attempt must acquire the
same interlock again before inspecting or mutating HA state.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Any, Callable, Protocol

from .ha_update_interlock import UpdateInterlockEvidence, hold_update_interlock
from .manual_failover import (
    ManualFailoverRejected,
    ManualFailoverTransition,
    NodeEvidence,
    begin_manual_failover,
    complete_manual_failover,
    promote_membership,
    record_final_sync_verified,
    record_source_fenced,
    record_source_quiesced,
    record_target_verified,
)
from .manual_failover_recovery import restore_manual_failover_transition
from .manual_failover_resume import decide_manual_failover_resume


class ManualFailoverExecutorRejected(RuntimeError):
    """The executor could not prove a safe bounded next action."""


class ManualFailoverBackend(Protocol):
    """Injected privileged operations required by the manual executor.

    Every mutating method must be idempotent for the same transition/epoch.  A
    backend must not infer a target from hostnames: node IDs come from durable
    membership and the transition journal.
    """

    def load_membership(self) -> dict[str, Any]: ...

    def load_transition(self) -> dict[str, Any] | None: ...

    def persist_transition(
        self,
        transition: ManualFailoverTransition,
        *,
        expected_phase: str | None,
    ) -> None: ...

    def commit_promotion(
        self,
        *,
        before_membership: dict[str, Any],
        after_membership: dict[str, Any],
        before_transition: ManualFailoverTransition,
        after_transition: ManualFailoverTransition,
    ) -> None: ...

    def node_evidence(self, node_id: str) -> NodeEvidence: ...

    def quiesce_source(self, node_id: str) -> None: ...

    def synchronize_authoritative_state(self, source_node_id: str, target_node_id: str) -> None: ...

    def apply_fence(self, node_id: str, mode: str) -> None: ...

    def verify_authoritative_write_readback(self, node_id: str) -> bool: ...

    def verify_write_rejected(self, node_id: str) -> bool: ...


InterlockFactory = Callable[[], AbstractContextManager[UpdateInterlockEvidence]]


def _require_interlock(evidence: object) -> None:
    if not isinstance(evidence, UpdateInterlockEvidence) or evidence.acquired is not True:
        raise ManualFailoverExecutorRejected("update_interlock_evidence_rejected")


def _restore_active_transition(payload: dict[str, Any]) -> ManualFailoverTransition:
    try:
        transition = restore_manual_failover_transition(payload)
    except ManualFailoverRejected as exc:
        raise ManualFailoverExecutorRejected(f"transition_restore_rejected:{exc}") from exc
    if transition.phase == "failed":
        raise ManualFailoverExecutorRejected("manual_failover_transition_failed")
    return transition


def _begin_transition(
    backend: ManualFailoverBackend,
    *,
    target_node_id: str,
    transition_id: str | None,
) -> ManualFailoverTransition:
    membership = backend.load_membership()
    source_node_id = membership.get("writer")
    if not isinstance(source_node_id, str) or not source_node_id:
        raise ManualFailoverExecutorRejected("writer_identity_unavailable")
    source = backend.node_evidence(source_node_id)
    target = backend.node_evidence(target_node_id)
    try:
        transition = begin_manual_failover(
            membership,
            target_node_id=target_node_id,
            source=source,
            target=target,
            transition_id=transition_id,
        )
    except ManualFailoverRejected as exc:
        raise ManualFailoverExecutorRejected(f"preflight_rejected:{exc}") from exc
    backend.persist_transition(transition, expected_phase=None)
    return transition


def _load_or_begin_transition(
    backend: ManualFailoverBackend,
    *,
    target_node_id: str | None,
    transition_id: str | None,
) -> ManualFailoverTransition:
    payload = backend.load_transition()
    if payload is None or payload.get("phase") in {"completed", "failed"}:
        if target_node_id is None:
            raise ManualFailoverExecutorRejected("target_node_required")
        return _begin_transition(
            backend,
            target_node_id=target_node_id,
            transition_id=transition_id,
        )

    transition = _restore_active_transition(payload)
    membership = backend.load_membership()
    try:
        decision = decide_manual_failover_resume(payload, membership)
    except ManualFailoverRejected as exc:
        raise ManualFailoverExecutorRejected(f"resume_rejected:{exc}") from exc
    if decision.terminal:
        raise ManualFailoverExecutorRejected("unexpected_terminal_resume_decision")
    if target_node_id is not None and target_node_id != transition.target_writer:
        raise ManualFailoverExecutorRejected("active_transition_target_mismatch")
    if transition_id is not None and transition_id != transition.transition_id:
        raise ManualFailoverExecutorRejected("active_transition_identity_mismatch")
    return transition


def _advance_once(
    backend: ManualFailoverBackend,
    transition: ManualFailoverTransition,
) -> ManualFailoverTransition:
    """Perform exactly one restart-safe phase advancement."""

    phase = transition.phase

    if phase == "planned":
        backend.quiesce_source(transition.source_writer)
        source = backend.node_evidence(transition.source_writer)
        try:
            advanced = record_source_quiesced(transition, source)
        except ManualFailoverRejected as exc:
            raise ManualFailoverExecutorRejected(f"source_quiesce_rejected:{exc}") from exc
        backend.persist_transition(advanced, expected_phase=phase)
        return advanced

    if phase == "source_quiesced":
        backend.synchronize_authoritative_state(
            transition.source_writer,
            transition.target_writer,
        )
        source = backend.node_evidence(transition.source_writer)
        target = backend.node_evidence(transition.target_writer)
        try:
            advanced = record_final_sync_verified(
                transition,
                source=source,
                target=target,
            )
        except ManualFailoverRejected as exc:
            raise ManualFailoverExecutorRejected(f"final_sync_rejected:{exc}") from exc
        backend.persist_transition(advanced, expected_phase=phase)
        return advanced

    if phase == "final_sync_verified":
        # Isolation is intentionally stricter than standby fencing at the
        # irreversible writer handoff boundary.
        backend.apply_fence(transition.source_writer, "isolated")
        source = backend.node_evidence(transition.source_writer)
        try:
            advanced = record_source_fenced(transition, source)
        except ManualFailoverRejected as exc:
            raise ManualFailoverExecutorRejected(f"source_fence_rejected:{exc}") from exc
        backend.persist_transition(advanced, expected_phase=phase)
        return advanced

    if phase == "source_fenced":
        before_membership = backend.load_membership()
        try:
            advanced, after_membership = promote_membership(transition, before_membership)
        except ManualFailoverRejected as exc:
            raise ManualFailoverExecutorRejected(f"promotion_rejected:{exc}") from exc
        # The backend must commit writer generation and transition phase in one
        # transaction.  No target un-fencing occurs before this boundary.
        backend.commit_promotion(
            before_membership=before_membership,
            after_membership=after_membership,
            before_transition=transition,
            after_transition=advanced,
        )
        return advanced

    if phase == "target_promoted":
        # Re-applying role-driven policy is idempotent and therefore also the
        # safe restart action if the process died immediately after promotion.
        backend.apply_fence(transition.target_writer, "auto")
        source = backend.node_evidence(transition.source_writer)
        target = backend.node_evidence(transition.target_writer)
        write_readback_verified = backend.verify_authoritative_write_readback(
            transition.target_writer
        )
        source_write_rejected = backend.verify_write_rejected(transition.source_writer)
        try:
            advanced = record_target_verified(
                transition,
                source=source,
                target=target,
                write_readback_verified=write_readback_verified,
                source_write_rejected=source_write_rejected,
            )
        except ManualFailoverRejected as exc:
            raise ManualFailoverExecutorRejected(f"target_verification_rejected:{exc}") from exc
        backend.persist_transition(advanced, expected_phase=phase)
        return advanced

    if phase == "target_verified":
        try:
            advanced = complete_manual_failover(transition)
        except ManualFailoverRejected as exc:
            raise ManualFailoverExecutorRejected(f"completion_rejected:{exc}") from exc
        backend.persist_transition(advanced, expected_phase=phase)
        return advanced

    if phase == "completed":
        return transition
    if phase == "failed":
        raise ManualFailoverExecutorRejected("manual_failover_transition_failed")
    raise ManualFailoverExecutorRejected("manual_failover_phase_rejected")


def execute_manual_failover(
    backend: ManualFailoverBackend,
    *,
    target_node_id: str | None = None,
    transition_id: str | None = None,
    interlock_factory: InterlockFactory = hold_update_interlock,
) -> ManualFailoverTransition:
    """Run or resume one manual role transition to a durable terminal state.

    This function intentionally has no retry loop around backend failures.  A
    failed side effect leaves the last proven durable phase unchanged.  The
    operator may invoke the executor again; the resume gate then proves the
    writer epoch before repeating the single idempotent next action.
    """

    with interlock_factory() as interlock:
        _require_interlock(interlock)
        transition = _load_or_begin_transition(
            backend,
            target_node_id=target_node_id,
            transition_id=transition_id,
        )
        # There are six non-terminal phase advances.  A fixed upper bound makes
        # unexpected phase cycles impossible even if a backend is defective.
        for _ in range(6):
            if transition.phase == "completed":
                return transition
            transition = _advance_once(backend, transition)
        if transition.phase != "completed":
            raise ManualFailoverExecutorRejected("manual_failover_did_not_terminate")
        return transition
