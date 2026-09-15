"""Fail-closed restart cursor for durable manual HA transitions.

Restoring a transition record is not enough to resume safely after a process or
node restart: the durable cluster membership must still represent the writer
and generation implied by that phase.  This module binds both records before
returning the one operation an executor may perform next.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .ha_state import HAStateConflict, validate_membership
from .manual_failover import ManualFailoverRejected
from .manual_failover_recovery import restore_manual_failover_transition

_PRE_PROMOTION_ACTIONS = {
    "planned": "quiesce_source",
    "source_quiesced": "verify_final_sync",
    "final_sync_verified": "fence_source",
    "source_fenced": "commit_promotion",
}
_POST_PROMOTION_ACTIONS = {
    "target_promoted": "verify_target",
    "target_verified": "complete_transition",
    "completed": "terminal_completed",
}


@dataclass(frozen=True, slots=True)
class ManualFailoverResumeDecision:
    """Exactly one restart-safe executor action derived from durable evidence."""

    transition_id: str
    phase: str
    action: str
    expected_writer: str
    expected_generation: int
    terminal: bool


def decide_manual_failover_resume(
    transition_payload: dict[str, Any],
    membership: dict[str, Any],
) -> ManualFailoverResumeDecision:
    """Return the only safe next action for a restored manual failover.

    The transition and membership are independently validated, then bound by
    cluster identity, exact member identities and the writer generation implied
    by the transition phase.  Any disagreement is a hard reject rather than an
    attempt to guess whether promotion happened before the restart.
    """

    transition = restore_manual_failover_transition(transition_payload)
    try:
        validate_membership(membership, expected_cluster_id=transition.cluster_id)
    except HAStateConflict as exc:
        raise ManualFailoverRejected(f"resume_membership_rejected:{exc}") from exc

    members = membership.get("members")
    member_ids = {member["node_id"] for member in members}
    expected_members = {transition.source_writer, transition.target_writer}
    if member_ids != expected_members:
        raise ManualFailoverRejected("resume_membership_identity_mismatch")

    writer = membership["writer"]
    generation = membership["generation"]

    if transition.phase == "failed":
        allowed_failed_epochs = {
            (transition.source_writer, transition.from_generation),
            (transition.target_writer, transition.to_generation),
        }
        if (writer, generation) not in allowed_failed_epochs:
            raise ManualFailoverRejected("resume_failed_membership_epoch_mismatch")
        return ManualFailoverResumeDecision(
            transition_id=transition.transition_id,
            phase=transition.phase,
            action="terminal_failed",
            expected_writer=writer,
            expected_generation=generation,
            terminal=True,
        )

    if transition.phase in _PRE_PROMOTION_ACTIONS:
        expected_writer = transition.source_writer
        expected_generation = transition.from_generation
        action = _PRE_PROMOTION_ACTIONS[transition.phase]
        terminal = False
    elif transition.phase in _POST_PROMOTION_ACTIONS:
        expected_writer = transition.target_writer
        expected_generation = transition.to_generation
        action = _POST_PROMOTION_ACTIONS[transition.phase]
        terminal = transition.phase == "completed"
    else:  # restore_manual_failover_transition already rejects unknown phases.
        raise ManualFailoverRejected("resume_transition_phase_rejected")

    if writer != expected_writer or generation != expected_generation:
        raise ManualFailoverRejected("resume_membership_phase_mismatch")

    return ManualFailoverResumeDecision(
        transition_id=transition.transition_id,
        phase=transition.phase,
        action=action,
        expected_writer=expected_writer,
        expected_generation=expected_generation,
        terminal=terminal,
    )
