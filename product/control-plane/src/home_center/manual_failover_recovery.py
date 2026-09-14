"""Strict restoration of durable manual-failover transition evidence.

A restart must never turn partially persisted or tampered transition evidence into
permission to advance writer membership.  This module validates the durable
record before reconstructing the pure transition state machine.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .manual_failover import (
    PHASES,
    TRANSITION_SCHEMA,
    ManualFailoverRejected,
    ManualFailoverTransition,
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_FIELDS = {
    "schema",
    "transition_id",
    "cluster_id",
    "source_writer",
    "target_writer",
    "from_generation",
    "to_generation",
    "phase",
    "version",
    "revision",
    "authoritative_sha256",
    "final_source_sequence",
    "started_at",
    "updated_at",
    "failure_reason",
}
_POST_SYNC_PHASES = {
    "final_sync_verified",
    "source_fenced",
    "target_promoted",
    "target_verified",
    "completed",
}
_PRE_SYNC_PHASES = {"planned", "source_quiesced"}


def _reject(reason: str) -> None:
    raise ManualFailoverRejected(f"transition_restore_{reason}")


def _bounded_string(payload: dict[str, Any], key: str, *, max_length: int = 128) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > max_length:
        _reject(f"{key}_rejected")
    return value


def _aware_datetime(value: Any, key: str) -> datetime:
    if not isinstance(value, str) or not value:
        _reject(f"{key}_rejected")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _reject(f"{key}_rejected")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        _reject(f"{key}_timezone_missing")
    return parsed


def restore_manual_failover_transition(payload: dict[str, Any]) -> ManualFailoverTransition:
    """Rebuild one durable transition record, failing closed on any ambiguity."""
    if not isinstance(payload, dict):
        _reject("payload_rejected")
    if set(payload) != _FIELDS:
        _reject("fields_rejected")
    if payload.get("schema") != TRANSITION_SCHEMA:
        _reject("schema_rejected")

    transition_id = _bounded_string(payload, "transition_id")
    cluster_id = _bounded_string(payload, "cluster_id")
    source_writer = _bounded_string(payload, "source_writer")
    target_writer = _bounded_string(payload, "target_writer")
    if source_writer == target_writer:
        _reject("writer_identity_rejected")

    from_generation = payload.get("from_generation")
    to_generation = payload.get("to_generation")
    if isinstance(from_generation, bool) or not isinstance(from_generation, int) or from_generation < 1:
        _reject("from_generation_rejected")
    if isinstance(to_generation, bool) or not isinstance(to_generation, int) or to_generation != from_generation + 1:
        _reject("to_generation_rejected")

    phase = payload.get("phase")
    if phase not in set(PHASES) | {"failed"}:
        _reject("phase_rejected")

    version = _bounded_string(payload, "version", max_length=64)
    revision = _bounded_string(payload, "revision", max_length=40)
    authoritative_sha256 = _bounded_string(payload, "authoritative_sha256", max_length=64)
    if _VERSION.fullmatch(version) is None:
        _reject("version_rejected")
    if _HEX40.fullmatch(revision) is None:
        _reject("revision_rejected")
    if _HEX64.fullmatch(authoritative_sha256) is None:
        _reject("authoritative_digest_rejected")

    final_source_sequence = payload.get("final_source_sequence")
    if final_source_sequence is not None and (
        isinstance(final_source_sequence, bool)
        or not isinstance(final_source_sequence, int)
        or final_source_sequence < 0
    ):
        _reject("final_source_sequence_rejected")
    if phase in _PRE_SYNC_PHASES and final_source_sequence is not None:
        _reject("premature_final_sequence")
    if phase in _POST_SYNC_PHASES and final_source_sequence is None:
        _reject("final_sequence_missing")

    started_at = payload.get("started_at")
    updated_at = payload.get("updated_at")
    started = _aware_datetime(started_at, "started_at")
    updated = _aware_datetime(updated_at, "updated_at")
    if updated < started:
        _reject("timestamp_order_rejected")

    failure_reason = payload.get("failure_reason")
    if phase == "failed":
        if not isinstance(failure_reason, str) or not failure_reason.strip() or len(failure_reason) > 256:
            _reject("failure_reason_missing")
    elif failure_reason is not None:
        _reject("unexpected_failure_reason")

    return ManualFailoverTransition(
        transition_id=transition_id,
        cluster_id=cluster_id,
        source_writer=source_writer,
        target_writer=target_writer,
        from_generation=from_generation,
        to_generation=to_generation,
        phase=phase,
        version=version,
        revision=revision,
        authoritative_sha256=authoritative_sha256,
        final_source_sequence=final_source_sequence,
        started_at=started_at,
        updated_at=updated_at,
        failure_reason=failure_reason,
    )
