"""Read-only HA status projection for the authenticated web API."""
from __future__ import annotations

import re
import uuid
from typing import Any

from .ha_admission import writer_admission
from .ha_state import HAStateConflict, load_membership, load_transition
from .util import utc_now

_SYNC_STATUS_SCHEMA = "home-center.ha-sync-status.v1"
_SYNC_STATUS_FIELDS = frozenset({
    "schema",
    "state",
    "reason",
    "direction",
    "writer_node_id",
    "generation",
    "authoritative_sha256",
    "source_instance_id",
    "source_sequence",
    "last_success_at",
    "changed",
})
_SYNC_STATES = frozenset({"inactive", "writer", "standby", "degraded"})
_SYNC_DEGRADED_REASONS = frozenset({
    "writer_peer_state_drift",
    "peer_stale_writer",
    "peer_epoch_behind",
})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _degraded_sync_status(*, reason: str, writer_node_id: str | None, generation: int | None) -> dict[str, Any]:
    return {
        "schema": _SYNC_STATUS_SCHEMA,
        "state": "degraded",
        "reason": reason,
        "direction": None,
        "writer_node_id": writer_node_id,
        "generation": generation,
        "authoritative_sha256": None,
        "source_instance_id": None,
        "source_sequence": None,
        "last_success_at": None,
        "changed": False,
    }


def _sync_status_is_well_formed(candidate: Any) -> bool:
    if not isinstance(candidate, dict) or set(candidate) != _SYNC_STATUS_FIELDS:
        return False
    if candidate.get("schema") != _SYNC_STATUS_SCHEMA:
        return False

    state = candidate.get("state")
    reason = candidate.get("reason")
    if state not in _SYNC_STATES or not isinstance(reason, str) or not reason:
        return False

    direction = candidate.get("direction")
    if direction is not None and (not isinstance(direction, str) or not direction):
        return False

    writer_node_id = candidate.get("writer_node_id")
    if writer_node_id is not None and (not isinstance(writer_node_id, str) or not writer_node_id):
        return False

    generation = candidate.get("generation")
    if generation is not None and (
        isinstance(generation, bool) or not isinstance(generation, int) or generation < 0
    ):
        return False

    digest = candidate.get("authoritative_sha256")
    if digest is not None and (not isinstance(digest, str) or _HEX64.fullmatch(digest) is None):
        return False

    source_instance_id = candidate.get("source_instance_id")
    if source_instance_id is not None:
        if not isinstance(source_instance_id, str):
            return False
        try:
            uuid.UUID(source_instance_id)
        except ValueError:
            return False

    source_sequence = candidate.get("source_sequence")
    if source_sequence is not None and (
        isinstance(source_sequence, bool) or not isinstance(source_sequence, int) or source_sequence < 0
    ):
        return False

    last_success_at = candidate.get("last_success_at")
    if last_success_at is not None and (
        not isinstance(last_success_at, str) or not last_success_at.endswith("Z")
    ):
        return False

    return isinstance(candidate.get("changed"), bool)


def status(runtime: Any) -> dict[str, Any]:
    """Return fail-closed HA state without mutating cluster state."""
    try:
        with runtime.store._lock:  # noqa: SLF001 - canonical StateStore transaction domain
            membership = load_membership(runtime.store._connection)  # noqa: SLF001
            transition = load_transition(runtime.store._connection)  # noqa: SLF001
            admission = writer_admission(
                runtime.store._connection,  # noqa: SLF001
                local_node_id=runtime.config.node_id,
                bootstrap_role=runtime.config.role,
            )
    except (HAStateConflict, ValueError, TypeError) as exc:
        return {
            "schema": "home-center.ha-status.v1",
            "observed_at": utc_now(),
            "cluster_id": runtime.config.cluster_id,
            "node_id": runtime.config.node_id,
            "initialized": True,
            "state": "degraded",
            "reason": "ha_state_invalid",
            "config_role": runtime.config.role,
            "effective_role": "unknown",
            "writer_node_id": None,
            "generation": None,
            "automatic_failover": False,
            "membership": None,
            "transition": None,
            "sync": None,
            "detail": type(exc).__name__,
        }

    initialized = membership is not None
    if membership is None:
        writer = runtime.config.node_id if runtime.config.role != "standby" else None
        generation = None
        effective_role = runtime.config.role
        state = "standalone" if runtime.config.role != "standby" else "standby"
        reason = admission.reason
    else:
        writer = membership["writer"]
        generation = membership["generation"]
        effective_role = "leader" if writer == runtime.config.node_id else "standby"
        state = "writer" if admission.allowed else "standby"
        reason = admission.reason

    detail = None
    sync_service = getattr(runtime, "ha_state_reconciler", None)
    sync = None
    if sync_service is not None:
        try:
            candidate = sync_service.status()
        except Exception as exc:  # status projection must fail closed on reconciler observability failure
            sync = _degraded_sync_status(
                reason="ha_sync_status_unavailable",
                writer_node_id=writer,
                generation=generation,
            )
            detail = type(exc).__name__
        else:
            if not _sync_status_is_well_formed(candidate):
                sync = _degraded_sync_status(
                    reason="ha_sync_status_invalid",
                    writer_node_id=writer,
                    generation=generation,
                )
                detail = type(candidate).__name__
            elif initialized and (
                not isinstance(candidate.get("writer_node_id"), str)
                or candidate.get("writer_node_id") != writer
                or isinstance(candidate.get("generation"), bool)
                or not isinstance(candidate.get("generation"), int)
                or candidate.get("generation") != generation
            ):
                sync = _degraded_sync_status(
                    reason="ha_sync_epoch_mismatch",
                    writer_node_id=writer,
                    generation=generation,
                )
                detail = "reconciler_epoch_mismatch"
            else:
                sync = candidate

    if initialized and sync is not None:
        sync_state = sync.get("state")
        sync_reason = sync.get("reason")
        if sync_state == "degraded" or sync_reason in _SYNC_DEGRADED_REASONS:
            state = "degraded"
            reason = sync_reason or "ha_sync_degraded"

    return {
        "schema": "home-center.ha-status.v1",
        "observed_at": utc_now(),
        "cluster_id": runtime.config.cluster_id,
        "node_id": runtime.config.node_id,
        "initialized": initialized,
        "state": state,
        "reason": reason,
        "config_role": runtime.config.role,
        "effective_role": effective_role,
        "writer_node_id": writer,
        "generation": generation,
        "automatic_failover": False,
        "membership": membership,
        "transition": transition,
        "sync": sync,
        "detail": detail,
    }
