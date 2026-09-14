"""Read-only HA status projection for the authenticated web API."""
from __future__ import annotations

from typing import Any

from .ha_admission import writer_admission
from .ha_state import HAStateConflict, load_membership, load_transition
from .util import utc_now


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

    sync_service = getattr(runtime, "ha_state_reconciler", None)
    sync = sync_service.status() if sync_service is not None else None
    if initialized and sync is not None and sync.get("state") == "degraded":
        state = "degraded"
        reason = sync.get("reason") or "ha_sync_degraded"

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
        "detail": None,
    }
