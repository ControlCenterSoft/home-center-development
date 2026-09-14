"""Authoritative mutation admission derived from durable HA membership."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .ha_state import HAStateConflict, load_membership


@dataclass(frozen=True, slots=True)
class WriterAdmission:
    allowed: bool
    reason: str
    writer_node_id: str | None
    generation: int | None


def writer_admission(
    connection: sqlite3.Connection,
    *,
    local_node_id: str,
    bootstrap_role: str,
) -> WriterAdmission:
    """Fail closed for stale/standby writers while preserving single-node compatibility."""
    try:
        membership = load_membership(connection)
    except (HAStateConflict, ValueError, TypeError, sqlite3.Error):
        return WriterAdmission(False, "ha_state_invalid", None, None)

    if membership is None:
        if bootstrap_role == "standby":
            return WriterAdmission(False, "standby_without_writer_epoch", None, None)
        return WriterAdmission(True, "single_node_or_pre_ha_bootstrap", local_node_id, None)

    writer = membership["writer"]
    generation = membership["generation"]
    if writer != local_node_id:
        return WriterAdmission(False, "local_node_is_not_writer", writer, generation)
    return WriterAdmission(True, "local_node_is_writer", writer, generation)
