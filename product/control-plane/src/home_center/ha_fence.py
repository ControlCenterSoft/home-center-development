"""Pure role-driven network-fence policy for two-node manual HA."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .config import Config
from .ha_state import load_membership

FENCE_MODES = frozenset({"writer", "standby", "isolated"})
FENCE_OVERRIDES = frozenset({"standby", "isolated"})


class HAFenceRejected(RuntimeError):
    """The local HA state cannot safely determine a fence policy."""


@dataclass(frozen=True, slots=True)
class HAFencePolicy:
    mode: str
    target_address: str
    peer_addresses: tuple[str, ...]
    protected_ports: tuple[int, ...] = (8443, 9443)
    peer_allowed_ports: tuple[int, ...] = (9443,)

    @property
    def fenced(self) -> bool:
        return self.mode != "writer"

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "home-center.ha-fence-policy.v1",
            "mode": self.mode,
            "target_address": self.target_address,
            "peer_addresses": list(self.peer_addresses),
            "protected_ports": list(self.protected_ports),
            "peer_allowed_ports": list(self.peer_allowed_ports) if self.mode == "standby" else [],
            "fenced": self.fenced,
        }


def resolve_fence_mode(
    connection: sqlite3.Connection | None,
    config: Config,
    *,
    override: str | None = None,
) -> str:
    """Resolve a fail-closed fence mode from an explicit override or durable writer epoch."""
    if override is not None:
        if override not in FENCE_OVERRIDES:
            raise HAFenceRejected("ha_fence_override_rejected")
        return override

    # Before the canonical DB exists there is no durable epoch yet; bootstrap role
    # is the only available source of truth. Once the DB exists callers must pass
    # a real connection so corruption/read failures cannot silently fall back.
    if connection is None:
        return "standby" if config.role == "standby" else "writer"

    membership = load_membership(connection)
    if membership is None:
        return "standby" if config.role == "standby" else "writer"

    member_ids = {member["node_id"] for member in membership["members"]}
    expected_ids = {config.node_id, *(peer.node_id for peer in config.peers)}
    if member_ids != expected_ids:
        raise HAFenceRejected("ha_fence_membership_identity_mismatch")
    return "writer" if membership["writer"] == config.node_id else "standby"


def fence_policy(
    connection: sqlite3.Connection | None,
    config: Config,
    *,
    override: str | None = None,
) -> HAFencePolicy:
    mode = resolve_fence_mode(connection, config, override=override)
    peer_addresses = tuple(sorted({peer.address for peer in config.peers}))
    membership_initialized = connection is not None and load_membership(connection) is not None
    if mode == "standby" and not peer_addresses and membership_initialized:
        raise HAFenceRejected("ha_fence_peer_address_missing")
    return HAFencePolicy(
        mode=mode,
        target_address=config.management_address,
        peer_addresses=peer_addresses,
    )
