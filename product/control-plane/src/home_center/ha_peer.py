"""Bounded HA protocol primitives for the existing mutually-authenticated peer TLS channel."""
from __future__ import annotations

import json
import re
import ssl
import threading
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any

from .authoritative_state import snapshot_authoritative
from .config import Config, Peer
from .ha_admission import writer_admission
from .ha_state import HAStateConflict, load_membership, load_transition
from .release_identity import ReleaseIdentityError, current_release_identity
from .util import utc_now

HA_STATUS_SCHEMA = "home-center.ha-peer-status.v1"
HA_SNAPSHOT_SCHEMA = "home-center.ha-peer-authoritative-state.v1"
MAX_HA_STATUS_BYTES = 512 * 1024
MAX_HA_SNAPSHOT_BYTES = 32 * 1024 * 1024
_HEX40 = re.compile(r"^[0-9a-f]{40}$")


class HAPeerProtocolError(RuntimeError):
    """The authenticated peer returned an invalid or unsafe HA response."""


@dataclass(frozen=True, slots=True)
class ExportClockValue:
    source_instance_id: str
    source_sequence: int


class HAPeerExportClock:
    """Process-local monotonic export sequence paired with a unique source instance."""

    def __init__(self, source_instance_id: str | None = None) -> None:
        self._instance_id = source_instance_id or str(uuid.uuid4())
        self._sequence = 0
        self._lock = threading.Lock()

    def current(self) -> ExportClockValue:
        with self._lock:
            return ExportClockValue(self._instance_id, self._sequence)

    def next(self) -> ExportClockValue:
        with self._lock:
            self._sequence += 1
            return ExportClockValue(self._instance_id, self._sequence)


def _qualified_release() -> dict[str, Any]:
    try:
        release = current_release_identity()
    except ReleaseIdentityError as exc:
        raise HAPeerProtocolError("ha_release_identity_unavailable") from exc
    if release.get("source") != "immutable-artifact":
        raise HAPeerProtocolError("ha_requires_immutable_release")
    revision = release.get("revision")
    if not isinstance(revision, str) or _HEX40.fullmatch(revision) is None:
        raise HAPeerProtocolError("ha_release_revision_unqualified")
    return release


def _local_ha_state(runtime: Any) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any], Any]:
    try:
        with runtime.store._lock:  # noqa: SLF001 - canonical StateStore transaction domain
            membership = load_membership(runtime.store._connection)  # noqa: SLF001
            transition = load_transition(runtime.store._connection)  # noqa: SLF001
            snapshot = snapshot_authoritative(runtime.store._connection)  # noqa: SLF001
            admission = writer_admission(
                runtime.store._connection,  # noqa: SLF001
                local_node_id=runtime.config.node_id,
                bootstrap_role=runtime.config.role,
            )
    except (HAStateConflict, ValueError, TypeError) as exc:
        raise HAPeerProtocolError("ha_local_state_invalid") from exc
    return membership, transition, snapshot, admission


def build_ha_status(runtime: Any) -> dict[str, Any]:
    """Build non-secret HA evidence for an authenticated cluster peer."""
    release = _qualified_release()
    clock = runtime.ha_export_clock.current()
    membership, transition, snapshot, admission = _local_ha_state(runtime)
    return {
        "schema": HA_STATUS_SCHEMA,
        "cluster_id": runtime.config.cluster_id,
        "node_id": runtime.config.node_id,
        "version": release["version"],
        "revision": release["revision"],
        "writer_admission": {
            "allowed": admission.allowed,
            "reason": admission.reason,
            "writer_node_id": admission.writer_node_id,
            "generation": admission.generation,
        },
        "membership": membership,
        "transition": transition,
        "authoritative_sha256": snapshot["authoritative_sha256"],
        "source_instance_id": clock.source_instance_id,
        "source_sequence": clock.source_sequence,
        "observed_at": utc_now(),
    }


def build_authoritative_export(runtime: Any) -> dict[str, Any]:
    """Export writer-owned state only when this node is the durable writer."""
    release = _qualified_release()
    membership, transition, snapshot, admission = _local_ha_state(runtime)
    if membership is None:
        raise HAPeerProtocolError("ha_membership_not_initialized")
    if not admission.allowed or membership.get("writer") != runtime.config.node_id:
        raise HAPeerProtocolError("ha_export_requires_durable_writer")
    clock = runtime.ha_export_clock.next()
    return {
        "schema": HA_SNAPSHOT_SCHEMA,
        "cluster_id": runtime.config.cluster_id,
        "node_id": runtime.config.node_id,
        "version": release["version"],
        "revision": release["revision"],
        "membership": membership,
        "transition": transition,
        "authoritative_sha256": snapshot["authoritative_sha256"],
        "source_instance_id": clock.source_instance_id,
        "source_sequence": clock.source_sequence,
        "generated_at": utc_now(),
        "snapshot": snapshot,
    }


class MTLHAPeerClient:
    """Read HA evidence through the existing cluster CA and node certificate identity."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def _context(self) -> ssl.SSLContext:
        context = ssl.create_default_context(cafile=str(self.config.cluster_ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(self.config.tls_certificate), str(self.config.tls_private_key))
        return context

    def _get_json(self, peer: Peer, path: str, *, max_bytes: int) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{peer.url}{path}",
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "User-Agent": "home-center-ha-peer/1",
            },
        )
        with urllib.request.urlopen(
            request,
            timeout=self.config.peer_timeout_seconds,
            context=self._context(),
        ) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise HAPeerProtocolError("ha_peer_response_rejected")
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise HAPeerProtocolError("ha_peer_response_too_large")
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HAPeerProtocolError("ha_peer_json_rejected") from exc
        if not isinstance(value, dict):
            raise HAPeerProtocolError("ha_peer_object_required")
        return value

    def fetch_status(self, peer: Peer) -> dict[str, Any]:
        return self._get_json(peer, "/internal/v1/ha/status", max_bytes=MAX_HA_STATUS_BYTES)

    def fetch_snapshot(self, peer: Peer) -> dict[str, Any]:
        return self._get_json(peer, "/internal/v1/ha/authoritative-state", max_bytes=MAX_HA_SNAPSHOT_BYTES)