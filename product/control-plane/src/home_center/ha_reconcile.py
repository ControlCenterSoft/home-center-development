"""Role-driven authoritative-state pull reconciliation over the peer mTLS channel."""
from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from typing import Any

from .authoritative_state import apply_authoritative_snapshot, snapshot_authoritative
from .config import Config, Peer
from .ha_peer import (
    HA_SNAPSHOT_SCHEMA,
    HA_STATUS_SCHEMA,
    HAPeerProtocolError,
    MTLHAPeerClient,
)
from .ha_state import (
    HAStateConflict,
    load_membership,
    load_transition,
    validate_membership,
    validate_transition,
)
from .release_identity import ReleaseIdentityError, current_release_identity
from .store import StateStore
from .util import utc_now

LOG = logging.getLogger("home_center.ha_reconcile")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
TAKEOVER_PHASES = frozenset({"target_promoted", "target_verified", "completed"})


class HAReconcileRejected(RuntimeError):
    """Peer evidence cannot safely advance local HA state."""


class HAStateReconciler:
    """Pull writer-owned state only from the authenticated durable writer."""

    def __init__(
        self,
        config: Config,
        store: StateStore,
        *,
        client: Any | None = None,
        release_identity_provider: Any = current_release_identity,
    ) -> None:
        self.config = config
        self.store = store
        self.client = client or MTLHAPeerClient(config)
        self._release_identity_provider = release_identity_provider
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="home-center-ha-reconcile", daemon=True)
        self._lock = threading.Lock()
        self._peer_clock: dict[str, tuple[str, int]] = {}
        self._status: dict[str, Any] = {
            "schema": "home-center.ha-sync-status.v1",
            "state": "inactive",
            "reason": "ha_not_initialized",
            "direction": None,
            "writer_node_id": None,
            "generation": None,
            "authoritative_sha256": None,
            "source_instance_id": None,
            "source_sequence": None,
            "last_success_at": None,
            "changed": False,
        }

    def start(self) -> None:
        """Start without making Home Center process startup depend on peer reachability."""
        try:
            self.reconcile_once()
        except Exception:
            LOG.exception("initial HA state reconciliation failed")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    def status(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._status))

    def _set_status(self, **changes: Any) -> None:
        with self._lock:
            self._status.update(changes)

    def _run(self) -> None:
        while not self._stop.wait(self.config.reconcile_interval_seconds):
            try:
                self.reconcile_once()
            except Exception:
                LOG.exception("HA state reconciliation failed")

    def _qualified_release(self) -> dict[str, Any]:
        try:
            release = self._release_identity_provider()
        except ReleaseIdentityError as exc:
            raise HAReconcileRejected("local_release_identity_unavailable") from exc
        if release.get("source") != "immutable-artifact":
            raise HAReconcileRejected("local_release_not_immutable")
        revision = release.get("revision")
        if not isinstance(revision, str) or _HEX40.fullmatch(revision) is None:
            raise HAReconcileRejected("local_release_revision_unqualified")
        return release

    def _single_peer(self, membership: dict[str, Any]) -> Peer:
        if len(self.config.peers) != 1:
            raise HAReconcileRejected("manual_two_node_ha_requires_one_peer")
        peer = self.config.peers[0]
        member_ids = {member["node_id"] for member in membership["members"]}
        if member_ids != {self.config.node_id, peer.node_id}:
            raise HAReconcileRejected("configured_peer_membership_mismatch")
        return peer

    def _validate_status(
        self,
        peer: Peer,
        status: dict[str, Any],
        release: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        required = {
            "schema", "cluster_id", "node_id", "version", "revision", "writer_admission",
            "membership", "transition", "authoritative_sha256", "source_instance_id",
            "source_sequence", "observed_at",
        }
        if set(status) != required or status.get("schema") != HA_STATUS_SCHEMA:
            raise HAReconcileRejected("peer_ha_status_shape_rejected")
        if status.get("cluster_id") != self.config.cluster_id or status.get("node_id") != peer.node_id:
            raise HAReconcileRejected("peer_ha_status_identity_rejected")
        if status.get("version") != release["version"] or status.get("revision") != release["revision"]:
            raise HAReconcileRejected("peer_release_drift")
        digest = status.get("authoritative_sha256")
        if not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
            raise HAReconcileRejected("peer_authoritative_digest_rejected")
        try:
            uuid.UUID(str(status.get("source_instance_id")))
        except (ValueError, AttributeError, TypeError) as exc:
            raise HAReconcileRejected("peer_source_instance_rejected") from exc
        sequence = status.get("source_sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise HAReconcileRejected("peer_source_sequence_rejected")
        membership = status.get("membership")
        if not isinstance(membership, dict):
            raise HAReconcileRejected("peer_membership_missing")
        validate_membership(membership, expected_cluster_id=self.config.cluster_id)
        transition = status.get("transition")
        if transition is not None:
            if not isinstance(transition, dict):
                raise HAReconcileRejected("peer_transition_rejected")
            validate_transition(transition, expected_cluster_id=self.config.cluster_id)
        admission = status.get("writer_admission")
        if not isinstance(admission, dict) or set(admission) != {
            "allowed", "reason", "writer_node_id", "generation"
        }:
            raise HAReconcileRejected("peer_writer_admission_rejected")
        if admission.get("writer_node_id") != membership["writer"] or admission.get("generation") != membership["generation"]:
            raise HAReconcileRejected("peer_writer_admission_epoch_mismatch")
        if membership["writer"] == peer.node_id:
            if admission.get("allowed") is not True:
                raise HAReconcileRejected("peer_writer_admission_not_active")
        elif admission.get("allowed") is not False:
            raise HAReconcileRejected("peer_nonwriter_admission_active")
        return membership, transition

    def _takeover_proven(
        self,
        local_membership: dict[str, Any],
        peer_membership: dict[str, Any],
        peer_transition: dict[str, Any] | None,
        peer: Peer,
    ) -> bool:
        if peer_membership["generation"] != local_membership["generation"] + 1:
            return False
        if local_membership["writer"] != self.config.node_id or peer_membership["writer"] != peer.node_id:
            return False
        if peer_transition is None or peer_transition.get("phase") not in TAKEOVER_PHASES:
            return False
        return (
            peer_transition.get("source_writer") == self.config.node_id
            and peer_transition.get("target_writer") == peer.node_id
            and peer_transition.get("from_generation") == local_membership["generation"]
            and peer_transition.get("to_generation") == peer_membership["generation"]
        )

    def _validate_export(
        self,
        peer: Peer,
        export: dict[str, Any],
        release: dict[str, Any],
        expected_membership: dict[str, Any],
    ) -> tuple[dict[str, Any], str, int]:
        required = {
            "schema", "cluster_id", "node_id", "version", "revision", "membership",
            "transition", "authoritative_sha256", "source_instance_id", "source_sequence",
            "generated_at", "snapshot",
        }
        if set(export) != required or export.get("schema") != HA_SNAPSHOT_SCHEMA:
            raise HAReconcileRejected("peer_ha_snapshot_shape_rejected")
        if export.get("cluster_id") != self.config.cluster_id or export.get("node_id") != peer.node_id:
            raise HAReconcileRejected("peer_ha_snapshot_identity_rejected")
        if export.get("version") != release["version"] or export.get("revision") != release["revision"]:
            raise HAReconcileRejected("peer_snapshot_release_drift")
        membership = export.get("membership")
        if membership != expected_membership or membership.get("writer") != peer.node_id:
            raise HAReconcileRejected("peer_snapshot_membership_changed")
        snapshot = export.get("snapshot")
        if not isinstance(snapshot, dict):
            raise HAReconcileRejected("peer_snapshot_missing")
        digest = export.get("authoritative_sha256")
        if digest != snapshot.get("authoritative_sha256") or not isinstance(digest, str) or _HEX64.fullmatch(digest) is None:
            raise HAReconcileRejected("peer_snapshot_digest_rejected")
        source_instance_id = export.get("source_instance_id")
        try:
            uuid.UUID(str(source_instance_id))
        except (ValueError, AttributeError, TypeError) as exc:
            raise HAReconcileRejected("peer_snapshot_source_instance_rejected") from exc
        source_sequence = export.get("source_sequence")
        if isinstance(source_sequence, bool) or not isinstance(source_sequence, int) or source_sequence < 1:
            raise HAReconcileRejected("peer_snapshot_source_sequence_rejected")
        previous = self._peer_clock.get(peer.node_id)
        if previous is not None and previous[0] == source_instance_id and source_sequence <= previous[1]:
            raise HAReconcileRejected("peer_snapshot_sequence_not_monotonic")
        return snapshot, str(source_instance_id), source_sequence

    def _local_digest(self) -> str:
        with self.store._lock:  # noqa: SLF001 - canonical StateStore transaction domain
            return snapshot_authoritative(self.store._connection)["authoritative_sha256"]  # noqa: SLF001

    def reconcile_once(self) -> None:
        with self.store._lock:  # noqa: SLF001 - canonical StateStore transaction domain
            local_membership = load_membership(self.store._connection)  # noqa: SLF001
        if local_membership is None:
            self._set_status(
                state="inactive",
                reason="ha_not_initialized",
                direction=None,
                writer_node_id=None,
                generation=None,
                changed=False,
            )
            return

        try:
            release = self._qualified_release()
            peer = self._single_peer(local_membership)
            peer_status = self.client.fetch_status(peer)
            peer_membership, peer_transition = self._validate_status(peer, peer_status, release)

            local_generation = local_membership["generation"]
            peer_generation = peer_membership["generation"]
            if peer_generation < local_generation:
                if local_membership["writer"] != self.config.node_id:
                    raise HAReconcileRejected("writer_peer_generation_regressed")
                reason = "peer_stale_writer" if peer_status["writer_admission"]["allowed"] else "peer_epoch_behind"
                self._set_status(
                    state="writer",
                    reason=reason,
                    direction=None,
                    writer_node_id=self.config.node_id,
                    generation=local_generation,
                    authoritative_sha256=self._local_digest(),
                    changed=False,
                )
                return

            if peer_generation == local_generation:
                if peer_membership["writer"] != local_membership["writer"]:
                    raise HAReconcileRejected("same_generation_writer_conflict")
                if peer_membership != local_membership:
                    raise HAReconcileRejected("same_generation_membership_conflict")
                if local_membership["writer"] == self.config.node_id:
                    local_digest = self._local_digest()
                    self._set_status(
                        state="writer",
                        reason=(
                            "writer_peer_in_sync"
                            if peer_status["authoritative_sha256"] == local_digest
                            else "writer_peer_state_drift"
                        ),
                        direction=None,
                        writer_node_id=self.config.node_id,
                        generation=local_generation,
                        authoritative_sha256=local_digest,
                        changed=False,
                    )
                    return
                if local_membership["writer"] != peer.node_id:
                    raise HAReconcileRejected("configured_writer_peer_missing")
            elif not self._takeover_proven(local_membership, peer_membership, peer_transition, peer):
                if peer_generation > local_generation + 1:
                    raise HAReconcileRejected("peer_membership_generation_gap")
                raise HAReconcileRejected("peer_takeover_not_proven")

            export = self.client.fetch_snapshot(peer)
            snapshot, source_instance_id, source_sequence = self._validate_export(
                peer,
                export,
                release,
                peer_membership,
            )
            with self.store._lock:  # noqa: SLF001 - canonical StateStore transaction domain
                result = apply_authoritative_snapshot(self.store._connection, snapshot)  # noqa: SLF001
                applied_membership = load_membership(self.store._connection)  # noqa: SLF001
                applied_transition = load_transition(self.store._connection)  # noqa: SLF001
            if applied_membership != export["membership"] or applied_transition != export["transition"]:
                raise HAReconcileRejected("post_apply_ha_state_mismatch")
            self._peer_clock[peer.node_id] = (source_instance_id, source_sequence)
            self._set_status(
                state="standby",
                reason="authoritative_state_synchronized",
                direction=f"{peer.node_id}->{self.config.node_id}",
                writer_node_id=peer.node_id,
                generation=peer_membership["generation"],
                authoritative_sha256=result["authoritative_sha256"],
                source_instance_id=source_instance_id,
                source_sequence=source_sequence,
                last_success_at=utc_now(),
                changed=result["changed"],
            )
        except (
            HAReconcileRejected,
            HAPeerProtocolError,
            HAStateConflict,
            ValueError,
            TypeError,
            KeyError,
        ) as exc:
            self._set_status(
                state="degraded",
                reason=str(exc),
                changed=False,
            )
            raise
