"""Read-only node reconciliation for an arbitrary configured peer set."""
from __future__ import annotations
import json, logging, ssl, threading, urllib.error, urllib.request
from typing import Any
from .config import Config, Peer
from .ha_peer_snapshot import HAPeerStateSnapshot, build_peer_state_snapshot
from .inventory import collect
from .store import StateStore

LOG = logging.getLogger("home_center.reconcile")

class Reconciler:
    def __init__(self, config: Config, store: StateStore) -> None:
        self.config = config
        self.store = store
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="home-center-reconcile", daemon=True)
        self._latest_local: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._peer_states = {peer.node_id: "unknown" for peer in config.peers}

    def start(self) -> None:
        self.reconcile_once(); self._thread.start()

    def stop(self) -> None:
        self._stop.set(); self._thread.join(timeout=5)

    def local_capability(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._latest_local))

    def ha_state_snapshot(self) -> HAPeerStateSnapshot:
        """Return an immutable fail-closed snapshot of configured HA membership."""

        configured_node_ids = (self.config.node_id, *(peer.node_id for peer in self.config.peers))
        return build_peer_state_snapshot(
            cluster_id=self.config.cluster_id,
            configured_node_ids=configured_node_ids,
            node_rows=self.store.nodes(),
            audit_events=self.store.audit_events(limit=500),
        )

    def _run(self) -> None:
        while not self._stop.wait(self.config.reconcile_interval_seconds):
            try: self.reconcile_once()
            except Exception: LOG.exception("reconcile iteration failed")

    def reconcile_once(self) -> None:
        local = collect(self.config.node_id, self.config.node_name, self.config.role, self.config.management_address)
        with self._lock: self._latest_local = local
        self.store.upsert_node(local, "ready")
        for peer in self.config.peers:
            try:
                capability = self._fetch_peer(peer)
                self._validate_peer(peer, capability)
                self.store.upsert_node(capability, "ready")
                self._transition_peer(peer, "ready", None)
            except Exception as exc:
                self.store.mark_node(peer.node_id, "unreachable")
                self._transition_peer(peer, "unreachable", self._failure_class(exc))

    def _fetch_peer(self, peer: Peer) -> dict[str, Any]:
        context = ssl.create_default_context(cafile=str(self.config.cluster_ca))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(str(self.config.tls_certificate), str(self.config.tls_private_key))
        request = urllib.request.Request(f"{peer.url}/internal/v1/node", headers={"Accept": "application/json", "User-Agent": "home-center-peer/1"})
        with urllib.request.urlopen(request, timeout=self.config.peer_timeout_seconds, context=context) as response:
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise RuntimeError("peer response rejected")
            body = response.read(256 * 1024 + 1)
            if len(body) > 256 * 1024: raise RuntimeError("peer response is too large")
        envelope = json.loads(body)
        if envelope.get("schema") != "home-center.peer-node.v1" or envelope.get("cluster_id") != self.config.cluster_id:
            raise ValueError("peer envelope rejected")
        capability = envelope.get("capability")
        if not isinstance(capability, dict): raise ValueError("missing peer capability")
        return capability

    @staticmethod
    def _validate_peer(peer: Peer, capability: dict[str, Any]) -> None:
        if capability.get("schema") != "home-center.node-capability.v1": raise ValueError("unsupported capability schema")
        node = capability.get("node")
        if not isinstance(node, dict): raise ValueError("missing node identity")
        expected = {"id": peer.node_id, "name": peer.name, "address": peer.address}
        if any(node.get(key) != value for key, value in expected.items()): raise ValueError("peer identity mismatch")

    def _transition_peer(self, peer: Peer, state: str, reason: str | None) -> None:
        old = self._peer_states.get(peer.node_id, "unknown")
        if state == old: return
        self._peer_states[peer.node_id] = state
        self.store.audit(actor="system:reconciler", action="peer.health.transition", target=peer.node_id, outcome=state, correlation_id=f"peer-{peer.node_id}", details={"from": old, "to": state, "reason_class": reason})

    @staticmethod
    def _failure_class(exc: Exception) -> str:
        if isinstance(exc, urllib.error.HTTPError): return f"http_{exc.code}"
        if isinstance(exc, urllib.error.URLError):
            reason = exc.reason
            if isinstance(reason, ssl.SSLCertVerificationError): return f"tls_verify_{reason.verify_code}"
            if isinstance(reason, ssl.SSLError): return "tls_handshake"
            if isinstance(reason, OSError) and reason.errno is not None: return f"transport_errno_{reason.errno}"
            return f"transport_{type(reason).__name__}"
        if isinstance(exc, json.JSONDecodeError): return "peer_json_invalid"
        return type(exc).__name__
