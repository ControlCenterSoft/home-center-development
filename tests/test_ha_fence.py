from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from home_center.config import Config, Peer
from home_center.ha_fence import HAFenceRejected, fence_policy, resolve_fence_mode
from home_center.ha_state import initialize_membership
from home_center.store import StateStore


def config(root: Path, *, node_id: str, role: str, peer: Peer) -> Config:
    return Config(
        cluster_id="cluster-test",
        node_id=node_id,
        node_name=node_id,
        role=role,
        management_address="192.0.2.10" if node_id == "node-a" else "192.0.2.11",
        web_port=8443,
        peer_port=9443,
        state_db=root / f"{node_id}.db",
        backup_dir=root / "backups",
        web_root=root / "web",
        local_admin_credentials_file=root / "local-admin.json",
        session_key_file=root / "session.key",
        audit_key_file=root / "audit.key",
        tls_certificate=root / "node.crt",
        tls_private_key=root / "node.key",
        cluster_ca=root / "ca.crt",
        web_ca=root / "web-ca.crt",
        deployment_profile=root / "deployment-profile.json",
        peers=(peer,),
        reconcile_interval_seconds=15,
        peer_timeout_seconds=3,
    )


def membership(*, writer: str = "node-a", peer_node_id: str = "node-b") -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": 1,
        "writer": writer,
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": peer_node_id, "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-14T12:00:00Z",
    }


class HAFencePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.peer_b = Peer(
            "node-b",
            "node-b",
            "192.0.2.11",
            "https://192.0.2.11:9443",
            "node-b-cert",
        )
        self.config_a = config(self.root, node_id="node-a", role="leader", peer=self.peer_b)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_bootstrap_without_database_uses_static_role_only(self) -> None:
        self.assertEqual("writer", resolve_fence_mode(None, self.config_a))
        standby_config = config(
            self.root,
            node_id="node-a",
            role="standby",
            peer=self.peer_b,
        )
        self.assertEqual("standby", resolve_fence_mode(None, standby_config))

    def test_durable_writer_epoch_overrides_bootstrap_config_role_both_directions(self) -> None:
        store = StateStore(self.root / "state-a.db", b"a" * 32, "cluster-test")
        try:
            initialize_membership(store._connection, membership(writer="node-b"))
            self.assertEqual("standby", resolve_fence_mode(store._connection, self.config_a))

            promoted_static_standby = config(
                self.root,
                node_id="node-b",
                role="standby",
                peer=Peer(
                    "node-a",
                    "node-a",
                    "192.0.2.10",
                    "https://192.0.2.10:9443",
                    "node-a-cert",
                ),
            )
            self.assertEqual("writer", resolve_fence_mode(store._connection, promoted_static_standby))
        finally:
            store.close()

    def test_isolated_and_standby_overrides_are_persistent_safe_modes_only(self) -> None:
        self.assertEqual("isolated", resolve_fence_mode(None, self.config_a, override="isolated"))
        self.assertEqual("standby", resolve_fence_mode(None, self.config_a, override="standby"))
        for unsafe in ("writer", "auto", "", "leader"):
            with self.assertRaisesRegex(HAFenceRejected, "override_rejected"):
                resolve_fence_mode(None, self.config_a, override=unsafe)

    def test_initialized_membership_identity_mismatch_fails_closed(self) -> None:
        store = StateStore(self.root / "state-mismatch.db", b"a" * 32, "cluster-test")
        try:
            initialize_membership(
                store._connection,
                membership(writer="node-a", peer_node_id="node-c"),
            )
            with self.assertRaisesRegex(HAFenceRejected, "identity_mismatch"):
                resolve_fence_mode(store._connection, self.config_a)
        finally:
            store.close()

    def test_standby_policy_protects_web_and_peer_ports_but_allows_peer_only_on_peer_port(self) -> None:
        store = StateStore(self.root / "state-policy.db", b"a" * 32, "cluster-test")
        try:
            initialize_membership(store._connection, membership(writer="node-b"))
            policy = fence_policy(store._connection, self.config_a)
            self.assertEqual("standby", policy.mode)
            self.assertTrue(policy.fenced)
            self.assertEqual("192.0.2.10", policy.target_address)
            self.assertEqual(("192.0.2.11",), policy.peer_addresses)
            self.assertEqual((8443, 9443), policy.protected_ports)
            self.assertEqual((9443,), policy.peer_allowed_ports)
            rendered = policy.as_dict()
            self.assertEqual([9443], rendered["peer_allowed_ports"])
            self.assertEqual([8443, 9443], rendered["protected_ports"])
        finally:
            store.close()

    def test_isolated_policy_allows_no_remote_peer_ports(self) -> None:
        policy = fence_policy(None, self.config_a, override="isolated")
        self.assertEqual("isolated", policy.mode)
        self.assertTrue(policy.fenced)
        self.assertEqual([], policy.as_dict()["peer_allowed_ports"])


if __name__ == "__main__":
    unittest.main()
