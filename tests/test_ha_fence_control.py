from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from home_center.config import Config, Peer
from home_center.ha_fence_control import (
    FenceOverrideStore,
    HAFenceControlError,
    execute_fence_command,
)
from home_center.ha_state import initialize_membership
from home_center.store import StateStore


class FakeFirewall:
    def __init__(self) -> None:
        self.chains: dict[str, list[tuple[str, ...]]] = {}
        self.jumps: set[tuple[int, str]] = set()
        self.fail_remove = False

    def managed_chains(self) -> tuple[str, ...]:
        return tuple(sorted(self.chains))

    def create_chain(self, chain: str) -> None:
        self.chains[chain] = []

    def append_rule(self, chain: str, rule) -> None:
        self.chains[chain].append(tuple(rule))

    def insert_jump(self, _policy, port: int, chain: str) -> None:
        self.jumps.add((port, chain))

    def remove_jump(self, _policy, port: int, chain: str) -> None:
        if self.fail_remove:
            raise RuntimeError("forced remove failure")
        self.jumps.discard((port, chain))

    def jump_exists(self, _policy, port: int, chain: str) -> bool:
        return (port, chain) in self.jumps

    def rule_exists(self, chain: str, rule) -> bool:
        return tuple(rule) in self.chains.get(chain, [])

    def rule_count(self, chain: str) -> int:
        return len(self.chains.get(chain, []))

    def delete_chain(self, chain: str) -> None:
        if any(target == chain for _, target in self.jumps):
            raise RuntimeError("chain referenced")
        self.chains.pop(chain, None)


def config(root: Path) -> Config:
    peer = Peer(
        "node-b",
        "node-b",
        "192.0.2.11",
        "https://192.0.2.11:9443",
        "node-b-cert",
    )
    return Config(
        cluster_id="cluster-test",
        node_id="node-a",
        node_name="node-a",
        role="leader",
        management_address="192.0.2.10",
        web_port=8443,
        peer_port=9443,
        state_db=root / "state.db",
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


def membership(writer: str = "node-a") -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": 1,
        "writer": writer,
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": "node-b", "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-14T12:00:00Z",
    }


class HAFenceControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = StateStore(self.root / "state.db", b"a" * 32, "cluster-test")
        initialize_membership(self.store._connection, membership())
        self.config = config(self.root)
        self.override_path = self.root / "fence-state" / "override"
        self.overrides = FenceOverrideStore(self.override_path, expected_uid=os.geteuid())

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_override_store_round_trip_is_exact_and_root_style_permissions_are_enforced(self) -> None:
        self.assertIsNone(self.overrides.read())
        self.overrides.write("isolated")
        self.assertEqual("isolated", self.overrides.read())
        self.assertEqual(0o700, self.override_path.parent.stat().st_mode & 0o777)
        self.assertEqual(0o600, self.override_path.stat().st_mode & 0o777)
        self.overrides.clear()
        self.assertIsNone(self.overrides.read())

    def test_malformed_or_relaxed_override_file_fails_closed(self) -> None:
        self.overrides.write("isolated")
        self.override_path.chmod(0o644)
        with self.assertRaisesRegex(HAFenceControlError, "file_rejected"):
            self.overrides.read()
        self.override_path.chmod(0o600)
        self.override_path.write_text("writer\n", encoding="ascii")
        self.override_path.chmod(0o600)
        with self.assertRaisesRegex(HAFenceControlError, "value_rejected"):
            self.overrides.read()

    def test_isolate_persists_before_firewall_activation(self) -> None:
        firewall = FakeFirewall()
        result = execute_fence_command(
            "isolate",
            config=self.config,
            connection=self.store._connection,
            firewall=firewall,
            overrides=self.overrides,
        )
        self.assertEqual("isolated", self.overrides.read())
        self.assertEqual("isolated", result["policy"]["mode"])
        self.assertTrue(result["runtime"]["active"])

    def test_auto_clears_override_only_after_writer_policy_is_applied(self) -> None:
        firewall = FakeFirewall()
        execute_fence_command(
            "isolate",
            config=self.config,
            connection=self.store._connection,
            firewall=firewall,
            overrides=self.overrides,
        )
        result = execute_fence_command(
            "auto",
            config=self.config,
            connection=self.store._connection,
            firewall=firewall,
            overrides=self.overrides,
        )
        self.assertIsNone(self.overrides.read())
        self.assertEqual("writer", result["policy"]["mode"])
        self.assertTrue(result["runtime"]["active"])
        self.assertEqual((), firewall.managed_chains())

    def test_failed_auto_keeps_restrictive_override_for_next_boot(self) -> None:
        firewall = FakeFirewall()
        execute_fence_command(
            "isolate",
            config=self.config,
            connection=self.store._connection,
            firewall=firewall,
            overrides=self.overrides,
        )
        firewall.fail_remove = True
        with self.assertRaisesRegex(RuntimeError, "forced remove failure"):
            execute_fence_command(
                "auto",
                config=self.config,
                connection=self.store._connection,
                firewall=firewall,
                overrides=self.overrides,
            )
        self.assertEqual("isolated", self.overrides.read())

    def test_standby_override_cannot_turn_into_writer_even_when_membership_says_local_writer(self) -> None:
        firewall = FakeFirewall()
        result = execute_fence_command(
            "standby",
            config=self.config,
            connection=self.store._connection,
            firewall=firewall,
            overrides=self.overrides,
        )
        self.assertEqual("standby", self.overrides.read())
        self.assertEqual("standby", result["policy"]["mode"])
        self.assertTrue(result["runtime"]["active"])

    def test_status_never_mutates_firewall_or_override(self) -> None:
        firewall = FakeFirewall()
        execute_fence_command(
            "isolate",
            config=self.config,
            connection=self.store._connection,
            firewall=firewall,
            overrides=self.overrides,
        )
        before_chains = dict(firewall.chains)
        before_jumps = set(firewall.jumps)
        result = execute_fence_command(
            "status",
            config=self.config,
            connection=self.store._connection,
            firewall=firewall,
            overrides=self.overrides,
        )
        self.assertEqual("isolated", result["override"])
        self.assertEqual(before_chains, firewall.chains)
        self.assertEqual(before_jumps, firewall.jumps)

    def test_invalid_command_is_rejected_before_state_change(self) -> None:
        with self.assertRaisesRegex(HAFenceControlError, "command_rejected"):
            execute_fence_command(
                "writer",
                config=self.config,
                connection=self.store._connection,
                firewall=FakeFirewall(),
                overrides=self.overrides,
            )
        self.assertIsNone(self.overrides.read())


if __name__ == "__main__":
    unittest.main()
