from __future__ import annotations

import unittest

from home_center.ha_fence import HAFencePolicy
from home_center.ha_fence_runtime import (
    HAFenceRuntimeError,
    apply_fence_policy,
    expected_chain_rules,
    fence_runtime_status,
)


class FakeFirewall:
    def __init__(self) -> None:
        self.chains: dict[str, list[tuple[str, ...]]] = {}
        self.jumps: set[tuple[int, str]] = set()
        self.fail_remove_chain: str | None = None
        self.fail_append = False

    def managed_chains(self) -> tuple[str, ...]:
        return tuple(sorted(self.chains))

    def create_chain(self, chain: str) -> None:
        if chain in self.chains:
            raise RuntimeError("duplicate chain")
        self.chains[chain] = []

    def append_rule(self, chain: str, rule: tuple[str, ...]) -> None:
        if self.fail_append:
            raise RuntimeError("append failed")
        self.chains[chain].append(tuple(rule))

    def insert_jump(self, _policy: HAFencePolicy, port: int, chain: str) -> None:
        self.jumps.add((port, chain))

    def remove_jump(self, _policy: HAFencePolicy, port: int, chain: str) -> None:
        if chain == self.fail_remove_chain:
            raise RuntimeError("remove jump failed")
        self.jumps.discard((port, chain))

    def jump_exists(self, _policy: HAFencePolicy, port: int, chain: str) -> bool:
        return (port, chain) in self.jumps

    def rule_exists(self, chain: str, rule: tuple[str, ...]) -> bool:
        return tuple(rule) in self.chains.get(chain, [])

    def rule_count(self, chain: str) -> int:
        return len(self.chains.get(chain, []))

    def delete_chain(self, chain: str) -> None:
        if any(jump_chain == chain for _, jump_chain in self.jumps):
            raise RuntimeError("chain still referenced")
        self.chains.pop(chain, None)


class HAFenceRuntimeTests(unittest.TestCase):
    def standby_policy(self) -> HAFencePolicy:
        return HAFencePolicy(
            mode="standby",
            target_address="192.0.2.10",
            peer_addresses=("192.0.2.11",),
        )

    def isolated_policy(self) -> HAFencePolicy:
        return HAFencePolicy(
            mode="isolated",
            target_address="192.0.2.10",
            peer_addresses=("192.0.2.11",),
        )

    def writer_policy(self) -> HAFencePolicy:
        return HAFencePolicy(
            mode="writer",
            target_address="192.0.2.10",
            peer_addresses=("192.0.2.11",),
        )

    def test_standby_rules_allow_only_loopback_self_and_peer_listener(self) -> None:
        rules = expected_chain_rules(self.standby_policy())
        self.assertEqual(("-i", "lo", "-j", "ACCEPT"), rules[0])
        self.assertIn(("-s", "192.0.2.10/32", "-j", "ACCEPT"), rules)
        self.assertIn(
            ("-s", "192.0.2.11/32", "-p", "tcp", "--dport", "9443", "-j", "ACCEPT"),
            rules,
        )
        self.assertNotIn(
            ("-s", "192.0.2.11/32", "-p", "tcp", "--dport", "8443", "-j", "ACCEPT"),
            rules,
        )
        self.assertEqual(("-j", "DROP"), rules[-1])

    def test_isolated_rules_have_no_remote_peer_allow(self) -> None:
        rules = expected_chain_rules(self.isolated_policy())
        self.assertEqual(
            (
                ("-i", "lo", "-j", "ACCEPT"),
                ("-s", "192.0.2.10/32", "-j", "ACCEPT"),
                ("-j", "DROP"),
            ),
            rules,
        )

    def test_apply_standby_builds_chain_before_activation_and_verifies_it(self) -> None:
        firewall = FakeFirewall()
        status = apply_fence_policy(
            self.standby_policy(),
            firewall,
            chain_factory=lambda: "HC-HA-F-11111111",
        )
        self.assertTrue(status.active)
        self.assertEqual("HC-HA-F-11111111", status.active_chain)
        self.assertEqual(
            {(8443, "HC-HA-F-11111111"), (9443, "HC-HA-F-11111111")},
            firewall.jumps,
        )
        self.assertEqual(
            list(expected_chain_rules(self.standby_policy())),
            firewall.chains["HC-HA-F-11111111"],
        )

    def test_standby_to_isolated_swaps_chain_then_removes_old(self) -> None:
        firewall = FakeFirewall()
        apply_fence_policy(
            self.standby_policy(),
            firewall,
            chain_factory=lambda: "HC-HA-F-11111111",
        )
        status = apply_fence_policy(
            self.isolated_policy(),
            firewall,
            chain_factory=lambda: "HC-HA-F-22222222",
        )
        self.assertTrue(status.active)
        self.assertEqual(("HC-HA-F-22222222",), firewall.managed_chains())
        self.assertEqual(
            {(8443, "HC-HA-F-22222222"), (9443, "HC-HA-F-22222222")},
            firewall.jumps,
        )
        self.assertEqual(
            list(expected_chain_rules(self.isolated_policy())),
            firewall.chains["HC-HA-F-22222222"],
        )

    def test_writer_mode_removes_all_managed_jumps_and_chains(self) -> None:
        firewall = FakeFirewall()
        apply_fence_policy(
            self.isolated_policy(),
            firewall,
            chain_factory=lambda: "HC-HA-F-11111111",
        )
        status = apply_fence_policy(self.writer_policy(), firewall)
        self.assertTrue(status.active)
        self.assertEqual((), firewall.managed_chains())
        self.assertEqual(set(), firewall.jumps)

    def test_failure_before_activation_removes_orphan_chain(self) -> None:
        firewall = FakeFirewall()
        firewall.fail_append = True
        with self.assertRaisesRegex(RuntimeError, "append failed"):
            apply_fence_policy(
                self.standby_policy(),
                firewall,
                chain_factory=lambda: "HC-HA-F-11111111",
            )
        self.assertEqual((), firewall.managed_chains())
        self.assertEqual(set(), firewall.jumps)

    def test_failure_after_new_chain_activation_leaves_new_restrictive_chain_connected(self) -> None:
        firewall = FakeFirewall()
        apply_fence_policy(
            self.standby_policy(),
            firewall,
            chain_factory=lambda: "HC-HA-F-11111111",
        )
        firewall.fail_remove_chain = "HC-HA-F-11111111"
        with self.assertRaisesRegex(RuntimeError, "remove jump failed"):
            apply_fence_policy(
                self.isolated_policy(),
                firewall,
                chain_factory=lambda: "HC-HA-F-22222222",
            )
        self.assertIn((8443, "HC-HA-F-22222222"), firewall.jumps)
        self.assertIn((9443, "HC-HA-F-22222222"), firewall.jumps)
        self.assertEqual(
            list(expected_chain_rules(self.isolated_policy())),
            firewall.chains["HC-HA-F-22222222"],
        )

    def test_status_rejects_multiple_active_managed_chains(self) -> None:
        firewall = FakeFirewall()
        apply_fence_policy(
            self.standby_policy(),
            firewall,
            chain_factory=lambda: "HC-HA-F-11111111",
        )
        firewall.chains["HC-HA-F-22222222"] = list(expected_chain_rules(self.standby_policy()))
        firewall.jumps.update({(8443, "HC-HA-F-22222222"), (9443, "HC-HA-F-22222222")})
        status = fence_runtime_status(self.standby_policy(), firewall)
        self.assertFalse(status.active)
        self.assertIsNone(status.active_chain)

    def test_chain_identity_and_address_family_mismatch_fail_closed(self) -> None:
        firewall = FakeFirewall()
        with self.assertRaisesRegex(HAFenceRuntimeError, "chain_identity"):
            apply_fence_policy(
                self.standby_policy(),
                firewall,
                chain_factory=lambda: "unsafe-chain",
            )
        mixed = HAFencePolicy(
            mode="standby",
            target_address="192.0.2.10",
            peer_addresses=("2001:db8::11",),
        )
        with self.assertRaisesRegex(HAFenceRuntimeError, "family_mismatch"):
            expected_chain_rules(mixed)


if __name__ == "__main__":
    unittest.main()
