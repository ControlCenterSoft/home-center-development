from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from home_center.ha_state import initialize_membership
from home_center.runtime import Runtime
from home_center.runtime_safe import ProductionRuntime
from home_center.store import StateStore


def membership(writer: str) -> dict:
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


class _DeniedRuntime(Runtime):
    def authoritative_mutations_allowed(self) -> bool:
        return False


class HAStartupAdmissionTests(unittest.TestCase):
    def test_runtime_start_skips_authoritative_recovery_when_hook_denies(self) -> None:
        runtime = object.__new__(_DeniedRuntime)
        runtime.config = SimpleNamespace(node_id="node-b", role="standby")
        runtime.device_management_enrollment_post_condition = SimpleNamespace(
            recover_incomplete=Mock(return_value=99)
        )
        runtime.store = SimpleNamespace(audit=Mock())
        runtime.reconciler = SimpleNamespace(start=Mock())

        Runtime.start(runtime)

        runtime.device_management_enrollment_post_condition.recover_incomplete.assert_not_called()
        runtime.reconciler.start.assert_called_once_with()
        details = runtime.store.audit.call_args.kwargs["details"]
        self.assertEqual(0, details["post_condition_recoveries"])
        self.assertFalse(details["authoritative_recovery_allowed"])

    def test_production_runtime_uses_durable_writer_not_bootstrap_config_role(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "cluster-test")
            try:
                initialize_membership(store._connection, membership("node-b"))

                stale = object.__new__(ProductionRuntime)
                stale.store = store
                stale.config = SimpleNamespace(node_id="node-a", role="leader")
                self.assertFalse(stale.authoritative_mutations_allowed())

                promoted = object.__new__(ProductionRuntime)
                promoted.store = store
                promoted.config = SimpleNamespace(node_id="node-b", role="standby")
                self.assertTrue(promoted.authoritative_mutations_allowed())
            finally:
                store.close()

    def test_pre_ha_standby_is_also_recovery_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = StateStore(Path(directory) / "state.db", b"a" * 32, "cluster-test")
            try:
                standby = object.__new__(ProductionRuntime)
                standby.store = store
                standby.config = SimpleNamespace(node_id="node-b", role="standby")
                self.assertFalse(standby.authoritative_mutations_allowed())
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
