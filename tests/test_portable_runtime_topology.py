from __future__ import annotations

import unittest

from home_center.config import Config
from home_center.core.upgrade_engine import ReleaseIdentity, UpgradeEngine
from home_center.resource_snapshot import ROLE_ID


class PortableRuntimeTopologyTests(unittest.TestCase):
    def test_runtime_uses_peer_collection_not_fixed_peer(self) -> None:
        fields = Config.__dataclass_fields__
        self.assertIn("peers", fields)
        self.assertNotIn("peer", fields)

    def test_resource_roles_are_not_leader_standby_locked(self) -> None:
        self.assertIsNotNone(ROLE_ID.fullmatch("worker"))
        self.assertIsNotNone(ROLE_ID.fullmatch("control-plane"))

    def test_upgrade_plan_uses_topology_neutral_rollout_steps(self) -> None:
        current = ReleaseIdentity("0.14.0", "a" * 40, "b" * 64)
        target = ReleaseIdentity("0.15.0", "c" * 40, "d" * 64)
        plan = UpgradeEngine().plan(current=current, target=target)
        self.assertEqual(
            plan.steps,
            ("preflight", "backup", "verify", "canary", "soak", "rollout", "accept"),
        )


if __name__ == "__main__":
    unittest.main()
