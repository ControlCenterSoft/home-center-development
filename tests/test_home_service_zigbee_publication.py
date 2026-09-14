from __future__ import annotations

import unittest

from home_center.home_services import (
    DeploymentPlanState,
    HomeServiceDeploymentPlanner,
    HomeServiceDeploymentRequest,
    NodeCapabilitySnapshot,
)


class ZigBeePublicationBoundaryTests(unittest.TestCase):
    def node(self, *capabilities: str) -> NodeCapabilitySnapshot:
        return NodeCapabilitySnapshot("home-node-a", tuple(capabilities), 32)

    def test_zigbee_bridge_remains_plannable_for_local_lan_use(self) -> None:
        plan = HomeServiceDeploymentPlanner().plan(
            HomeServiceDeploymentRequest("zigbee-bridge", "home-node-a"),
            self.node("devices.usb.v1", "network.lan.v1", "runtime.container.v1"),
        )

        self.assertEqual(DeploymentPlanState.PLANNED, plan.state)
        self.assertEqual((), plan.blockers)
        self.assertFalse(plan.external_publication_enabled)
        self.assertTrue(plan.approval_required)
        self.assertFalse(plan.execution_authorized)
        self.assertFalse(plan.production_mutation_enabled)

    def test_zigbee_bridge_rejects_external_publication_even_with_capability(self) -> None:
        plan = HomeServiceDeploymentPlanner().plan(
            HomeServiceDeploymentRequest("zigbee-bridge", "home-node-a", True),
            self.node(
                "devices.usb.v1",
                "network.external-publication.v1",
                "network.lan.v1",
                "runtime.container.v1",
            ),
        )

        self.assertEqual(DeploymentPlanState.BLOCKED, plan.state)
        self.assertEqual(("publication_forbidden",), plan.blockers)
        self.assertFalse(plan.external_publication_enabled)
        self.assertTrue(plan.approval_required)
        self.assertFalse(plan.execution_authorized)
        self.assertFalse(plan.production_mutation_enabled)


if __name__ == "__main__":
    unittest.main()
