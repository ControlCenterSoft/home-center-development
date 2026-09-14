from __future__ import annotations

import unittest

from home_center.home_services import (
    DeploymentPlanState,
    HomeServiceDeploymentPlanner,
    HomeServiceDeploymentRequest,
    NodeCapabilitySnapshot,
    PublicationPolicy,
    HOME_SERVICE_BY_ID,
)


class BuiltinExplicitPublicationTests(unittest.TestCase):
    CASES = {
        "android-mdm": (
            "certificates.lifecycle.v1",
            "network.lan.v1",
            "runtime.container.v1",
        ),
        "minecraft-server": (
            "network.lan.v1",
            "runtime.container.v1",
        ),
        "yandex-smart-home": (
            "devices.registry.v1",
            "network.outbound.v1",
            "runtime.container.v1",
        ),
    }

    def test_builtin_explicit_services_require_publication_capability_and_remain_non_authoritative(self) -> None:
        planner = HomeServiceDeploymentPlanner()

        for service_id, required_capabilities in self.CASES.items():
            with self.subTest(service_id=service_id):
                self.assertEqual(
                    PublicationPolicy.EXPLICIT,
                    HOME_SERVICE_BY_ID[service_id].publication_policy,
                )

                request = HomeServiceDeploymentRequest(
                    service_id,
                    "home-node-a",
                    external_publication_requested=True,
                )

                blocked = planner.plan(
                    request,
                    NodeCapabilitySnapshot(
                        "home-node-a",
                        required_capabilities,
                        free_storage_gib=64,
                    ),
                )
                self.assertEqual(DeploymentPlanState.BLOCKED, blocked.state)
                self.assertEqual(
                    ("missing_capability:network.external-publication.v1",),
                    blocked.blockers,
                )
                self.assertFalse(blocked.external_publication_enabled)

                planned = planner.plan(
                    request,
                    NodeCapabilitySnapshot(
                        "home-node-a",
                        (*required_capabilities, "network.external-publication.v1"),
                        free_storage_gib=64,
                    ),
                )
                self.assertEqual(DeploymentPlanState.PLANNED, planned.state)
                self.assertEqual((), planned.blockers)
                self.assertTrue(planned.external_publication_enabled)
                self.assertTrue(planned.approval_required)
                self.assertFalse(planned.execution_authorized)
                self.assertFalse(planned.production_mutation_enabled)


if __name__ == "__main__":
    unittest.main()
