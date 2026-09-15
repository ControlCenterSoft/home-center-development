from __future__ import annotations

import unittest

from home_center.home_services import (
    HOME_SERVICE_BY_ID,
    DeploymentPlanState,
    HomeServiceDeploymentPlanner,
    HomeServiceDeploymentRequest,
    NodeCapabilitySnapshot,
)


class HomeServiceCatalogIsolationTests(unittest.TestCase):
    def test_builtin_catalog_mapping_and_profiles_are_immutable(self) -> None:
        profile = HOME_SERVICE_BY_ID["minecraft-server"]

        with self.assertRaises(TypeError):
            HOME_SERVICE_BY_ID["minecraft-server"] = HOME_SERVICE_BY_ID["android-mdm"]  # type: ignore[index]

        with self.assertRaises(AttributeError):
            profile.minimum_storage_gib = 1  # type: ignore[misc]

        self.assertEqual(16, HOME_SERVICE_BY_ID["minecraft-server"].minimum_storage_gib)

    def test_planner_snapshots_injected_catalog_mapping(self) -> None:
        profiles = dict(HOME_SERVICE_BY_ID)
        planner = HomeServiceDeploymentPlanner(profiles)

        profiles["minecraft-server"] = HOME_SERVICE_BY_ID["android-mdm"]

        plan = planner.plan(
            HomeServiceDeploymentRequest("minecraft-server", "home-node-a"),
            NodeCapabilitySnapshot(
                "home-node-a",
                ("network.lan.v1", "runtime.container.v1"),
                32,
            ),
        )

        self.assertEqual(DeploymentPlanState.PLANNED, plan.state)
        self.assertEqual((), plan.blockers)
        self.assertFalse(plan.external_publication_enabled)
        self.assertTrue(plan.approval_required)
        self.assertFalse(plan.execution_authorized)
        self.assertFalse(plan.production_mutation_enabled)


if __name__ == "__main__":
    unittest.main()
