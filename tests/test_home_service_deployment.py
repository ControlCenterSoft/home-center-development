from __future__ import annotations

import json
import unittest
from pathlib import Path

from home_center.home_services import (
    DeploymentPlanState,
    HomeServiceDeploymentPlanner,
    HomeServiceDeploymentRequest,
    NodeCapabilitySnapshot,
)


ROOT = Path(__file__).resolve().parents[1]


class HomeServiceDeploymentPlannerTests(unittest.TestCase):
    def node(self, *capabilities: str, free_storage_gib: int = 32) -> NodeCapabilitySnapshot:
        return NodeCapabilitySnapshot("home-node-a", tuple(capabilities), free_storage_gib)

    def test_local_plan_is_deterministic_and_requires_separate_execution_authority(self) -> None:
        request = HomeServiceDeploymentRequest("minecraft-server", "home-node-a")
        node = self.node("network.lan.v1", "runtime.container.v1")
        value = HomeServiceDeploymentPlanner().plan(request, node).to_dict()
        self.assertEqual("planned", value["state"])
        self.assertEqual([], value["blockers"])
        self.assertIs(value["external_publication_enabled"], False)
        self.assertIs(value["approval_required"], True)
        self.assertIs(value["execution_authorized"], False)
        self.assertIs(value["production_mutation_enabled"], False)

    def test_external_publication_requires_explicit_request_and_capability(self) -> None:
        request = HomeServiceDeploymentRequest("minecraft-server", "home-node-a", True)
        blocked = HomeServiceDeploymentPlanner().plan(
            request,
            self.node("network.lan.v1", "runtime.container.v1"),
        )
        self.assertEqual(DeploymentPlanState.BLOCKED, blocked.state)
        self.assertEqual(
            ("missing_capability:network.external-publication.v1",),
            blocked.blockers,
        )
        allowed = HomeServiceDeploymentPlanner().plan(
            request,
            self.node(
                "network.external-publication.v1",
                "network.lan.v1",
                "runtime.container.v1",
            ),
        )
        self.assertEqual(DeploymentPlanState.PLANNED, allowed.state)
        self.assertTrue(allowed.external_publication_enabled)

    def test_local_only_service_rejects_publication(self) -> None:
        plan = HomeServiceDeploymentPlanner().plan(
            HomeServiceDeploymentRequest("torrent-client", "home-node-a", True),
            self.node(
                "network.external-publication.v1",
                "network.lan.v1",
                "runtime.container.v1",
                "storage.bulk.v1",
            ),
        )
        self.assertIn("publication_forbidden", plan.blockers)
        self.assertFalse(plan.external_publication_enabled)

    def test_preflight_reports_all_capacity_and_capability_blockers(self) -> None:
        plan = HomeServiceDeploymentPlanner().plan(
            HomeServiceDeploymentRequest("android-mdm", "home-node-a"),
            self.node("runtime.container.v1", free_storage_gib=2),
        )
        self.assertEqual(
            (
                "insufficient_storage",
                "missing_capability:certificates.lifecycle.v1",
                "missing_capability:network.lan.v1",
            ),
            plan.blockers,
        )

    def test_unknown_service_and_wrong_target_fail_closed(self) -> None:
        plan = HomeServiceDeploymentPlanner().plan(
            HomeServiceDeploymentRequest("unknown-service", "home-node-b"),
            self.node(),
        )
        self.assertEqual(("target_node_mismatch", "unknown_service"), plan.blockers)

    def test_contract_is_closed_and_non_authoritative(self) -> None:
        contract = json.loads(
            (ROOT / "contracts/market/home-service-deployment-plan.v1.schema.json").read_text(encoding="utf-8")
        )
        self.assertIs(contract["additionalProperties"], False)
        self.assertIs(contract["properties"]["approval_required"]["const"], True)
        self.assertIs(contract["properties"]["execution_authorized"]["const"], False)
        self.assertIs(contract["properties"]["production_mutation_enabled"]["const"], False)


if __name__ == "__main__":
    unittest.main()
