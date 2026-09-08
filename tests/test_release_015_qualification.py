from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace

import home_center
from home_center.deployment_profiles import (
    DeploymentPlanner,
    DeploymentProfile,
    DiscoveredNode,
    NodeRequirement,
    PlacementPolicy,
)
from home_center.infrastructure_inventory import normalize_infrastructure_inventory
from home_center.node_discovery import discover_nodes
from home_center.runtime import Runtime


ROOT = Path(__file__).resolve().parents[1]
RELEASE = home_center.__version__


def _inventory(node_id: str, name: str, observed_at: str) -> dict[str, object]:
    return {
        "schema": "home-center.infrastructure-inventory.v2",
        "observed_at": observed_at,
        "source": "local-trusted",
        "node": {"id": node_id, "name": name, "role": "worker"},
        "hardware": {
            "architecture": "amd64",
            "cpu_count": 4,
            "memory_bytes": 8 * 1024**3,
            "virtualization": {"supported": True, "technology": "hypervisor"},
        },
        "storage": [
            {"id": "root", "kind": "ssd", "total_bytes": 128 * 1024**3, "removable": False}
        ],
        "network": [{"id": "lan0", "kind": "ethernet", "speed_mbps": 1000, "carrier": "up"}],
        "capabilities": ["inventory.v1", "compute.vm.v1"],
    }


class PortableFoundationQualificationTests(unittest.TestCase):
    def test_release_identity_is_consistent(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
        release_notes = (ROOT / f"docs/releases/{RELEASE}.md").read_text(encoding="utf-8")
        self.assertEqual(project["version"], RELEASE)
        self.assertEqual(home_center.__version__, RELEASE)
        self.assertIn(f"# Home Center {RELEASE}", release_notes)

    def test_runtime_loads_the_shipped_v2_profile(self) -> None:
        profile = Runtime._load_profile(ROOT / "deploy/examples/deployment-profile.example.json")
        name, version, nodes = Runtime._profile_details(profile)
        self.assertEqual((name, version), ("example-lab", 2))
        self.assertEqual([node["node_id"] for node in nodes], ["node-a"])

        class OverviewStore:
            @staticmethod
            def nodes() -> list[dict[str, str]]:
                return [{"status": "ready"}]

            @staticmethod
            def jobs(_limit: int) -> list[object]:
                return []

            @staticmethod
            def verify_audit_chain() -> str:
                return "0" * 64

        runtime = Runtime.__new__(Runtime)
        runtime.profile = profile
        runtime.config = SimpleNamespace(cluster_id="example-lab", role="control-plane")
        runtime.store = OverviewStore()
        overview = runtime.overview()
        self.assertEqual(overview["cluster"]["profile"], "example-lab")
        self.assertEqual(overview["cluster"]["profile_version"], 2)
        self.assertEqual(overview["cluster"]["expected_nodes"], 1)
        self.assertEqual(overview["cluster"]["status"], "healthy")

    def test_inventory_discovery_and_placement_are_deterministic_and_plan_only(self) -> None:
        first = _inventory("node-b", "node-b.example.test", "2026-01-01T03:00:00+03:00")
        second = _inventory("node-a", "node-a.example.test", "2026-01-01T00:00:00Z")
        normalized = normalize_infrastructure_inventory(first)
        self.assertFalse(normalized["production_mutation_enabled"])

        discovery = discover_nodes(
            scope_id="example-lab",
            accepted_after="2026-01-01T00:00:00Z",
            accepted_before="2026-01-01T00:01:00Z",
            inventories=(first, second),
        )
        self.assertEqual([node["id"] for node in discovery["nodes"]], ["node-a", "node-b"])
        self.assertFalse(discovery["role_assignment_enabled"])
        self.assertFalse(discovery["enrollment_enabled"])
        self.assertFalse(discovery["production_mutation_enabled"])

        profile = DeploymentProfile(
            profile_id="example-lab",
            nodes=(
                NodeRequirement("control", required_capabilities=("inventory.v1",)),
                NodeRequirement("worker", required_capabilities=("compute.vm.v1",)),
            ),
            placement=PlacementPolicy(minimum_ready_nodes=2),
        )
        discovered = tuple(
            DiscoveredNode(node["id"], tuple(node["capabilities"]), True)
            for node in discovery["nodes"]
        )
        plan = DeploymentPlanner().plan(profile, discovered)
        self.assertEqual(plan.state, "planned")
        self.assertEqual(plan.assignments, (("control", "node-a"), ("worker", "node-b")))
        self.assertFalse(plan.production_mutation_enabled)
        self.assertFalse(plan.to_dict()["production_mutation_enabled"])

    def test_shipped_action_registry_is_valid_json(self) -> None:
        path = ROOT / "product/control-plane/src/home_center/action_registry.v1.json"
        registry = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(registry["schema"], "home-center.action-registry.v1")
        self.assertTrue(registry["actions"])


if __name__ == "__main__":
    unittest.main()
