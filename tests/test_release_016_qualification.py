from __future__ import annotations

import json
import tomllib
import unittest
from pathlib import Path

import home_center
from home_center.core import (
    ComputeFrameworkError,
    ComputeProviderDescriptor,
    ComputeProviderKind,
    ComputeResourceKind,
    ComputeResourceRequest,
    LxcAction,
    LxcLifecycleError,
    LxcLifecyclePlanner,
    LxcLifecycleRequest,
    LxcSnapshot,
    LxcState,
    PlacementRequest,
    ProviderCapacity,
    ResourceScheduler,
    ResourceSchedulerError,
    VmAction,
    VmLifecycleError,
    VmLifecyclePlanner,
    VmLifecycleRequest,
    VmSnapshot,
    VmState,
    normalize_proxmox_discovery,
)


ROOT = Path(__file__).resolve().parents[1]


def provider(*, healthy: bool = True, capabilities: tuple[str, ...] = ("compute.vm.v1", "compute.lxc.v1")) -> ComputeProviderDescriptor:
    return ComputeProviderDescriptor.create(
        provider_id="provider-a",
        kind=ComputeProviderKind.PROXMOX,
        healthy=healthy,
        capabilities=capabilities,
    )


def discovery_document(*, split_capacity: bool = False) -> dict[str, object]:
    available_cpu = 2 if split_capacity else 8
    available_memory = 1024 if split_capacity else 16_384
    available_storage = 16 if split_capacity else 512
    return {
        "schema": "home-center.proxmox-discovery.v1",
        "observed_at": "2026-09-08T10:00:00Z",
        "source": "proxmox-trusted",
        "provider": {
            "provider_id": "provider-a",
            "profile_id": "profile-a",
            "reported_health": "healthy",
            "auth_state": "available",
        },
        "cluster": {"cluster_id": "cluster-a", "quorate": True},
        "nodes": [
            {
                "node_id": "node-a",
                "state": "online",
                "cpu_total": 16,
                "cpu_available": available_cpu,
                "memory_total_mib": 32_768,
                "memory_available_mib": available_memory,
                "storage_total_gib": 1024,
                "storage_available_gib": available_storage,
                "capabilities": ["compute.ha.v1", "compute.lxc.v1", "compute.vm.v1"],
            },
            {
                "node_id": "node-b",
                "state": "online",
                "cpu_total": 16,
                "cpu_available": available_cpu,
                "memory_total_mib": 32_768,
                "memory_available_mib": available_memory,
                "storage_total_gib": 1024,
                "storage_available_gib": available_storage,
                "capabilities": ["compute.ha.v1", "compute.lxc.v1", "compute.vm.v1"],
            },
        ],
        "resources": [],
    }


class ReleaseIdentityTests(unittest.TestCase):
    def test_release_versions_are_identical(self) -> None:
        version_file = (ROOT / "VERSION").read_text(encoding="ascii").strip()
        with (ROOT / "pyproject.toml").open("rb") as stream:
            project = tomllib.load(stream)
        package_version = project["project"]["version"]
        self.assertEqual(version_file, "0.16.0")
        self.assertEqual(package_version, version_file)
        self.assertEqual(home_center.__version__, version_file)
        self.assertIn(
            "*.json",
            project["tool"]["setuptools"]["package-data"]["home_center"],
        )

    def test_plan_schemas_are_closed_and_plan_only(self) -> None:
        names = (
            "compute-plan.v1.schema.json",
            "resource-placement-plan.v1.schema.json",
            "vm-lifecycle-plan.v1.schema.json",
            "lxc-lifecycle-plan.v1.schema.json",
        )
        for name in names:
            with self.subTest(contract=name):
                contract = json.loads((ROOT / "contracts" / "compute" / name).read_text(encoding="utf-8"))
                self.assertIs(contract["additionalProperties"], False)
                self.assertIs(contract["properties"]["production_mutation_enabled"]["const"], False)


class ComputeBoundaryTests(unittest.TestCase):
    def test_direct_provider_construction_cannot_bypass_validation(self) -> None:
        with self.assertRaisesRegex(ComputeFrameworkError, "invalid_provider"):
            ComputeProviderDescriptor("provider-a", ComputeProviderKind.PROXMOX, 1, ())
        with self.assertRaisesRegex(ComputeFrameworkError, "invalid_provider_capability"):
            ComputeProviderDescriptor.create(
                provider_id="provider-a",
                kind=ComputeProviderKind.PROXMOX,
                healthy=True,
                capabilities=(f"compute.feature-{index}.v1" for index in range(129)),
            )
        with self.assertRaisesRegex(ComputeFrameworkError, "invalid_compute_request"):
            ComputeResourceRequest(None, ComputeResourceKind.VM, 2, 1024, 16)

    def test_proxmox_does_not_pool_capacity_for_one_guest(self) -> None:
        discovered = normalize_proxmox_discovery(discovery_document(split_capacity=True))
        request = ComputeResourceRequest("guest-a", ComputeResourceKind.VM, 4, 2048, 32)
        plan = discovered.plan_create(request)
        self.assertEqual(plan.state.value, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_node",))
        self.assertIs(plan.production_mutation_enabled, False)

    def test_proxmox_plans_guest_that_fits_one_node(self) -> None:
        discovered = normalize_proxmox_discovery(discovery_document())
        request = ComputeResourceRequest("guest-a", ComputeResourceKind.VM, 4, 2048, 32, True)
        plan = discovered.plan_create(request)
        self.assertEqual(plan.state.value, "planned")
        self.assertEqual(plan.blockers, ())
        self.assertIs(plan.to_dict()["production_mutation_enabled"], False)

    def test_proxmox_ha_requires_two_nodes_with_failover_capacity(self) -> None:
        document = discovery_document()
        document["nodes"] = document["nodes"][:1]
        discovered = normalize_proxmox_discovery(document)
        request = ComputeResourceRequest("guest-a", ComputeResourceKind.VM, 4, 2048, 32, True)
        plan = discovered.plan_create(request)
        self.assertEqual(plan.state.value, "blocked")
        self.assertEqual(plan.blockers, ("insufficient_ha_nodes",))

    def test_proxmox_discovery_rejects_unknown_fields(self) -> None:
        document = discovery_document()
        document["endpoint"] = "https://not-part-of-discovery.example.test"
        with self.assertRaisesRegex(ValueError, "invalid_discovery_shape"):
            normalize_proxmox_discovery(document)


class LifecycleBoundaryTests(unittest.TestCase):
    def test_vm_snapshot_must_match_requested_identity(self) -> None:
        request = VmLifecycleRequest("operation-a", "guest-a", VmAction.DELETE)
        snapshot = VmSnapshot("guest-b", "provider-a", VmState.STOPPED, 2, 2048, 32)
        plan = VmLifecyclePlanner().plan(request, provider=provider(), snapshot=snapshot)
        self.assertEqual(plan.state, "blocked")
        self.assertIn("snapshot_identity_mismatch", plan.blockers)
        self.assertIs(plan.to_dict()["production_mutation_enabled"], False)

    def test_lxc_action_is_blocked_when_provider_is_unhealthy(self) -> None:
        request = LxcLifecycleRequest("operation-a", "container-a", LxcAction.START)
        snapshot = LxcSnapshot("container-a", "provider-a", LxcState.STOPPED, 2, 1024, 16)
        plan = LxcLifecyclePlanner().plan(
            request,
            provider=provider(healthy=False),
            snapshot=snapshot,
        )
        self.assertEqual(plan.state, "blocked")
        self.assertIn("provider_not_healthy", plan.blockers)
        self.assertIs(plan.to_dict()["production_mutation_enabled"], False)

    def test_lifecycle_requests_reject_ambiguous_or_unbounded_values(self) -> None:
        with self.assertRaisesRegex(VmLifecycleError, "non_create_resources_forbidden"):
            VmLifecycleRequest("operation-a", "guest-a", VmAction.START, vcpu=2)
        with self.assertRaisesRegex(LxcLifecycleError, "invalid_create_resources"):
            LxcLifecycleRequest("operation-a", "container-a", LxcAction.CREATE, True, 1024, 16)


class PlacementBoundaryTests(unittest.TestCase):
    def test_preference_order_is_honoured_deterministically(self) -> None:
        request = PlacementRequest(
            "placement-a",
            ComputeResourceRequest("guest-a", ComputeResourceKind.VM, 2, 1024, 16),
            preferred_providers=("provider-b", "provider-a"),
        )
        provider_a = ProviderCapacity(provider(), 8, 8192, 128)
        provider_b = ProviderCapacity(
            ComputeProviderDescriptor.create(
                provider_id="provider-b",
                kind=ComputeProviderKind.PROXMOX,
                healthy=True,
                capabilities=("compute.vm.v1",),
            ),
            8,
            8192,
            128,
        )
        plan = ResourceScheduler().plan(request, (provider_a, provider_b))
        self.assertEqual(plan.provider_id, "provider-b")
        self.assertIs(plan.to_dict()["production_mutation_enabled"], False)

    def test_invalid_or_duplicate_capacity_observations_fail_closed(self) -> None:
        with self.assertRaisesRegex(ResourceSchedulerError, "invalid_available_cpu"):
            ProviderCapacity(provider(), -1, 1024, 16)
        request = PlacementRequest(
            "placement-a",
            ComputeResourceRequest("guest-a", ComputeResourceKind.VM, 2, 1024, 16),
        )
        observation = ProviderCapacity(provider(), 8, 8192, 128)
        with self.assertRaisesRegex(ResourceSchedulerError, "duplicate_provider_id"):
            ResourceScheduler().plan(request, (observation, observation))

    def test_empty_provider_observation_returns_a_blocked_plan(self) -> None:
        request = PlacementRequest(
            "placement-a",
            ComputeResourceRequest("guest-a", ComputeResourceKind.VM, 2, 1024, 16),
        )
        plan = ResourceScheduler().plan(request, ())
        self.assertEqual(plan.state, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))


if __name__ == "__main__":
    unittest.main()
