from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from home_center.core import (
    CertificateLifecyclePlanner,
    CertificateRecord,
    ComputePlanner,
    ComputeProviderDescriptor,
    ComputeProviderKind,
    ComputeResourceKind,
    ComputeResourceRequest,
    NodeDescriptor,
    NodeManager,
    NodeState,
)


class CoreFoundationTests(unittest.TestCase):
    def test_compute_uses_provider_capabilities_not_fixed_hosts(self) -> None:
        provider = ComputeProviderDescriptor.create(
            provider_id="provider-a",
            kind=ComputeProviderKind.PROXMOX,
            healthy=True,
            capabilities=("compute.vm.v1",),
        )
        request = ComputeResourceRequest("workload-a", ComputeResourceKind.VM, 2, 2048, 32)
        plan = ComputePlanner().plan_create(provider, request, available_cpu=4, available_memory_mib=4096, available_storage_gib=100)
        self.assertEqual(plan.state.value, "planned")

    def test_node_identity_is_runtime_supplied(self) -> None:
        node = NodeDescriptor.create(node_id="node-a", hostname="node-a.example.test", state=NodeState.DISCOVERED, capabilities=("inventory.v1",))
        manager = NodeManager((node,))
        plan = manager.plan_transition("node-a", NodeState.PREFLIGHTED)
        self.assertEqual(plan.state, "planned")

    def test_certificate_planning_is_secret_free(self) -> None:
        now = datetime.now(timezone.utc)
        record = CertificateRecord("web-a", "a" * 64, "web", now + timedelta(days=10), True, True)
        plan = CertificateLifecyclePlanner().plan_renewal(record, now=now, issuer_available=True, service_reload_supported=True)
        self.assertEqual(plan.state.value, "planned")


if __name__ == "__main__":
    unittest.main()
