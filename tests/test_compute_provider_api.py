from __future__ import annotations

import copy
import json
import unittest
from types import SimpleNamespace

from home_center.api import RuntimeRequestHandler
from home_center.compute_api import ComputeCapacityPlanningApi
from home_center.core import (
    ComputeCapacity,
    ComputeCapacityPlanningRequest,
    ComputeCapacitySnapshot,
    ComputeFrameworkError,
    ComputePlanner,
    ComputeProviderDescriptor,
    ComputeProviderProfile,
    ComputeProviderState,
    ComputeResourceKind,
    ComputeResourceRequest,
    proxmox_compute_profile,
)


def capacity(
    provider_id: str,
    *,
    sequence: int = 1,
    total: tuple[int, int, int] = (16, 32_768, 500),
    allocated: tuple[int, int, int] = (0, 0, 0),
    reserved: tuple[int, int, int] = (0, 0, 0),
) -> ComputeCapacitySnapshot:
    def vector(value: tuple[int, int, int]) -> ComputeCapacity:
        return ComputeCapacity(vcpu=value[0], memory_mib=value[1], storage_gib=value[2])

    return ComputeCapacitySnapshot(
        provider_id=provider_id,
        sequence=sequence,
        total=vector(total),
        allocated=vector(allocated),
        reserved=vector(reserved),
    )


def state(
    provider_id: str,
    *,
    capabilities: tuple[str, ...] = ("compute.capacity.v1", "compute.vm.v1"),
    healthy: bool = True,
    profile_id: str = "generic.virtualization.v1",
    snapshot: ComputeCapacitySnapshot | None = None,
) -> ComputeProviderState:
    return ComputeProviderState(
        provider=ComputeProviderDescriptor.create(
            provider_id=provider_id,
            profile_id=profile_id,
            healthy=healthy,
            capabilities=capabilities,
        ),
        capacity=snapshot or capacity(provider_id),
    )


def resource(kind: ComputeResourceKind = ComputeResourceKind.VM, *, ha: bool = False) -> ComputeResourceRequest:
    return ComputeResourceRequest(
        resource_id="workload-a",
        kind=kind,
        vcpu=2,
        memory_mib=2048,
        disk_gib=32,
        high_availability=ha,
    )


class ComputeProviderProfileTests(unittest.TestCase):
    def test_proxmox_is_a_capability_profile_without_runtime_configuration(self) -> None:
        profile = proxmox_compute_profile()
        self.assertEqual(profile.profile_id, "proxmox.virtualization.v1")
        self.assertEqual(
            profile.to_dict()["resource_kinds"],
            ["container", "lxc", "vm"],
        )
        self.assertNotIn("endpoint", profile.to_dict())
        descriptor = profile.describe(provider_id="provider-a", healthy=True)
        self.assertEqual(descriptor.profile_id, profile.profile_id)
        self.assertIn("compute.vm.v1", descriptor.capabilities)
        self.assertIn("compute.container.v1", descriptor.capabilities)

    def test_profile_requires_each_declared_runtime_capability(self) -> None:
        with self.assertRaisesRegex(ComputeFrameworkError, "provider_profile_capability_missing"):
            ComputeProviderProfile.create(
                profile_id="adapter.virtualization.v1",
                resource_kinds=(ComputeResourceKind.VM, ComputeResourceKind.CONTAINER),
                capabilities=("compute.vm.v1",),
            )

    def test_profile_cannot_enable_an_undeclared_capability(self) -> None:
        with self.assertRaisesRegex(ComputeFrameworkError, "provider_capability_not_in_profile"):
            proxmox_compute_profile().describe(
                provider_id="provider-a",
                healthy=True,
                enabled_capabilities=("compute.vm.v1", "provider.secret-access.v1"),
            )


class ComputeCapacityPlanningTests(unittest.TestCase):
    def test_selection_is_stable_for_different_provider_input_order(self) -> None:
        provider_a = state(
            "provider-a",
            snapshot=capacity(
                "provider-a",
                sequence=7,
                allocated=(8, 16_384, 100),
                reserved=(1, 1024, 20),
            ),
        )
        provider_b = state(
            "provider-b",
            snapshot=capacity(
                "provider-b",
                sequence=4,
                total=(8, 16_384, 200),
                allocated=(1, 1024, 10),
            ),
        )
        planner = ComputePlanner()
        first = planner.plan_capacity(
            ComputeCapacityPlanningRequest("plan-a", resource(), (provider_a, provider_b))
        ).to_dict()
        second = planner.plan_capacity(
            ComputeCapacityPlanningRequest("plan-a", resource(), (provider_b, provider_a))
        ).to_dict()
        self.assertEqual(first, second)
        self.assertEqual(first["selected_provider_id"], "provider-b")
        self.assertEqual(
            [item["provider_id"] for item in first["evaluations"]],
            ["provider-a", "provider-b"],
        )
        self.assertFalse(first["production_mutation_enabled"])

    def test_equal_utilization_uses_provider_id_tie_break(self) -> None:
        request = ComputeCapacityPlanningRequest(
            "plan-a",
            resource(),
            (state("provider-z"), state("provider-a")),
        )
        plan = ComputePlanner().plan_capacity(request)
        self.assertEqual(plan.selected_provider_id, "provider-a")

    def test_generic_container_and_lxc_are_typed_separately(self) -> None:
        profile = proxmox_compute_profile()
        provider = ComputeProviderState(
            provider=profile.describe(provider_id="provider-a", healthy=True),
            capacity=capacity("provider-a"),
        )
        for kind in (ComputeResourceKind.CONTAINER, ComputeResourceKind.LXC):
            with self.subTest(kind=kind.value):
                plan = ComputePlanner().plan_capacity(
                    ComputeCapacityPlanningRequest("plan-a", resource(kind), (provider,))
                )
                self.assertEqual(plan.state.value, "planned")

    def test_all_rejection_reasons_have_canonical_order(self) -> None:
        broken = state(
            "provider-a",
            capabilities=(),
            healthy=False,
            snapshot=capacity(
                "provider-a",
                total=(1, 1024, 10),
                allocated=(2, 2048, 20),
            ),
        )
        plan = ComputePlanner().plan_capacity(
            ComputeCapacityPlanningRequest("plan-a", resource(ha=True), (broken,))
        )
        self.assertEqual(plan.state.value, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))
        self.assertEqual(
            plan.evaluations[0].blockers,
            (
                "provider_not_healthy",
                "provider_capacity_unsupported",
                "provider_runtime_unsupported",
                "provider_ha_unsupported",
                "capacity_accounting_exceeds_total",
                "insufficient_cpu_capacity",
                "insufficient_memory_capacity",
                "insufficient_storage_capacity",
            ),
        )
        self.assertIsNone(plan.evaluations[0].available_after)
        self.assertIsNone(plan.evaluations[0].maximum_utilization_bps_after)

    def test_empty_provider_set_returns_a_typed_blocked_plan(self) -> None:
        plan = ComputePlanner().plan_capacity(
            ComputeCapacityPlanningRequest("plan-a", resource(), ())
        )
        self.assertEqual(plan.state.value, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))
        self.assertEqual(plan.evaluations, ())

    def test_duplicate_and_mismatched_provider_identity_are_rejected(self) -> None:
        same = state("provider-a")
        with self.assertRaisesRegex(ComputeFrameworkError, "duplicate_provider_id"):
            ComputeCapacityPlanningRequest("plan-a", resource(), (same, same))
        with self.assertRaisesRegex(ComputeFrameworkError, "provider_capacity_identity_mismatch"):
            ComputeProviderState(provider=same.provider, capacity=capacity("provider-b"))


class ComputeCapacityApiTests(unittest.TestCase):
    def request_payload(self) -> dict[str, object]:
        provider = state(
            "provider-a",
            capabilities=("compute.capacity.v1", "compute.container.v1"),
        )
        return ComputeCapacityPlanningRequest(
            "plan-a",
            resource(ComputeResourceKind.CONTAINER),
            (provider,),
        ).to_dict()

    def test_closed_payload_round_trip_has_canonical_output(self) -> None:
        payload = self.request_payload()
        output = ComputeCapacityPlanningApi().plan(payload)
        self.assertEqual(output["schema"], "home-center.compute-capacity-plan.v1")
        self.assertEqual(output["selected_provider_id"], "provider-a")
        self.assertEqual(
            json.dumps(output, sort_keys=True, separators=(",", ":")),
            json.dumps(ComputeCapacityPlanningApi().plan(copy.deepcopy(payload)), sort_keys=True, separators=(",", ":")),
        )

    def test_http_handler_records_audit_and_returns_the_typed_plan(self) -> None:
        class AuditStore:
            def __init__(self) -> None:
                self.events: list[dict[str, object]] = []

            def audit(self, **event: object) -> str:
                self.events.append(event)
                return "event-a"

        store = AuditStore()
        responses: list[tuple[int, dict[str, object]]] = []
        handler = object.__new__(RuntimeRequestHandler)
        handler.server = SimpleNamespace(runtime=SimpleNamespace(store=store))
        handler._read_json = lambda max_bytes: self.request_payload()
        handler._json = lambda status, value: responses.append((status, value))

        handler._plan_compute_capacity("local-admin:admin", "correlation-a")

        self.assertEqual(responses[0][0], 200)
        self.assertEqual(responses[0][1]["selected_provider_id"], "provider-a")
        self.assertEqual(store.events[0]["action"], "compute.capacity-plan")
        self.assertEqual(store.events[0]["outcome"], "accepted")

    def test_unknown_fields_and_secret_shaped_provider_configuration_are_rejected(self) -> None:
        payload = self.request_payload()
        payload["providers"][0]["provider"]["endpoint"] = "https://provider.example.test"
        with self.assertRaisesRegex(ComputeFrameworkError, "invalid_provider_descriptor"):
            ComputeCapacityPlanningApi().plan(payload)

        payload = self.request_payload()
        payload["providers"][0]["provider"]["capabilities"].append("compute.container.v1")
        with self.assertRaisesRegex(ComputeFrameworkError, "invalid_provider_capability"):
            ComputeCapacityPlanningApi().plan(payload)

    def test_boolean_capacity_and_physical_resource_are_rejected(self) -> None:
        payload = self.request_payload()
        payload["providers"][0]["capacity"]["total"]["vcpu"] = True
        with self.assertRaisesRegex(ComputeFrameworkError, "invalid_capacity_vcpu"):
            ComputeCapacityPlanningApi().plan(payload)

        payload = self.request_payload()
        payload["resource"]["kind"] = "physical"
        with self.assertRaisesRegex(ComputeFrameworkError, "unsupported_resource_kind"):
            ComputeCapacityPlanningApi().plan(payload)


if __name__ == "__main__":
    unittest.main()
