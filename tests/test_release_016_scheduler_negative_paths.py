from __future__ import annotations

import unittest

from home_center.core import (
    ComputeProviderDescriptor,
    ComputeProviderKind,
    ComputeResourceKind,
    ComputeResourceRequest,
    PlacementRequest,
    ProviderCapacity,
    ResourceScheduler,
    ResourceSchedulerError,
)


def provider(
    provider_id: str,
    *,
    healthy: bool = True,
    capabilities: tuple[str, ...] = ("compute.vm.v1",),
) -> ComputeProviderDescriptor:
    return ComputeProviderDescriptor.create(
        provider_id=provider_id,
        kind=ComputeProviderKind.PROXMOX,
        healthy=healthy,
        capabilities=capabilities,
    )


def request(*, high_availability: bool = False) -> ComputeResourceRequest:
    return ComputeResourceRequest(
        "guest-a",
        ComputeResourceKind.VM,
        2,
        1024,
        16,
        high_availability,
    )


class ResourceSchedulerNegativePathTests(unittest.TestCase):
    def test_unhealthy_provider_is_not_eligible(self) -> None:
        plan = ResourceScheduler().plan(
            PlacementRequest("placement-a", request()),
            (ProviderCapacity(provider("provider-a", healthy=False), 8, 8192, 128),),
        )
        self.assertEqual(plan.state, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))
        self.assertIs(plan.production_mutation_enabled, False)

    def test_missing_runtime_capability_is_not_eligible(self) -> None:
        plan = ResourceScheduler().plan(
            PlacementRequest("placement-a", request()),
            (
                ProviderCapacity(
                    provider("provider-a", capabilities=("compute.lxc.v1",)),
                    8,
                    8192,
                    128,
                ),
            ),
        )
        self.assertEqual(plan.state, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))

    def test_ha_request_requires_ha_capability(self) -> None:
        plan = ResourceScheduler().plan(
            PlacementRequest("placement-a", request(high_availability=True)),
            (ProviderCapacity(provider("provider-a"), 8, 8192, 128),),
        )
        self.assertEqual(plan.state, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))
        self.assertIs(plan.production_mutation_enabled, False)

    def test_required_labels_fail_closed(self) -> None:
        plan = ResourceScheduler().plan(
            PlacementRequest(
                "placement-a",
                request(),
                required_labels=("storage.fast",),
            ),
            (
                ProviderCapacity(
                    provider("provider-a"),
                    8,
                    8192,
                    128,
                    labels=("storage.standard",),
                ),
            ),
        )
        self.assertEqual(plan.state, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))

    def test_avoided_failure_domain_is_not_selected(self) -> None:
        plan = ResourceScheduler().plan(
            PlacementRequest(
                "placement-a",
                request(),
                avoid_failure_domains=("rack-a",),
            ),
            (
                ProviderCapacity(
                    provider("provider-a"),
                    8,
                    8192,
                    128,
                    failure_domain="rack-a",
                ),
            ),
        )
        self.assertEqual(plan.state, "blocked")
        self.assertEqual(plan.blockers, ("no_eligible_provider",))

    def test_equal_scores_use_provider_id_as_deterministic_tie_breaker(self) -> None:
        plan = ResourceScheduler().plan(
            PlacementRequest("placement-a", request()),
            (
                ProviderCapacity(provider("provider-z"), 8, 8192, 128),
                ProviderCapacity(provider("provider-a"), 8, 8192, 128),
            ),
        )
        self.assertEqual(plan.state, "planned")
        self.assertEqual(plan.provider_id, "provider-a")
        self.assertIs(plan.production_mutation_enabled, False)

    def test_provider_observation_is_bounded(self) -> None:
        observations = tuple(
            ProviderCapacity(provider(f"provider-{index:02d}"), 8, 8192, 128)
            for index in range(65)
        )
        with self.assertRaisesRegex(ResourceSchedulerError, "invalid_providers"):
            ResourceScheduler().plan(
                PlacementRequest("placement-a", request()),
                observations,
            )

    def test_duplicate_preference_is_rejected(self) -> None:
        with self.assertRaisesRegex(ResourceSchedulerError, "invalid_preferred_providers"):
            PlacementRequest(
                "placement-a",
                request(),
                preferred_providers=("provider-a", "provider-a"),
            )


if __name__ == "__main__":
    unittest.main()
