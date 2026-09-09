from __future__ import annotations

import unittest

from home_center.placement_constraints import PlacementCandidate, PlacementRequest, rank_candidates


class PlacementConstraintTests(unittest.TestCase):
    def test_filters_labels_and_failure_domains(self) -> None:
        request = PlacementRequest(
            workload_id="vm-01",
            required_labels=("ssd",),
            forbidden_failure_domains=("rack-b",),
        )
        candidates = [
            PlacementCandidate("node-a", labels=("ssd",), failure_domain="rack-a", free_cpu=8, free_memory_mb=8192),
            PlacementCandidate("node-b", labels=("ssd",), failure_domain="rack-b", free_cpu=16, free_memory_mb=16384),
            PlacementCandidate("node-c", labels=("hdd",), failure_domain="rack-c", free_cpu=32, free_memory_mb=32768),
        ]

        ranked = rank_candidates(request, candidates)
        self.assertEqual([item.node_id for item in ranked], ["node-a"])

    def test_ranks_by_free_cpu_then_memory_then_node_id(self) -> None:
        request = PlacementRequest(workload_id="ct-01")
        candidates = [
            PlacementCandidate("node-c", free_cpu=4, free_memory_mb=8192),
            PlacementCandidate("node-a", free_cpu=8, free_memory_mb=4096),
            PlacementCandidate("node-b", free_cpu=8, free_memory_mb=16384),
        ]

        ranked = rank_candidates(request, candidates)
        self.assertEqual([item.node_id for item in ranked], ["node-b", "node-a", "node-c"])

    def test_skips_unschedulable_nodes(self) -> None:
        ranked = rank_candidates(
            PlacementRequest(workload_id="vm-02"),
            [PlacementCandidate("node-a", schedulable=False, free_cpu=100, free_memory_mb=100000)],
        )
        self.assertEqual(ranked, [])


if __name__ == "__main__":
    unittest.main()
