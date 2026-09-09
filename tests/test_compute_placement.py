from __future__ import annotations

import unittest

from home_center.compute_placement import ComputeNode, rank_placement_candidates


class ComputePlacementTests(unittest.TestCase):
    def test_filters_nodes_without_capacity_and_ranks_headroom(self) -> None:
        nodes = (
            ComputeNode("node-b", 8, 16000, 200),
            ComputeNode("node-a", 12, 32000, 500),
            ComputeNode("node-c", 2, 1000, 10),
        )
        result = rank_placement_candidates(nodes, cpu=4, memory_mb=4000, disk_gb=50)
        self.assertEqual([item.node_id for item in result], ["node-a", "node-b"])

    def test_rejects_negative_requirements(self) -> None:
        with self.assertRaises(ValueError):
            rank_placement_candidates((), cpu=-1, memory_mb=0, disk_gb=0)


if __name__ == "__main__":
    unittest.main()
