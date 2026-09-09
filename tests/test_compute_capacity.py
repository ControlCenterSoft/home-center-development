from __future__ import annotations

import unittest

from home_center.compute_capacity import Capacity, evaluate_capacity


class ComputeCapacityTests(unittest.TestCase):
    def test_request_fits_and_remaining_capacity_is_returned(self) -> None:
        decision = evaluate_capacity(
            Capacity(cpu_millicores=8000, memory_mib=32768, storage_gib=1000),
            Capacity(cpu_millicores=2500, memory_mib=4096, storage_gib=120),
        )
        self.assertTrue(decision.fits)
        self.assertEqual(Capacity(5500, 28672, 880), decision.remaining)
        self.assertEqual((), decision.limiting_resources)

    def test_all_limiting_resources_are_reported(self) -> None:
        decision = evaluate_capacity(
            Capacity(cpu_millicores=1000, memory_mib=2048, storage_gib=20),
            Capacity(cpu_millicores=2000, memory_mib=4096, storage_gib=40),
        )
        self.assertFalse(decision.fits)
        self.assertIsNone(decision.remaining)
        self.assertEqual(("cpu", "memory", "storage"), decision.limiting_resources)

    def test_negative_capacity_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Capacity(cpu_millicores=-1, memory_mib=0, storage_gib=0)


if __name__ == "__main__":
    unittest.main()
