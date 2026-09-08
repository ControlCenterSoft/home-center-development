from __future__ import annotations

import unittest

from home_center.node_health import HealthSignal, HealthState, aggregate_node_health


class NodeHealthTests(unittest.TestCase):
    def test_empty_signal_set_is_unknown(self) -> None:
        health = aggregate_node_health([])
        self.assertEqual(HealthState.UNKNOWN, health.state)
        self.assertFalse(health.ready)

    def test_worst_signal_wins(self) -> None:
        health = aggregate_node_health(
            [
                HealthSignal("storage", HealthState.HEALTHY),
                HealthSignal("network", HealthState.DEGRADED, "packet loss"),
                HealthSignal("service", HealthState.UNHEALTHY, "stopped"),
            ]
        )
        self.assertEqual(HealthState.UNHEALTHY, health.state)
        self.assertFalse(health.ready)

    def test_signals_are_stably_sorted(self) -> None:
        health = aggregate_node_health(
            [
                HealthSignal("zeta", HealthState.HEALTHY),
                HealthSignal("alpha", HealthState.HEALTHY),
            ]
        )
        self.assertEqual(["alpha", "zeta"], [signal.source for signal in health.signals])


if __name__ == "__main__":
    unittest.main()
