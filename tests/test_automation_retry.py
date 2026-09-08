from __future__ import annotations

import unittest

from home_center.automation_retry import RetryPolicy, retry_delay


class AutomationRetryTests(unittest.TestCase):
    def test_exponential_backoff_is_bounded(self) -> None:
        policy = RetryPolicy(max_attempts=5, initial_delay_seconds=10, multiplier=3, max_delay_seconds=50)
        self.assertEqual(retry_delay(policy, 1), 10)
        self.assertEqual(retry_delay(policy, 2), 30)
        self.assertEqual(retry_delay(policy, 3), 50)
        self.assertEqual(retry_delay(policy, 5), None)

    def test_invalid_policy_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RetryPolicy(max_attempts=0)


if __name__ == "__main__":
    unittest.main()
