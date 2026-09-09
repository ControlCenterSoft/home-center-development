from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from home_center.certificate_policy import RenewalState, evaluate_certificate


class CertificatePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)

    def test_valid_certificate_outside_window(self) -> None:
        decision = evaluate_certificate(
            now=self.now,
            not_after=self.now + timedelta(days=90),
        )
        self.assertEqual(RenewalState.VALID, decision.state)

    def test_certificate_inside_window_requires_renewal(self) -> None:
        decision = evaluate_certificate(
            now=self.now,
            not_after=self.now + timedelta(days=10),
        )
        self.assertEqual(RenewalState.RENEW, decision.state)

    def test_expired_certificate_is_detected(self) -> None:
        decision = evaluate_certificate(
            now=self.now,
            not_after=self.now - timedelta(seconds=1),
        )
        self.assertEqual(RenewalState.EXPIRED, decision.state)

    def test_naive_timestamps_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            evaluate_certificate(
                now=datetime(2026, 9, 8, 12, 0),
                not_after=datetime(2026, 10, 8, 12, 0),
            )


if __name__ == "__main__":
    unittest.main()
