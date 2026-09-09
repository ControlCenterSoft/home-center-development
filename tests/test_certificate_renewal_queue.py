from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from home_center.certificate_renewal_queue import CertificateRecord, build_renewal_queue


class CertificateRenewalQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)

    def test_prioritizes_expired_before_due(self) -> None:
        queue = build_renewal_queue(
            [
                CertificateRecord("due", self.now + timedelta(days=10), renew_before_days=30),
                CertificateRecord("expired", self.now - timedelta(minutes=1), renew_before_days=30),
            ],
            self.now,
        )
        self.assertEqual([item.certificate_id for item in queue], ["expired", "due"])
        self.assertEqual([item.reason for item in queue], ["expired", "renewal-window"])

    def test_omits_certificate_outside_renewal_window(self) -> None:
        queue = build_renewal_queue(
            [CertificateRecord("later", self.now + timedelta(days=90), renew_before_days=30)],
            self.now,
        )
        self.assertEqual(queue, [])

    def test_rejects_duplicate_ids(self) -> None:
        with self.assertRaises(ValueError):
            build_renewal_queue(
                [
                    CertificateRecord("same", self.now + timedelta(days=1)),
                    CertificateRecord("same", self.now + timedelta(days=2)),
                ],
                self.now,
            )

    def test_requires_timezone_aware_now(self) -> None:
        with self.assertRaises(ValueError):
            build_renewal_queue([], datetime(2026, 9, 8, 12, 0))


if __name__ == "__main__":
    unittest.main()
