from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from home_center.certificate_inventory import CertificateRecord, expired, expiring_first


class CertificateInventoryTests(unittest.TestCase):
    def test_orders_by_expiration_and_filters_expired(self) -> None:
        now = datetime(2026, 9, 8, tzinfo=timezone.utc)
        later = CertificateRecord("b", "service-b", now + timedelta(days=10))
        older = CertificateRecord("a", "service-a", now - timedelta(days=1))
        records = (later, older)
        self.assertEqual([item.certificate_id for item in expiring_first(records)], ["a", "b"])
        self.assertEqual([item.certificate_id for item in expired(records, now=now)], ["a"])

    def test_rejects_naive_expiration(self) -> None:
        with self.assertRaises(ValueError):
            CertificateRecord("x", "service", datetime(2026, 9, 8))


if __name__ == "__main__":
    unittest.main()
