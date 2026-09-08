"""Certificate renewal queue planning for Home Center."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class CertificateRecord:
    certificate_id: str
    not_after: datetime
    renew_before_days: int = 30


@dataclass(frozen=True)
class RenewalItem:
    certificate_id: str
    priority: int
    reason: str
    not_after: datetime


def build_renewal_queue(records: list[CertificateRecord], now: datetime) -> list[RenewalItem]:
    """Return expired/due certificates ordered by urgency and identifier."""

    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")

    seen: set[str] = set()
    queue: list[RenewalItem] = []
    for record in records:
        certificate_id = record.certificate_id.strip()
        if not certificate_id:
            raise ValueError("certificate_id is required")
        if certificate_id in seen:
            raise ValueError(f"duplicate certificate_id: {certificate_id}")
        seen.add(certificate_id)
        if record.not_after.tzinfo is None or record.not_after.utcoffset() is None:
            raise ValueError("not_after must be timezone-aware")
        if record.renew_before_days < 0:
            raise ValueError("renew_before_days must be non-negative")

        if record.not_after <= now:
            queue.append(RenewalItem(certificate_id, 0, "expired", record.not_after))
            continue

        renewal_at = record.not_after - timedelta(days=record.renew_before_days)
        if renewal_at <= now:
            queue.append(RenewalItem(certificate_id, 1, "renewal-window", record.not_after))

    queue.sort(key=lambda item: (item.priority, item.not_after, item.certificate_id))
    return queue
