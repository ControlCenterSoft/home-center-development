"""Certificate inventory helpers for Home Center 0.18."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True, slots=True)
class CertificateRecord:
    certificate_id: str
    subject: str
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.certificate_id.strip():
            raise ValueError("certificate_id must not be empty")
        if not self.subject.strip():
            raise ValueError("subject must not be empty")
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware")


def expiring_first(records: tuple[CertificateRecord, ...]) -> tuple[CertificateRecord, ...]:
    return tuple(sorted(records, key=lambda item: (item.expires_at.astimezone(timezone.utc), item.certificate_id)))


def expired(records: tuple[CertificateRecord, ...], *, now: datetime) -> tuple[CertificateRecord, ...]:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    current = now.astimezone(timezone.utc)
    return tuple(item for item in expiring_first(records) if item.expires_at.astimezone(timezone.utc) <= current)
