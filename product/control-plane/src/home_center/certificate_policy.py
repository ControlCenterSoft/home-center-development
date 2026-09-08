"""Certificate renewal policy primitives for Home Center."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum


class RenewalState(StrEnum):
    VALID = "valid"
    RENEW = "renew"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class CertificateDecision:
    state: RenewalState
    remaining: timedelta
    renewal_due_at: datetime


def evaluate_certificate(
    *,
    now: datetime,
    not_after: datetime,
    renewal_window: timedelta = timedelta(days=30),
) -> CertificateDecision:
    if now.tzinfo is None or not_after.tzinfo is None:
        raise ValueError("certificate timestamps must be timezone-aware")
    if renewal_window < timedelta(0):
        raise ValueError("renewal_window must be non-negative")

    remaining = not_after - now
    renewal_due_at = not_after - renewal_window
    if remaining <= timedelta(0):
        state = RenewalState.EXPIRED
    elif now >= renewal_due_at:
        state = RenewalState.RENEW
    else:
        state = RenewalState.VALID

    return CertificateDecision(
        state=state,
        remaining=remaining,
        renewal_due_at=renewal_due_at,
    )
