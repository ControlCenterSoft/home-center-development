"""Retry policy primitives for Home Center 0.17 automation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_delay_seconds: int = 5
    multiplier: int = 2
    max_delay_seconds: int = 300

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.initial_delay_seconds < 0:
            raise ValueError("initial_delay_seconds must be non-negative")
        if self.multiplier < 1:
            raise ValueError("multiplier must be at least 1")
        if self.max_delay_seconds < self.initial_delay_seconds:
            raise ValueError("max_delay_seconds must not be below initial_delay_seconds")


def retry_delay(policy: RetryPolicy, failed_attempt: int) -> int | None:
    """Return delay before the next attempt, or None when retries are exhausted."""
    if failed_attempt < 1:
        raise ValueError("failed_attempt must be at least 1")
    if failed_attempt >= policy.max_attempts:
        return None
    delay = policy.initial_delay_seconds * (policy.multiplier ** (failed_attempt - 1))
    return min(delay, policy.max_delay_seconds)
