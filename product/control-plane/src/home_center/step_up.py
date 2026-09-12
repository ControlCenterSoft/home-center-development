"""Short-lived single-use step-up grants for sensitive Home Center mutations."""
from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable

SCOPE = re.compile(r"^[a-z][a-z0-9._:-]{2,255}$")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{32,192}$")


class StepUpError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class StepUpGrantManager:
    """In-memory one-time grants.

    Grants deliberately do not survive process restart or failover. Losing them is
    fail-closed: the operator must re-authenticate, while durable jobs/evidence stay
    intact and are never replayed merely because a grant disappeared.
    """

    def __init__(
        self,
        *,
        lifetime_seconds: int = 300,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(lifetime_seconds, bool) or not 30 <= lifetime_seconds <= 900:
            raise ValueError("invalid_step_up_lifetime")
        self._lifetime = lifetime_seconds
        self._clock = clock
        self._grants: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _validate_identity(actor: object, scope: object) -> tuple[str, str]:
        if not isinstance(actor, str) or not actor or len(actor) > 320:
            raise StepUpError("step_up_actor_invalid")
        if not isinstance(scope, str) or SCOPE.fullmatch(scope) is None:
            raise StepUpError("step_up_scope_invalid")
        return actor, scope

    def _purge(self, now: float) -> None:
        expired = [token for token, (_actor, _scope, deadline) in self._grants.items() if deadline <= now]
        for token in expired:
            self._grants.pop(token, None)

    def issue(self, *, actor: str, scope: str) -> tuple[str, int]:
        actor, scope = self._validate_identity(actor, scope)
        now = self._clock()
        with self._lock:
            self._purge(now)
            token = secrets.token_urlsafe(32)
            while token in self._grants:
                token = secrets.token_urlsafe(32)
            self._grants[token] = (actor, scope, now + self._lifetime)
        return token, self._lifetime

    def consume(self, *, actor: str, scope: str, token: object) -> None:
        actor, scope = self._validate_identity(actor, scope)
        if not isinstance(token, str) or TOKEN.fullmatch(token) is None:
            raise StepUpError("step_up_required")
        now = self._clock()
        with self._lock:
            self._purge(now)
            grant = self._grants.pop(token, None)
        if grant is None:
            raise StepUpError("step_up_required")
        expected_actor, expected_scope, deadline = grant
        if deadline <= now:
            raise StepUpError("step_up_expired")
        if expected_actor != actor or expected_scope != scope:
            raise StepUpError("step_up_binding_mismatch")
