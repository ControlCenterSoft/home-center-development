"""Public HTTP idempotency boundary for Home Center 0.59 policy reconciliation.

The underlying reconciliation runtime is deliberately read-only.  This facade adds a
persistent request-idempotency fence suitable for HTTP retries without weakening the
runtime's Household authorization, exact Desired State binding, durable Job/Audit or
post-condition evidence rules.  The raw client idempotency key is never persisted.
"""

from __future__ import annotations

import hashlib
import re
import threading
from typing import Any

from .household_policy_reconciliation_runtime import (
    HouseholdPolicyReconciliationRuntimeError,
    HouseholdPolicyReconciliationRuntimeService,
)
from .store import StateStore
from .util import canonical_json, utc_now

HTTP_REQUEST_SCHEMA = "home-center.household-policy-reconciliation-http-request.v1"
HTTP_IDEMPOTENCY_SCHEMA = "home-center.household-policy-reconciliation-http-idempotency.v1"
HTTP_IDEMPOTENCY_KEY_PREFIX = "cozy.household.policy.reconciliation.http-idempotency."
IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _idempotency_meta_key(actor: str, idempotency_key: str) -> str:
    identity = hashlib.sha256(
        (actor + "\x00" + idempotency_key).encode("utf-8")
    ).hexdigest()
    return HTTP_IDEMPOTENCY_KEY_PREFIX + identity


def _request(value: object) -> dict[str, Any]:
    expected = {
        "schema",
        "member_id",
        "backend_id",
        "max_observed_age_seconds",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("schema") != HTTP_REQUEST_SCHEMA
        or not isinstance(value.get("member_id"), str)
        or not value["member_id"]
        or not isinstance(value.get("backend_id"), str)
        or not value["backend_id"]
        or not isinstance(value.get("max_observed_age_seconds"), int)
        or isinstance(value.get("max_observed_age_seconds"), bool)
        or not 1 <= value["max_observed_age_seconds"] <= 900
    ):
        raise HouseholdPolicyReconciliationRuntimeError(
            "invalid_household_policy_reconciliation_http_request"
        )
    return dict(value)


class HouseholdPolicyReconciliationApiService:
    """Persist one exact HTTP request identity and replay its terminal result safely."""

    def __init__(
        self,
        store: StateStore,
        runtime: HouseholdPolicyReconciliationRuntimeService,
        *,
        now=utc_now,
    ) -> None:
        self.store = store
        self.runtime = runtime
        self._now = now
        self._lock = threading.RLock()

    def reconcile(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        idempotency_key: object,
        correlation_id: str,
    ) -> dict[str, object]:
        body = _request(request)
        if not isinstance(idempotency_key, str):
            raise HouseholdPolicyReconciliationRuntimeError(
                "household_policy_reconciliation_http_idempotency_key_required"
            )
        if IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None:
            raise HouseholdPolicyReconciliationRuntimeError(
                "invalid_household_policy_reconciliation_http_idempotency_key"
            )

        request_hash = _digest({"actor": actor, "request": body})
        key = _idempotency_meta_key(actor, idempotency_key)
        idempotency_key_sha256 = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()

        with self._lock:
            existing = self.store.get_meta(key)
            if existing is not None:
                if (
                    not isinstance(existing, dict)
                    or existing.get("schema") != HTTP_IDEMPOTENCY_SCHEMA
                    or existing.get("actor") != actor
                    or existing.get("idempotency_key_sha256") != idempotency_key_sha256
                ):
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_http_idempotency_state_invalid"
                    )
                if existing.get("request_hash") != request_hash:
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_http_idempotency_conflict"
                    )
                status = existing.get("status")
                if status == "completed":
                    completion = existing.get("completion")
                    if isinstance(completion, dict):
                        return dict(completion)
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_http_idempotency_state_invalid"
                    )
                if status == "failed":
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_http_previous_attempt_failed"
                    )
                if status == "in-progress":
                    raise HouseholdPolicyReconciliationRuntimeError(
                        "household_policy_reconciliation_http_in_progress"
                    )
                raise HouseholdPolicyReconciliationRuntimeError(
                    "household_policy_reconciliation_http_idempotency_state_invalid"
                )

            envelope: dict[str, object] = {
                "schema": HTTP_IDEMPOTENCY_SCHEMA,
                "status": "in-progress",
                "actor": actor,
                "idempotency_key_sha256": idempotency_key_sha256,
                "request_hash": request_hash,
                "request": body,
                "started_at": self._now(),
                "completion": None,
                "failure_code": None,
            }
            self.store.set_meta(key, envelope)

        try:
            completion = self.runtime.reconcile(
                actor=actor,
                member_id=str(body["member_id"]),
                backend_id=str(body["backend_id"]),
                max_observed_age_seconds=int(body["max_observed_age_seconds"]),
                correlation_id=correlation_id,
            )
        except HouseholdPolicyReconciliationRuntimeError as exc:
            failed = dict(envelope)
            failed.update(
                status="failed",
                failure_code=exc.code,
                finished_at=self._now(),
            )
            self.store.set_meta(key, failed)
            raise
        except Exception as exc:
            code = "household_policy_reconciliation_http_runtime_failed"
            failed = dict(envelope)
            failed.update(status="failed", failure_code=code, finished_at=self._now())
            self.store.set_meta(key, failed)
            raise HouseholdPolicyReconciliationRuntimeError(code) from exc

        if not isinstance(completion, dict):
            failed = dict(envelope)
            failed.update(
                status="failed",
                failure_code="household_policy_reconciliation_http_completion_invalid",
                finished_at=self._now(),
            )
            self.store.set_meta(key, failed)
            raise HouseholdPolicyReconciliationRuntimeError(
                "household_policy_reconciliation_http_completion_invalid"
            )

        completed = dict(envelope)
        completed.update(
            status="completed",
            completion=dict(completion),
            finished_at=self._now(),
        )
        self.store.set_meta(key, completed)
        return dict(completion)
