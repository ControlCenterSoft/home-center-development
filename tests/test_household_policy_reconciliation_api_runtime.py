from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household_policy_reconciliation_api_runtime import (
    HTTP_REQUEST_SCHEMA,
    HouseholdPolicyReconciliationApiService,
)
from home_center.household_policy_reconciliation_runtime import (
    HouseholdPolicyReconciliationRuntimeError,
)
from home_center.store import StateStore

ACTOR = "local-admin:admin"
MEMBER = "member-child"
BACKEND = "policy-backend.readonly"


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"i" * 32, "cluster-test")


def _request(*, max_age: int = 300) -> dict[str, object]:
    return {
        "schema": HTTP_REQUEST_SCHEMA,
        "member_id": MEMBER,
        "backend_id": BACKEND,
        "max_observed_age_seconds": max_age,
    }


class SuccessfulRuntime:
    def __init__(self) -> None:
        self.calls = 0

    def reconcile(self, **kwargs: object) -> dict[str, object]:
        self.calls += 1
        return {
            "schema": "home-center.household-policy-reconciliation-runtime-completion.v1",
            "state": "verified",
            "request_id": "hprq-0123456789abcdef01234567",
            "backend_id": kwargs["backend_id"],
            "member_id": kwargs["member_id"],
            "job_id": "job-test",
            "evidence": {"enforcement_verified": True},
            "desired_state_transition_performed": False,
            "backend_mutation_performed": False,
            "infrastructure_mutation_performed": False,
            "external_publication_performed": False,
        }


class FailingRuntime:
    def __init__(self) -> None:
        self.calls = 0

    def reconcile(self, **_kwargs: object) -> dict[str, object]:
        self.calls += 1
        raise HouseholdPolicyReconciliationRuntimeError(
            "household_policy_reconciliation_backend_read_failed"
        )


def test_http_replay_returns_cached_completion_without_reinvoking_runtime(tmp_path: Path) -> None:
    store = _store(tmp_path)
    runtime = SuccessfulRuntime()
    service = HouseholdPolicyReconciliationApiService(store, runtime)  # type: ignore[arg-type]

    first = service.reconcile(
        actor=ACTOR,
        request=_request(),
        idempotency_key="policy-reconcile-0001",
        correlation_id="corr-first",
    )
    second = service.reconcile(
        actor=ACTOR,
        request=_request(),
        idempotency_key="policy-reconcile-0001",
        correlation_id="corr-replay",
    )

    assert first == second
    assert runtime.calls == 1
    store.close()


def test_http_idempotency_key_reuse_with_different_request_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    runtime = SuccessfulRuntime()
    service = HouseholdPolicyReconciliationApiService(store, runtime)  # type: ignore[arg-type]

    service.reconcile(
        actor=ACTOR,
        request=_request(max_age=300),
        idempotency_key="policy-reconcile-0002",
        correlation_id="corr-first",
    )

    with pytest.raises(
        HouseholdPolicyReconciliationRuntimeError,
        match="household_policy_reconciliation_http_idempotency_conflict",
    ):
        service.reconcile(
            actor=ACTOR,
            request=_request(max_age=120),
            idempotency_key="policy-reconcile-0002",
            correlation_id="corr-conflict",
        )

    assert runtime.calls == 1
    store.close()


def test_failed_http_attempt_is_fail_closed_and_not_reinvoked(tmp_path: Path) -> None:
    store = _store(tmp_path)
    runtime = FailingRuntime()
    service = HouseholdPolicyReconciliationApiService(store, runtime)  # type: ignore[arg-type]

    with pytest.raises(
        HouseholdPolicyReconciliationRuntimeError,
        match="household_policy_reconciliation_backend_read_failed",
    ):
        service.reconcile(
            actor=ACTOR,
            request=_request(),
            idempotency_key="policy-reconcile-0003",
            correlation_id="corr-first",
        )

    with pytest.raises(
        HouseholdPolicyReconciliationRuntimeError,
        match="household_policy_reconciliation_http_previous_attempt_failed",
    ):
        service.reconcile(
            actor=ACTOR,
            request=_request(),
            idempotency_key="policy-reconcile-0003",
            correlation_id="corr-replay",
        )

    assert runtime.calls == 1
    store.close()


def test_http_idempotency_key_is_required_and_bounded(tmp_path: Path) -> None:
    store = _store(tmp_path)
    runtime = SuccessfulRuntime()
    service = HouseholdPolicyReconciliationApiService(store, runtime)  # type: ignore[arg-type]

    with pytest.raises(
        HouseholdPolicyReconciliationRuntimeError,
        match="household_policy_reconciliation_http_idempotency_key_required",
    ):
        service.reconcile(
            actor=ACTOR,
            request=_request(),
            idempotency_key=None,
            correlation_id="corr-missing",
        )

    with pytest.raises(
        HouseholdPolicyReconciliationRuntimeError,
        match="invalid_household_policy_reconciliation_http_idempotency_key",
    ):
        service.reconcile(
            actor=ACTOR,
            request=_request(),
            idempotency_key="short",
            correlation_id="corr-short",
        )

    assert runtime.calls == 0
    store.close()
