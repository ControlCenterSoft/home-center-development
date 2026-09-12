from __future__ import annotations

import pytest

from home_center.household_policy_history import (
    POLICY_ROLLBACK_REQUEST_SCHEMA,
    HouseholdPolicyHistoryError,
    _rollback_id,
)
from home_center.household_policy_rollback_audit import (
    ROLLBACK_BEGIN_ACTION,
    ROLLBACK_COMPLETE_ACTION,
    validate_rollback_audit_binding,
)
from home_center.store import StateStore


ACTOR = "parent@example.test"
RESOURCE_KEY = "household-policy:household-test:member-test"
BUNDLE_ID = "hpb-" + "4" * 24


class _Probe:
    def __init__(self, store: StateStore, *, include_current: bool = True) -> None:
        self.store = store
        self.values = {
            (RESOURCE_KEY, 1): {
                "resource_key": RESOURCE_KEY,
                "generation": 1,
                "bundle_id": BUNDLE_ID,
                "evidence_sha256": "1" * 64,
            }
        }
        if include_current:
            self.values[(RESOURCE_KEY, 2)] = {
                "resource_key": RESOURCE_KEY,
                "generation": 2,
                "bundle_id": BUNDLE_ID,
                "evidence_sha256": "2" * 64,
            }

    def read(self, *, resource_key: str, generation: int) -> dict[str, object]:
        try:
            return self.values[(resource_key, generation)]
        except KeyError as exc:
            raise HouseholdPolicyHistoryError("household_policy_history_not_found") from exc


def _request() -> dict[str, object]:
    return {
        "schema": POLICY_ROLLBACK_REQUEST_SCHEMA,
        "resource_key": RESOURCE_KEY,
        "expected_generation": 2,
        "expected_bundle_id": BUNDLE_ID,
        "target_generation": 1,
        "confirmed": True,
    }


def _receipt(audit_event_id: str) -> dict[str, object]:
    return {
        "schema": "home-center.household-policy-rollback-receipt.v1",
        "rollback_id": _rollback_id(ACTOR, _request()),
        "resource_key": RESOURCE_KEY,
        "target_history_generation": 1,
        "target_history_bundle_id": BUNDLE_ID,
        "generation": 2,
        "bundle_id": BUNDLE_ID,
        "changed": False,
        "recovered": False,
        "outcome": "already-current",
        "audit_event_id": audit_event_id,
        "desired_state_materialized": True,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def test_noop_rollback_requires_exact_already_current_completion_evidence(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"n" * 32, "policy-rollback-noop-test")
    service = _Probe(store)
    request = _request()
    rollback_id = _rollback_id(ACTOR, request)
    begin_id = store.audit(
        actor=ACTOR,
        action=ROLLBACK_BEGIN_ACTION,
        target=RESOURCE_KEY,
        outcome="accepted",
        correlation_id="rollback-noop-begin",
        details={
            "rollback_id": rollback_id,
            "expected_generation": 2,
            "expected_bundle_id": BUNDLE_ID,
            "target_history_generation": 1,
            "target_history_bundle_id": BUNDLE_ID,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )
    complete_id = store.audit(
        actor=ACTOR,
        action=ROLLBACK_COMPLETE_ACTION,
        target=RESOURCE_KEY,
        outcome="already-current",
        correlation_id="rollback-noop-complete",
        details={
            "rollback_id": rollback_id,
            "begin_audit_event_id": begin_id,
            "generation": 2,
            "bundle_id": BUNDLE_ID,
            "target_history_generation": 1,
            "history_evidence_sha256": "2" * 64,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )

    validate_rollback_audit_binding(
        service,
        actor=ACTOR,
        request=request,
        receipt=_receipt(complete_id),
    )
    store.close()


def test_missing_current_history_is_integrity_failure_not_not_found(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"m" * 32, "policy-rollback-missing-history-test")
    service = _Probe(store, include_current=False)

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            service,
            actor=ACTOR,
            request=_request(),
            receipt=_receipt("missing-event"),
        )
    store.close()
