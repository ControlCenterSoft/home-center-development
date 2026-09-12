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
    ROLLBACK_RECOVER_ACTION,
    validate_rollback_audit_binding,
)
from home_center.store import StateStore


ACTOR = "parent@example.test"
RESOURCE_KEY = "household-policy:household-test:member-test"
TARGET_BUNDLE = "hpb-" + "1" * 24
CURRENT_BEFORE_BUNDLE = "hpb-" + "2" * 24
CURRENT_GENERATION = 3
CURRENT_EVIDENCE = "c" * 64
TARGET_VALUE = {
    "schema": "home-center.household-policy-bundle.v1",
    "bundle_id": TARGET_BUNDLE,
    "desired_state_resource_key": RESOURCE_KEY,
    "policy": {"internet": {"mode": "family-safe"}},
}


class _HistoryProbe:
    def __init__(self, store: StateStore) -> None:
        self.store = store
        self.values = {
            (RESOURCE_KEY, 1): {
                "resource_key": RESOURCE_KEY,
                "generation": 1,
                "bundle_id": TARGET_BUNDLE,
                "value": TARGET_VALUE,
                "evidence_sha256": "a" * 64,
            },
            (RESOURCE_KEY, CURRENT_GENERATION): {
                "resource_key": RESOURCE_KEY,
                "generation": CURRENT_GENERATION,
                "bundle_id": TARGET_BUNDLE,
                "value": TARGET_VALUE,
                "evidence_sha256": CURRENT_EVIDENCE,
            },
        }

    def read(self, *, resource_key: str, generation: int) -> dict[str, object]:
        return self.values[(resource_key, generation)]


def _request() -> dict[str, object]:
    return {
        "schema": POLICY_ROLLBACK_REQUEST_SCHEMA,
        "resource_key": RESOURCE_KEY,
        "expected_generation": 2,
        "expected_bundle_id": CURRENT_BEFORE_BUNDLE,
        "target_generation": 1,
        "confirmed": True,
    }


def _receipt(*, audit_event_id: str, recovered: bool = False) -> dict[str, object]:
    return {
        "schema": "home-center.household-policy-rollback-receipt.v1",
        "rollback_id": _rollback_id(ACTOR, _request()),
        "resource_key": RESOURCE_KEY,
        "target_history_generation": 1,
        "target_history_bundle_id": TARGET_BUNDLE,
        "generation": CURRENT_GENERATION,
        "bundle_id": TARGET_BUNDLE,
        "changed": True,
        "recovered": recovered,
        "outcome": "rolled-back",
        "audit_event_id": audit_event_id,
        "desired_state_materialized": True,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


def _store(tmp_path) -> StateStore:
    return StateStore(tmp_path / "state.db", b"r" * 32, "policy-rollback-audit-test")


def _normal_audit(store: StateStore, request: dict[str, object]) -> str:
    rollback_id = _rollback_id(ACTOR, request)
    begin_id = store.audit(
        actor=ACTOR,
        action=ROLLBACK_BEGIN_ACTION,
        target=RESOURCE_KEY,
        outcome="accepted",
        correlation_id="rollback-audit-begin",
        details={
            "rollback_id": rollback_id,
            "expected_generation": 2,
            "expected_bundle_id": CURRENT_BEFORE_BUNDLE,
            "target_history_generation": 1,
            "target_history_bundle_id": TARGET_BUNDLE,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )
    return store.audit(
        actor=ACTOR,
        action=ROLLBACK_COMPLETE_ACTION,
        target=RESOURCE_KEY,
        outcome="succeeded",
        correlation_id="rollback-audit-complete",
        details={
            "rollback_id": rollback_id,
            "begin_audit_event_id": begin_id,
            "generation": CURRENT_GENERATION,
            "bundle_id": TARGET_BUNDLE,
            "target_history_generation": 1,
            "history_evidence_sha256": CURRENT_EVIDENCE,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )


def test_exact_rollback_completion_audit_is_accepted_and_replay_uses_same_evidence(tmp_path) -> None:
    store = _store(tmp_path)
    service = _HistoryProbe(store)
    request = _request()
    complete_id = _normal_audit(store, request)

    receipt = _receipt(audit_event_id=complete_id)
    validate_rollback_audit_binding(service, actor=ACTOR, request=request, receipt=receipt)

    replay = dict(receipt)
    replay["outcome"] = "already-rolled-back"
    validate_rollback_audit_binding(service, actor=ACTOR, request=request, receipt=replay)
    store.close()


def test_rollback_receipt_cannot_point_to_unrelated_audit_event(tmp_path) -> None:
    store = _store(tmp_path)
    service = _HistoryProbe(store)
    request = _request()
    unrelated_id = store.audit(
        actor=ACTOR,
        action="household.policy.request",
        target=RESOURCE_KEY,
        outcome="accepted",
        correlation_id="unrelated",
        details={
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            service,
            actor=ACTOR,
            request=request,
            receipt=_receipt(audit_event_id=unrelated_id),
        )
    store.close()


def test_rollback_completion_requires_exact_begin_event_binding(tmp_path) -> None:
    store = _store(tmp_path)
    service = _HistoryProbe(store)
    request = _request()
    rollback_id = _rollback_id(ACTOR, request)
    wrong_begin_id = store.audit(
        actor=ACTOR,
        action=ROLLBACK_BEGIN_ACTION,
        target=RESOURCE_KEY,
        outcome="accepted",
        correlation_id="rollback-wrong-begin",
        details={
            "rollback_id": rollback_id,
            "expected_generation": 999,
            "expected_bundle_id": CURRENT_BEFORE_BUNDLE,
            "target_history_generation": 1,
            "target_history_bundle_id": TARGET_BUNDLE,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )
    complete_id = store.audit(
        actor=ACTOR,
        action=ROLLBACK_COMPLETE_ACTION,
        target=RESOURCE_KEY,
        outcome="succeeded",
        correlation_id="rollback-complete-wrong-begin",
        details={
            "rollback_id": rollback_id,
            "begin_audit_event_id": wrong_begin_id,
            "generation": CURRENT_GENERATION,
            "bundle_id": TARGET_BUNDLE,
            "target_history_generation": 1,
            "history_evidence_sha256": CURRENT_EVIDENCE,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            service,
            actor=ACTOR,
            request=request,
            receipt=_receipt(audit_event_id=complete_id),
        )
    store.close()


def test_recovered_rollback_is_bound_to_exact_recovery_audit(tmp_path) -> None:
    store = _store(tmp_path)
    service = _HistoryProbe(store)
    request = _request()
    rollback_id = _rollback_id(ACTOR, request)
    recover_id = store.audit(
        actor=ACTOR,
        action=ROLLBACK_RECOVER_ACTION,
        target=RESOURCE_KEY,
        outcome="finalized-existing-write",
        correlation_id="rollback-recover",
        details={
            "rollback_id": rollback_id,
            "generation": CURRENT_GENERATION,
            "bundle_id": TARGET_BUNDLE,
            "history_evidence_sha256": CURRENT_EVIDENCE,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
        },
    )

    validate_rollback_audit_binding(
        service,
        actor=ACTOR,
        request=request,
        receipt=_receipt(audit_event_id=recover_id, recovered=True),
    )
    store.close()


def test_rollback_evidence_requires_exact_materialized_target_value(tmp_path) -> None:
    store = _store(tmp_path)
    service = _HistoryProbe(store)
    request = _request()
    complete_id = _normal_audit(store, request)
    service.values[(RESOURCE_KEY, CURRENT_GENERATION)] = {
        **service.values[(RESOURCE_KEY, CURRENT_GENERATION)],
        "value": {
            **TARGET_VALUE,
            "policy": {"internet": {"mode": "unrestricted"}},
        },
    }

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            service,
            actor=ACTOR,
            request=request,
            receipt=_receipt(audit_event_id=complete_id),
        )
    store.close()
