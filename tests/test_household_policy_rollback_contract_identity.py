from __future__ import annotations

from types import SimpleNamespace

import pytest

from home_center.household_policy_history import (
    POLICY_ROLLBACK_RECEIPT_SCHEMA,
    POLICY_ROLLBACK_REQUEST_SCHEMA,
    HouseholdPolicyHistoryError,
    _rollback_id,
)
from home_center.household_policy_rollback_audit import validate_rollback_audit_binding


ACTOR = "parent@example.test"
RESOURCE_KEY = "household-policy:household-test:member-test"


class _NoAuditAccessStore:
    path = "unused.db"

    def verify_audit_chain(self) -> None:
        raise AssertionError("malformed rollback evidence reached Audit lookup")


def _service():
    return SimpleNamespace(store=_NoAuditAccessStore())


def _request() -> dict[str, object]:
    return {
        "schema": POLICY_ROLLBACK_REQUEST_SCHEMA,
        "resource_key": RESOURCE_KEY,
        "expected_generation": 2,
        "expected_bundle_id": "hpb-" + "2" * 24,
        "target_generation": 1,
        "confirmed": True,
    }


def _receipt(request: dict[str, object]) -> dict[str, object]:
    return {
        "schema": POLICY_ROLLBACK_RECEIPT_SCHEMA,
        "rollback_id": _rollback_id(ACTOR, request),
        "resource_key": RESOURCE_KEY,
        "target_history_generation": 1,
        "target_history_bundle_id": "hpb-" + "1" * 24,
        "generation": 3,
        "bundle_id": "hpb-" + "1" * 24,
        "changed": True,
        "recovered": False,
        "outcome": "rolled-back",
        "audit_event_id": "audit-test",
        "desired_state_materialized": True,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda request, receipt: request.__setitem__("schema", "home-center.household-policy-rollback-request.v999"),
        lambda request, receipt: request.__setitem__("confirmed", False),
        lambda request, receipt: request.__setitem__("unexpected_authority", True),
        lambda request, receipt: receipt.__setitem__("schema", "home-center.household-policy-rollback-receipt.v999"),
        lambda request, receipt: receipt.__setitem__("policy_application_authorized", True),
        lambda request, receipt: receipt.pop("external_publication_authorized"),
    ],
)
def test_malformed_rollback_contract_is_rejected_before_audit_lookup(mutate) -> None:
    request = _request()
    receipt = _receipt(request)
    mutate(request, receipt)

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            _service(),
            actor=ACTOR,
            request=request,
            receipt=receipt,
        )


def test_target_generation_must_precede_expected_generation_before_audit_lookup() -> None:
    request = _request()
    request["expected_generation"] = 1
    receipt = _receipt(request)
    receipt["generation"] = 2

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            _service(),
            actor=ACTOR,
            request=request,
            receipt=receipt,
        )


def test_changed_rollback_generation_must_be_exact_successor_before_audit_lookup() -> None:
    request = _request()
    receipt = _receipt(request)
    receipt["generation"] = 4

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            _service(),
            actor=ACTOR,
            request=request,
            receipt=receipt,
        )


def test_unchanged_rollback_generation_must_equal_expected_before_audit_lookup() -> None:
    request = _request()
    receipt = _receipt(request)
    receipt["changed"] = False
    receipt["outcome"] = "already-current"

    with pytest.raises(HouseholdPolicyHistoryError, match="household_policy_rollback_evidence_mismatch"):
        validate_rollback_audit_binding(
            _service(),
            actor=ACTOR,
            request=request,
            receipt=receipt,
        )
