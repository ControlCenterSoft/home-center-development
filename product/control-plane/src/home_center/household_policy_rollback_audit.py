"""Exact Audit binding for Home Center 0.59 policy rollback receipts.

The rollback engine already uses exact Desired State/history preconditions and emits
append-only Audit events. This layer closes the final evidence gap: a successful
or replayed rollback receipt is trusted only when its ``audit_event_id`` resolves
to the exact completion/recovery event for the same actor, request, history
revision and materialized result. Normal completion is also chained to the exact
``rollback.begin`` event.

No method here grants provider execution, infrastructure mutation or external
publication authority.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .household_policy_authorized_history import ScopedHouseholdPolicyHistoryService
from .household_policy_history import HouseholdPolicyHistoryError, _rollback_id


ROLLBACK_BEGIN_ACTION = "household.policy.desired-state.rollback.begin"
ROLLBACK_COMPLETE_ACTION = "household.policy.desired-state.rollback.complete"
ROLLBACK_RECOVER_ACTION = "household.policy.desired-state.rollback.recover"
ROLLBACK_EVIDENCE_ERROR = "household_policy_rollback_evidence_mismatch"


def _audit_row(
    service: ScopedHouseholdPolicyHistoryService,
    event_id: object,
) -> sqlite3.Row:
    if not isinstance(event_id, str) or not event_id:
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)
    connection = sqlite3.connect(service.store.path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT event_id,actor,action,target,outcome,details_json FROM audit WHERE event_id=?",
            (event_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)
    return row


def _audit_details(row: sqlite3.Row) -> dict[str, Any]:
    try:
        details = json.loads(row["details_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR) from exc
    if not isinstance(details, dict):
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)
    return details


def _authority_is_denied(details: dict[str, Any]) -> bool:
    return (
        details.get("provider_execution_authorized") is False
        and details.get("infrastructure_mutation_authorized") is False
    )


def validate_rollback_audit_binding(
    service: ScopedHouseholdPolicyHistoryService,
    *,
    actor: str,
    request: dict[str, Any],
    receipt: dict[str, object],
) -> None:
    """Fail closed unless one rollback receipt is bound to its exact Audit evidence."""

    if not isinstance(actor, str) or not actor or not isinstance(request, dict) or not isinstance(receipt, dict):
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)

    try:
        service.store.verify_audit_chain()
    except RuntimeError as exc:
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR) from exc

    try:
        expected_rollback_id = _rollback_id(actor, request)
    except (KeyError, TypeError, ValueError) as exc:
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR) from exc
    resource_key = request.get("resource_key")
    target_generation = request.get("target_generation")
    expected_generation = request.get("expected_generation")
    expected_bundle_id = request.get("expected_bundle_id")
    generation = receipt.get("generation")
    bundle_id = receipt.get("bundle_id")
    audit_event_id = receipt.get("audit_event_id")
    recovered = receipt.get("recovered")
    changed = receipt.get("changed")
    outcome = receipt.get("outcome")

    if (
        not isinstance(resource_key, str)
        or not resource_key
        or isinstance(target_generation, bool)
        or not isinstance(target_generation, int)
        or target_generation < 1
        or isinstance(expected_generation, bool)
        or not isinstance(expected_generation, int)
        or expected_generation < 1
        or not isinstance(expected_bundle_id, str)
        or not expected_bundle_id
        or isinstance(generation, bool)
        or not isinstance(generation, int)
        or generation < 1
        or not isinstance(bundle_id, str)
        or not bundle_id
        or not isinstance(recovered, bool)
        or not isinstance(changed, bool)
        or receipt.get("rollback_id") != expected_rollback_id
        or receipt.get("resource_key") != resource_key
        or receipt.get("target_history_generation") != target_generation
        or receipt.get("desired_state_materialized") is not True
        or receipt.get("provider_execution_authorized") is not False
        or receipt.get("infrastructure_mutation_authorized") is not False
        or receipt.get("external_publication_authorized") is not False
    ):
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)

    allowed_receipt_outcomes = (
        {"rolled-back", "already-rolled-back"}
        if changed
        else {"already-current", "already-rolled-back"}
    )
    if outcome not in allowed_receipt_outcomes or (recovered and changed is not True):
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)

    try:
        target_history = service.read(resource_key=resource_key, generation=target_generation)
        current_history = service.read(resource_key=resource_key, generation=generation)
    except HouseholdPolicyHistoryError as exc:
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR) from exc
    target_bundle_id = target_history.get("bundle_id")
    history_evidence_sha256 = current_history.get("evidence_sha256")
    if (
        receipt.get("target_history_bundle_id") != target_bundle_id
        or current_history.get("bundle_id") != bundle_id
        or not isinstance(history_evidence_sha256, str)
        or len(history_evidence_sha256) != 64
        or any(char not in "0123456789abcdef" for char in history_evidence_sha256)
    ):
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)

    row = _audit_row(service, audit_event_id)
    details = _audit_details(row)

    if recovered:
        if (
            row["actor"] != actor
            or row["action"] != ROLLBACK_RECOVER_ACTION
            or row["target"] != resource_key
            or row["outcome"] != "finalized-existing-write"
            or details.get("rollback_id") != expected_rollback_id
            or details.get("generation") != generation
            or details.get("bundle_id") != bundle_id
            or details.get("history_evidence_sha256") != history_evidence_sha256
            or not _authority_is_denied(details)
        ):
            raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)
        return

    expected_outcome = "succeeded" if changed else "already-current"
    begin_event_id = details.get("begin_audit_event_id")
    if (
        row["actor"] != actor
        or row["action"] != ROLLBACK_COMPLETE_ACTION
        or row["target"] != resource_key
        or row["outcome"] != expected_outcome
        or details.get("rollback_id") != expected_rollback_id
        or details.get("generation") != generation
        or details.get("bundle_id") != bundle_id
        or details.get("target_history_generation") != target_generation
        or details.get("history_evidence_sha256") != history_evidence_sha256
        or not _authority_is_denied(details)
        or not isinstance(begin_event_id, str)
        or not begin_event_id
    ):
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)

    begin_row = _audit_row(service, begin_event_id)
    begin_details = _audit_details(begin_row)
    if (
        begin_row["actor"] != actor
        or begin_row["action"] != ROLLBACK_BEGIN_ACTION
        or begin_row["target"] != resource_key
        or begin_row["outcome"] != "accepted"
        or begin_details.get("rollback_id") != expected_rollback_id
        or begin_details.get("expected_generation") != expected_generation
        or begin_details.get("expected_bundle_id") != expected_bundle_id
        or begin_details.get("target_history_generation") != target_generation
        or begin_details.get("target_history_bundle_id") != target_bundle_id
        or not _authority_is_denied(begin_details)
    ):
        raise HouseholdPolicyHistoryError(ROLLBACK_EVIDENCE_ERROR)
