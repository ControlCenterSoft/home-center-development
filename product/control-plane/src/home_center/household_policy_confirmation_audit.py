"""Audit-bound Policy Composer Desired State materialization for Home Center 0.59.

The 0.59 confirmation envelope is stored in cluster metadata while the authoritative
confirmation event lives in the keyed append-only Audit chain.  This production
wrapper refuses every Desired State apply/replay unless the persisted confirmation
points to the exact matching Audit event.  It never grants provider execution or
infrastructure mutation authority.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .household_policy_desired_state import (
    HouseholdPolicyDesiredStateError,
    HouseholdPolicyDesiredStateService,
    _proposal_key,
)


CONFIRM_ACTION = "household.policy.confirm"


def validate_confirmation_audit_binding(
    service: HouseholdPolicyDesiredStateService,
    *,
    proposal: dict[str, Any],
    confirmation: dict[str, Any],
) -> None:
    """Fail closed unless confirmation metadata is bound to the exact Audit event."""

    audit_event_id = confirmation.get("audit_event_id")
    bundle = proposal.get("bundle")
    if not isinstance(audit_event_id, str) or not audit_event_id or not isinstance(bundle, dict):
        raise HouseholdPolicyDesiredStateError("household_policy_confirmation_audit_invalid")

    try:
        service.store.verify_audit_chain()
    except RuntimeError as exc:
        raise HouseholdPolicyDesiredStateError("household_policy_confirmation_audit_invalid") from exc

    connection = sqlite3.connect(service.store.path, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT action,target,outcome,details_json FROM audit WHERE event_id=?",
            (audit_event_id,),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise HouseholdPolicyDesiredStateError("household_policy_confirmation_audit_missing")

    try:
        details = json.loads(row["details_json"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise HouseholdPolicyDesiredStateError("household_policy_confirmation_audit_invalid") from exc
    if not isinstance(details, dict):
        raise HouseholdPolicyDesiredStateError("household_policy_confirmation_audit_invalid")

    expected = {
        "proposal_id": proposal.get("proposal_id"),
        "confirmation_id": confirmation.get("confirmation_id"),
        "snapshot_id": proposal.get("snapshot_id"),
        "resource_version": proposal.get("resource_version"),
        "bundle_id": bundle.get("bundle_id"),
        "expected_desired_state_generation": proposal.get("expected_desired_state_generation"),
        "expected_desired_state_bundle_id": proposal.get("expected_desired_state_bundle_id"),
        "desired_state_write_ready": True,
        "desired_state_write_authorized": False,
        "infrastructure_mutation_authorized": False,
    }
    if (
        row["action"] != CONFIRM_ACTION
        or row["target"] != bundle.get("desired_state_resource_key")
        or row["outcome"] != "accepted"
        or any(details.get(key) != value for key, value in expected.items())
    ):
        raise HouseholdPolicyDesiredStateError("household_policy_confirmation_audit_mismatch")


class AuditBoundHouseholdPolicyDesiredStateService(HouseholdPolicyDesiredStateService):
    """Production 0.59 writer that verifies confirmation Audit evidence before use."""

    def apply(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        proposal_id = request.get("proposal_id") if isinstance(request, dict) else None
        proposal_key = _proposal_key(proposal_id)
        raw_proposal, confirmation = self._confirmed_envelope(self.store.get_meta(proposal_key))
        if confirmation.get("confirmation_id") != request.get("confirmation_id"):
            raise HouseholdPolicyDesiredStateError("household_policy_confirmation_evidence_mismatch")
        validate_confirmation_audit_binding(
            self,
            proposal=raw_proposal,
            confirmation=confirmation,
        )
        return super().apply(actor=actor, request=request, correlation_id=correlation_id)
