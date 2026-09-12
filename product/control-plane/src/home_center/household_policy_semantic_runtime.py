"""Semantic and actor-bound runtime for Home Center 0.59 Policy Composer.

A proposal must never use only a persisted bundle ID as its optimistic-concurrency
anchor. This production runtime verifies the full current PolicyBundle semantics
before recording the observed generation/bundle precondition. It also prevents
terminal confirmation/recovery state from becoming a cross-member information or
replay surface: an existing proposal is visible/replayable only to the actor bound
to the exact member that created it in the active Household.
"""

from __future__ import annotations

from typing import Any

from .household_policy_evidence import HouseholdPolicyEvidenceError, validate_policy_bundle_evidence
from .household_policy_runtime import (
    POLICY_CONFIRM_REQUEST_SCHEMA,
    POLICY_RECOVERY_REQUEST_SCHEMA,
    HouseholdPolicyRuntimeError,
    HouseholdPolicyRuntimeService,
    _proposal_key,
)


class SemanticHouseholdPolicyRuntimeService(HouseholdPolicyRuntimeService):
    """Production policy runtime with semantic state and exact proposal actor binding."""

    def _desired_state_revision(self, resource_key: str) -> tuple[int, str | None]:
        matches = [item for item in self.store.desired_state() if item.get("resource_key") == resource_key]
        if not matches:
            return 0, None
        if len(matches) != 1:
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")

        record = matches[0]
        generation = record.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        try:
            bundle = validate_policy_bundle_evidence(
                record.get("value"),
                expected_resource_key=resource_key,
            )
        except HouseholdPolicyEvidenceError as exc:
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid") from exc
        bundle_id = bundle.get("bundle_id")
        if not isinstance(bundle_id, str):
            raise HouseholdPolicyRuntimeError("household_policy_desired_state_invalid")
        return generation, bundle_id

    def _authorize_existing_proposal(self, *, actor: str, proposal_id: object) -> None:
        key = _proposal_key(proposal_id)
        envelope = self._validate_envelope(self.store.get_meta(key))
        proposal = envelope.get("proposal")
        if not isinstance(proposal, dict):
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")

        snapshot, bindings = self._read_household_state()
        actor_member_id = self._actor_member(actor, bindings)
        if (
            proposal.get("household_id") != snapshot.household_id
            or proposal.get("actor_member_id") != actor_member_id
        ):
            raise HouseholdPolicyRuntimeError("household_policy_composition_actor_mismatch")

    def confirm(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        valid_shape = (
            isinstance(request, dict)
            and set(request) == {"schema", "proposal_id", "confirmed"}
            and request.get("schema") == POLICY_CONFIRM_REQUEST_SCHEMA
            and request.get("confirmed") is True
        )
        if not valid_shape:
            return super().confirm(actor=actor, request=request, correlation_id=correlation_id)

        with self._lock:
            self._authorize_existing_proposal(actor=actor, proposal_id=request.get("proposal_id"))
            return super().confirm(actor=actor, request=request, correlation_id=correlation_id)

    def recover(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        valid_shape = (
            isinstance(request, dict)
            and set(request) == {"schema", "proposal_id"}
            and request.get("schema") == POLICY_RECOVERY_REQUEST_SCHEMA
        )
        if not valid_shape:
            return super().recover(actor=actor, request=request, correlation_id=correlation_id)

        with self._lock:
            self._authorize_existing_proposal(actor=actor, proposal_id=request.get("proposal_id"))
            return super().recover(actor=actor, request=request, correlation_id=correlation_id)
