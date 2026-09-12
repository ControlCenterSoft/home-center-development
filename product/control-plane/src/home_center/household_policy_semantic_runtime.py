"""Semantic current-state boundary for Home Center 0.59 Policy Composer planning.

A proposal must never use only a persisted bundle ID as its optimistic-concurrency
anchor.  This production runtime verifies the full current PolicyBundle semantics
before recording the observed generation/bundle precondition, so corrupted local
state cannot be silently accepted or overwritten by a later confirmation.
"""

from __future__ import annotations

from .household_policy_evidence import HouseholdPolicyEvidenceError, validate_policy_bundle_evidence
from .household_policy_runtime import HouseholdPolicyRuntimeError, HouseholdPolicyRuntimeService


class SemanticHouseholdPolicyRuntimeService(HouseholdPolicyRuntimeService):
    """Production policy planner that requires semantically valid current Desired State."""

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
