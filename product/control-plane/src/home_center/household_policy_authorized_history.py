"""Exact Household authorization boundary for Home Center 0.59 policy history.

Readable policy resource keys intentionally retain the Household identifier, but
identifier delimiters make prefix-only authorization unsafe.  This production
history service authorizes against the semantically verified current PolicyBundle
instead: the exact resource key must recompute from the persisted household/member
identity and that household must equal the active Household snapshot.
"""

from __future__ import annotations

from .household import effective_policy
from .household_policy_desired_state import HouseholdPolicyDesiredStateError
from .household_policy_evidence import HouseholdPolicyEvidenceError, validate_policy_bundle_evidence
from .household_policy_history import HouseholdPolicyHistoryError, HouseholdPolicyHistoryService
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict


class ScopedHouseholdPolicyHistoryService(HouseholdPolicyHistoryService):
    """Production history/rollback service with exact semantic Household scoping."""

    def _authorized_actor(self, actor: str, resource_key: str) -> None:
        if not isinstance(resource_key, str) or not resource_key:
            raise HouseholdPolicyHistoryError("invalid_household_policy_resource_key")

        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyHistoryError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyHistoryError(getattr(exc, "code", "household_state_invalid")) from exc

        actor_member_id = next((item.member_id for item in bindings if item.actor == actor), None)
        if actor_member_id is None:
            raise HouseholdPolicyHistoryError("household_actor_not_bound")
        try:
            actor_policy = effective_policy(snapshot.household, actor_member_id)
        except Exception as exc:
            raise HouseholdPolicyHistoryError(
                getattr(exc, "code", "household_policy_rollback_not_authorized")
            ) from exc
        if not actor_policy.administration_allowed:
            raise HouseholdPolicyHistoryError("household_policy_rollback_not_authorized")

        try:
            current = self.repository.read(resource_key)
        except HouseholdPolicyDesiredStateError as exc:
            raise HouseholdPolicyHistoryError("household_policy_history_evidence_mismatch") from exc
        if current is None:
            raise HouseholdPolicyHistoryError("household_policy_desired_state_missing")
        try:
            bundle = validate_policy_bundle_evidence(
                current.get("value"),
                expected_resource_key=resource_key,
            )
        except HouseholdPolicyEvidenceError as exc:
            raise HouseholdPolicyHistoryError(exc.code) from exc

        if bundle.get("household_id") != snapshot.household_id:
            raise HouseholdPolicyHistoryError("household_policy_rollback_resource_mismatch")

        member_id = bundle.get("member_id")
        if not isinstance(member_id, str):
            raise HouseholdPolicyHistoryError("household_policy_history_evidence_mismatch")
        try:
            snapshot.household.member(member_id)
        except Exception as exc:
            raise HouseholdPolicyHistoryError("household_policy_rollback_resource_mismatch") from exc
