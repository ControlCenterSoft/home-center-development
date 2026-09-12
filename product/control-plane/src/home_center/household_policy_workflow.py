"""Production-safe orchestration boundary for Home Center 0.59 household policies.

This service connects the durable Policy Composer plan/confirm protocol to one
shared Cozy/Full presentation model, immutable revision evidence and the protected
local Desired State writer. A single explicit confirmation can materialize the
exact policy revision, but this boundary never executes a device/provider action,
mutates infrastructure, or enables external publication.
"""

from __future__ import annotations

from typing import Any

from .household_policy_composer import (
    HouseholdPolicyComposerError,
    PolicyCompositionProposal,
    build_policy_composition_proposal,
)
from .household_policy_desired_state import POLICY_APPLY_REQUEST_SCHEMA
from .household_policy_history import HouseholdPolicyHistoryService
from .household_policy_presentation import build_policy_presentation
from .household_policy_runtime import HouseholdPolicyRuntimeError, HouseholdPolicyRuntimeService
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore


POLICY_PLAN_RESULT_SCHEMA = "home-center.household-policy-plan-result.v1"
POLICY_CONFIRM_APPLY_RESULT_SCHEMA = "home-center.household-policy-confirm-apply-result.v1"


class HouseholdPolicyWorkflowService:
    """Bind policy planning, presentation, confirmation, history and Desired State materialization."""

    def __init__(
        self,
        store: StateStore,
        *,
        policy_runtime: HouseholdPolicyRuntimeService,
        history: HouseholdPolicyHistoryService,
    ) -> None:
        self.store = store
        self.policy_runtime = policy_runtime
        self.history = history

    def _snapshot_and_actor(self, actor: str) -> tuple[object, str]:
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise HouseholdPolicyRuntimeError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
        except Exception as exc:
            raise HouseholdPolicyRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc
        actor_member_id = next(
            (binding.member_id for binding in bindings if isinstance(binding, ActorBinding) and binding.actor == actor),
            None,
        )
        if actor_member_id is None:
            raise HouseholdPolicyRuntimeError("household_actor_not_bound")
        return snapshot, actor_member_id

    def _rebuild_exact_proposal(self, *, actor: str, raw: dict[str, Any]) -> tuple[object, PolicyCompositionProposal]:
        snapshot, actor_member_id = self._snapshot_and_actor(actor)
        try:
            proposal = build_policy_composition_proposal(
                snapshot,
                actor_member_id=actor_member_id,
                member_id=raw.get("member_id"),
                expected_desired_state_generation=raw.get("expected_desired_state_generation"),
                expected_desired_state_bundle_id=raw.get("expected_desired_state_bundle_id"),
            )
        except (HouseholdPolicyComposerError, TypeError) as exc:
            raise HouseholdPolicyRuntimeError(
                getattr(exc, "code", "household_policy_proposal_invalid")
            ) from exc
        if proposal.to_dict() != raw:
            raise HouseholdPolicyRuntimeError("household_policy_proposal_evidence_mismatch")
        return snapshot, proposal

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        """Persist an exact proposal and return the same evidence for Cozy and Full UI."""

        raw_proposal = self.policy_runtime.plan(
            actor=actor,
            request=request,
            correlation_id=correlation_id,
        )
        snapshot, proposal = self._rebuild_exact_proposal(actor=actor, raw=raw_proposal)
        presentation = build_policy_presentation(snapshot, proposal)
        return {
            "schema": POLICY_PLAN_RESULT_SCHEMA,
            "proposal": raw_proposal,
            "presentation": presentation,
            "confirmation_required": True,
            "desired_state_materialized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def confirm_and_apply(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        """Consume one explicit confirmation and materialize only the exact local policy Desired State."""

        confirmation = self.policy_runtime.confirm(
            actor=actor,
            request=request,
            correlation_id=correlation_id,
        )
        confirmation_id = confirmation.get("confirmation_id")
        proposal_id = confirmation.get("proposal_id")
        if not isinstance(confirmation_id, str) or not isinstance(proposal_id, str):
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_invalid")
        receipt = self.history.materialize(
            actor=actor,
            request={
                "schema": POLICY_APPLY_REQUEST_SCHEMA,
                "proposal_id": proposal_id,
                "confirmation_id": confirmation_id,
            },
            correlation_id=correlation_id,
        )
        resource_key = receipt.get("resource_key")
        generation = receipt.get("generation")
        if not isinstance(resource_key, str) or isinstance(generation, bool) or not isinstance(generation, int):
            raise HouseholdPolicyRuntimeError("household_policy_materialization_receipt_invalid")
        history = self.history.read(resource_key=resource_key, generation=generation)
        return {
            "schema": POLICY_CONFIRM_APPLY_RESULT_SCHEMA,
            "confirmation": confirmation,
            "receipt": receipt,
            "desired_state_materialized": receipt.get("desired_state_materialized") is True,
            "history_evidence_sha256": history.get("evidence_sha256"),
            "history_audit_event_id": history.get("audit_event_id"),
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def recover(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        """Expose the durable confirmation recovery protocol without applying anything implicitly."""

        return self.policy_runtime.recover(
            actor=actor,
            request=request,
            correlation_id=correlation_id,
        )

    def rollback(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        """Restore one exact historical policy bundle as a new monotonic revision."""

        return self.history.rollback(
            actor=actor,
            request=request,
            correlation_id=correlation_id,
        )