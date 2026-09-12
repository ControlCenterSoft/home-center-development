"""Fail-closed presentation and rollback-evidence guards for Home Center 0.59 policies.

The base workflow already revalidates exact Household evidence while rebuilding a
proposal and again before Desired State materialization. This adapter closes two
remaining trust gaps without adding any provider or infrastructure authority:

* Cozy/Full UI is returned only if the policy Desired State revision observed by
  the original plan is still current;
* rollback success/replay is returned only if the receipt is bound to the exact
  keyed Audit completion/recovery evidence for the same actor and request.
"""

from __future__ import annotations

from typing import Any

from .household_policy_composer import (
    HouseholdPolicyComposerError,
    revalidate_policy_composition_proposal,
)
from .household_policy_desired_state import (
    HouseholdPolicyDesiredStateError,
    HouseholdPolicyDesiredStateRepository,
)
from .household_policy_presentation import build_policy_presentation
from .household_policy_rollback_audit import validate_rollback_audit_binding
from .household_policy_runtime import HouseholdPolicyRuntimeError
from .household_policy_workflow import (
    POLICY_PLAN_RESULT_SCHEMA,
    HouseholdPolicyWorkflowService,
)


class GuardedHouseholdPolicyWorkflowService(HouseholdPolicyWorkflowService):
    """Reject stale presentation and unbound rollback evidence before success."""

    def plan(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        raw_proposal = self.policy_runtime.plan(
            actor=actor,
            request=request,
            correlation_id=correlation_id,
        )
        planned_snapshot, proposal = self._rebuild_exact_proposal(actor=actor, raw=raw_proposal)

        # Re-read both independent preconditions after durable planning. A change
        # in Household membership/roles or in protected policy Desired State must
        # invalidate the UI result instead of presenting stale evidence as
        # "ready-for-confirmation".
        current_snapshot, actor_member_id = self._snapshot_and_actor(actor)
        try:
            current_record = self.history.repository.read(proposal.bundle.desired_state_resource_key)
            current_generation, current_bundle_id = HouseholdPolicyDesiredStateRepository.revision(
                current_record
            )
            revalidate_policy_composition_proposal(
                current_snapshot,
                proposal,
                actor_member_id=actor_member_id,
                current_desired_state_generation=current_generation,
                current_desired_state_bundle_id=current_bundle_id,
            )
        except (HouseholdPolicyComposerError, HouseholdPolicyDesiredStateError, TypeError) as exc:
            raise HouseholdPolicyRuntimeError(
                getattr(exc, "code", "household_policy_presentation_precondition_failed")
            ) from exc

        # ``planned_snapshot`` and ``current_snapshot`` are intentionally both
        # involved: proposal rebuild proves the persisted plan, while the second
        # read above proves it is still current at presentation time.
        if planned_snapshot != current_snapshot:
            raise HouseholdPolicyRuntimeError("household_policy_composition_stale")

        presentation = build_policy_presentation(current_snapshot, proposal)
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

    def rollback(
        self,
        *,
        actor: str,
        request: dict[str, Any],
        correlation_id: str,
    ) -> dict[str, object]:
        """Return rollback success only after exact Audit evidence is independently proven."""

        receipt = super().rollback(
            actor=actor,
            request=request,
            correlation_id=correlation_id,
        )
        validate_rollback_audit_binding(
            self.history,
            actor=actor,
            request=request,
            receipt=receipt,
        )
        return receipt
