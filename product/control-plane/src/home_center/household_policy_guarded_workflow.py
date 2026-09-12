"""Fail-closed presentation guard for Home Center 0.59 household policies.

The base workflow already revalidates exact Household evidence while rebuilding a
proposal and again before Desired State materialization. This adapter closes the
remaining presentation-time race: Cozy/Full UI is returned only if the policy
Desired State revision observed by the original plan is still current.

The guard is deliberately non-executing. It cannot call providers, mutate
infrastructure, publish externally, or materialize Desired State.
"""

from __future__ import annotations

from typing import Any

from .household_policy_change_preview import (
    HouseholdPolicyChangePreviewError,
    build_policy_change_preview,
)
from .household_policy_composer import (
    HouseholdPolicyComposerError,
    revalidate_policy_composition_proposal,
)
from .household_policy_desired_state import (
    HouseholdPolicyDesiredStateError,
    HouseholdPolicyDesiredStateRepository,
)
from .household_policy_presentation import build_policy_presentation
from .household_policy_runtime import HouseholdPolicyRuntimeError
from .household_policy_workflow import (
    POLICY_PLAN_RESULT_SCHEMA,
    HouseholdPolicyWorkflowService,
)


class GuardedHouseholdPolicyWorkflowService(HouseholdPolicyWorkflowService):
    """Reject a stale plan before it can be shown as ready for confirmation."""

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
            change_preview = build_policy_change_preview(proposal, current_record)
        except (
            HouseholdPolicyComposerError,
            HouseholdPolicyDesiredStateError,
            HouseholdPolicyChangePreviewError,
            TypeError,
        ) as exc:
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
            "change_preview": change_preview,
            "confirmation_required": True,
            "desired_state_materialized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }
