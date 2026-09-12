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
from .household_policy_desired_state import (
    POLICY_APPLY_RECEIPT_SCHEMA,
    POLICY_APPLY_REQUEST_SCHEMA,
    HouseholdPolicyDesiredStateRepository,
)
from .household_policy_evidence import (
    HouseholdPolicyEvidenceError,
    validate_policy_bundle_evidence,
)
from .household_policy_history import (
    POLICY_ROLLBACK_RECEIPT_SCHEMA,
    HouseholdPolicyHistoryError,
    HouseholdPolicyHistoryService,
)
from .household_policy_presentation import build_policy_presentation
from .household_policy_runtime import (
    POLICY_CONFIRMATION_SCHEMA,
    POLICY_PROPOSAL_KEY_PREFIX,
    HouseholdPolicyRuntimeError,
    HouseholdPolicyRuntimeService,
    _confirmation_id,
)
from .household_runtime import ActorBinding, HOUSEHOLD_STATE_KEY, _state_from_dict
from .store import StateStore


POLICY_PLAN_RESULT_SCHEMA = "home-center.household-policy-plan-result.v1"
POLICY_CONFIRM_APPLY_RESULT_SCHEMA = "home-center.household-policy-confirm-apply-result.v1"
POLICY_HISTORY_OVERVIEW_SCHEMA = "home-center.household-policy-history-overview.v1"
POLICY_HISTORY_WINDOW = 100


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

    @staticmethod
    def _validate_confirmation_evidence(
        proposal: PolicyCompositionProposal,
        confirmation: dict[str, Any],
    ) -> None:
        """Fail closed unless confirmation is bound to the exact immutable proposal evidence."""

        expected = {
            "proposal_id": proposal.proposal_id,
            "household_id": proposal.household_id,
            "snapshot_id": proposal.snapshot_id,
            "resource_version": proposal.resource_version,
            "generation": proposal.generation,
            "actor_member_id": proposal.actor_member_id,
            "member_id": proposal.member_id,
            "bundle_id": proposal.bundle.bundle_id,
            "desired_state_resource_key": proposal.bundle.desired_state_resource_key,
            "expected_desired_state_generation": proposal.expected_desired_state_generation,
            "expected_desired_state_bundle_id": proposal.expected_desired_state_bundle_id,
        }
        if confirmation.get("schema") != POLICY_CONFIRMATION_SCHEMA:
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")
        if confirmation.get("confirmation_id") != _confirmation_id(proposal):
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")
        if any(confirmation.get(key) != value for key, value in expected.items()):
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")
        if confirmation.get("outcome") not in {"confirmed-for-desired-state-write", "already-confirmed"}:
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")
        if confirmation.get("desired_state_write_ready") is not True:
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")
        if (
            confirmation.get("desired_state_write_authorized") is not False
            or confirmation.get("infrastructure_mutation_authorized") is not False
            or confirmation.get("external_publication_authorized") is not False
        ):
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")
        audit_event_id = confirmation.get("audit_event_id")
        if not isinstance(audit_event_id, str) or not audit_event_id:
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")

    @staticmethod
    def _validate_materialized_evidence(
        proposal: PolicyCompositionProposal,
        *,
        confirmation_id: str,
        receipt: dict[str, object],
        history: dict[str, object],
    ) -> tuple[str, int]:
        """Reject false success unless receipt and immutable history prove the exact planned bundle."""

        resource_key = proposal.bundle.desired_state_resource_key
        bundle_id = proposal.bundle.bundle_id
        expected_bundle = proposal.bundle.to_dict()
        generation = receipt.get("generation")
        if (
            receipt.get("schema") != POLICY_APPLY_RECEIPT_SCHEMA
            or receipt.get("proposal_id") != proposal.proposal_id
            or receipt.get("confirmation_id") != confirmation_id
            or receipt.get("resource_key") != resource_key
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 1
            or receipt.get("bundle_id") != bundle_id
            or not isinstance(receipt.get("changed"), bool)
            or not isinstance(receipt.get("recovered"), bool)
            or receipt.get("outcome") not in {"applied", "already-current", "already-applied"}
            or receipt.get("desired_state_materialized") is not True
            or receipt.get("provider_execution_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
        ):
            raise HouseholdPolicyRuntimeError("household_policy_materialization_receipt_invalid")

        evidence_sha256 = history.get("evidence_sha256")
        audit_event_id = history.get("audit_event_id")
        if (
            history.get("resource_key") != resource_key
            or history.get("generation") != generation
            or history.get("bundle_id") != bundle_id
            or history.get("value") != expected_bundle
            or not isinstance(evidence_sha256, str)
            or len(evidence_sha256) != 64
            or any(char not in "0123456789abcdef" for char in evidence_sha256)
            or not isinstance(audit_event_id, str)
            or not audit_event_id
            or history.get("provider_execution_authorized") is not False
            or history.get("infrastructure_mutation_authorized") is not False
            or history.get("external_publication_authorized") is not False
        ):
            raise HouseholdPolicyRuntimeError("household_policy_history_evidence_mismatch")
        try:
            validate_policy_bundle_evidence(history.get("value"), expected_resource_key=resource_key)
        except HouseholdPolicyEvidenceError as exc:
            raise HouseholdPolicyRuntimeError(exc.code) from exc
        return resource_key, generation

    def _validate_rollback_evidence(
        self,
        *,
        request: dict[str, Any],
        receipt: dict[str, object],
    ) -> None:
        """Prove that rollback success is the exact historical bundle now stored as current state."""

        resource_key = request.get("resource_key")
        expected_generation = request.get("expected_generation")
        target_generation = request.get("target_generation")
        generation = receipt.get("generation")
        changed = receipt.get("changed")
        outcome = receipt.get("outcome")
        if (
            not isinstance(resource_key, str)
            or not resource_key
            or isinstance(expected_generation, bool)
            or not isinstance(expected_generation, int)
            or expected_generation < 1
            or isinstance(target_generation, bool)
            or not isinstance(target_generation, int)
            or target_generation < 1
            or target_generation >= expected_generation
            or receipt.get("schema") != POLICY_ROLLBACK_RECEIPT_SCHEMA
            or receipt.get("resource_key") != resource_key
            or receipt.get("target_history_generation") != target_generation
            or isinstance(generation, bool)
            or not isinstance(generation, int)
            or not isinstance(changed, bool)
            or not isinstance(receipt.get("recovered"), bool)
            or outcome not in {"rolled-back", "already-current", "already-rolled-back"}
            or (outcome == "rolled-back" and changed is not True)
            or (outcome == "already-current" and changed is not False)
            or generation != expected_generation + (1 if changed else 0)
            or receipt.get("desired_state_materialized") is not True
            or receipt.get("provider_execution_authorized") is not False
            or receipt.get("infrastructure_mutation_authorized") is not False
            or receipt.get("external_publication_authorized") is not False
            or not isinstance(receipt.get("audit_event_id"), str)
            or not receipt.get("audit_event_id")
        ):
            raise HouseholdPolicyRuntimeError("household_policy_rollback_evidence_mismatch")

        target_history = self.history.read(resource_key=resource_key, generation=target_generation)
        current = self.history.repository.read(resource_key)
        if current is None:
            raise HouseholdPolicyRuntimeError("household_policy_rollback_evidence_mismatch")
        current_generation, current_bundle_id = HouseholdPolicyDesiredStateRepository.revision(current)
        current_history = self.history.read(resource_key=resource_key, generation=generation)
        if (
            receipt.get("target_history_bundle_id") != target_history.get("bundle_id")
            or current_generation != generation
            or current_bundle_id != receipt.get("bundle_id")
            or current.get("value") != target_history.get("value")
            or current_history.get("bundle_id") != current_bundle_id
            or current_history.get("value") != current.get("value")
        ):
            raise HouseholdPolicyRuntimeError("household_policy_rollback_evidence_mismatch")
        try:
            validate_policy_bundle_evidence(target_history.get("value"), expected_resource_key=resource_key)
            validate_policy_bundle_evidence(current.get("value"), expected_resource_key=resource_key)
        except HouseholdPolicyEvidenceError as exc:
            raise HouseholdPolicyRuntimeError(exc.code) from exc

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

        envelope = self.store.get_meta(POLICY_PROPOSAL_KEY_PREFIX + proposal_id)
        if not isinstance(envelope, dict):
            raise HouseholdPolicyRuntimeError("household_policy_proposal_state_invalid")
        raw_proposal = envelope.get("proposal")
        stored_confirmation = envelope.get("confirmation")
        if not isinstance(raw_proposal, dict) or not isinstance(stored_confirmation, dict):
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_invalid")
        _snapshot, proposal = self._rebuild_exact_proposal(actor=actor, raw=raw_proposal)
        self._validate_confirmation_evidence(proposal, stored_confirmation)
        self._validate_confirmation_evidence(proposal, confirmation)
        if confirmation.get("audit_event_id") != stored_confirmation.get("audit_event_id"):
            raise HouseholdPolicyRuntimeError("household_policy_confirmation_evidence_mismatch")

        receipt = self.history.materialize(
            actor=actor,
            request={
                "schema": POLICY_APPLY_REQUEST_SCHEMA,
                "proposal_id": proposal_id,
                "confirmation_id": confirmation_id,
            },
            correlation_id=correlation_id,
        )
        if not isinstance(receipt, dict):
            raise HouseholdPolicyRuntimeError("household_policy_materialization_receipt_invalid")
        resource_key = receipt.get("resource_key")
        generation = receipt.get("generation")
        if not isinstance(resource_key, str) or isinstance(generation, bool) or not isinstance(generation, int):
            raise HouseholdPolicyRuntimeError("household_policy_materialization_receipt_invalid")
        history = self.history.read(resource_key=resource_key, generation=generation)
        self._validate_materialized_evidence(
            proposal,
            confirmation_id=confirmation_id,
            receipt=receipt,
            history=history,
        )
        return {
            "schema": POLICY_CONFIRM_APPLY_RESULT_SCHEMA,
            "confirmation": confirmation,
            "receipt": receipt,
            "desired_state_materialized": True,
            "history_evidence_sha256": history["evidence_sha256"],
            "history_audit_event_id": history["audit_event_id"],
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

    def history_overview(self, *, actor: str, resource_key: str) -> dict[str, object]:
        """Return a bounded, verified internal-only history view for one policy resource."""

        self.history._authorized_actor(actor, resource_key)
        current = self.history.repository.read(resource_key)
        if current is None:
            raise HouseholdPolicyHistoryError("household_policy_desired_state_missing")
        current_generation, current_bundle_id = HouseholdPolicyDesiredStateRepository.revision(current)
        start_generation = max(1, current_generation - POLICY_HISTORY_WINDOW + 1)
        revisions: list[dict[str, object]] = []
        for generation in range(start_generation, current_generation + 1):
            try:
                value = self.history.read(resource_key=resource_key, generation=generation)
                validate_policy_bundle_evidence(value.get("value"), expected_resource_key=resource_key)
            except HouseholdPolicyEvidenceError as exc:
                raise HouseholdPolicyHistoryError(exc.code) from exc
            except HouseholdPolicyHistoryError as exc:
                if exc.code == "household_policy_history_not_found":
                    raise HouseholdPolicyHistoryError("household_policy_history_gap") from exc
                raise
            revisions.append(
                {
                    "generation": value["generation"],
                    "bundle_id": value["bundle_id"],
                    "recorded_at": value["recorded_at"],
                    "evidence_sha256": value["evidence_sha256"],
                    "audit_event_id": value["audit_event_id"],
                    "rollback_target": generation < current_generation,
                }
            )
        return {
            "schema": POLICY_HISTORY_OVERVIEW_SCHEMA,
            "resource_key": resource_key,
            "current_generation": current_generation,
            "current_bundle_id": current_bundle_id,
            "window_start_generation": start_generation,
            "truncated": start_generation > 1,
            "revisions": revisions,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }

    def rollback(self, *, actor: str, request: dict[str, Any], correlation_id: str) -> dict[str, object]:
        """Restore one exact historical policy bundle as a new monotonic revision."""

        receipt = self.history.rollback(
            actor=actor,
            request=request,
            correlation_id=correlation_id,
        )
        if not isinstance(receipt, dict):
            raise HouseholdPolicyRuntimeError("household_policy_rollback_evidence_mismatch")
        self._validate_rollback_evidence(request=request, receipt=receipt)
        return receipt
