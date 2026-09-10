"""Hash-chained completion evidence for verified home-service transitions."""

from __future__ import annotations

from dataclasses import dataclass, field

from home_center.home_service_state import HomeServiceInstanceStateStore
from home_center.home_service_transition_audit import HomeServiceAuditedTransitionApply
from home_center.home_service_transition_verify import (
    HomeServiceTransitionVerification,
    TransitionVerificationStatus,
)
from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.store import StateStore


COMPLETION_AUDIT_SCHEMA = "home-center.home-service-transition-completion-audit.v1"


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionCompletionContext:
    actor: str
    reason: str
    correlation_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "actor", _identifier(self.actor, "invalid_transition_actor"))
        object.__setattr__(
            self,
            "correlation_id",
            _identifier(self.correlation_id, "invalid_transition_correlation_id"),
        )
        reason = self.reason.strip()
        if reason != self.reason or not reason or len(reason) > 512:
            raise HomeServiceCatalogError("invalid_transition_reason")
        if any(ord(character) < 32 and character not in "\t\n" for character in reason):
            raise HomeServiceCatalogError("invalid_transition_reason")


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionCompletionAudit:
    audit_event_id: str
    preapply_audit_event_id: str
    verification_id: str
    receipt_id: str
    instance_id: str
    status: str
    mismatch_codes: tuple[str, ...]
    schema: str = field(default=COMPLETION_AUDIT_SCHEMA, init=False)
    service_state_mutation_authorized: bool = field(default=False, init=False)
    further_mutation_authorized: bool = field(default=False, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "audit_event_id": self.audit_event_id,
            "preapply_audit_event_id": self.preapply_audit_event_id,
            "verification_id": self.verification_id,
            "receipt_id": self.receipt_id,
            "instance_id": self.instance_id,
            "status": self.status,
            "mismatch_codes": list(self.mismatch_codes),
            "service_state_mutation_authorized": False,
            "further_mutation_authorized": False,
        }


def record_transition_completion_audit(
    applied: HomeServiceAuditedTransitionApply,
    verification: HomeServiceTransitionVerification,
    instances: HomeServiceInstanceStateStore,
    context: HomeServiceTransitionCompletionContext,
) -> HomeServiceTransitionCompletionAudit:
    """Append final verification evidence without changing service state."""

    if not isinstance(applied, HomeServiceAuditedTransitionApply):
        raise TypeError("invalid_audited_transition_apply")
    if not isinstance(verification, HomeServiceTransitionVerification):
        raise TypeError("invalid_transition_verification")
    if not isinstance(instances, HomeServiceInstanceStateStore):
        raise TypeError("invalid_instance_state_store")
    if not isinstance(context, HomeServiceTransitionCompletionContext):
        raise TypeError("invalid_transition_completion_context")

    receipt = applied.receipt
    if (
        verification.receipt_id != receipt.receipt_id
        or verification.authorization_id != receipt.authorization_id
        or verification.commit_id != receipt.commit_id
        or verification.decision_id != receipt.decision_id
        or verification.instance_id != receipt.instance_id
        or verification.expected_state != receipt.target_state
        or verification.expected_generation != receipt.generation
        or verification.expected_resource_version != receipt.resource_version
    ):
        raise HomeServiceCatalogError("transition_completion_binding_mismatch")
    if verification.further_mutation_authorized is not False or verification.production_mutation_enabled is not False:
        raise HomeServiceCatalogError("unsafe_transition_verification")

    state_store = getattr(instances, "_store", None)
    if not isinstance(state_store, StateStore):
        raise HomeServiceCatalogError("transition_audit_store_unavailable")

    preapply = next(
        (event for event in state_store.audit_events(limit=500) if event["event_id"] == applied.audit_event_id),
        None,
    )
    if preapply is None:
        raise HomeServiceCatalogError("transition_preapply_audit_not_found")
    details = preapply["details"]
    if (
        preapply["action"] != "home-service.transition.apply.requested"
        or preapply["outcome"] != "authorized"
        or preapply["target"] != receipt.instance_id
        or preapply["correlation_id"] != applied.correlation_id
        or details.get("authorization_id") != receipt.authorization_id
        or details.get("commit_id") != receipt.commit_id
        or details.get("decision_id") != receipt.decision_id
        or details.get("target_state") != receipt.target_state
        or details.get("next_generation") != receipt.generation
        or details.get("next_resource_version") != receipt.resource_version
    ):
        raise HomeServiceCatalogError("transition_preapply_audit_binding_mismatch")

    mismatch_codes = tuple(code.value for code in verification.mismatch_codes)
    action = (
        "home-service.transition.apply.verified"
        if verification.status is TransitionVerificationStatus.VERIFIED
        else "home-service.transition.apply.drifted"
    )
    event_id = state_store.audit(
        actor=context.actor,
        action=action,
        target=verification.instance_id,
        outcome=verification.status.value,
        correlation_id=context.correlation_id,
        details={
            "reason": context.reason,
            "preapply_audit_event_id": applied.audit_event_id,
            "preapply_correlation_id": applied.correlation_id,
            "verification_id": verification.verification_id,
            "receipt_id": verification.receipt_id,
            "authorization_id": verification.authorization_id,
            "commit_id": verification.commit_id,
            "decision_id": verification.decision_id,
            "expected_state": verification.expected_state,
            "expected_generation": verification.expected_generation,
            "expected_resource_version": verification.expected_resource_version,
            "observed_state": verification.observed_state,
            "observed_generation": verification.observed_generation,
            "observed_resource_version": verification.observed_resource_version,
            "mismatch_codes": list(mismatch_codes),
        },
    )
    return HomeServiceTransitionCompletionAudit(
        audit_event_id=event_id,
        preapply_audit_event_id=applied.audit_event_id,
        verification_id=verification.verification_id,
        receipt_id=verification.receipt_id,
        instance_id=verification.instance_id,
        status=verification.status.value,
        mismatch_codes=mismatch_codes,
    )
