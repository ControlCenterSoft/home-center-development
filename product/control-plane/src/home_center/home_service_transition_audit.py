"""Hash-chained audit boundary for authorized home-service state commits."""

from __future__ import annotations

from dataclasses import dataclass

from home_center.home_service_state import HomeServiceInstanceStateStore
from home_center.home_service_state_transition import HomeServiceTransitionCommit
from home_center.home_service_transition_apply import (
    HomeServiceTransitionApplyReceipt,
    HomeServiceTransitionAuthorization,
    apply_transition_commit,
)
from home_center.home_services import HomeServiceCatalogError, _identifier
from home_center.store import StateStore


@dataclass(frozen=True, slots=True)
class HomeServiceTransitionApplyContext:
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
class HomeServiceAuditedTransitionApply:
    audit_event_id: str
    correlation_id: str
    receipt: HomeServiceTransitionApplyReceipt

    def to_dict(self) -> dict[str, object]:
        return {
            "audit_event_id": self.audit_event_id,
            "correlation_id": self.correlation_id,
            "receipt": self.receipt.to_dict(),
        }


def apply_transition_commit_audited(
    commit: HomeServiceTransitionCommit,
    authorization: HomeServiceTransitionAuthorization,
    instances: HomeServiceInstanceStateStore,
    context: HomeServiceTransitionApplyContext,
) -> HomeServiceAuditedTransitionApply:
    """Audit the exact authorized intent before entering the durable CAS boundary.

    The audit entry is written first. Therefore an unavailable or invalid audit
    store fails closed before service state can change. The existing durable
    transition log and apply receipt provide the result evidence after the
    compare-and-swap commit.
    """

    if not isinstance(context, HomeServiceTransitionApplyContext):
        raise TypeError("invalid_transition_apply_context")
    if not isinstance(instances, HomeServiceInstanceStateStore):
        raise TypeError("invalid_instance_state_store")

    state_store = getattr(instances, "_store", None)
    if not isinstance(state_store, StateStore):
        raise HomeServiceCatalogError("transition_audit_store_unavailable")

    # Reuse the apply boundary's binding rules before writing an audit record so
    # malformed or cross-boundary requests do not pollute the audit chain.
    if not isinstance(commit, HomeServiceTransitionCommit):
        raise TypeError("invalid_transition_commit")
    if not isinstance(authorization, HomeServiceTransitionAuthorization):
        raise TypeError("invalid_transition_authorization")
    if (
        authorization.commit_id != commit.commit_id
        or authorization.decision_id != commit.decision_id
        or authorization.instance_id != commit.instance_id
        or authorization.expected_generation != commit.expected_generation
        or authorization.expected_resource_version != commit.expected_resource_version
    ):
        raise HomeServiceCatalogError("transition_authorization_binding_mismatch")

    audit_event_id = state_store.audit(
        actor=context.actor,
        action="home-service.transition.apply.requested",
        target=commit.instance_id,
        outcome="authorized",
        correlation_id=context.correlation_id,
        details={
            "reason": context.reason,
            "authorization_id": authorization.authorization_id,
            "commit_id": commit.commit_id,
            "decision_id": commit.decision_id,
            "source_state": commit.source_state.value,
            "target_state": commit.target_state.value,
            "expected_generation": commit.expected_generation,
            "expected_resource_version": commit.expected_resource_version,
            "next_generation": commit.next_generation,
            "next_resource_version": commit.next_resource_version,
        },
    )
    receipt = apply_transition_commit(commit, authorization, instances)
    return HomeServiceAuditedTransitionApply(
        audit_event_id=audit_event_id,
        correlation_id=context.correlation_id,
        receipt=receipt,
    )
