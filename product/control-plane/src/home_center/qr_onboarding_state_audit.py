"""StateStore Audit wiring for bounded Home Center 0.63 QR onboarding.

The wrapper records only the receipt-derived privacy-minimized projection after a
successful durable QR runtime operation. Raw onboarding codes and QR payloads are
never passed to StateStore.audit.
"""
from __future__ import annotations

import re
from typing import Any, Protocol

from .qr_onboarding_audit import qr_onboarding_audit_details
from .store import StateStore

_CORRELATION_ID = re.compile(r"[A-Za-z0-9._:-]{1,96}\Z")


class QrOnboardingRuntimeDelegate(Protocol):
    repository: Any

    def issue(self, **kwargs: Any) -> Any: ...

    def consume(self, **kwargs: Any) -> Any: ...

    def revoke(self, **kwargs: Any) -> Any: ...

    def plan_redemption(self, **kwargs: Any) -> Any: ...


class QrOnboardingStateAuditError(ValueError):
    """Reject unsafe Audit envelope material before persistence."""


class QrOnboardingAuditedRuntimeService:
    """Audit-decorated QR runtime with receipt-only durable evidence.

    Runtime mutation is always delegated first. Audit is appended only after the
    underlying operation succeeds and returns its durable receipt. A failure in
    the delegate therefore cannot create a false-success Audit event.
    """

    def __init__(self, runtime: QrOnboardingRuntimeDelegate, store: StateStore) -> None:
        if runtime is None:
            raise TypeError("qr_audited_runtime_invalid")
        if not isinstance(store, StateStore):
            raise TypeError("qr_audited_state_store_invalid")
        self.runtime = runtime
        self.store = store

    @property
    def repository(self) -> Any:
        """Expose the same read-only repository seam expected by the API adapter."""
        repository = getattr(self.runtime, "repository", None)
        if repository is None:
            raise QrOnboardingStateAuditError("qr_audited_repository_unavailable")
        return repository

    def plan_redemption(self, **kwargs: Any) -> Any:
        """Forward the read-only redemption plan without appending Audit."""
        return self.runtime.plan_redemption(**kwargs)

    @staticmethod
    def _correlation_id(value: str) -> str:
        if not isinstance(value, str) or _CORRELATION_ID.fullmatch(value) is None:
            raise QrOnboardingStateAuditError("qr_audit_correlation_id_invalid")
        return value

    def _append(self, *, receipt: Any, actor: str, correlation_id: str) -> str:
        correlation_id = self._correlation_id(correlation_id)
        details = qr_onboarding_audit_details(receipt).to_dict()
        return self.store.audit(
            actor=actor,
            action=f"qr.onboarding.{receipt.operation.value}",
            target=f"qr-onboarding:{receipt.invitation_id}",
            outcome="succeeded",
            correlation_id=correlation_id,
            details=details,
        )

    def issue(self, *, correlation_id: str, **kwargs: Any) -> Any:
        self._correlation_id(correlation_id)
        result = self.runtime.issue(**kwargs)
        actor = kwargs.get("issuer_member_id")
        if not isinstance(actor, str) or not actor:
            raise QrOnboardingStateAuditError("qr_audit_actor_invalid")
        self._append(receipt=result.receipt, actor=actor, correlation_id=correlation_id)
        return result

    def consume(self, *, correlation_id: str, **kwargs: Any) -> Any:
        self._correlation_id(correlation_id)
        result = self.runtime.consume(**kwargs)
        actor = kwargs.get("actor")
        if not isinstance(actor, str) or not actor:
            raise QrOnboardingStateAuditError("qr_audit_actor_invalid")
        _, receipt = result
        self._append(receipt=receipt, actor=actor, correlation_id=correlation_id)
        return result

    def revoke(self, *, correlation_id: str, **kwargs: Any) -> Any:
        self._correlation_id(correlation_id)
        result = self.runtime.revoke(**kwargs)
        actor = kwargs.get("actor_member_id")
        if not isinstance(actor, str) or not actor:
            raise QrOnboardingStateAuditError("qr_audit_actor_invalid")
        _, receipt = result
        self._append(receipt=receipt, actor=actor, correlation_id=correlation_id)
        return result
