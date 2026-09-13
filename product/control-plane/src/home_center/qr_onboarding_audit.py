"""Privacy-minimized Audit projection for Home Center 0.63 QR onboarding.

The projection is intentionally receipt-only. It cannot accept or serialize the
raw onboarding code or QR payload and therefore can be passed to StateStore.audit
without turning Audit into a credential store.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .qr_onboarding_runtime import QrOnboardingOperationReceipt, RuntimeOperation

QR_AUDIT_DETAILS_SCHEMA = "home-center.qr-onboarding-audit-details.v1"


@dataclass(frozen=True, slots=True)
class QrOnboardingAuditDetails:
    receipt_id: str
    operation: RuntimeOperation
    runtime_record_id: str
    invitation_id: str
    target_member_id: str
    before_state: str | None
    after_state: str
    record_version: int
    invitation_evidence_sha256: str
    next_required_boundary: str
    schema: str = field(default=QR_AUDIT_DETAILS_SCHEMA, init=False)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "operation": self.operation.value,
            "runtime_record_id": self.runtime_record_id,
            "invitation_id": self.invitation_id,
            "target_member_id": self.target_member_id,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "record_version": self.record_version,
            "invitation_evidence_sha256": self.invitation_evidence_sha256,
            "next_required_boundary": self.next_required_boundary,
            "raw_onboarding_code_included": False,
            "qr_payload_included": False,
            "account_creation_authorized": False,
            "device_registration_authorized": False,
            "managed_state_change_authorized": False,
            "provider_execution_authorized": False,
            "infrastructure_mutation_authorized": False,
            "external_publication_authorized": False,
        }


def qr_onboarding_audit_details(receipt: QrOnboardingOperationReceipt) -> QrOnboardingAuditDetails:
    if not isinstance(receipt, QrOnboardingOperationReceipt):
        raise TypeError("qr_audit_receipt_invalid")
    return QrOnboardingAuditDetails(
        receipt_id=receipt.receipt_id,
        operation=receipt.operation,
        runtime_record_id=receipt.runtime_record_id,
        invitation_id=receipt.invitation_id,
        target_member_id=receipt.target_member_id,
        before_state=receipt.before_state.value if receipt.before_state else None,
        after_state=receipt.after_state.value,
        record_version=receipt.record_version,
        invitation_evidence_sha256=receipt.invitation_evidence_sha256,
        next_required_boundary=receipt.next_required_boundary,
    )
