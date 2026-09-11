"""Fail-closed validation for serialized module legal/compliance clearance.

A serialized clearance is trusted only when it exactly matches the deterministic
clearance recomputed from the supplied validated evidence. This boundary remains
evidence-only and never grants release or external-publication authority.
"""

from __future__ import annotations

from home_center.module_legal_compliance_clearance import (
    ModuleLegalComplianceClearance,
    evaluate_module_legal_compliance_clearance,
)


class ModuleLegalComplianceClearanceValidationError(ValueError):
    """Stable rejection code for stale, tampered, or malformed clearance."""

    def __init__(self, code: str = "legal_compliance_clearance_rejected") -> None:
        super().__init__(code)
        self.code = code


def _payload(value: object) -> dict[str, object]:
    if isinstance(value, ModuleLegalComplianceClearance):
        return value.to_dict()
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ModuleLegalComplianceClearanceValidationError()
        return dict(value)
    raise ModuleLegalComplianceClearanceValidationError()


def validate_module_legal_compliance_clearance(
    value: object,
    *,
    evidence: object,
) -> ModuleLegalComplianceClearance:
    """Validate a serialized clearance against the exact evidence that produced it.

    The canonical clearance is recomputed from evidence and the supplied payload
    must match it byte-semantically at the JSON object level: exact field set,
    values, reason/obligation ordering, exact artifact/evidence binding, and both
    authority flags remaining false.
    """

    expected = evaluate_module_legal_compliance_clearance(evidence)
    if _payload(value) != expected.to_dict():
        raise ModuleLegalComplianceClearanceValidationError()
    return expected
