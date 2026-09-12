"""Fail-closed current-vs-planned preview for Home Center 0.59 policies.

The preview is read-only evidence for the Cozy/Full confirmation surface. It
compares the exact protected Policy Desired State revision observed by a proposal
with the proposal's deterministic target bundle. It never writes Desired State,
executes providers, changes infrastructure, or grants mutation authority.
"""

from __future__ import annotations

from typing import Any

from .household_policy_composer import PolicyCompositionProposal
from .household_policy_desired_state import (
    HouseholdPolicyDesiredStateError,
    HouseholdPolicyDesiredStateRepository,
)
from .household_policy_evidence import (
    HouseholdPolicyEvidenceError,
    validate_policy_bundle_evidence,
)


POLICY_CHANGE_PREVIEW_SCHEMA = "home-center.household-policy-change-preview.v1"

_POLICY_FIELDS = (
    "role",
    "internet_policy",
    "vpn_allowed",
    "managed_device_required",
    "home_files_allowed",
    "smart_home_control_allowed",
    "administration_allowed",
)

_FIELD_LABELS = {
    "role": "роль",
    "internet_policy": "доступ в интернет",
    "vpn_allowed": "VPN",
    "managed_device_required": "требование управляемого устройства",
    "home_files_allowed": "домашние файлы",
    "smart_home_control_allowed": "управление умным домом",
    "administration_allowed": "администрирование Home Center",
}


class HouseholdPolicyChangePreviewError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _technical_policy(bundle: dict[str, Any]) -> dict[str, Any]:
    policy = bundle.get("technical_policy")
    if not isinstance(policy, dict):
        raise HouseholdPolicyChangePreviewError("household_policy_change_preview_evidence_invalid")
    return policy


def _summary(change_state: str, changed_fields: tuple[str, ...]) -> list[str]:
    if change_state == "initial":
        return ["Правила будут сохранены для этого пользователя впервые."]
    if change_state == "unchanged":
        return ["Текущие правила уже совпадают с предлагаемыми."]
    labels = [_FIELD_LABELS[field] for field in changed_fields]
    return ["Изменятся: " + ", ".join(labels) + "."]


def build_policy_change_preview(
    proposal: PolicyCompositionProposal,
    current_record: dict[str, object] | None,
) -> dict[str, object]:
    """Build exact, non-mutating change evidence for one composition proposal."""

    if not isinstance(proposal, PolicyCompositionProposal):
        raise TypeError("invalid_household_policy_change_preview")

    resource_key = proposal.bundle.desired_state_resource_key
    expected_generation = proposal.expected_desired_state_generation
    expected_bundle_id = proposal.expected_desired_state_bundle_id
    target_bundle = proposal.bundle.to_dict()
    target_policy = _technical_policy(target_bundle)

    if current_record is None:
        if expected_generation != 0 or expected_bundle_id is not None:
            raise HouseholdPolicyChangePreviewError("household_policy_change_preview_precondition_failed")
        baseline_generation = 0
        baseline_bundle_id = None
        change_state = "initial"
        changed_fields = _POLICY_FIELDS
    else:
        if current_record.get("resource_key") != resource_key:
            raise HouseholdPolicyChangePreviewError("household_policy_change_preview_resource_mismatch")
        try:
            baseline_generation, baseline_bundle_id = HouseholdPolicyDesiredStateRepository.revision(
                current_record
            )
        except HouseholdPolicyDesiredStateError as exc:
            raise HouseholdPolicyChangePreviewError(
                "household_policy_change_preview_evidence_invalid"
            ) from exc
        if baseline_generation != expected_generation or baseline_bundle_id != expected_bundle_id:
            raise HouseholdPolicyChangePreviewError("household_policy_change_preview_precondition_failed")
        try:
            current_bundle = validate_policy_bundle_evidence(
                current_record.get("value"),
                expected_resource_key=resource_key,
            )
        except HouseholdPolicyEvidenceError as exc:
            raise HouseholdPolicyChangePreviewError(
                "household_policy_change_preview_evidence_invalid"
            ) from exc
        current_policy = _technical_policy(current_bundle)
        changed_fields = tuple(
            field for field in _POLICY_FIELDS if current_policy.get(field) != target_policy.get(field)
        )
        if current_bundle == target_bundle:
            if changed_fields:
                raise HouseholdPolicyChangePreviewError(
                    "household_policy_change_preview_evidence_invalid"
                )
            change_state = "unchanged"
        else:
            # A bundle mismatch with no explainable policy-field delta must not be
            # rendered as a harmless no-op. It indicates incompatible/corrupted
            # evidence and is therefore fail-closed.
            if not changed_fields:
                raise HouseholdPolicyChangePreviewError(
                    "household_policy_change_preview_evidence_invalid"
                )
            change_state = "changed"

    return {
        "schema": POLICY_CHANGE_PREVIEW_SCHEMA,
        "resource_key": resource_key,
        "baseline_generation": baseline_generation,
        "baseline_bundle_id": baseline_bundle_id,
        "target_bundle_id": proposal.bundle.bundle_id,
        "change_state": change_state,
        "changed_fields": list(changed_fields),
        "cozy_summary": _summary(change_state, changed_fields),
        "confirmation_required": True,
        "mutation_started": False,
        "provider_execution_authorized": False,
        "infrastructure_mutation_authorized": False,
        "external_publication_authorized": False,
    }
