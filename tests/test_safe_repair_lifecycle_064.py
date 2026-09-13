from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from home_center.home_services import HomeServiceCatalogError
from home_center.household import FamilyMember, Household, HouseholdRole, ManagedDevice
from home_center.safe_recommendations import (
    RecommendationEvidence,
    RecommendationKind,
    household_snapshot_sha256,
    plan_safe_repair,
)
from home_center.safe_repair_lifecycle import (
    SafeRepairAdmissionMode,
    SafeRepairHistoryStatus,
    SafeRepairOutcome,
    admit_safe_repair,
    build_safe_repair_completion,
    project_safe_repair_history,
    safe_repair_admission_from_dict,
    safe_repair_completion_from_dict,
    validate_completion_binding,
)


ROOT = Path(__file__).resolve().parents[1]


def _household(*, device_managed: bool = False) -> Household:
    return Household(
        household_id="home.primary",
        members=(
            FamilyMember(member_id="member.parent", display_name="Родитель", role=HouseholdRole.PARENT),
            FamilyMember(member_id="member.child", display_name="Ребёнок", role=HouseholdRole.CHILD),
        ),
        devices=(
            ManagedDevice(
                device_id="device.child-phone",
                member_id="member.child",
                display_name="Телефон",
                managed=device_managed,
            ),
        ),
    )


def _evidence(
    household: Household,
    *,
    kind: RecommendationKind = RecommendationKind.MANAGED_DEVICE_POLICY,
    target_id: str = "device.child-phone",
) -> RecommendationEvidence:
    return RecommendationEvidence(
        evidence_id="evidence.recommendation-1",
        household_id=household.household_id,
        kind=kind,
        subject_member_id="member.child",
        target_id=target_id,
        household_sha256=household_snapshot_sha256(household),
        observation_sha256="sha256:" + "a" * 64,
        observed_at_epoch=1_000,
        expires_at_epoch=1_600,
    )


def _manual_admission():
    household = _household()
    evidence = _evidence(household)
    plan = plan_safe_repair(
        household,
        actor_member_id="member.parent",
        evidence=evidence,
        now_epoch_seconds=1_200,
    )
    admission = admit_safe_repair(
        household,
        plan=plan,
        evidence=evidence,
        now_epoch_seconds=1_200,
        confirmed=True,
    )
    return household, evidence, plan, admission


def test_elevated_repair_requires_explicit_confirmation_and_still_grants_no_execution() -> None:
    household = _household()
    evidence = _evidence(household)
    plan = plan_safe_repair(
        household,
        actor_member_id="member.parent",
        evidence=evidence,
        now_epoch_seconds=1_200,
    )
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_admission_confirmation_required"):
        admit_safe_repair(
            household,
            plan=plan,
            evidence=evidence,
            now_epoch_seconds=1_200,
            confirmed=False,
        )

    admission = admit_safe_repair(
        household,
        plan=plan,
        evidence=evidence,
        now_epoch_seconds=1_200,
        confirmed=True,
    )
    payload = admission.to_dict()
    assert admission.mode is SafeRepairAdmissionMode.MANUAL_CONFIRMED
    assert payload["durable_job_required"] is True
    assert payload["audit_required"] is True
    assert payload["post_condition_verification_required"] is True
    assert payload["recovery_evidence_required"] is True
    assert payload["execution_authorized"] is False
    assert payload["automatic_execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert safe_repair_admission_from_dict(payload) == admission


def test_low_risk_automation_candidate_is_classification_only() -> None:
    household = _household()
    evidence = _evidence(
        household,
        kind=RecommendationKind.COMPATIBILITY_EVIDENCE_REFRESH,
        target_id="compatibility.catalog",
    )
    plan = plan_safe_repair(
        household,
        actor_member_id="member.parent",
        evidence=evidence,
        now_epoch_seconds=1_200,
    )
    admission = admit_safe_repair(
        household,
        plan=plan,
        evidence=evidence,
        now_epoch_seconds=1_200,
        confirmed=False,
    )
    assert admission.mode is SafeRepairAdmissionMode.AUTOMATION_CANDIDATE
    assert admission.automation_candidate is True
    assert admission.confirmed is False
    assert admission.execution_authorized is False
    assert admission.automatic_execution_authorized is False
    assert admission.durable_job_required is True


def test_admission_revalidates_fresh_exact_plan_and_rejects_state_drift() -> None:
    household = _household()
    evidence = _evidence(household)
    plan = plan_safe_repair(
        household,
        actor_member_id="member.parent",
        evidence=evidence,
        now_epoch_seconds=1_200,
    )
    changed = _household(device_managed=True)
    with pytest.raises(HomeServiceCatalogError):
        admit_safe_repair(
            changed,
            plan=plan,
            evidence=evidence,
            now_epoch_seconds=1_200,
            confirmed=True,
        )


def test_admission_rejects_evidence_rebinding() -> None:
    household = _household()
    evidence = _evidence(household)
    plan = plan_safe_repair(
        household,
        actor_member_id="member.parent",
        evidence=evidence,
        now_epoch_seconds=1_200,
    )
    rebound = RecommendationEvidence(
        evidence_id="evidence.recommendation-2",
        household_id=evidence.household_id,
        kind=evidence.kind,
        subject_member_id=evidence.subject_member_id,
        target_id=evidence.target_id,
        household_sha256=evidence.household_sha256,
        observation_sha256=evidence.observation_sha256,
        observed_at_epoch=evidence.observed_at_epoch,
        expires_at_epoch=evidence.expires_at_epoch,
    )
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_admission_evidence_binding_mismatch"):
        admit_safe_repair(
            household,
            plan=plan,
            evidence=rebound,
            now_epoch_seconds=1_200,
            confirmed=True,
        )


def test_completion_cannot_claim_success_without_postcondition_verification() -> None:
    _, _, _, admission = _manual_admission()
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_completion_false_success"):
        build_safe_repair_completion(
            admission=admission,
            job_id="job.repair-1",
            before_evidence_sha256="sha256:" + "1" * 64,
            after_evidence_sha256="sha256:" + "2" * 64,
            post_condition_evidence_sha256="sha256:" + "3" * 64,
            recovery_evidence_sha256="sha256:" + "4" * 64,
            outcome=SafeRepairOutcome.VERIFIED,
            post_condition_verified=False,
            completed_at_epoch=1_300,
        )


def test_verified_completion_round_trips_and_projects_fixed_history() -> None:
    _, _, _, admission = _manual_admission()
    completion = build_safe_repair_completion(
        admission=admission,
        job_id="job.repair-1",
        before_evidence_sha256="sha256:" + "1" * 64,
        after_evidence_sha256="sha256:" + "2" * 64,
        post_condition_evidence_sha256="sha256:" + "3" * 64,
        recovery_evidence_sha256="sha256:" + "4" * 64,
        outcome=SafeRepairOutcome.VERIFIED,
        post_condition_verified=True,
        completed_at_epoch=1_300,
    )
    assert completion.repair_verified is True
    assert safe_repair_completion_from_dict(completion.to_dict()) == completion
    validate_completion_binding(admission, completion)

    history = project_safe_repair_history(admission, completion)
    assert history.status is SafeRepairHistoryStatus.FIXED
    assert history.title_ru == "Исправлено"
    assert history.repair_verified is True
    assert "результат проверен" in history.detail_ru


def test_reconcile_required_never_projects_fixed_history() -> None:
    _, _, _, admission = _manual_admission()
    completion = build_safe_repair_completion(
        admission=admission,
        job_id="job.repair-2",
        before_evidence_sha256="sha256:" + "1" * 64,
        after_evidence_sha256="sha256:" + "2" * 64,
        post_condition_evidence_sha256="sha256:" + "3" * 64,
        recovery_evidence_sha256="sha256:" + "4" * 64,
        outcome=SafeRepairOutcome.RECONCILE_REQUIRED,
        post_condition_verified=False,
        completed_at_epoch=1_301,
    )
    history = project_safe_repair_history(admission, completion)
    assert completion.repair_verified is False
    assert history.status is SafeRepairHistoryStatus.NEEDS_ATTENTION
    assert history.title_ru == "Требуется проверка"
    assert history.repair_verified is False


def test_strict_transport_rejects_authority_forgery_and_content_id_drift() -> None:
    _, _, _, admission = _manual_admission()
    admission_payload = admission.to_dict()
    forged = copy.deepcopy(admission_payload)
    forged["execution_authorized"] = True
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_admission_contract_invalid"):
        safe_repair_admission_from_dict(forged)

    drifted = copy.deepcopy(admission_payload)
    drifted["admission_id"] = "sra-" + "f" * 24
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_admission_contract_invalid"):
        safe_repair_admission_from_dict(drifted)

    completion = build_safe_repair_completion(
        admission=admission,
        job_id="job.repair-3",
        before_evidence_sha256="sha256:" + "1" * 64,
        after_evidence_sha256="sha256:" + "2" * 64,
        post_condition_evidence_sha256="sha256:" + "3" * 64,
        recovery_evidence_sha256="sha256:" + "4" * 64,
        outcome=SafeRepairOutcome.FAILED,
        post_condition_verified=False,
        completed_at_epoch=1_302,
    )
    completion_payload = completion.to_dict()
    false_success = copy.deepcopy(completion_payload)
    false_success["repair_verified"] = True
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_completion_contract_invalid"):
        safe_repair_completion_from_dict(false_success)

    rebound = copy.deepcopy(completion_payload)
    rebound["completion_id"] = "src-" + "e" * 24
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_completion_contract_invalid"):
        safe_repair_completion_from_dict(rebound)


def test_public_lifecycle_contracts_are_closed_and_fail_closed() -> None:
    admission_schema = json.loads(
        (ROOT / "contracts/household/safe-repair-admission.v1.schema.json").read_text(encoding="utf-8")
    )
    completion_schema = json.loads(
        (ROOT / "contracts/household/safe-repair-completion-evidence.v1.schema.json").read_text(encoding="utf-8")
    )
    history_schema = json.loads(
        (ROOT / "contracts/household/safe-repair-history-entry.v1.schema.json").read_text(encoding="utf-8")
    )
    assert admission_schema["additionalProperties"] is False
    assert completion_schema["additionalProperties"] is False
    assert history_schema["additionalProperties"] is False
    assert admission_schema["properties"]["execution_authorized"] == {"const": False}
    assert admission_schema["properties"]["automatic_execution_authorized"] == {"const": False}
    assert completion_schema["properties"]["automatic_success_claim_authorized"] == {"const": False}
