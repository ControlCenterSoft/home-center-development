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
    recommendation_evidence_from_dict,
    safe_repair_plan_from_dict,
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
    subject_member_id: str = "member.child",
    target_id: str = "device.child-phone",
) -> RecommendationEvidence:
    return RecommendationEvidence(
        evidence_id="evidence.recommendation-1",
        household_id=household.household_id,
        kind=kind,
        subject_member_id=subject_member_id,
        target_id=target_id,
        household_sha256=household_snapshot_sha256(household),
        observation_sha256="sha256:" + "a" * 64,
        observed_at_epoch=1_000,
        expires_at_epoch=1_600,
    )


def test_managed_device_repair_plan_is_exact_bound_and_non_authorizing() -> None:
    household = _household()
    plan = plan_safe_repair(
        household,
        actor_member_id="member.parent",
        evidence=_evidence(household),
        now_epoch_seconds=1_200,
    )
    payload = plan.to_dict()

    assert payload["recommendation_kind"] == "managed-device-policy"
    assert payload["repair_action"] == "household.device.reconcile-managed-policy"
    assert payload["confirmation_required"] is True
    assert payload["automation_eligible"] is False
    assert payload["post_condition_verification_required"] is True
    assert payload["recovery_required"] is True
    assert payload["mutation_authorized"] is False
    assert payload["automatic_execution_authorized"] is False
    assert payload["provider_execution_authorized"] is False
    assert payload["infrastructure_mutation_authorized"] is False
    assert payload["external_publication_authorized"] is False
    assert safe_repair_plan_from_dict(payload) == plan


def test_read_only_compatibility_refresh_may_be_eligible_but_never_authorized() -> None:
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
    assert plan.automation_eligible is True
    assert plan.confirmation_required is False
    assert plan.recovery_contract == "read-only-refresh"
    assert plan.automatic_execution_authorized is False
    assert plan.mutation_authorized is False


def test_household_state_drift_blocks_stale_recommendation() -> None:
    household = _household()
    evidence = _evidence(household)
    changed = _household(device_managed=True)
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_household_stale"):
        plan_safe_repair(
            changed,
            actor_member_id="member.parent",
            evidence=evidence,
            now_epoch_seconds=1_200,
        )


def test_managed_device_signal_fails_closed_when_no_longer_applicable() -> None:
    household = _household(device_managed=True)
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_no_longer_applicable"):
        plan_safe_repair(
            household,
            actor_member_id="member.parent",
            evidence=_evidence(household),
            now_epoch_seconds=1_200,
        )


def test_expired_and_future_evidence_are_rejected() -> None:
    household = _household()
    evidence = _evidence(household)
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_evidence_expired"):
        plan_safe_repair(
            household,
            actor_member_id="member.parent",
            evidence=evidence,
            now_epoch_seconds=1_601,
        )
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_evidence_from_future"):
        plan_safe_repair(
            household,
            actor_member_id="member.parent",
            evidence=evidence,
            now_epoch_seconds=999,
        )


def test_recommendation_requires_parent_administration_authority() -> None:
    household = _household()
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_not_authorized"):
        plan_safe_repair(
            household,
            actor_member_id="member.child",
            evidence=_evidence(household),
            now_epoch_seconds=1_200,
        )


def test_transport_reconstruction_rejects_extra_fields_and_authority_forgery() -> None:
    household = _household()
    evidence = _evidence(household)
    evidence_payload = evidence.to_dict()
    assert recommendation_evidence_from_dict(evidence_payload) == evidence

    extra = dict(evidence_payload)
    extra["provider_execution_authorized"] = True
    with pytest.raises(HomeServiceCatalogError, match="recommendation_evidence_contract_invalid"):
        recommendation_evidence_from_dict(extra)

    plan = plan_safe_repair(
        household,
        actor_member_id="member.parent",
        evidence=evidence,
        now_epoch_seconds=1_200,
    )
    forged = copy.deepcopy(plan.to_dict())
    forged["automatic_execution_authorized"] = True
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_plan_contract_invalid"):
        safe_repair_plan_from_dict(forged)

    rebound = copy.deepcopy(plan.to_dict())
    rebound["evidence_sha256"] = "sha256:" + "b" * 64
    with pytest.raises(HomeServiceCatalogError, match="safe_repair_plan_contract_invalid"):
        safe_repair_plan_from_dict(rebound)


def test_public_contracts_are_closed_and_match_plan_shape() -> None:
    evidence_schema = json.loads(
        (ROOT / "contracts/household/recommendation-evidence.v1.schema.json").read_text(encoding="utf-8")
    )
    plan_schema = json.loads(
        (ROOT / "contracts/household/safe-repair-plan.v1.schema.json").read_text(encoding="utf-8")
    )
    assert evidence_schema["additionalProperties"] is False
    assert plan_schema["additionalProperties"] is False
    assert plan_schema["properties"]["mutation_authorized"] == {"const": False}
    assert plan_schema["properties"]["automatic_execution_authorized"] == {"const": False}
    assert plan_schema["properties"]["post_condition_verification_required"] == {"const": True}
    assert plan_schema["properties"]["recovery_required"] == {"const": True}
