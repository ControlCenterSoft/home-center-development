from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import HouseholdRole
from home_center.role_identity_provider_qualification import (
    IdentityProviderQualificationError,
    IdentityProviderQualificationEvidence,
    evaluate_identity_provider_qualification,
)
from home_center.role_identity_provisioning import IdentityProviderKind

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64
REVISION = "b" * 40


def _evidence(**overrides: object) -> IdentityProviderQualificationEvidence:
    values: dict[str, object] = {
        "version": "0.62.0",
        "revision": REVISION,
        "candidate_artifact_sha256": DIGEST,
        "provider_id": "local-account",
        "provider_version": "1.0.0",
        "provider_kind": IdentityProviderKind.LOCAL,
        "supported_roles": (HouseholdRole.PARENT, HouseholdRole.CHILD, HouseholdRole.GUEST),
        "account_create_supported": True,
        "portable_home_supported": False,
        "portable_profile_supported": False,
        "secret_reference_supported": True,
        "adapter_artifact_sha256": DIGEST,
        "execution_transcript_sha256": DIGEST,
        "readback_transcript_sha256": DIGEST,
        "environment_evidence_sha256": DIGEST,
        "real_provider_exercised": True,
        "real_target_exercised": True,
        "account_absence_preflight_exercised": True,
        "create_contract_validated": True,
        "readback_contract_validated": True,
        "secret_reference_only": True,
        "secret_values_absent_from_evidence": True,
        "one_shot_mutation_preserved": True,
        "ambiguous_outcome_fail_closed": True,
        "exact_operation_binding_verified": True,
        "account_identity_verified": True,
        "home_directory_verified": True,
        "profile_verified": True,
        "emergency_admin_isolated": True,
        "arbitrary_privilege_grant_forbidden": True,
        "unrelated_account_mutation_forbidden": True,
        "external_publication_forbidden": True,
        "portable_home_exercised": False,
        "portable_profile_exercised": False,
    }
    values.update(overrides)
    return IdentityProviderQualificationEvidence(**values)  # type: ignore[arg-type]


def test_complete_real_provider_evidence_materializes_trusted_capability_without_authority() -> None:
    decision = evaluate_identity_provider_qualification(_evidence())
    assert decision.qualified is True
    assert decision.blockers == ()
    assert decision.evidence_sha256 != "0" * 64
    assert decision.execution_authorized is False
    assert decision.infrastructure_mutation_authorized is False
    assert decision.external_publication_authorized is False

    capability = decision.to_capability()
    assert capability.provider_id == "local-account"
    assert capability.evidence_sha256 == decision.evidence_sha256
    assert capability.execution_authorized is False
    assert capability.emergency_admin_isolated is True
    assert capability.arbitrary_privilege_grant_supported is False


def test_missing_real_target_or_readback_blocks_qualification() -> None:
    decision = evaluate_identity_provider_qualification(
        _evidence(real_target_exercised=False, readback_contract_validated=False)
    )
    assert decision.qualified is False
    assert decision.evidence_sha256 == "0" * 64
    assert decision.blockers == ("real_target", "readback_contract")
    with pytest.raises(IdentityProviderQualificationError, match="identity_provider_not_qualified"):
        decision.to_capability()


def test_claimed_portable_storage_requires_matching_real_exercise() -> None:
    blocked = evaluate_identity_provider_qualification(
        _evidence(portable_home_supported=True, portable_profile_supported=True)
    )
    assert blocked.blockers == ("portable_home_not_exercised", "portable_profile_not_exercised")

    qualified = evaluate_identity_provider_qualification(
        _evidence(
            portable_home_supported=True,
            portable_profile_supported=True,
            portable_home_exercised=True,
            portable_profile_exercised=True,
        )
    )
    assert qualified.qualified is True
    capability = qualified.to_capability()
    assert capability.portable_home_supported is True
    assert capability.portable_profile_supported is True


def test_secret_and_privilege_safety_evidence_is_mandatory() -> None:
    decision = evaluate_identity_provider_qualification(
        _evidence(
            secret_reference_only=False,
            secret_values_absent_from_evidence=False,
            emergency_admin_isolated=False,
            arbitrary_privilege_grant_forbidden=False,
            unrelated_account_mutation_forbidden=False,
            external_publication_forbidden=False,
        )
    )
    assert decision.qualified is False
    assert decision.blockers == (
        "secret_reference_only",
        "secret_values_absent",
        "emergency_admin_isolation",
        "privilege_grant_forbidden",
        "unrelated_account_mutation_forbidden",
        "external_publication_forbidden",
    )


def test_decision_validates_against_closed_public_schema() -> None:
    schema = json.loads(
        (ROOT / "contracts/household/role-identity-provider-qualification.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(
        evaluate_identity_provider_qualification(_evidence()).to_dict()
    )


def test_invalid_candidate_identity_is_rejected_before_evaluation() -> None:
    with pytest.raises(
        IdentityProviderQualificationError,
        match="identity_provider_qualification_revision_invalid",
    ):
        evaluate_identity_provider_qualification(_evidence(revision="latest"))
