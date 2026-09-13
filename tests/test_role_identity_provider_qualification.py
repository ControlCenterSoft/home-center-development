from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import HouseholdRole
from home_center.role_identity_provider_qualification import (
    IdentityProviderQualificationError,
    IdentityProviderQualificationEvidence,
    bind_qualified_identity_provider_adapter,
    decision_from_dict,
    evaluate_identity_provider_qualification,
)
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
)

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.62.0"
REVISION = "1" * 40
DIGEST = "a" * 64
ADAPTER_DIGEST = "b" * 64
PROVIDER_DIGEST = "c" * 64


class _Adapter:
    def __init__(self) -> None:
        self.started = 0
        self.observed = 0

    def start(self, request: object) -> object:
        self.started += 1
        return {"accepted": True}

    def observe(self, *, provider_operation_id: str, account_name: str) -> object:
        self.observed += 1
        return {"provider_operation_id": provider_operation_id, "account_name": account_name}


def _provider() -> IdentityProviderCapability:
    return IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        evidence_sha256=PROVIDER_DIGEST,
    )


def _evidence(**overrides: object) -> IdentityProviderQualificationEvidence:
    values: dict[str, object] = {
        "version": VERSION,
        "revision": REVISION,
        "candidate_artifact_sha256": DIGEST,
        "provider_id": "local-account",
        "provider_version": "1.0.0",
        "provider_kind": IdentityProviderKind.LOCAL,
        "provider_evidence_sha256": PROVIDER_DIGEST,
        "adapter_artifact_sha256": ADAPTER_DIGEST,
        "execution_transcript_sha256": "d" * 64,
        "environment_evidence_sha256": "e" * 64,
        "recovery_evidence_sha256": "f" * 64,
        "real_provider_exercised": True,
        "real_target_exercised": True,
        "account_absence_preflight_validated": True,
        "start_contract_validated": True,
        "readback_contract_validated": True,
        "secret_reference_only": True,
        "secret_values_absent_from_evidence": True,
        "durable_job_before_side_effect": True,
        "ambiguous_outcome_fail_closed": True,
        "automatic_retry_forbidden": True,
        "provider_acceptance_not_success": True,
        "post_condition_readback_required": True,
        "emergency_admin_isolated": True,
        "arbitrary_privilege_grant_forbidden": True,
        "external_publication_forbidden": True,
        "recovery_semantics_validated": True,
    }
    values.update(overrides)
    return IdentityProviderQualificationEvidence(**values)  # type: ignore[arg-type]


def test_complete_exact_bound_evidence_is_qualified_but_non_authorizing() -> None:
    decision = evaluate_identity_provider_qualification(_evidence())
    assert decision.qualified is True
    assert decision.blockers == ()
    assert decision.provider_execution_authorized is False
    assert decision.durable_state_change_authorized is False
    assert decision.emergency_admin_mutation_authorized is False
    assert decision.privilege_grant_authorized is False
    assert decision.release_authorized is False
    assert decision.external_publication_authorized is False


def test_missing_real_or_recovery_safety_evidence_blocks_qualification() -> None:
    decision = evaluate_identity_provider_qualification(
        _evidence(
            real_target_exercised=False,
            ambiguous_outcome_fail_closed=False,
            recovery_semantics_validated=False,
        )
    )
    assert decision.qualified is False
    assert decision.blockers == (
        "real_target",
        "ambiguous_outcome_fail_closed",
        "recovery_semantics",
    )


def test_invalid_exact_identity_fails_before_qualification() -> None:
    with pytest.raises(
        IdentityProviderQualificationError,
        match="identity_provider_qualification_identity_invalid",
    ):
        evaluate_identity_provider_qualification(_evidence(revision="latest"))


def test_closed_decision_parser_rejects_authority_escalation_and_unknown_fields() -> None:
    raw = evaluate_identity_provider_qualification(_evidence()).to_dict()
    raw["provider_execution_authorized"] = True
    with pytest.raises(
        IdentityProviderQualificationError,
        match="identity_provider_qualification_decision_invalid",
    ):
        decision_from_dict(raw)

    raw = evaluate_identity_provider_qualification(_evidence()).to_dict()
    raw["extra"] = "unsafe"
    with pytest.raises(
        IdentityProviderQualificationError,
        match="identity_provider_qualification_decision_invalid",
    ):
        decision_from_dict(raw)


def test_decision_round_trip_validates_public_contract_schema() -> None:
    decision = evaluate_identity_provider_qualification(_evidence())
    raw = decision.to_dict()
    assert decision_from_dict(raw) == decision
    schema = json.loads(
        (ROOT / "contracts/household/role-identity-provider-qualification.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.Draft202012Validator(schema).validate(raw)


def test_adapter_binding_rejects_cross_candidate_or_provider_drift() -> None:
    decision = evaluate_identity_provider_qualification(_evidence())
    adapter = _Adapter()
    bound = bind_qualified_identity_provider_adapter(
        adapter=adapter,
        provider=_provider(),
        decision=decision,
        expected_version=VERSION,
        expected_revision=REVISION,
        expected_candidate_artifact_sha256=DIGEST,
        expected_adapter_artifact_sha256=ADAPTER_DIGEST,
    )
    assert bound.provider.provider_id == "local-account"
    assert bound.decision.qualification_evidence_sha256 == decision.qualification_evidence_sha256
    assert adapter.started == 0
    assert adapter.observed == 0

    with pytest.raises(
        IdentityProviderQualificationError,
        match="identity_provider_qualification_binding_invalid",
    ):
        bind_qualified_identity_provider_adapter(
            adapter=adapter,
            provider=_provider(),
            decision=decision,
            expected_version=VERSION,
            expected_revision="2" * 40,
            expected_candidate_artifact_sha256=DIGEST,
            expected_adapter_artifact_sha256=ADAPTER_DIGEST,
        )


def test_unqualified_decision_cannot_be_bound_to_runtime_adapter() -> None:
    decision = evaluate_identity_provider_qualification(_evidence(real_provider_exercised=False))
    with pytest.raises(
        IdentityProviderQualificationError,
        match="identity_provider_qualification_binding_invalid",
    ):
        bind_qualified_identity_provider_adapter(
            adapter=_Adapter(),
            provider=_provider(),
            decision=decision,
            expected_version=VERSION,
            expected_revision=REVISION,
            expected_candidate_artifact_sha256=DIGEST,
            expected_adapter_artifact_sha256=ADAPTER_DIGEST,
        )
