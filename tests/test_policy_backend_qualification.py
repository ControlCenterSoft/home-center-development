from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from home_center.policy_backend_qualification import (
    PolicyBackendQualificationError,
    PolicyBackendQualificationEvidence,
    evaluate_policy_backend_qualification,
    registration_metadata_from_policy_backend_qualification,
)

VERSION = "0.59.0"
REVISION = "a" * 40
CANDIDATE_SHA = "b" * 64
BACKEND = "policy-backend.test"
ADAPTER_VERSION = "1.0.0"
ADAPTER_SHA = "c" * 64


def _evidence(**changes: object) -> PolicyBackendQualificationEvidence:
    values: dict[str, object] = {
        "version": VERSION,
        "revision": REVISION,
        "candidate_artifact_sha256": CANDIDATE_SHA,
        "backend_id": BACKEND,
        "adapter_id": BACKEND,
        "adapter_version": ADAPTER_VERSION,
        "adapter_artifact_sha256": ADAPTER_SHA,
        "execution_transcript_sha256": "d" * 64,
        "environment_evidence_sha256": "e" * 64,
        "real_backend_exercised": True,
        "real_target_exercised": True,
        "plan_contract_validated": True,
        "confirmation_contract_validated": True,
        "exact_desired_state_bound": True,
        "secret_values_absent_from_evidence": True,
        "single_invocation_proven": True,
        "ambiguous_outcome_fail_closed": True,
        "automatic_retry_disabled": True,
        "reconciliation_required_after_mutation": True,
        "post_condition_readback_exercised": True,
        "verified_state_transition_separate": True,
        "restart_recovery_exercised": True,
        "recovery_path_exercised": True,
        "infrastructure_scope_bounded": True,
        "external_publication_forbidden": True,
    }
    values.update(changes)
    return PolicyBackendQualificationEvidence(**values)  # type: ignore[arg-type]


def _registration(decision: object) -> dict[str, str]:
    return registration_metadata_from_policy_backend_qualification(
        decision,  # type: ignore[arg-type]
        expected_version=VERSION,
        expected_revision=REVISION,
        expected_candidate_artifact_sha256=CANDIDATE_SHA,
        expected_backend_id=BACKEND,
        expected_adapter_version=ADAPTER_VERSION,
        expected_adapter_artifact_sha256=ADAPTER_SHA,
    )


def test_complete_real_backend_evidence_can_be_qualified_without_granting_authority() -> None:
    decision = evaluate_policy_backend_qualification(_evidence())
    assert decision.qualified is True
    assert decision.blockers == ()
    assert len(decision.evidence_sha256) == 64
    assert decision.backend_mutation_authorized is False
    assert decision.release_authorized is False
    assert decision.external_publication_authorized is False


def test_missing_runtime_safety_evidence_fails_closed() -> None:
    decision = evaluate_policy_backend_qualification(
        _evidence(
            real_target_exercised=False,
            single_invocation_proven=False,
            ambiguous_outcome_fail_closed=False,
            post_condition_readback_exercised=False,
            recovery_path_exercised=False,
        )
    )
    assert decision.qualified is False
    assert decision.blockers == (
        "real_target",
        "single_invocation",
        "ambiguous_outcome_fail_closed",
        "post_condition_readback",
        "recovery_path",
    )
    assert decision.backend_mutation_authorized is False


def test_qualification_digest_is_bound_to_semantic_evidence() -> None:
    qualified = evaluate_policy_backend_qualification(_evidence())
    degraded = evaluate_policy_backend_qualification(
        _evidence(restart_recovery_exercised=False)
    )
    assert qualified.evidence_sha256 != degraded.evidence_sha256
    assert degraded.qualified is False
    assert degraded.blockers == ("restart_recovery",)


def test_exact_qualified_decision_can_supply_registration_metadata() -> None:
    decision = evaluate_policy_backend_qualification(_evidence())
    metadata = _registration(decision)
    assert metadata == {
        "adapter_id": BACKEND,
        "adapter_version": ADAPTER_VERSION,
        "adapter_artifact_sha256": ADAPTER_SHA,
        "qualification_evidence_sha256": decision.evidence_sha256,
    }


def test_registration_handoff_rejects_candidate_or_artifact_drift() -> None:
    decision = evaluate_policy_backend_qualification(_evidence())
    with pytest.raises(
        PolicyBackendQualificationError,
        match="policy_backend_qualification_candidate_mismatch",
    ):
        registration_metadata_from_policy_backend_qualification(
            decision,
            expected_version=VERSION,
            expected_revision="f" * 40,
            expected_candidate_artifact_sha256=CANDIDATE_SHA,
            expected_backend_id=BACKEND,
            expected_adapter_version=ADAPTER_VERSION,
            expected_adapter_artifact_sha256=ADAPTER_SHA,
        )
    with pytest.raises(
        PolicyBackendQualificationError,
        match="policy_backend_qualification_candidate_mismatch",
    ):
        registration_metadata_from_policy_backend_qualification(
            decision,
            expected_version=VERSION,
            expected_revision=REVISION,
            expected_candidate_artifact_sha256=CANDIDATE_SHA,
            expected_backend_id=BACKEND,
            expected_adapter_version=ADAPTER_VERSION,
            expected_adapter_artifact_sha256="f" * 64,
        )


def test_registration_handoff_rejects_unqualified_decision() -> None:
    decision = evaluate_policy_backend_qualification(
        _evidence(post_condition_readback_exercised=False)
    )
    with pytest.raises(
        PolicyBackendQualificationError,
        match="policy_backend_qualification_decision_invalid",
    ):
        _registration(decision)


@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"version": "0.59"}, "policy_backend_qualification_version_invalid"),
        ({"revision": "not-a-revision"}, "policy_backend_qualification_revision_invalid"),
        ({"backend_id": "INVALID"}, "policy_backend_qualification_backend_id_invalid"),
        ({"adapter_id": "other-backend"}, "policy_backend_qualification_identity_mismatch"),
        ({"adapter_version": "latest"}, "policy_backend_qualification_adapter_version_invalid"),
        ({"candidate_artifact_sha256": "bad"}, "policy_backend_qualification_digest_invalid"),
    ],
)
def test_malformed_or_cross_backend_evidence_is_rejected(
    changes: dict[str, object], error: str
) -> None:
    with pytest.raises(PolicyBackendQualificationError, match=error):
        evaluate_policy_backend_qualification(_evidence(**changes))


def test_decision_contract_is_valid_and_accepts_evaluator_output() -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "contracts"
        / "releases"
        / "policy-backend-qualification.v1.schema.json"
    )
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(
        evaluate_policy_backend_qualification(_evidence()).to_dict()
    )
