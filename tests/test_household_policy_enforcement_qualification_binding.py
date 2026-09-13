from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from home_center.household_policy_enforcement_qualification_binding import (
    HouseholdPolicyEnforcementQualificationBindingError,
    bounded_binding_summary,
    build_qualification_bound_policy_adapter_registration,
    qualification_binding_from_dict,
    revalidate_qualification_bound_policy_adapter_registration,
)
from home_center.policy_backend_qualification import (
    PolicyBackendQualificationEvidence,
    evaluate_policy_backend_qualification,
)

VERSION = "0.59.0"
REVISION = "a" * 40
CANDIDATE_SHA = "b" * 64
BACKEND = "policy-backend.test"
ADAPTER_VERSION = "1.0.0"
ADAPTER_SHA = "c" * 64


class ConcreteAdapter:
    policy_mutation_capable = True
    adapter_id = BACKEND
    adapter_version = ADAPTER_VERSION
    adapter_artifact_sha256 = ADAPTER_SHA

    def __init__(self) -> None:
        self.calls = 0

    def apply_policy(self, request: dict[str, object]) -> object:
        self.calls += 1
        return {"accepted": True}


class SelfDeclaredQualifiedAdapter(ConcreteAdapter):
    policy_backend_qualified = True
    qualification_binding_schema = "home-center.policy-backend-qualification.v1"
    qualification_evidence_sha256 = "f" * 64


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


def _registration(adapter: object | None = None):
    decision = evaluate_policy_backend_qualification(_evidence())
    return build_qualification_bound_policy_adapter_registration(
        ConcreteAdapter() if adapter is None else adapter,
        decision,
        expected_version=VERSION,
        expected_revision=REVISION,
        expected_candidate_artifact_sha256=CANDIDATE_SHA,
        expected_backend_id=BACKEND,
        expected_adapter_version=ADAPTER_VERSION,
        expected_adapter_artifact_sha256=ADAPTER_SHA,
    )


def test_exact_qualified_registration_exposes_non_authorizing_persistable_binding() -> None:
    registration = _registration()
    value = registration.binding.to_dict()
    assert value["version"] == VERSION
    assert value["revision"] == REVISION
    assert value["candidate_artifact_sha256"] == CANDIDATE_SHA
    assert value["backend_id"] == BACKEND
    assert value["adapter_version"] == ADAPTER_VERSION
    assert value["adapter_artifact_sha256"] == ADAPTER_SHA
    assert len(str(value["qualification_evidence_sha256"])) == 64
    assert value["backend_mutation_authorized"] is False
    assert value["automatic_retry_authorized"] is False
    assert value["enforcement_success_claim_authorized"] is False
    assert value["release_authorized"] is False
    assert value["external_publication_authorized"] is False


def test_persisted_exact_binding_revalidates_without_backend_invocation() -> None:
    concrete = ConcreteAdapter()
    registration = _registration(concrete)
    persisted = registration.binding.to_dict()
    restored = revalidate_qualification_bound_policy_adapter_registration(
        registration, persisted
    )
    assert restored == registration.binding
    assert concrete.calls == 0


def test_restart_with_different_candidate_qualification_fails_closed() -> None:
    first = _registration()
    second_decision = evaluate_policy_backend_qualification(
        _evidence(revision="9" * 40, candidate_artifact_sha256="8" * 64)
    )
    second = build_qualification_bound_policy_adapter_registration(
        ConcreteAdapter(),
        second_decision,
        expected_version=VERSION,
        expected_revision="9" * 40,
        expected_candidate_artifact_sha256="8" * 64,
        expected_backend_id=BACKEND,
        expected_adapter_version=ADAPTER_VERSION,
        expected_adapter_artifact_sha256=ADAPTER_SHA,
    )
    with pytest.raises(
        HouseholdPolicyEnforcementQualificationBindingError,
        match="household_policy_enforcement_qualification_binding_stale",
    ):
        revalidate_qualification_bound_policy_adapter_registration(
            second, first.binding.to_dict()
        )


def test_tampered_adapter_or_evidence_binding_fails_closed() -> None:
    registration = _registration()
    persisted = registration.binding.to_dict()
    persisted["qualification_evidence_sha256"] = "0" * 64
    with pytest.raises(
        HouseholdPolicyEnforcementQualificationBindingError,
        match="household_policy_enforcement_qualification_binding_stale",
    ):
        revalidate_qualification_bound_policy_adapter_registration(
            registration, persisted
        )


def test_unknown_or_authorizing_persisted_fields_are_rejected() -> None:
    registration = _registration()
    value = registration.binding.to_dict()
    value["backend_mutation_authorized"] = True
    with pytest.raises(
        HouseholdPolicyEnforcementQualificationBindingError,
        match="household_policy_enforcement_qualification_binding_invalid",
    ):
        qualification_binding_from_dict(value)

    value = registration.binding.to_dict()
    value["unexpected"] = "rejected"
    with pytest.raises(
        HouseholdPolicyEnforcementQualificationBindingError,
        match="household_policy_enforcement_qualification_binding_invalid",
    ):
        qualification_binding_from_dict(value)


def test_self_declared_flags_are_not_a_qualification_registration() -> None:
    fake = SelfDeclaredQualifiedAdapter()
    with pytest.raises(
        HouseholdPolicyEnforcementQualificationBindingError,
        match="household_policy_enforcement_qualification_registration_invalid",
    ):
        revalidate_qualification_bound_policy_adapter_registration(
            fake,
            _registration().binding.to_dict(),
        )
    assert fake.calls == 0


def test_binding_summary_is_bounded_and_contract_accepts_exact_binding() -> None:
    registration = _registration()
    summary = bounded_binding_summary(registration.binding)
    assert set(summary) == {
        "schema",
        "version",
        "revision",
        "candidate_artifact_sha256",
        "backend_id",
        "adapter_version",
        "adapter_artifact_sha256",
        "qualification_evidence_sha256",
    }

    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (
            root
            / "contracts/household/household-policy-enforcement-qualification-binding.v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(registration.binding.to_dict())
