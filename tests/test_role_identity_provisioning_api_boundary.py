from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import HouseholdRole
from home_center.role_identity_binding_transition import RoleIdentityBindingTransitionService
from home_center.role_identity_provider_qualification import (
    IdentityProviderQualificationEvidence,
    bind_qualified_identity_provider_adapter,
    evaluate_identity_provider_qualification,
)
from home_center.role_identity_provisioning import (
    IdentityProviderCapability,
    IdentityProviderKind,
)
from home_center.role_identity_provisioning_api_runtime import (
    IdentityProvisioningApiRuntimeError,
    RoleIdentityProvisioningApiRuntimeService,
)
from home_center.role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeService
from home_center.store import StateStore

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.62.0"
REVISION = "b" * 40
CANDIDATE_DIGEST = "a" * 64
PROVIDER_DIGEST = "c" * 64
ADAPTER_DIGEST = "d" * 64
TRANSCRIPT_DIGEST = "e" * 64
ENVIRONMENT_DIGEST = "f" * 64
RECOVERY_DIGEST = "1" * 64


class _MutationAdapter:
    def start(self, request):  # pragma: no cover - registration-only fixture
        raise AssertionError("registration must not invoke provider mutation")

    def observe(self, *, provider_operation_id: str, account_name: str):  # pragma: no cover
        raise AssertionError("registration must not invoke provider read-back")


class _PreflightObserver:
    identity_preflight_read_only = True
    provider_id = "local-account"
    provider_version = "1.0.0"
    provider_evidence_sha256 = PROVIDER_DIGEST
    adapter_artifact_sha256 = ADAPTER_DIGEST

    def __init__(self, qualification_evidence_sha256: str) -> None:
        self.qualification_evidence_sha256 = qualification_evidence_sha256

    def preflight(self, *, plan):  # pragma: no cover - registration-only fixture
        raise AssertionError("registration must not invoke provider preflight")


def _provider() -> IdentityProviderCapability:
    return IdentityProviderCapability(
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD, HouseholdRole.GUEST),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        evidence_sha256=PROVIDER_DIGEST,
    )


def _bound_adapter():
    evidence = IdentityProviderQualificationEvidence(
        version=VERSION,
        revision=REVISION,
        candidate_artifact_sha256=CANDIDATE_DIGEST,
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER_DIGEST,
        adapter_artifact_sha256=ADAPTER_DIGEST,
        execution_transcript_sha256=TRANSCRIPT_DIGEST,
        environment_evidence_sha256=ENVIRONMENT_DIGEST,
        recovery_evidence_sha256=RECOVERY_DIGEST,
        real_provider_exercised=True,
        real_target_exercised=True,
        account_absence_preflight_validated=True,
        start_contract_validated=True,
        readback_contract_validated=True,
        secret_reference_only=True,
        secret_values_absent_from_evidence=True,
        durable_job_before_side_effect=True,
        ambiguous_outcome_fail_closed=True,
        automatic_retry_forbidden=True,
        provider_acceptance_not_success=True,
        post_condition_readback_required=True,
        emergency_admin_isolated=True,
        arbitrary_privilege_grant_forbidden=True,
        external_publication_forbidden=True,
        recovery_semantics_validated=True,
    )
    decision = evaluate_identity_provider_qualification(evidence)
    provider = _provider()
    bound = bind_qualified_identity_provider_adapter(
        adapter=_MutationAdapter(),
        provider=provider,
        decision=decision,
        expected_version=VERSION,
        expected_revision=REVISION,
        expected_candidate_artifact_sha256=CANDIDATE_DIGEST,
        expected_adapter_artifact_sha256=ADAPTER_DIGEST,
    )
    return bound


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", audit_key=b"k" * 32, cluster_id="test-cluster")


def test_registration_requires_exact_qualified_mutation_adapter_and_read_only_preflight(tmp_path: Path) -> None:
    store = _store(tmp_path)
    execution = RoleIdentityProvisioningRuntimeService(store)
    api = RoleIdentityProvisioningApiRuntimeService(
        store,
        execution,
        RoleIdentityBindingTransitionService(store),
    )
    bound = _bound_adapter()
    observer = _PreflightObserver(bound.decision.qualification_evidence_sha256)

    api.register_provider(bound_adapter=bound, preflight_observer=observer)

    with pytest.raises(
        IdentityProvisioningApiRuntimeError,
        match="identity_api_provider_registration_invalid",
    ):
        api.register_provider(bound_adapter=bound, preflight_observer=observer)
    store.close()


def test_preflight_observer_cannot_drift_from_qualified_adapter_artifact(tmp_path: Path) -> None:
    store = _store(tmp_path)
    api = RoleIdentityProvisioningApiRuntimeService(
        store,
        RoleIdentityProvisioningRuntimeService(store),
        RoleIdentityBindingTransitionService(store),
    )
    bound = _bound_adapter()
    observer = _PreflightObserver(bound.decision.qualification_evidence_sha256)
    observer.adapter_artifact_sha256 = "9" * 64  # type: ignore[misc]

    with pytest.raises(
        IdentityProvisioningApiRuntimeError,
        match="identity_api_provider_registration_invalid",
    ):
        api.register_provider(bound_adapter=bound, preflight_observer=observer)
    store.close()


def test_http_request_contracts_are_closed_and_do_not_accept_provider_evidence() -> None:
    cases = {
        "role-identity-provisioning-api-plan-request.v1.schema.json": {
            "schema": "home-center.role-identity-provisioning-api-plan-request.v1",
            "member_id": "member-child",
            "provider_id": "local-account",
            "account_name": "artemiy",
            "home_directory_mode": "local",
            "profile_mode": "local",
        },
        "role-identity-provisioning-api-preflight-request.v1.schema.json": {
            "schema": "home-center.role-identity-provisioning-api-preflight-request.v1",
            "plan_id": "hcidp-" + "2" * 24,
        },
        "role-identity-provisioning-api-execute-request.v1.schema.json": {
            "schema": "home-center.role-identity-provisioning-api-execute-request.v1",
            "plan_id": "hcidp-" + "2" * 24,
            "confirmed": True,
            "credential_references": [
                {"name": "initial-password", "reference": "secret://identity/artemiy/initial"}
            ],
        },
        "role-identity-provisioning-api-bind-request.v1.schema.json": {
            "schema": "home-center.role-identity-provisioning-api-bind-request.v1",
            "plan_id": "hcidp-" + "2" * 24,
            "execution_job_id": "123e4567-e89b-12d3-a456-426614174000",
        },
    }
    for name, request in cases.items():
        schema = json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))
        assert schema["additionalProperties"] is False
        jsonschema.Draft202012Validator(schema).validate(request)
        serialized = json.dumps(schema, sort_keys=True)
        assert "preflight_observation" not in serialized
        assert "provider_evidence_sha256" not in serialized
        assert "qualification_evidence_sha256" not in serialized
        assert "execution_receipt" not in serialized


def test_http_source_preserves_origin_auth_external_confirmation_and_idempotency_fences() -> None:
    source = (ROOT / "product/control-plane/src/home_center/api_v9.py").read_text(encoding="utf-8")
    for suffix in ("/plan", "/preflight", "/execute", "/bind"):
        assert f"/api/v1/household/identity/provisioning{suffix}" in source
    assert "_blocked_for_external" in source
    assert "_same_origin_post_allowed" in source
    assert "_require_actor" in source
    assert 'self.headers.get("Idempotency-Key")' in source
    assert "confirmed=self._boolean" in source


def test_bind_path_loads_verified_receipt_from_state_store_instead_of_client_payload() -> None:
    source = (
        ROOT / "product/control-plane/src/home_center/role_identity_provisioning_api_runtime.py"
    ).read_text(encoding="utf-8")
    assert "job = self.store.job(execution_job_id)" in source
    assert 'receipt = job["evidence"]["receipt"]' in source
    assert "execution_receipt=receipt" in source
