from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from home_center.household import HouseholdRole
from home_center.role_identity_provider_qualification import (
    IdentityProviderQualificationEvidence,
    evaluate_identity_provider_qualification,
)
from home_center.role_identity_provisioning import IdentityProviderKind
from home_center.role_identity_provisioning_api_runtime import (
    IdentityProvisioningApiRuntimeError,
    RoleIdentityProvisioningApiRuntimeService,
)
from home_center.role_identity_provisioning_runtime import RoleIdentityProvisioningRuntimeService
from home_center.store import StateStore

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64
REVISION = "b" * 40


def _decision():
    evidence = IdentityProviderQualificationEvidence(
        version="0.62.0",
        revision=REVISION,
        candidate_artifact_sha256=DIGEST,
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        supported_roles=(HouseholdRole.PARENT, HouseholdRole.CHILD, HouseholdRole.GUEST),
        account_create_supported=True,
        portable_home_supported=False,
        portable_profile_supported=False,
        secret_reference_supported=True,
        adapter_artifact_sha256=DIGEST,
        execution_transcript_sha256=DIGEST,
        readback_transcript_sha256=DIGEST,
        environment_evidence_sha256=DIGEST,
        real_provider_exercised=True,
        real_target_exercised=True,
        account_absence_preflight_exercised=True,
        create_contract_validated=True,
        readback_contract_validated=True,
        secret_reference_only=True,
        secret_values_absent_from_evidence=True,
        one_shot_mutation_preserved=True,
        ambiguous_outcome_fail_closed=True,
        exact_operation_binding_verified=True,
        account_identity_verified=True,
        home_directory_verified=True,
        profile_verified=True,
        emergency_admin_isolated=True,
        arbitrary_privilege_grant_forbidden=True,
        unrelated_account_mutation_forbidden=True,
        external_publication_forbidden=True,
    )
    return evaluate_identity_provider_qualification(evidence)


class _Adapter:
    identity_provisioning_qualified = True
    provider_id = "local-account"
    provider_version = "1.0.0"
    adapter_artifact_sha256 = DIGEST

    def __init__(self, evidence_sha256: str) -> None:
        self.qualification_evidence_sha256 = evidence_sha256

    def preflight(self, *, plan):  # pragma: no cover - registration test only
        raise AssertionError("provider must not be called during registration")

    def start(self, request):  # pragma: no cover - registration test only
        raise AssertionError("provider must not be called during registration")

    def observe(self, *, provider_operation_id: str, account_name: str):  # pragma: no cover
        raise AssertionError("provider must not be called during registration")


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.db", audit_key=b"k" * 32, cluster_id="test-cluster")


def test_only_exact_qualified_adapter_can_enter_server_provider_registry(tmp_path: Path) -> None:
    store = _store(tmp_path)
    execution = RoleIdentityProvisioningRuntimeService(store)
    api = RoleIdentityProvisioningApiRuntimeService(store, execution)
    decision = _decision()
    adapter = _Adapter(decision.evidence_sha256)

    api.register_provider(decision, adapter)

    with pytest.raises(IdentityProvisioningApiRuntimeError, match="identity_api_provider_registration_invalid"):
        api.register_provider(decision, adapter)
    store.close()


def test_adapter_artifact_or_qualification_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    api = RoleIdentityProvisioningApiRuntimeService(store, RoleIdentityProvisioningRuntimeService(store))
    decision = _decision()

    forged = _Adapter("f" * 64)
    with pytest.raises(IdentityProvisioningApiRuntimeError, match="identity_api_provider_registration_invalid"):
        api.register_provider(decision, forged)
    store.close()


def test_http_request_contracts_are_closed_and_client_cannot_supply_provider_evidence() -> None:
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
            "plan_id": "hcidp-" + "c" * 24,
        },
        "role-identity-provisioning-api-execute-request.v1.schema.json": {
            "schema": "home-center.role-identity-provisioning-api-execute-request.v1",
            "plan_id": "hcidp-" + "c" * 24,
            "confirmed": True,
            "credential_references": [
                {"name": "initial-password", "reference": "secret://identity/artemiy/initial"}
            ],
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


def test_http_wiring_preserves_origin_auth_external_and_idempotency_fences() -> None:
    source = (ROOT / "product/control-plane/src/home_center/api_v9.py").read_text(encoding="utf-8")
    assert "/api/v1/household/identity/provisioning/plan" in source
    assert "/api/v1/household/identity/provisioning/preflight" in source
    assert "/api/v1/household/identity/provisioning/execute" in source
    assert "_blocked_for_external" in source
    assert "_same_origin_post_allowed" in source
    assert "_require_actor" in source
    assert 'self.headers.get("Idempotency-Key")' in source
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")
    assert "RuntimeRequestHandlerV9" in server
