from __future__ import annotations

from pathlib import Path

import pytest

from home_center.household import HouseholdRole
from home_center.role_identity_provider_qualification import (
    IdentityProviderQualificationEvidence,
    bind_qualified_identity_provider_adapter,
    evaluate_identity_provider_qualification,
)
from home_center.role_identity_provisioning import IdentityProviderCapability, IdentityProviderKind
from home_center.role_identity_provisioning_runtime import IdentityProvisioningRuntimeError
from home_center.role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService
from home_center.store import StateStore

VERSION = "0.62.0"
REVISION = "1" * 40
CANDIDATE = "a" * 64
ADAPTER = "b" * 64
PROVIDER = "c" * 64


class _Adapter:
    def start(self, request: object) -> object:
        return {"accepted": True}

    def observe(self, *, provider_operation_id: str, account_name: str) -> object:
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
        evidence_sha256=PROVIDER,
    )


def _registration():
    evidence = IdentityProviderQualificationEvidence(
        version=VERSION,
        revision=REVISION,
        candidate_artifact_sha256=CANDIDATE,
        provider_id="local-account",
        provider_version="1.0.0",
        provider_kind=IdentityProviderKind.LOCAL,
        provider_evidence_sha256=PROVIDER,
        adapter_artifact_sha256=ADAPTER,
        execution_transcript_sha256="d" * 64,
        environment_evidence_sha256="e" * 64,
        recovery_evidence_sha256="f" * 64,
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
    return bind_qualified_identity_provider_adapter(
        adapter=_Adapter(),
        provider=_provider(),
        decision=decision,
        expected_version=VERSION,
        expected_revision=REVISION,
        expected_candidate_artifact_sha256=CANDIDATE,
        expected_adapter_artifact_sha256=ADAPTER,
    )


def _store(tmp_path: Path) -> StateStore:
    return StateStore(tmp_path / "state.sqlite3", b"a" * 32, "cluster-test")


def test_unqualified_registration_is_forbidden(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = SafeRoleIdentityProvisioningRuntimeService(store)
    with pytest.raises(
        IdentityProvisioningRuntimeError,
        match="identity_runtime_unqualified_adapter_registration_forbidden",
    ):
        service.register_adapter("local-account", _Adapter())
    store.close()


def test_exact_qualified_registration_exposes_only_server_side_provider_evidence(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = SafeRoleIdentityProvisioningRuntimeService(store)
    registration = _registration()
    service.register_qualified_adapter(registration)
    assert service.qualified_provider("local-account") == registration.provider
    assert (
        service.qualification_evidence_sha256("local-account")
        == registration.decision.qualification_evidence_sha256
    )
    with pytest.raises(
        IdentityProvisioningRuntimeError,
        match="identity_runtime_qualified_adapter_registration_invalid",
    ):
        service.register_qualified_adapter(registration)
    store.close()


def test_unknown_qualified_provider_fails_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    service = SafeRoleIdentityProvisioningRuntimeService(store)
    with pytest.raises(
        IdentityProvisioningRuntimeError,
        match="identity_runtime_qualified_provider_unavailable",
    ):
        service.qualified_provider("missing")
    with pytest.raises(
        IdentityProvisioningRuntimeError,
        match="identity_runtime_qualified_provider_unavailable",
    ):
        service.qualification_evidence_sha256("missing")
    store.close()
