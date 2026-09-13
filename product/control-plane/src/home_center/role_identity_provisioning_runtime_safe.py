"""Qualification-gated production registry for Home Center 0.62 identity providers."""
from __future__ import annotations

from .role_identity_provider_qualification import QualificationBoundIdentityProviderAdapter
from .role_identity_provisioning import IdentityProviderCapability
from .role_identity_provisioning_runtime import (
    IdentityProvisioningRuntimeError,
    RoleIdentityProvisioningRuntimeAdapter,
    RoleIdentityProvisioningRuntimeService,
)


class SafeRoleIdentityProvisioningRuntimeService(RoleIdentityProvisioningRuntimeService):
    """Production-safe runtime that rejects self-declared/unqualified adapters."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._qualified_providers: dict[str, IdentityProviderCapability] = {}
        self._qualification_evidence: dict[str, str] = {}

    def register_adapter(self, provider_id: str, adapter: RoleIdentityProvisioningRuntimeAdapter) -> None:
        del provider_id, adapter
        raise IdentityProvisioningRuntimeError("identity_runtime_unqualified_adapter_registration_forbidden")

    def register_qualified_adapter(self, registration: object) -> None:
        if not isinstance(registration, QualificationBoundIdentityProviderAdapter):
            raise IdentityProvisioningRuntimeError("identity_runtime_qualified_adapter_registration_invalid")
        provider = registration.provider
        decision = registration.decision
        if (
            decision.qualified is not True
            or decision.blockers
            or decision.provider_id != provider.provider_id
            or decision.provider_version != provider.provider_version
            or decision.provider_kind != provider.provider_kind.value
            or decision.provider_evidence_sha256 != provider.evidence_sha256
            or provider.provider_id in self._qualified_providers
        ):
            raise IdentityProvisioningRuntimeError("identity_runtime_qualified_adapter_registration_invalid")
        super().register_adapter(provider.provider_id, registration)
        self._qualified_providers[provider.provider_id] = provider
        self._qualification_evidence[provider.provider_id] = decision.qualification_evidence_sha256

    def qualified_provider(self, provider_id: str) -> IdentityProviderCapability:
        provider = self._qualified_providers.get(provider_id)
        if provider is None:
            raise IdentityProvisioningRuntimeError("identity_runtime_qualified_provider_unavailable")
        return provider

    def qualification_evidence_sha256(self, provider_id: str) -> str:
        value = self._qualification_evidence.get(provider_id)
        if value is None:
            raise IdentityProvisioningRuntimeError("identity_runtime_qualified_provider_unavailable")
        return value
