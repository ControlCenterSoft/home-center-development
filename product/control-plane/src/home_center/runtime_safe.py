"""Production-safe Home Center runtime composition.

This composition keeps the generic Runtime reusable for tests and internal composition while
ensuring the actual server process exposes identity provisioning only through the qualification-
bound provider registry. No provider is registered automatically. QR onboarding uses the
canonical StateStore migration and the same SQLite transaction lock; the adapter never performs
its own production schema mutation.
"""
from __future__ import annotations

from .qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from .role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService
from .runtime import Runtime


class ProductionRuntime(Runtime):
    """Server runtime with fail-closed provider and bounded QR admission."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.role_identity_provisioning = SafeRoleIdentityProvisioningRuntimeService(self.store)
        self.qr_onboarding = QrOnboardingRuntimeService(
            SQLiteQrOnboardingRuntimeRepository(
                self.store._connection,  # noqa: SLF001 - same-package canonical StateStore DB
                self.store._lock,  # noqa: SLF001 - share the canonical transaction lock
            )
        )
