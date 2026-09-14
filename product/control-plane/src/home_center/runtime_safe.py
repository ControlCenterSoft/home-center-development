"""Production-safe Home Center runtime composition.

This composition keeps the generic Runtime reusable for tests and internal composition while
ensuring the actual server process exposes identity provisioning only through the qualification-
bound provider registry. No provider is registered automatically. QR onboarding uses the
canonical StateStore migration and the same SQLite transaction lock; the adapter never performs
its own production schema mutation. Home Center 0.64 also exposes bounded safe-repair history
and Job evidence repositories without registering a repair worker or action adapter.
"""
from __future__ import annotations

from .qr_onboarding_effect_admission import QrOnboardingEffectAdmissionService
from .qr_onboarding_effect_execution import QrOnboardingEffectExecutionService
from .qr_onboarding_effect_source import QrOnboardingEffectSourceService
from .qr_onboarding_effect_worker import QrOnboardingEffectWorkerService
from .qr_onboarding_product_state import QrOnboardingProductStateAdapter, SUPPORTED_JOB_TYPES
from .qr_onboarding_runtime import QrOnboardingRuntimeService, SQLiteQrOnboardingRuntimeRepository
from .role_identity_provisioning_runtime_safe import SafeRoleIdentityProvisioningRuntimeService
from .runtime import Runtime
from .safe_auto_repair_history import SQLiteSafeAutoRepairHistoryRepository
from .safe_auto_repair_job_store import SQLiteSafeAutoRepairJobRepository


class ProductionRuntime(Runtime):
    """Server runtime with fail-closed providers, bounded QR effects and read-only repair evidence."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.safe_repair_history = SQLiteSafeAutoRepairHistoryRepository(
            self.store._connection,  # noqa: SLF001 - same-package canonical StateStore DB
            self.store._lock,  # noqa: SLF001 - share canonical transaction lock
        )
        self.safe_repair_jobs = SQLiteSafeAutoRepairJobRepository(
            self.store._connection,  # noqa: SLF001
            self.store._lock,  # noqa: SLF001
        )
        self.role_identity_provisioning = SafeRoleIdentityProvisioningRuntimeService(self.store)
        qr_repository = SQLiteQrOnboardingRuntimeRepository(
            self.store._connection,  # noqa: SLF001 - same-package canonical StateStore DB
            self.store._lock,  # noqa: SLF001 - share the canonical transaction lock
        )
        self.qr_onboarding = QrOnboardingRuntimeService(qr_repository)
        self.qr_effect_source = QrOnboardingEffectSourceService(qr_repository)
        self.qr_effect_admission = QrOnboardingEffectAdmissionService(self.store)
        self.qr_effect_execution = QrOnboardingEffectExecutionService(self.store)
        qr_product_state = QrOnboardingProductStateAdapter(self.store)
        for job_type in SUPPORTED_JOB_TYPES:
            self.qr_effect_execution.register(job_type, qr_product_state)
        self.qr_effect_worker = QrOnboardingEffectWorkerService(self.store, self.qr_effect_execution)
