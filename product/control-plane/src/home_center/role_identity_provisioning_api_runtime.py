"""Server-authoritative product API boundary for Home Center 0.62 identity provisioning.

This service deliberately accepts only user intent from the HTTP layer. Household
RBAC, the exact provisioning plan, qualified provider capability, account-absence
preflight evidence, durable execution evidence and the final Home Center binding
are all resolved or re-read on the server.

The module does not register a built-in provider. Without an exact qualification-
bound provider adapter and a separately bound read-only preflight observer every
provider operation remains fail-closed/unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
import threading
from typing import Callable, Protocol

from .home_services import HomeServiceCatalogError, _identifier
from .household import HouseholdRole, effective_policy
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .role_identity_binding_transition import (
    RoleIdentityBindingTransitionError,
    RoleIdentityBindingTransitionService,
)
from .role_identity_provider_qualification import QualificationBoundIdentityProviderAdapter
from .role_identity_provisioning import (
    IdentityProvisioningError,
    RoleIdentityProvisioningPlan,
    StorageMode,
    build_role_identity_provisioning_plan,
    plan_from_dict,
)
from .role_identity_provisioning_preflight import (
    IdentityProvisioningPreflightError,
    evaluate_account_preflight,
    observation_from_dict,
)
from .role_identity_provisioning_runtime import (
    IdentityProvisioningRuntimeError,
    RoleIdentityProvisioningRuntimeService,
)
from .store import StateStore
from .util import utc_now

PLAN_STATE_SCHEMA = "home-center.role-identity-provisioning-api-state.v1"
PLAN_KEY_PREFIX = "cozy.household.identity.provisioning."
_PLAN_ID = re.compile(r"hcidp-[0-9a-f]{24}\Z")
_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class IdentityProvisioningApiRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QualifiedIdentityPreflightObserver(Protocol):
    """Read-only preflight capability bound to the same qualified adapter artifact."""

    identity_preflight_read_only: bool
    provider_id: str
    provider_version: str
    provider_evidence_sha256: str
    adapter_artifact_sha256: str
    qualification_evidence_sha256: str

    def preflight(self, *, plan: RoleIdentityProvisioningPlan) -> object: ...


@dataclass(frozen=True, slots=True)
class _ProviderRegistration:
    bound_adapter: QualificationBoundIdentityProviderAdapter
    preflight_observer: QualifiedIdentityPreflightObserver

    @property
    def provider(self):
        return self.bound_adapter.provider

    @property
    def decision(self):
        return self.bound_adapter.decision


def _id(value: object, code: str) -> str:
    try:
        return _identifier(value, code)
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningApiRuntimeError(exc.code) from exc


def _actor_plan_key(actor: str, plan_id: str) -> str:
    if not isinstance(actor, str) or not actor:
        raise IdentityProvisioningApiRuntimeError("identity_api_actor_invalid")
    if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
        raise IdentityProvisioningApiRuntimeError("identity_api_plan_id_invalid")
    actor_digest = hashlib.sha256(actor.encode("utf-8")).hexdigest()[:24]
    return f"{PLAN_KEY_PREFIX}{actor_digest}.{plan_id}"


class RoleIdentityProvisioningApiRuntimeService:
    """Server-side plan/preflight/execute/bind workflow for qualified providers."""

    def __init__(
        self,
        store: StateStore,
        execution: RoleIdentityProvisioningRuntimeService,
        binding_transition: RoleIdentityBindingTransitionService,
        *,
        now: Callable[[], str] = utc_now,
    ) -> None:
        self.store = store
        self.execution = execution
        self.binding_transition = binding_transition
        self._now = now
        self._lock = threading.RLock()
        self._providers: dict[str, _ProviderRegistration] = {}

    @staticmethod
    def _validate_registration(
        bound_adapter: QualificationBoundIdentityProviderAdapter,
        preflight_observer: object,
    ) -> None:
        if not isinstance(bound_adapter, QualificationBoundIdentityProviderAdapter):
            raise IdentityProvisioningApiRuntimeError("identity_api_provider_registration_invalid")
        provider = bound_adapter.provider
        decision = bound_adapter.decision
        if (
            decision.qualified is not True
            or decision.blockers
            or decision.provider_id != provider.provider_id
            or decision.provider_version != provider.provider_version
            or decision.provider_kind != provider.provider_kind.value
            or decision.provider_evidence_sha256 != provider.evidence_sha256
            or not isinstance(decision.adapter_artifact_sha256, str)
            or _SHA256.fullmatch(decision.adapter_artifact_sha256) is None
            or not isinstance(decision.qualification_evidence_sha256, str)
            or _SHA256.fullmatch(decision.qualification_evidence_sha256) is None
            or getattr(preflight_observer, "identity_preflight_read_only", None) is not True
            or getattr(preflight_observer, "provider_id", None) != provider.provider_id
            or getattr(preflight_observer, "provider_version", None) != provider.provider_version
            or getattr(preflight_observer, "provider_evidence_sha256", None) != provider.evidence_sha256
            or getattr(preflight_observer, "adapter_artifact_sha256", None) != decision.adapter_artifact_sha256
            or getattr(preflight_observer, "qualification_evidence_sha256", None)
            != decision.qualification_evidence_sha256
            or not callable(getattr(preflight_observer, "preflight", None))
        ):
            raise IdentityProvisioningApiRuntimeError("identity_api_provider_registration_invalid")

    def register_provider(
        self,
        *,
        bound_adapter: QualificationBoundIdentityProviderAdapter,
        preflight_observer: QualifiedIdentityPreflightObserver,
    ) -> None:
        """Register only an exact qualification-bound mutation/readback adapter.

        The read-only preflight observer is a separate interface so the production
        HTTP boundary never pretends the #228 mutation/readback wrapper grants an
        unqualified discovery capability.
        """

        self._validate_registration(bound_adapter, preflight_observer)
        provider_id = bound_adapter.provider.provider_id
        with self._lock:
            if provider_id in self._providers:
                raise IdentityProvisioningApiRuntimeError("identity_api_provider_registration_invalid")
            try:
                self.execution.register_adapter(provider_id, bound_adapter)
            except IdentityProvisioningRuntimeError as exc:
                raise IdentityProvisioningApiRuntimeError(exc.code) from exc
            self._providers[provider_id] = _ProviderRegistration(
                bound_adapter=bound_adapter,
                preflight_observer=preflight_observer,
            )

    def _provider(self, provider_id: object) -> _ProviderRegistration:
        provider_id = _id(provider_id, "identity_api_provider_id_invalid")
        registration = self._providers.get(provider_id)
        if registration is None:
            raise IdentityProvisioningApiRuntimeError("identity_api_provider_unavailable")
        return registration

    def _authorized_context(self, *, actor: str, member_id: str):
        """Authorize the caller before resolving target/provider details."""

        if not isinstance(actor, str) or not actor:
            raise IdentityProvisioningApiRuntimeError("identity_api_actor_invalid")
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise IdentityProvisioningApiRuntimeError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
            actor_member_id = next(
                (item.member_id for item in bindings if getattr(item, "actor", None) == actor),
                None,
            )
            if actor_member_id is None:
                raise IdentityProvisioningApiRuntimeError("household_actor_not_bound")
            actor_member = snapshot.household.member(actor_member_id)
            actor_policy = effective_policy(snapshot.household, actor_member_id)
        except IdentityProvisioningApiRuntimeError:
            raise
        except HomeServiceCatalogError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
        except Exception as exc:
            raise IdentityProvisioningApiRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        if not actor_member.enabled:
            raise IdentityProvisioningApiRuntimeError("household_member_disabled")
        if actor_policy.role is not HouseholdRole.PARENT or not actor_policy.administration_allowed:
            raise IdentityProvisioningApiRuntimeError("identity_api_not_authorized")

        try:
            target_member = snapshot.household.member(member_id)
            target_policy = effective_policy(snapshot.household, member_id)
        except HomeServiceCatalogError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
        except Exception as exc:
            raise IdentityProvisioningApiRuntimeError(
                getattr(exc, "code", "household_state_invalid")
            ) from exc
        if not target_member.enabled:
            raise IdentityProvisioningApiRuntimeError("household_member_disabled")
        return snapshot, target_policy

    def plan(
        self,
        *,
        actor: str,
        member_id: object,
        provider_id: object,
        account_name: object,
        home_directory_mode: object,
        profile_mode: object,
        correlation_id: str,
    ) -> dict[str, object]:
        member_id = _id(member_id, "identity_api_member_id_invalid")
        # RBAC precedes provider lookup so unauthorized callers cannot enumerate
        # which providers are registered on this Home Center instance.
        snapshot, policy = self._authorized_context(actor=actor, member_id=member_id)
        registration = self._provider(provider_id)
        try:
            plan = build_role_identity_provisioning_plan(
                snapshot=snapshot,
                policy=policy,
                provider=registration.provider,
                member_id=member_id,
                account_name=account_name,
                home_directory_mode=StorageMode(home_directory_mode),
                profile_mode=StorageMode(profile_mode),
            )
        except (IdentityProvisioningError, ValueError, TypeError) as exc:
            raise IdentityProvisioningApiRuntimeError(
                getattr(exc, "code", "identity_api_plan_invalid")
            ) from exc

        key = _actor_plan_key(actor, plan.plan_id)
        state = {"schema": PLAN_STATE_SCHEMA, "actor": actor, "plan": plan.to_dict()}
        with self._lock:
            existing = self.store.get_meta(key)
            if existing is not None and existing != state:
                raise IdentityProvisioningApiRuntimeError("identity_api_plan_conflict")
            if existing is None:
                self.store.set_meta(key, state)
                self.store.audit(
                    actor=actor,
                    action="household.identity.provisioning.plan",
                    target=member_id,
                    outcome="planned",
                    correlation_id=correlation_id,
                    details={
                        "plan_id": plan.plan_id,
                        "provider_id": registration.provider.provider_id,
                        "provider_qualification_evidence_sha256": (
                            registration.decision.qualification_evidence_sha256
                        ),
                        "credential_material_included": False,
                        "execution_authorized": False,
                        "external_publication_authorized": False,
                    },
                )
        return plan.to_dict()

    def _load_plan(self, *, actor: str, plan_id: str) -> RoleIdentityProvisioningPlan:
        state = self.store.get_meta(_actor_plan_key(actor, plan_id))
        if (
            not isinstance(state, dict)
            or set(state) != {"schema", "actor", "plan"}
            or state.get("schema") != PLAN_STATE_SCHEMA
            or state.get("actor") != actor
        ):
            raise IdentityProvisioningApiRuntimeError("identity_api_plan_not_found")
        try:
            plan = plan_from_dict(state.get("plan"))
        except IdentityProvisioningError as exc:
            raise IdentityProvisioningApiRuntimeError("identity_api_plan_state_invalid") from exc
        if plan.plan_id != plan_id:
            raise IdentityProvisioningApiRuntimeError("identity_api_plan_state_invalid")
        return plan

    def _revalidate_plan(
        self,
        *,
        actor: str,
        plan: RoleIdentityProvisioningPlan,
    ) -> _ProviderRegistration:
        snapshot, policy = self._authorized_context(actor=actor, member_id=plan.member_id)
        registration = self._provider(plan.provider_id)
        try:
            current = build_role_identity_provisioning_plan(
                snapshot=snapshot,
                policy=policy,
                provider=registration.provider,
                member_id=plan.member_id,
                account_name=plan.account_name,
                home_directory_mode=plan.home_directory_mode,
                profile_mode=plan.profile_mode,
            )
        except IdentityProvisioningError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
        if current.to_dict() != plan.to_dict():
            raise IdentityProvisioningApiRuntimeError("identity_api_plan_stale")
        return registration

    def _fresh_preflight(
        self,
        *,
        registration: _ProviderRegistration,
        plan: RoleIdentityProvisioningPlan,
    ):
        try:
            raw = registration.preflight_observer.preflight(plan=plan)
            observation = observation_from_dict(raw)
            decision = evaluate_account_preflight(
                plan=plan,
                provider=registration.provider,
                observation=observation,
                now=self._now(),
            )
            return decision, observation
        except IdentityProvisioningPreflightError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
        except Exception as exc:
            raise IdentityProvisioningApiRuntimeError("identity_api_preflight_unavailable") from exc

    def preflight(
        self,
        *,
        actor: str,
        plan_id: str,
        correlation_id: str,
    ) -> dict[str, object]:
        plan = self._load_plan(actor=actor, plan_id=plan_id)
        registration = self._revalidate_plan(actor=actor, plan=plan)
        decision, _observation = self._fresh_preflight(registration=registration, plan=plan)
        self.store.audit(
            actor=actor,
            action="household.identity.provisioning.preflight",
            target=plan.member_id,
            outcome="accepted" if decision.ready else "blocked",
            correlation_id=correlation_id,
            details={
                "plan_id": plan.plan_id,
                "provider_id": plan.provider_id,
                "observation_evidence_sha256": decision.observation_evidence_sha256,
                "blockers": list(decision.blockers),
                "read_only": True,
                "execution_authorized": False,
            },
        )
        return decision.to_dict()

    def execute(
        self,
        *,
        actor: str,
        plan_id: str,
        credential_references: object,
        confirmed: bool,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, object]:
        if confirmed is not True:
            raise IdentityProvisioningApiRuntimeError("identity_api_confirmation_required")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise IdentityProvisioningApiRuntimeError("identity_api_idempotency_key_invalid")
        plan = self._load_plan(actor=actor, plan_id=plan_id)
        registration = self._revalidate_plan(actor=actor, plan=plan)
        # A fresh server-side observation is required immediately before the
        # durable execution runtime. A UI preflight response is never reused as
        # authorization evidence.
        preflight, observation = self._fresh_preflight(registration=registration, plan=plan)
        if not preflight.ready or preflight.blockers:
            raise IdentityProvisioningApiRuntimeError("identity_api_preflight_not_ready")
        try:
            return self.execution.execute(
                actor=actor,
                plan=plan,
                provider=registration.provider,
                preflight_observation=observation,
                credential_references=credential_references,
                confirmed=True,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
            )
        except IdentityProvisioningRuntimeError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc

    def bind(
        self,
        *,
        actor: str,
        plan_id: str,
        execution_job_id: str,
        idempotency_key: str,
        correlation_id: str,
    ) -> dict[str, object]:
        """Persist the Home Center binding from server-side verified Job evidence.

        The HTTP client supplies only the exact durable Job identity. The verified
        receipt itself is loaded from StateStore and is never trusted from the
        request body.
        """

        if not isinstance(execution_job_id, str) or _JOB_ID.fullmatch(execution_job_id) is None:
            raise IdentityProvisioningApiRuntimeError("identity_api_execution_job_id_invalid")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise IdentityProvisioningApiRuntimeError("identity_api_idempotency_key_invalid")
        plan = self._load_plan(actor=actor, plan_id=plan_id)
        self._revalidate_plan(actor=actor, plan=plan)
        job = self.store.job(execution_job_id)
        if (
            not isinstance(job, dict)
            or job.get("initiator") != actor
            or not isinstance(job.get("evidence"), dict)
            or not isinstance(job["evidence"].get("receipt"), dict)
        ):
            raise IdentityProvisioningApiRuntimeError("identity_api_verified_execution_not_found")
        receipt = job["evidence"]["receipt"]
        try:
            return self.binding_transition.transition(
                actor=actor,
                plan=plan,
                execution_receipt=receipt,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
            )
        except RoleIdentityBindingTransitionError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
