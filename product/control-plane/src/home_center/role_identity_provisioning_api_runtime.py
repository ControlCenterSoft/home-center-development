"""Server-authoritative API service for Home Center 0.62 identity provisioning.

Client requests may select an already-qualified provider by ID and may supply only
bounded user intent plus opaque ``secret://`` references. Provider capability,
qualification evidence, Household authority, effective policy and account-absence
preflight are resolved or re-read on the server. The service never accepts provider
capability evidence or preflight observations from an HTTP client.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import threading
from typing import Callable, Protocol

from .home_services import HomeServiceCatalogError, _identifier
from .household import HouseholdRole, effective_policy
from .household_runtime import HOUSEHOLD_STATE_KEY, _state_from_dict
from .role_identity_provider_qualification import (
    IdentityProviderQualificationDecision,
    IdentityProviderQualificationError,
)
from .role_identity_provisioning import (
    IdentityProviderCapability,
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
_IDEMPOTENCY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class IdentityProvisioningApiRuntimeError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class QualifiedIdentityProvisioningAdapter(Protocol):
    identity_provisioning_qualified: bool
    provider_id: str
    provider_version: str
    adapter_artifact_sha256: str
    qualification_evidence_sha256: str

    def preflight(self, *, plan: RoleIdentityProvisioningPlan) -> object: ...
    def start(self, request: object) -> object: ...
    def observe(self, *, provider_operation_id: str, account_name: str) -> object: ...


@dataclass(frozen=True, slots=True)
class _ProviderRegistration:
    capability: IdentityProviderCapability
    qualification: IdentityProviderQualificationDecision
    adapter: QualifiedIdentityProvisioningAdapter


def _id(value: object, code: str) -> str:
    try:
        return _identifier(value, code)
    except HomeServiceCatalogError as exc:
        raise IdentityProvisioningApiRuntimeError(exc.code) from exc


class RoleIdentityProvisioningApiRuntimeService:
    """Bind product API operations to server-side Household/provider authority."""

    def __init__(
        self,
        store: StateStore,
        execution: RoleIdentityProvisioningRuntimeService,
        *,
        now: Callable[[], str] = utc_now,
    ) -> None:
        self.store = store
        self.execution = execution
        self._now = now
        self._lock = threading.RLock()
        self._providers: dict[str, _ProviderRegistration] = {}

    @staticmethod
    def _validate_adapter(decision: IdentityProviderQualificationDecision, adapter: object) -> None:
        if (
            decision.qualified is not True
            or decision.blockers
            or decision.evidence_sha256 == "0" * 64
            or getattr(adapter, "identity_provisioning_qualified", None) is not True
            or getattr(adapter, "provider_id", None) != decision.provider_id
            or getattr(adapter, "provider_version", None) != decision.provider_version
            or getattr(adapter, "adapter_artifact_sha256", None) != decision.adapter_artifact_sha256
            or getattr(adapter, "qualification_evidence_sha256", None) != decision.evidence_sha256
            or not isinstance(decision.adapter_artifact_sha256, str)
            or _SHA256.fullmatch(decision.adapter_artifact_sha256) is None
            or not callable(getattr(adapter, "preflight", None))
            or not callable(getattr(adapter, "start", None))
            or not callable(getattr(adapter, "observe", None))
        ):
            raise IdentityProvisioningApiRuntimeError("identity_api_provider_registration_invalid")

    def register_provider(self, decision: IdentityProviderQualificationDecision, adapter: QualifiedIdentityProvisioningAdapter) -> None:
        if not isinstance(decision, IdentityProviderQualificationDecision):
            raise IdentityProvisioningApiRuntimeError("identity_api_provider_registration_invalid")
        try:
            capability = decision.to_capability()
        except IdentityProviderQualificationError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
        self._validate_adapter(decision, adapter)
        with self._lock:
            if capability.provider_id in self._providers:
                raise IdentityProvisioningApiRuntimeError("identity_api_provider_registration_invalid")
            try:
                self.execution.register_adapter(capability.provider_id, adapter)
            except IdentityProvisioningRuntimeError as exc:
                raise IdentityProvisioningApiRuntimeError(exc.code) from exc
            self._providers[capability.provider_id] = _ProviderRegistration(capability, decision, adapter)

    def _provider(self, provider_id: object) -> _ProviderRegistration:
        provider_id = _id(provider_id, "identity_api_provider_id_invalid")
        registration = self._providers.get(provider_id)
        if registration is None:
            raise IdentityProvisioningApiRuntimeError("identity_api_provider_unavailable")
        return registration

    def _context(self, actor: str, member_id: str):
        """Authorize the actor before resolving target-member details."""

        if not isinstance(actor, str) or not actor:
            raise IdentityProvisioningApiRuntimeError("identity_api_actor_invalid")
        raw = self.store.get_meta(HOUSEHOLD_STATE_KEY)
        if raw is None:
            raise IdentityProvisioningApiRuntimeError("household_not_configured")
        try:
            snapshot, bindings = _state_from_dict(raw)
            actor_member_id = next((item.member_id for item in bindings if getattr(item, "actor", None) == actor), None)
            if actor_member_id is None:
                raise IdentityProvisioningApiRuntimeError("household_actor_not_bound")
            actor_member = snapshot.household.member(actor_member_id)
            actor_policy = effective_policy(snapshot.household, actor_member_id)
        except IdentityProvisioningApiRuntimeError:
            raise
        except HomeServiceCatalogError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
        except Exception as exc:
            raise IdentityProvisioningApiRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc
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
            raise IdentityProvisioningApiRuntimeError(getattr(exc, "code", "household_state_invalid")) from exc
        if not target_member.enabled:
            raise IdentityProvisioningApiRuntimeError("household_member_disabled")
        return snapshot, target_policy

    @staticmethod
    def _plan_key(plan_id: str) -> str:
        if not isinstance(plan_id, str) or not re.fullmatch(r"hcidp-[0-9a-f]{24}", plan_id):
            raise IdentityProvisioningApiRuntimeError("identity_api_plan_id_invalid")
        return PLAN_KEY_PREFIX + plan_id

    def _load_plan(self, actor: str, plan_id: str) -> RoleIdentityProvisioningPlan:
        state = self.store.get_meta(self._plan_key(plan_id))
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

    def _revalidate_plan(self, actor: str, plan: RoleIdentityProvisioningPlan) -> _ProviderRegistration:
        snapshot, policy = self._context(actor, plan.member_id)
        registration = self._provider(plan.provider_id)
        try:
            current = build_role_identity_provisioning_plan(
                snapshot=snapshot,
                policy=policy,
                provider=registration.capability,
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

    def plan(self, *, actor: str, member_id: object, provider_id: object, account_name: object, home_directory_mode: object, profile_mode: object, correlation_id: str) -> dict[str, object]:
        member_id = _id(member_id, "identity_api_member_id_invalid")
        snapshot, policy = self._context(actor, member_id)
        registration = self._provider(provider_id)
        try:
            plan = build_role_identity_provisioning_plan(
                snapshot=snapshot,
                policy=policy,
                provider=registration.capability,
                member_id=member_id,
                account_name=account_name,
                home_directory_mode=StorageMode(home_directory_mode),
                profile_mode=StorageMode(profile_mode),
            )
        except (IdentityProvisioningError, ValueError, TypeError) as exc:
            raise IdentityProvisioningApiRuntimeError(getattr(exc, "code", "identity_api_plan_invalid")) from exc
        key = self._plan_key(plan.plan_id)
        expected = {"schema": PLAN_STATE_SCHEMA, "actor": actor, "plan": plan.to_dict()}
        with self._lock:
            existing = self.store.get_meta(key)
            if existing is not None and existing != expected:
                raise IdentityProvisioningApiRuntimeError("identity_api_plan_conflict")
            if existing is None:
                self.store.set_meta(key, expected)
                self.store.audit(
                    actor=actor,
                    action="household.identity.provisioning.plan",
                    target=member_id,
                    outcome="planned",
                    correlation_id=correlation_id,
                    details={
                        "plan_id": plan.plan_id,
                        "provider_id": registration.capability.provider_id,
                        "provider_qualification_evidence_sha256": registration.qualification.evidence_sha256,
                        "credential_material_included": False,
                        "execution_authorized": False,
                        "external_publication_authorized": False,
                    },
                )
        return plan.to_dict()

    def _observe_preflight(self, *, registration: _ProviderRegistration, plan: RoleIdentityProvisioningPlan):
        try:
            observation = observation_from_dict(registration.adapter.preflight(plan=plan))
            decision = evaluate_account_preflight(
                plan=plan,
                provider=registration.capability,
                observation=observation,
                now=self._now(),
            )
            return decision, observation
        except IdentityProvisioningPreflightError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
        except Exception as exc:
            raise IdentityProvisioningApiRuntimeError("identity_api_preflight_unavailable") from exc

    def preflight(self, *, actor: str, plan_id: str, correlation_id: str) -> dict[str, object]:
        plan = self._load_plan(actor, plan_id)
        registration = self._revalidate_plan(actor, plan)
        decision, _ = self._observe_preflight(registration=registration, plan=plan)
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

    def execute(self, *, actor: str, plan_id: str, credential_references: object, confirmed: bool, idempotency_key: str, correlation_id: str) -> dict[str, object]:
        if confirmed is not True:
            raise IdentityProvisioningApiRuntimeError("identity_api_confirmation_required")
        if not isinstance(idempotency_key, str) or _IDEMPOTENCY.fullmatch(idempotency_key) is None:
            raise IdentityProvisioningApiRuntimeError("identity_api_idempotency_key_invalid")
        plan = self._load_plan(actor, plan_id)
        registration = self._revalidate_plan(actor, plan)
        decision, observation = self._observe_preflight(registration=registration, plan=plan)
        if not decision.ready or decision.blockers:
            raise IdentityProvisioningApiRuntimeError("identity_api_preflight_not_ready")
        try:
            return self.execution.execute(
                actor=actor,
                plan=plan,
                provider=registration.capability,
                preflight_observation=observation,
                credential_references=credential_references,
                confirmed=True,
                idempotency_key=idempotency_key,
                correlation_id=correlation_id,
            )
        except IdentityProvisioningRuntimeError as exc:
            raise IdentityProvisioningApiRuntimeError(exc.code) from exc
