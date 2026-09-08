"""Аутентифицированный сервис планирования intents без побочных эффектов для Home Center 0.13."""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any, Callable, Final, Mapping

from .core.intent_engine import IntentEngine, IntentKind, IntentPlan, IntentPlanState, IntentRequest
from .core.policy_engine import AccessMode, PolicyEngine, PolicyRule
from .intent_preflight import IntentPreflightError, resource_preflight
from .resource_snapshot import ResourceSnapshotError


LOCAL_ADMIN_ACTOR: Final = re.compile(r"^local-admin:[a-z][a-z0-9._-]{2,63}$")
AD_ADMIN_ACTOR: Final = re.compile(r"^ad-admin:[a-z0-9][a-z0-9._-]{0,63}@[A-Z0-9][A-Z0-9.-]{2,254}$")

PERMISSION_BY_KIND = MappingProxyType(
    {
        IntentKind.NODE_DRAIN: "intent.node.plan",
        IntentKind.STORAGE_SHARE_CREATE: "intent.storage.plan",
        IntentKind.VIRTUALIZATION_WORKLOAD_CREATE: "intent.virtualization.plan",
        IntentKind.MODULE_INSTALL: "intent.module.plan",
    }
)
RESOURCE_AWARE_KINDS = frozenset(
    {
        IntentKind.STORAGE_SHARE_CREATE,
        IntentKind.VIRTUALIZATION_WORKLOAD_CREATE,
    }
)


class IntentAuthorizationError(PermissionError):
    code = "intent_permission_denied"


def _default_policy_engine() -> PolicyEngine:
    return PolicyEngine(
        [
            PolicyRule(
                permission=permission,
                module="intent-engine",
                action=f"intent.{kind.value}.plan.v1",
                mode=AccessMode.PLAN,
            )
            for kind, permission in PERMISSION_BY_KIND.items()
        ]
    )


class IntentPlanningService:
    """Связывает личности администраторов и доверенные данные о ресурсах с intents режима plan-only."""

    def __init__(
        self,
        engine: IntentEngine | None = None,
        *,
        resource_snapshot_provider: Callable[[], Mapping[str, Any]] | None = None,
    ) -> None:
        self._engine = engine or IntentEngine(_default_policy_engine())
        self._resource_snapshot_provider = resource_snapshot_provider

    @staticmethod
    def actor_is_administrator(actor: str) -> bool:
        return bool(LOCAL_ADMIN_ACTOR.fullmatch(actor) or AD_ADMIN_ACTOR.fullmatch(actor))

    @staticmethod
    def _blocked(request: IntentRequest, *blockers: str) -> IntentPlan:
        return IntentPlan(
            intent_id=request.intent_id,
            kind=request.kind,
            target_id=request.target_id,
            state=IntentPlanState.BLOCKED,
            code="intent_blocked",
            steps=(),
            blockers=tuple(blockers),
        )

    def plan(self, *, actor: str, request: IntentRequest) -> IntentPlan:
        if not self.actor_is_administrator(actor):
            raise IntentAuthorizationError("administrator actor required")
        if request.actor != actor:
            raise IntentAuthorizationError("request actor does not match authenticated actor")
        permission = PERMISSION_BY_KIND.get(request.kind)
        if permission is None:
            raise IntentAuthorizationError("intent permission unavailable")

        plan = self._engine.compile(request, permissions={permission})
        if plan.state is not IntentPlanState.PLANNED or request.kind not in RESOURCE_AWARE_KINDS:
            return plan

        provider = self._resource_snapshot_provider
        if provider is None:
            return self._blocked(request, "resource_snapshot_unavailable")
        try:
            snapshot = provider()
        except ResourceSnapshotError:
            return self._blocked(request, "resource_snapshot_unavailable")
        if not isinstance(snapshot, Mapping):
            return self._blocked(request, "resource_snapshot_invalid")
        try:
            blockers = resource_preflight(request, snapshot)
        except IntentPreflightError:
            return self._blocked(request, "resource_snapshot_invalid")
        if blockers:
            return self._blocked(request, *blockers)
        return plan
