"""Решения авторизации default-deny для планировщиков Core 0.10."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Iterable


PRODUCTION_MUTATION_ENABLED = False


class AccessMode(StrEnum):
    READ = "read"
    PLAN = "plan"
    MUTATE = "mutate"


@dataclass(frozen=True, slots=True)
class PolicyRule:
    permission: str
    module: str
    action: str
    mode: AccessMode


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: str
    schema: str = field(default="home-center.policy-decision.v1", init=False)

    def to_dict(self) -> dict[str, object]:
        return {"schema": self.schema, "allowed": self.allowed, "code": self.code}


class PolicyEngine:
    """Проверяет точные правила; wildcard-доступ и неявный доступ администратора отсутствуют."""

    def __init__(self, rules: Iterable[PolicyRule] = ()) -> None:
        self._rules = tuple(rules)

    def authorize(
        self,
        *,
        module: str,
        action: str,
        mode: AccessMode,
        permissions: Iterable[str],
    ) -> PolicyDecision:
        if mode is AccessMode.MUTATE and not PRODUCTION_MUTATION_ENABLED:
            return PolicyDecision(False, "production_mutation_not_certified")
        granted = frozenset(permissions)
        for rule in self._rules:
            if (rule.module, rule.action, rule.mode) == (module, action, mode) and rule.permission in granted:
                return PolicyDecision(True, "allowed_by_exact_rule")
        return PolicyDecision(False, "default_deny")
