"""Fail-closed product-scope admission for Home Center runtime extensions.

The validator operates only on already-validated symbolic identifiers. It
prevents module manifests from introducing namespaces that do not belong to
Home Center's user-infrastructure product surface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


class ProductBoundaryError(ValueError):
    """Stable, input-free rejection code for out-of-scope identifiers."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_TOKEN_SPLIT = re.compile(r"[._:/-]+")
_BOUNDARY_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_FORBIDDEN_SINGLETONS = frozenset({"ci", "build", "runner", "scm", "developer"})
_FORBIDDEN_SEQUENCES = (
    ("ai", "development"),
    ("ai", "fabric"),
    ("ai", "provider"),
    ("model", "router"),
    ("release", "engineering"),
)


@dataclass(frozen=True, slots=True)
class ProductBoundaryDecision:
    allowed: bool
    code: str
    violations: tuple[str, ...]
    schema: str = "home-center.product-boundary-decision.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "allowed": self.allowed,
            "code": self.code,
            "violations": list(self.violations),
        }


def _tokens(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or _BOUNDARY_VALUE.fullmatch(value) is None:
        raise ProductBoundaryError("invalid_boundary_identifier")
    return tuple(part for part in _TOKEN_SPLIT.split(value.casefold()) if part)


def _out_of_scope(value: str) -> bool:
    parts = _tokens(value)
    if any(part in _FORBIDDEN_SINGLETONS for part in parts):
        return True
    for sequence in _FORBIDDEN_SEQUENCES:
        width = len(sequence)
        if any(parts[index : index + width] == sequence for index in range(len(parts) - width + 1)):
            return True
    return False


def evaluate_product_scope(
    *,
    module_id: str,
    dependencies: Iterable[str] = (),
    capabilities: Iterable[str] = (),
    permissions: Iterable[str] = (),
    actions: Iterable[str] = (),
) -> ProductBoundaryDecision:
    """Return a deterministic decision without executing or mutating anything."""

    categories = {
        "module": (module_id,),
        "dependency": tuple(dependencies),
        "capability": tuple(capabilities),
        "permission": tuple(permissions),
        "action": tuple(actions),
    }
    violations: list[str] = []
    for category, values in categories.items():
        for value in values:
            if _out_of_scope(value):
                violations.append(category)

    normalized = tuple(sorted(set(violations)))
    if normalized:
        return ProductBoundaryDecision(
            allowed=False,
            code="product_scope_rejected",
            violations=normalized,
        )
    return ProductBoundaryDecision(
        allowed=True,
        code="product_scope_allowed",
        violations=(),
    )


def assert_product_scope(
    *,
    module_id: str,
    dependencies: Iterable[str] = (),
    capabilities: Iterable[str] = (),
    permissions: Iterable[str] = (),
    actions: Iterable[str] = (),
) -> None:
    decision = evaluate_product_scope(
        module_id=module_id,
        dependencies=dependencies,
        capabilities=capabilities,
        permissions=permissions,
        actions=actions,
    )
    if not decision.allowed:
        raise ProductBoundaryError(decision.code)
