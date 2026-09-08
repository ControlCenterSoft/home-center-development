"""Home Center module admission: structural validation plus product-scope policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .module_manifest import ModuleManifestIdentity, load_manifest, validate_manifest
from .product_boundary import ProductBoundaryDecision, evaluate_product_scope


class ModuleAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AdmittedModule:
    identity: ModuleManifestIdentity
    boundary: ProductBoundaryDecision


def validate_module_admission(value: dict[str, Any]) -> AdmittedModule:
    """Validate the manifest and reject development-only namespaces fail-closed."""

    identity = validate_manifest(value)
    dependencies = tuple(item["id"] for item in value["dependencies"])
    capabilities = tuple(value["capabilities"])
    permissions = tuple(value["permissions"])
    actions = tuple(item["id"] for item in value["actions"])
    boundary = evaluate_product_scope(
        module_id=identity.module_id,
        dependencies=dependencies,
        capabilities=capabilities,
        permissions=permissions,
        actions=actions,
    )
    if not boundary.allowed:
        raise ModuleAdmissionError(boundary.code)
    return AdmittedModule(identity=identity, boundary=boundary)


def load_and_validate_module_admission(payload: bytes) -> AdmittedModule:
    return validate_module_admission(load_manifest(payload))
