"""Fail-closed Home Center module admission and runtime compatibility evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .module_artifact import VerifiedModuleArtifact, manifest_binding_sha256
from .module_manifest import (
    DIGEST,
    KEY_ID,
    MODULE_ID,
    SEMVER,
    SYMBOLIC_ID,
    ModuleManifestIdentity,
    load_manifest,
    validate_manifest,
)
from .product_boundary import ProductBoundaryDecision, evaluate_product_scope


MAX_RUNTIME_CAPABILITIES = 256
MAX_INSTALLED_MODULES = 256


class ModuleAdmissionError(ValueError):
    """Stable rejection code for malformed or mismatched admission evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AdmittedModule:
    identity: ModuleManifestIdentity
    boundary: ProductBoundaryDecision


@dataclass(frozen=True, slots=True)
class ModuleAdmissionDecision:
    """Reproducible compatibility decision with no installation authority."""

    decision_id: str
    status: str
    module_id: str
    module_version: str
    publisher: str
    manifest_binding_sha256: str
    provenance_statement_sha256: str
    verified_signing_key_ids: tuple[str, ...]
    artifact_sha256: str
    home_center_version: str
    architecture: str
    operating_system: str
    available_capabilities: tuple[str, ...]
    installed_modules: tuple[tuple[str, str], ...]
    missing_capabilities: tuple[str, ...]
    unsatisfied_dependencies: tuple[str, ...]
    active_conflicts: tuple[str, ...]
    reasons: tuple[str, ...]
    schema: str = "home-center.module-admission-decision.v1"
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    @property
    def compatible(self) -> bool:
        return self.status == "compatible"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "decision_id": self.decision_id,
            "status": self.status,
            "module_id": self.module_id,
            "module_version": self.module_version,
            "publisher": self.publisher,
            "manifest_binding_sha256": self.manifest_binding_sha256,
            "provenance_statement_sha256": self.provenance_statement_sha256,
            "verified_signing_key_ids": list(self.verified_signing_key_ids),
            "artifact_sha256": self.artifact_sha256,
            "home_center_version": self.home_center_version,
            "architecture": self.architecture,
            "operating_system": self.operating_system,
            "available_capabilities": list(self.available_capabilities),
            "installed_modules": [
                {"id": module_id, "version": version}
                for module_id, version in self.installed_modules
            ],
            "missing_capabilities": list(self.missing_capabilities),
            "unsatisfied_dependencies": list(self.unsatisfied_dependencies),
            "active_conflicts": list(self.active_conflicts),
            "reasons": list(self.reasons),
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": self.external_publication_authorized,
        }


def _semver(value: object, code: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or len(value) > 64 or SEMVER.fullmatch(value) is None:
        raise ModuleAdmissionError(code)
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def _symbolic(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or SYMBOLIC_ID.fullmatch(value) is None:
        raise ModuleAdmissionError(code)
    return value


def _module_id(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) > 128 or MODULE_ID.fullmatch(value) is None:
        raise ModuleAdmissionError(code)
    return value


def _normalize_capabilities(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ModuleAdmissionError("runtime_capabilities_rejected")
    result: list[str] = []
    for value in values:
        result.append(_symbolic(value, "runtime_capability_rejected"))
        if len(result) > MAX_RUNTIME_CAPABILITIES:
            raise ModuleAdmissionError("runtime_capabilities_rejected")
    if len(result) != len(set(result)):
        raise ModuleAdmissionError("runtime_capability_duplicate")
    return tuple(sorted(result))


def _normalize_installed_modules(values: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, Mapping) or len(values) > MAX_INSTALLED_MODULES:
        raise ModuleAdmissionError("installed_modules_rejected")
    result: list[tuple[str, str]] = []
    for raw_id, raw_version in values.items():
        module_id = _module_id(raw_id, "installed_module_id_rejected")
        if not isinstance(raw_version, str):
            raise ModuleAdmissionError("installed_module_version_rejected")
        _semver(raw_version, "installed_module_version_rejected")
        result.append((module_id, raw_version))
    return tuple(sorted(result))


def _canonical_sha256(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ModuleAdmissionError("admission_evidence_rejected") from exc
    return hashlib.sha256(payload).hexdigest()


def _assert_verified_binding(
    manifest: dict[str, Any],
    identity: ModuleManifestIdentity,
    verified: VerifiedModuleArtifact,
) -> tuple[str, str, tuple[str, ...]]:
    expected_binding = manifest_binding_sha256(manifest)
    provenance = manifest["artifact"]["provenance"]
    expected_statement = provenance["statement_sha256"]
    declared_signers = set(provenance["signer_key_ids"])
    threshold = provenance["threshold"]
    expected_object_key = (
        f"sha256/{identity.artifact_sha256[:2]}/"
        f"{identity.artifact_sha256}/artifact.tar.gz"
    )
    expected = (
        identity.module_id,
        identity.version,
        manifest["module"]["publisher"],
        expected_binding,
        expected_statement,
        identity.artifact_sha256,
        identity.artifact_size_bytes,
        expected_object_key,
    )
    actual = (
        verified.module_id,
        verified.version,
        verified.publisher,
        verified.manifest_binding_sha256,
        verified.statement_sha256,
        verified.artifact_sha256,
        verified.artifact_size_bytes,
        verified.object_key,
    )
    raw_signers = verified.signing_key_ids
    if (
        actual != expected
        or not isinstance(raw_signers, tuple)
        or not 1 <= len(raw_signers) <= 16
        or len(raw_signers) != len(set(raw_signers))
        or any(
            not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None
            for key_id in raw_signers
        )
        or not set(raw_signers).issubset(declared_signers)
        or len(raw_signers) < threshold
    ):
        raise ModuleAdmissionError("verified_artifact_mismatch")
    if (
        not isinstance(verified.version, str)
        or SEMVER.fullmatch(verified.version) is None
        or not isinstance(verified.publisher, str)
        or MODULE_ID.fullmatch(verified.publisher) is None
        or not isinstance(verified.statement_sha256, str)
        or DIGEST.fullmatch(verified.statement_sha256) is None
    ):
        raise ModuleAdmissionError("verified_artifact_mismatch")
    return expected_binding, expected_statement, tuple(sorted(raw_signers))


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


def evaluate_module_compatibility(
    manifest: dict[str, Any],
    verified: VerifiedModuleArtifact,
    *,
    home_center_version: str,
    architecture: str,
    operating_system: str,
    available_capabilities: Iterable[str],
    installed_modules: Mapping[str, str],
) -> ModuleAdmissionDecision:
    """Evaluate exact module/runtime compatibility without installing or executing it."""

    admitted = validate_module_admission(manifest)
    identity = admitted.identity
    binding_sha256, statement_sha256, signing_key_ids = _assert_verified_binding(
        manifest,
        identity,
        verified,
    )

    current_version = _semver(home_center_version, "home_center_version_rejected")
    architecture = _symbolic(architecture, "runtime_architecture_rejected")
    operating_system = _symbolic(operating_system, "runtime_operating_system_rejected")
    capabilities = _normalize_capabilities(available_capabilities)
    installed = _normalize_installed_modules(installed_modules)
    installed_map = dict(installed)

    compatibility = manifest["compatibility"]
    home_center = compatibility["home_center"]
    minimum = _semver(home_center["minimum"], "home_center_minimum_rejected")
    maximum = _semver(home_center["maximum_exclusive"], "home_center_maximum_rejected")

    missing_capabilities = tuple(
        sorted(set(manifest["capabilities"]) - set(capabilities))
    )

    unsatisfied_dependencies: list[str] = []
    for dependency in manifest["dependencies"]:
        dependency_id = dependency["id"]
        installed_version = installed_map.get(dependency_id)
        if installed_version is None:
            if not dependency["optional"]:
                unsatisfied_dependencies.append(dependency_id)
            continue
        installed_semver = _semver(
            installed_version,
            "installed_module_version_rejected",
        )
        dependency_minimum = _semver(
            dependency["minimum_version"],
            "dependency_minimum_rejected",
        )
        dependency_maximum = _semver(
            dependency["maximum_version_exclusive"],
            "dependency_maximum_rejected",
        )
        if not dependency_minimum <= installed_semver < dependency_maximum:
            unsatisfied_dependencies.append(dependency_id)

    active_conflicts = tuple(
        sorted(set(manifest["conflicts"]).intersection(installed_map))
    )
    unsatisfied = tuple(sorted(set(unsatisfied_dependencies)))

    reasons: list[str] = []
    if not minimum <= current_version < maximum:
        reasons.append("home_center_version_unsupported")
    if architecture not in manifest["compatibility"]["architectures"]:
        reasons.append("architecture_unsupported")
    if operating_system not in manifest["compatibility"]["operating_systems"]:
        reasons.append("operating_system_unsupported")
    if missing_capabilities:
        reasons.append("capability_missing")
    if unsatisfied:
        reasons.append("dependency_unsatisfied")
    if active_conflicts:
        reasons.append("conflict_present")
    normalized_reasons = tuple(sorted(reasons))
    status = "compatible" if not normalized_reasons else "blocked"

    evidence = {
        "schema": "home-center.module-admission-decision.v1",
        "status": status,
        "module_id": identity.module_id,
        "module_version": identity.version,
        "publisher": manifest["module"]["publisher"],
        "manifest_binding_sha256": binding_sha256,
        "provenance_statement_sha256": statement_sha256,
        "verified_signing_key_ids": signing_key_ids,
        "artifact_sha256": identity.artifact_sha256,
        "home_center_version": home_center_version,
        "architecture": architecture,
        "operating_system": operating_system,
        "available_capabilities": capabilities,
        "installed_modules": [
            {"id": module_id, "version": version}
            for module_id, version in installed
        ],
        "missing_capabilities": missing_capabilities,
        "unsatisfied_dependencies": unsatisfied,
        "active_conflicts": active_conflicts,
        "reasons": normalized_reasons,
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    decision_id = "madm-" + _canonical_sha256(evidence)[:24]
    return ModuleAdmissionDecision(
        decision_id=decision_id,
        status=status,
        module_id=identity.module_id,
        module_version=identity.version,
        publisher=manifest["module"]["publisher"],
        manifest_binding_sha256=binding_sha256,
        provenance_statement_sha256=statement_sha256,
        verified_signing_key_ids=signing_key_ids,
        artifact_sha256=identity.artifact_sha256,
        home_center_version=home_center_version,
        architecture=architecture,
        operating_system=operating_system,
        available_capabilities=capabilities,
        installed_modules=installed,
        missing_capabilities=missing_capabilities,
        unsatisfied_dependencies=unsatisfied,
        active_conflicts=active_conflicts,
        reasons=normalized_reasons,
    )


def load_and_evaluate_module_compatibility(
    manifest_payload: bytes,
    verified: VerifiedModuleArtifact,
    *,
    home_center_version: str,
    architecture: str,
    operating_system: str,
    available_capabilities: Iterable[str],
    installed_modules: Mapping[str, str],
) -> ModuleAdmissionDecision:
    """Decode a bounded manifest, then evaluate the compatibility admission."""

    return evaluate_module_compatibility(
        load_manifest(manifest_payload),
        verified,
        home_center_version=home_center_version,
        architecture=architecture,
        operating_system=operating_system,
        available_capabilities=available_capabilities,
        installed_modules=installed_modules,
    )
