"""Canonical runtime compatibility snapshots for Home Center module admission."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

from .module_admission import ModuleAdmissionDecision
from .module_manifest import DIGEST, KEY_ID, MODULE_ID, SEMVER, SYMBOLIC_ID


MAX_RUNTIME_CAPABILITIES = 256
MAX_INSTALLED_MODULES = 256
MAX_ADMISSION_DECISIONS = 256


class ModuleCompatibilitySnapshotError(ValueError):
    """Stable rejection code for malformed or mixed compatibility evidence."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ModuleCompatibilitySnapshot:
    """Canonical identity for one Home Center module compatibility runtime state."""

    snapshot_id: str
    home_center_version: str
    architecture: str
    operating_system: str
    available_capabilities: tuple[str, ...]
    installed_modules: tuple[tuple[str, str], ...]
    schema: str = "home-center.module-compatibility-snapshot.v1"
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "snapshot_id": self.snapshot_id,
            "home_center_version": self.home_center_version,
            "architecture": self.architecture,
            "operating_system": self.operating_system,
            "available_capabilities": list(self.available_capabilities),
            "installed_modules": [
                {"id": module_id, "version": version}
                for module_id, version in self.installed_modules
            ],
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": self.external_publication_authorized,
        }


@dataclass(frozen=True, slots=True)
class ModuleAdmissionSnapshotBinding:
    """Binding of multiple exact admission decisions to one runtime snapshot."""

    binding_id: str
    snapshot_id: str
    home_center_version: str
    architecture: str
    operating_system: str
    available_capabilities: tuple[str, ...]
    installed_modules: tuple[tuple[str, str], ...]
    decisions: tuple[tuple[str, str, str, str, str, str], ...]
    schema: str = "home-center.module-admission-snapshot-binding.v1"
    installation_authorized: bool = False
    execution_authorized: bool = False
    production_mutation_enabled: bool = False
    external_publication_authorized: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "binding_id": self.binding_id,
            "snapshot_id": self.snapshot_id,
            "home_center_version": self.home_center_version,
            "architecture": self.architecture,
            "operating_system": self.operating_system,
            "available_capabilities": list(self.available_capabilities),
            "installed_modules": [
                {"id": module_id, "version": version}
                for module_id, version in self.installed_modules
            ],
            "decisions": [
                {
                    "module_id": module_id,
                    "module_version": module_version,
                    "decision_id": decision_id,
                    "status": status,
                    "manifest_binding_sha256": manifest_binding_sha256,
                    "artifact_sha256": artifact_sha256,
                }
                for (
                    module_id,
                    module_version,
                    decision_id,
                    status,
                    manifest_binding_sha256,
                    artifact_sha256,
                ) in self.decisions
            ],
            "installation_authorized": self.installation_authorized,
            "execution_authorized": self.execution_authorized,
            "production_mutation_enabled": self.production_mutation_enabled,
            "external_publication_authorized": self.external_publication_authorized,
        }


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
        raise ModuleCompatibilitySnapshotError(
            "compatibility_snapshot_evidence_rejected"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _semver(value: object, code: str) -> str:
    if not isinstance(value, str) or len(value) > 64 or SEMVER.fullmatch(value) is None:
        raise ModuleCompatibilitySnapshotError(code)
    return value


def _symbolic(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or SYMBOLIC_ID.fullmatch(value) is None
    ):
        raise ModuleCompatibilitySnapshotError(code)
    return value


def _module_id(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or MODULE_ID.fullmatch(value) is None
    ):
        raise ModuleCompatibilitySnapshotError(code)
    return value


def _normalize_capabilities(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ModuleCompatibilitySnapshotError("runtime_capabilities_rejected")
    result: list[str] = []
    for value in values:
        result.append(_symbolic(value, "runtime_capability_rejected"))
        if len(result) > MAX_RUNTIME_CAPABILITIES:
            raise ModuleCompatibilitySnapshotError("runtime_capabilities_rejected")
    if len(result) != len(set(result)):
        raise ModuleCompatibilitySnapshotError("runtime_capability_duplicate")
    return tuple(sorted(result))


def _normalize_installed_modules(
    values: Mapping[str, str],
) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, Mapping) or len(values) > MAX_INSTALLED_MODULES:
        raise ModuleCompatibilitySnapshotError("installed_modules_rejected")
    result: list[tuple[str, str]] = []
    for raw_id, raw_version in values.items():
        module_id = _module_id(raw_id, "installed_module_id_rejected")
        version = _semver(raw_version, "installed_module_version_rejected")
        result.append((module_id, version))
    return tuple(sorted(result))


def _snapshot_evidence(
    *,
    home_center_version: str,
    architecture: str,
    operating_system: str,
    available_capabilities: tuple[str, ...],
    installed_modules: tuple[tuple[str, str], ...],
) -> dict[str, object]:
    return {
        "schema": "home-center.module-compatibility-snapshot.v1",
        "home_center_version": home_center_version,
        "architecture": architecture,
        "operating_system": operating_system,
        "available_capabilities": available_capabilities,
        "installed_modules": [
            {"id": module_id, "version": version}
            for module_id, version in installed_modules
        ],
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }


def build_module_compatibility_snapshot(
    *,
    home_center_version: str,
    architecture: str,
    operating_system: str,
    available_capabilities: Iterable[str],
    installed_modules: Mapping[str, str],
) -> ModuleCompatibilitySnapshot:
    """Build one canonical runtime compatibility snapshot without side effects."""

    version = _semver(home_center_version, "home_center_version_rejected")
    architecture = _symbolic(architecture, "runtime_architecture_rejected")
    operating_system = _symbolic(
        operating_system,
        "runtime_operating_system_rejected",
    )
    capabilities = _normalize_capabilities(available_capabilities)
    installed = _normalize_installed_modules(installed_modules)
    evidence = _snapshot_evidence(
        home_center_version=version,
        architecture=architecture,
        operating_system=operating_system,
        available_capabilities=capabilities,
        installed_modules=installed,
    )
    snapshot_id = "mcs-" + _canonical_sha256(evidence)[:24]
    return ModuleCompatibilitySnapshot(
        snapshot_id=snapshot_id,
        home_center_version=version,
        architecture=architecture,
        operating_system=operating_system,
        available_capabilities=capabilities,
        installed_modules=installed,
    )


def _reconstruct_snapshot(
    snapshot: ModuleCompatibilitySnapshot,
) -> ModuleCompatibilitySnapshot:
    if not isinstance(snapshot, ModuleCompatibilitySnapshot):
        raise ModuleCompatibilitySnapshotError("compatibility_snapshot_rejected")
    try:
        reconstructed = build_module_compatibility_snapshot(
            home_center_version=snapshot.home_center_version,
            architecture=snapshot.architecture,
            operating_system=snapshot.operating_system,
            available_capabilities=snapshot.available_capabilities,
            installed_modules=dict(snapshot.installed_modules),
        )
    except (TypeError, ValueError) as exc:
        raise ModuleCompatibilitySnapshotError("compatibility_snapshot_rejected") from exc
    if snapshot.to_dict() != reconstructed.to_dict():
        raise ModuleCompatibilitySnapshotError("compatibility_snapshot_rejected")
    return reconstructed


def _validate_decision_identity(decision: ModuleAdmissionDecision) -> None:
    if not isinstance(decision, ModuleAdmissionDecision):
        raise ModuleCompatibilitySnapshotError("admission_decision_rejected")
    try:
        malformed = (
            decision.schema != "home-center.module-admission-decision.v1"
            or decision.status not in {"compatible", "blocked"}
            or not isinstance(decision.module_id, str)
            or MODULE_ID.fullmatch(decision.module_id) is None
            or not isinstance(decision.module_version, str)
            or SEMVER.fullmatch(decision.module_version) is None
            or not isinstance(decision.publisher, str)
            or MODULE_ID.fullmatch(decision.publisher) is None
            or not isinstance(decision.manifest_binding_sha256, str)
            or DIGEST.fullmatch(decision.manifest_binding_sha256) is None
            or not isinstance(decision.provenance_statement_sha256, str)
            or DIGEST.fullmatch(decision.provenance_statement_sha256) is None
            or not isinstance(decision.artifact_sha256, str)
            or DIGEST.fullmatch(decision.artifact_sha256) is None
            or not isinstance(decision.verified_signing_key_ids, tuple)
            or not 1 <= len(decision.verified_signing_key_ids) <= 16
            or len(decision.verified_signing_key_ids)
            != len(set(decision.verified_signing_key_ids))
            or any(
                not isinstance(key_id, str) or KEY_ID.fullmatch(key_id) is None
                for key_id in decision.verified_signing_key_ids
            )
            or not isinstance(decision.available_capabilities, tuple)
            or decision.available_capabilities
            != tuple(sorted(decision.available_capabilities))
            or len(decision.available_capabilities)
            != len(set(decision.available_capabilities))
            or any(
                not isinstance(capability, str)
                or SYMBOLIC_ID.fullmatch(capability) is None
                for capability in decision.available_capabilities
            )
            or not isinstance(decision.installed_modules, tuple)
            or decision.installed_modules != tuple(sorted(decision.installed_modules))
            or len(decision.installed_modules)
            != len({module_id for module_id, _ in decision.installed_modules})
            or any(
                not isinstance(module_id, str)
                or MODULE_ID.fullmatch(module_id) is None
                or not isinstance(version, str)
                or SEMVER.fullmatch(version) is None
                for module_id, version in decision.installed_modules
            )
            or decision.installation_authorized is not False
            or decision.execution_authorized is not False
            or decision.production_mutation_enabled is not False
            or decision.external_publication_authorized is not False
        )
    except (TypeError, ValueError):
        malformed = True
    if malformed:
        raise ModuleCompatibilitySnapshotError("admission_decision_rejected")

    payload = decision.to_dict()
    raw_decision_id = payload.pop("decision_id", None)
    if (
        not isinstance(raw_decision_id, str)
        or raw_decision_id != "madm-" + _canonical_sha256(payload)[:24]
    ):
        raise ModuleCompatibilitySnapshotError("admission_decision_rejected")


def bind_module_admission_decisions_to_snapshot(
    snapshot: ModuleCompatibilitySnapshot,
    decisions: Sequence[ModuleAdmissionDecision],
) -> ModuleAdmissionSnapshotBinding:
    """Bind one or more exact admission decisions to one canonical runtime state."""

    trusted_snapshot = _reconstruct_snapshot(snapshot)
    if isinstance(decisions, (str, bytes)) or not isinstance(decisions, Sequence):
        raise ModuleCompatibilitySnapshotError("admission_decisions_rejected")
    if not 1 <= len(decisions) <= MAX_ADMISSION_DECISIONS:
        raise ModuleCompatibilitySnapshotError("admission_decisions_rejected")

    refs: list[tuple[str, str, str, str, str, str]] = []
    module_ids: set[str] = set()
    decision_ids: set[str] = set()
    for decision in decisions:
        _validate_decision_identity(decision)
        if (
            decision.home_center_version != trusted_snapshot.home_center_version
            or decision.architecture != trusted_snapshot.architecture
            or decision.operating_system != trusted_snapshot.operating_system
            or decision.available_capabilities
            != trusted_snapshot.available_capabilities
            or decision.installed_modules != trusted_snapshot.installed_modules
        ):
            raise ModuleCompatibilitySnapshotError(
                "admission_decision_snapshot_mismatch"
            )
        if decision.module_id in module_ids:
            raise ModuleCompatibilitySnapshotError(
                "admission_module_duplicate"
            )
        if decision.decision_id in decision_ids:
            raise ModuleCompatibilitySnapshotError(
                "admission_decision_duplicate"
            )
        module_ids.add(decision.module_id)
        decision_ids.add(decision.decision_id)
        refs.append(
            (
                decision.module_id,
                decision.module_version,
                decision.decision_id,
                decision.status,
                decision.manifest_binding_sha256,
                decision.artifact_sha256,
            )
        )

    normalized_refs = tuple(sorted(refs))
    evidence = {
        "schema": "home-center.module-admission-snapshot-binding.v1",
        "snapshot_id": trusted_snapshot.snapshot_id,
        "home_center_version": trusted_snapshot.home_center_version,
        "architecture": trusted_snapshot.architecture,
        "operating_system": trusted_snapshot.operating_system,
        "available_capabilities": trusted_snapshot.available_capabilities,
        "installed_modules": [
            {"id": module_id, "version": version}
            for module_id, version in trusted_snapshot.installed_modules
        ],
        "decisions": [
            {
                "module_id": module_id,
                "module_version": module_version,
                "decision_id": decision_id,
                "status": status,
                "manifest_binding_sha256": manifest_binding_sha256,
                "artifact_sha256": artifact_sha256,
            }
            for (
                module_id,
                module_version,
                decision_id,
                status,
                manifest_binding_sha256,
                artifact_sha256,
            ) in normalized_refs
        ],
        "installation_authorized": False,
        "execution_authorized": False,
        "production_mutation_enabled": False,
        "external_publication_authorized": False,
    }
    binding_id = "masb-" + _canonical_sha256(evidence)[:24]
    return ModuleAdmissionSnapshotBinding(
        binding_id=binding_id,
        snapshot_id=trusted_snapshot.snapshot_id,
        home_center_version=trusted_snapshot.home_center_version,
        architecture=trusted_snapshot.architecture,
        operating_system=trusted_snapshot.operating_system,
        available_capabilities=trusted_snapshot.available_capabilities,
        installed_modules=trusted_snapshot.installed_modules,
        decisions=normalized_refs,
    )
