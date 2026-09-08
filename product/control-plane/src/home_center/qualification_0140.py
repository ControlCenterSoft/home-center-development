"""Закрытая детерминированная квалификация релиза Home Center 0.14.0.

Квалификатор принимает ограниченные наблюдения без секретов и возвращает неизменяемый
отчёт plan-only. Он не предоставляет полномочий на deployment, выполнение или изменения production.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from .util import canonical_json


EVIDENCE_SCHEMA = "home-center.release-qualification-evidence.0140.v1"
REPORT_SCHEMA = "home-center.release-qualification.0140.v1"
RELEASE = "0.14.0"
PROFILE = "deterministic-ci"
SCENARIO_ID = "hc-0.14.0-closed-qualification"
MAX_EVIDENCE_BYTES = 32 * 1024
REQUIRED_CAPABILITIES = (
    "product_boundary_cleanup",
    "core_lifecycle_v2",
    "compute_framework",
    "home_lab_manager",
    "certificate_lifecycle",
    "read_only_planning_ui",
)
REQUIRED_RUNTIMES = ("python_3_12", "python_3_14")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Qualification0140Error(ValueError):
    """Стабильный fail-closed код для отклонённого свидетельства квалификации."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _reject(code: str) -> None:
    raise Qualification0140Error(code)


def _object(value: Any, keys: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys or not all(isinstance(key, str) for key in value):
        _reject(code)
    return value


def _exact_statuses(value: Any, names: tuple[str, ...], code: str) -> tuple[str, ...]:
    item = _object(value, set(names), code)
    if any(item[name] != "passed" for name in names):
        _reject(code)
    return names


def _false(value: Any, code: str) -> None:
    if value is not False:
        _reject(code)


def _true(value: Any, code: str) -> None:
    if value is not True:
        _reject(code)


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _reject("qualification_json_duplicate_key")
        value[key] = item
    return value


def load_qualification_evidence(raw: bytes) -> Mapping[str, Any]:
    """Загружает ограниченный документ свидетельств strict-JSON без принятия повторяющихся ключей."""

    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_EVIDENCE_BYTES:
        _reject("qualification_document_size_rejected")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_reject)
    except Qualification0140Error:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Qualification0140Error("qualification_json_rejected") from exc
    if not isinstance(value, Mapping):
        _reject("qualification_document_shape_rejected")
    return value


@dataclass(frozen=True, slots=True)
class Qualification0140Report:
    revision: str
    artifact_sha256: str
    qualification_id: str
    capabilities: tuple[str, ...] = REQUIRED_CAPABILITIES
    runtimes: tuple[str, ...] = REQUIRED_RUNTIMES
    schema: str = field(default=REPORT_SCHEMA, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "release": RELEASE,
            "revision": self.revision,
            "artifact_sha256": self.artifact_sha256,
            "profile": PROFILE,
            "scenario_id": SCENARIO_ID,
            "qualification_id": self.qualification_id,
            "capabilities": list(self.capabilities),
            "runtimes": list(self.runtimes),
            "state": "qualified",
            "plan_only": True,
            "production_mutation_enabled": False,
            "production_activation_authorized": False,
        }


def qualify_release_0140(evidence: Mapping[str, Any]) -> Qualification0140Report:
    """Квалифицирует точные наблюдения 0.14.0 или отклоняет их без побочных эффектов."""

    root = _object(
        evidence,
        {"schema", "release", "revision", "profile", "scenario_id", "artifacts", "capabilities", "runtimes", "postconditions"},
        "qualification_document_shape_rejected",
    )
    if root["schema"] != EVIDENCE_SCHEMA or root["release"] != RELEASE:
        _reject("qualification_release_identity_rejected")
    if root["profile"] != PROFILE or root["scenario_id"] != SCENARIO_ID:
        _reject("qualification_environment_rejected")
    revision = root["revision"]
    if not isinstance(revision, str) or _HEX40.fullmatch(revision) is None:
        _reject("qualification_revision_rejected")

    artifacts = _object(
        root["artifacts"],
        {"first_build_sha256", "second_build_sha256"},
        "qualification_artifact_shape_rejected",
    )
    first_digest = artifacts["first_build_sha256"]
    second_digest = artifacts["second_build_sha256"]
    if (
        not isinstance(first_digest, str)
        or _HEX64.fullmatch(first_digest) is None
        or not isinstance(second_digest, str)
        or _HEX64.fullmatch(second_digest) is None
        or first_digest != second_digest
    ):
        _reject("qualification_artifact_reproducibility_rejected")

    capabilities = _exact_statuses(
        root["capabilities"], REQUIRED_CAPABILITIES, "qualification_capabilities_rejected"
    )
    runtimes = _exact_statuses(root["runtimes"], REQUIRED_RUNTIMES, "qualification_runtimes_rejected")
    postconditions = _object(
        root["postconditions"],
        {
            "plan_only",
            "production_mutation_enabled",
            "visible_version",
            "mobile_nodes_one_per_row",
            "mobile_planning_one_per_row",
            "browser_network_surface",
            "browser_mutation_surface",
        },
        "qualification_postconditions_rejected",
    )
    _true(postconditions["plan_only"], "qualification_plan_only_rejected")
    _false(postconditions["production_mutation_enabled"], "qualification_mutation_boundary_rejected")
    if postconditions["visible_version"] != RELEASE:
        _reject("qualification_visible_version_rejected")
    _true(postconditions["mobile_nodes_one_per_row"], "qualification_mobile_nodes_rejected")
    _true(postconditions["mobile_planning_one_per_row"], "qualification_mobile_planning_rejected")
    _false(postconditions["browser_network_surface"], "qualification_browser_network_rejected")
    _false(postconditions["browser_mutation_surface"], "qualification_browser_mutation_rejected")

    normalized = {
        "schema": EVIDENCE_SCHEMA,
        "release": RELEASE,
        "revision": revision,
        "profile": PROFILE,
        "scenario_id": SCENARIO_ID,
        "artifact_sha256": first_digest,
        "capabilities": list(capabilities),
        "runtimes": list(runtimes),
        "postconditions": dict(postconditions),
    }
    qualification_id = "sha256:" + hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    return Qualification0140Report(
        revision=revision,
        artifact_sha256=first_digest,
        qualification_id=qualification_id,
        capabilities=capabilities,
        runtimes=runtimes,
    )
