#!/usr/bin/env python3
"""Fail-closed, deterministic qualification for a Home Center wheel."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import tomllib
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any


REQUIRED_MEMBERS = frozenset(
    {
        "home_center/__init__.py",
        "home_center/__main__.py",
        "home_center/action_registry.v1.json",
        "home_center/authorization_0180.py",
        "home_center/certificate_inventory_0180.py",
        "home_center/deployment_profiles.py",
        "home_center/infrastructure_inventory.py",
        "home_center/home_services.py",
        "home_center/home_service_operations.py",
        "home_center/home_service_admission.py",
        "home_center/home_service_state.py",
        "home_center/home_service_worker_claim.py",
        "home_center/home_service_execution_revalidation.py",
        "home_center/home_service_execution_result.py",
        "home_center/home_service_state_transition.py",
        "home_center/home_service_transition_apply.py",
        "home_center/home_service_transition_audit.py",
        "home_center/home_service_transition_completion.py",
        "home_center/home_service_transition_verify.py",
        "home_center/node_discovery.py",
        "home_center/node_drain_preflight.py",
        "home_center/node_health.py",
        "home_center/node_inventory_api.py",
        "home_center/node_maintenance.py",
        "home_center/automation_engine.py",
        "home_center/automation_execution.py",
        "home_center/automation_retry.py",
        "home_center/automation_runbook.py",
        "home_center/device_registry.py",
        "home_center/runbook_state.py",
        "home_center/remote_access_0180.py",
        "home_center/zigbee.py",
        "home_center/core/__init__.py",
        "home_center/core/compute_framework.py",
        "home_center/core/lxc_lifecycle.py",
        "home_center/core/proxmox_provider.py",
        "home_center/core/resource_scheduler.py",
        "home_center/core/vm_lifecycle.py",
    }
)


class QualificationError(ValueError):
    """Stable release-artifact rejection."""


def _runtime_version(package_init: Path) -> str:
    tree = ast.parse(package_init.read_text(encoding="utf-8"), filename=str(package_init))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets):
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    raise QualificationError("runtime_version_missing")


def _single_wheel(directory: Path) -> Path:
    wheels = sorted(directory.glob("*.whl"))
    if len(wheels) != 1 or not wheels[0].is_file():
        raise QualificationError("expected_exactly_one_wheel")
    return wheels[0]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def qualify(wheel: Path, *, repository_root: Path) -> dict[str, Any]:
    pyproject = tomllib.loads((repository_root / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject.get("project")
    if not isinstance(project, dict):
        raise QualificationError("project_metadata_missing")
    expected_version = project.get("version")
    if not isinstance(expected_version, str):
        raise QualificationError("project_version_missing")
    try:
        release_version = (repository_root / "VERSION").read_text(encoding="ascii").strip()
    except UnicodeDecodeError as exc:
        raise QualificationError("release_version_invalid") from exc
    if release_version != expected_version:
        raise QualificationError("project_release_version_mismatch")
    runtime_version = _runtime_version(
        repository_root / "product/control-plane/src/home_center/__init__.py"
    )
    if runtime_version != expected_version:
        raise QualificationError("project_runtime_version_mismatch")

    release_notes = repository_root / f"docs/releases/{expected_version}.md"
    if not release_notes.is_file() or f"# Home Center {expected_version}" not in release_notes.read_text(
        encoding="utf-8"
    ):
        raise QualificationError("release_notes_identity_mismatch")

    try:
        with zipfile.ZipFile(wheel) as archive:
            members = archive.namelist()
            if len(members) != len(set(members)):
                raise QualificationError("duplicate_archive_member")
            if any(
                name.startswith("/") or ".." in PurePosixPath(name).parts
                for name in members
            ):
                raise QualificationError("unsafe_archive_member")
            if REQUIRED_MEMBERS.difference(members):
                raise QualificationError("required_runtime_member_missing")
            if any(name.endswith(".pyc") or "__pycache__" in PurePosixPath(name).parts for name in members):
                raise QualificationError("generated_bytecode_in_artifact")
            try:
                action_registry = json.loads(archive.read("home_center/action_registry.v1.json"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise QualificationError("runtime_data_invalid") from exc
            if (
                not isinstance(action_registry, dict)
                or action_registry.get("schema") != "home-center.action-registry.v1"
                or not isinstance(action_registry.get("actions"), list)
                or not action_registry["actions"]
            ):
                raise QualificationError("runtime_data_invalid")
            metadata_members = [name for name in members if name.endswith(".dist-info/METADATA")]
            if len(metadata_members) != 1:
                raise QualificationError("wheel_metadata_missing")
            metadata = BytesParser().parsebytes(archive.read(metadata_members[0]))
    except zipfile.BadZipFile as exc:
        raise QualificationError("invalid_wheel_archive") from exc

    if metadata.get("Name") != "home-center":
        raise QualificationError("distribution_identity_mismatch")
    if metadata.get("Version") != expected_version:
        raise QualificationError("artifact_version_mismatch")

    return {
        "schema": "home-center.release-artifact-qualification.v1",
        "release": expected_version,
        "artifact": wheel.name,
        "artifact_sha256": _sha256(wheel),
        "state": "qualified",
        "checks": {
            "identity_consistent": True,
            "runtime_data_present": True,
            "archive_members_safe": True,
            "generated_bytecode_absent": True,
        },
        "production_mutation_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--compare-wheel-dir", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    args = parser.parse_args()

    try:
        wheel = _single_wheel(args.wheel_dir)
        report = qualify(wheel, repository_root=args.repository_root.resolve())
        comparison = _single_wheel(args.compare_wheel_dir)
        if wheel.name != comparison.name or _sha256(wheel) != _sha256(comparison):
            raise QualificationError("artifact_reproducibility_mismatch")
        report["checks"]["reproducible_build"] = True
    except (OSError, KeyError, tomllib.TOMLDecodeError, QualificationError) as exc:
        code = str(exc) if isinstance(exc, QualificationError) else "qualification_io_rejected"
        print(f"RELEASE_ARTIFACT_QUALIFICATION=FAIL code={code}")
        return 1

    print("RELEASE_ARTIFACT_QUALIFICATION=PASS")
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
