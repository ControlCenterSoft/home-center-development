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
        "home_center/household.py",
        "home_center/household_intent.py",
        "home_center/household_intent_proposal.py",
        "home_center/household_store.py",
        "home_center/household_runtime.py",
        "home_center/household_member_change.py",
        "home_center/household_device_change.py",
        "home_center/household_device_runtime.py",
        "home_center/household_device_management.py",
        "home_center/household_device_management_runtime.py",
        "home_center/household_device_enrollment.py",
        "home_center/household_device_enrollment_runtime.py",
        "home_center/device_management_provider.py",
        "home_center/device_management_provider_runtime.py",
        "home_center/device_management_provider_selection.py",
        "home_center/device_management_provider_selection_runtime.py",
        "home_center/device_management_enrollment_execution.py",
        "home_center/device_management_enrollment_execution_runtime.py",
        "home_center/device_management_enrollment_execution_runtime_safe.py",
        "home_center/device_management_enrollment_execution_recovery.py",
        "home_center/device_management_enrollment_verification.py",
        "home_center/device_management_enrollment_post_condition_runtime.py",
        "home_center/device_management_deenrollment.py",
        "home_center/device_management_deenrollment_runtime.py",
        "home_center/device_management_deenrollment_execution_runtime.py",
        "home_center/device_management_failed_enrollment_cleanup_runtime.py",
        "home_center/device_management_failed_enrollment_cleanup_execution_runtime.py",
        "home_center/qr_onboarding.py",
        "home_center/qr_onboarding_validation.py",
        "home_center/qr_onboarding_runtime.py",
        "home_center/qr_onboarding_api.py",
        "home_center/qr_onboarding_audit.py",
        "home_center/qr_onboarding_effect_handoff.py",
        "home_center/qr_onboarding_effect_verification.py",
        "home_center/qr_onboarding_effect_admission.py",
        "home_center/qr_onboarding_effect_execution.py",
        "home_center/qr_onboarding_effect_source.py",
        "home_center/qr_onboarding_product_state.py",
        "home_center/qr_onboarding_effect_worker.py",
        "home_center/qr_onboarding_effect_api.py",
        "home_center/api_v3.py",
        "home_center/api_v4.py",
        "home_center/api_v5.py",
        "home_center/api_v6.py",
        "home_center/api_v7.py",
        "home_center/api_v8.py",
        "home_center/api_v10.py",
        "home_center/api_v11.py",
        "home_center/api_v12.py",
        "home_center/household_policy_api.py",
        "home_center/household_policy_composer.py",
        "home_center/household_policy_effective_state.py",
        "home_center/household_policy_enforcement_admission.py",
        "home_center/household_policy_enforcement_qualification_binding.py",
        "home_center/household_policy_enforcement_reconciliation_snapshot.py",
        "home_center/household_policy_enforcement_runtime.py",
        "home_center/household_policy_reconciliation.py",
        "home_center/household_policy_reconciliation_api_runtime.py",
        "home_center/household_policy_reconciliation_recovery.py",
        "home_center/household_policy_reconciliation_runtime.py",
        "home_center/household_policy_runtime.py",
        "home_center/household_policy_verification_state.py",
        "home_center/household_policy_verification_transition.py",
        "home_center/policy_backend_qualification.py",
        "home_center/release_promotion_gate.py",
        "home_center/target_node_qualification.py",
        "home_center/technical_stable_profile.py",
        "home_center/parental_internet_policy.py",
        "home_center/parental_internet_policy_validation.py",
        "home_center/parental_internet_verified_base.py",
        "home_center/parental_internet_policy_runtime.py",
        "home_center/parental_internet_policy_change_api.py",
        "home_center/parental_internet_policy_api.py",
        "home_center/parental_internet_policy_adapter.py",
        "home_center/parental_internet_policy_reconciliation.py",
        "home_center/module_home_service_multi_compatibility.py",
        "home_center/module_home_service_multi_compatibility_revalidation.py",
        "home_center/module_home_service_compatibility_state.py",
        "home_center/module_home_service_compatibility_state_index.py",
        "home_center/node_discovery.py",
        "home_center/node_drain_preflight.py",
        "home_center/node_health.py",
        "home_center/node_inventory_api.py",
        "home_center/node_maintenance.py",
        "home_center/automation_engine.py",
        "home_center/automation_execution.py",
        "home_center/automation_retry.py",
        "home_center/automation_runbook.py",
        "home_center/safe_auto_repair.py",
        "home_center/safe_auto_repair_history.py",
        "home_center/safe_auto_repair_admission.py",
        "home_center/safe_auto_repair_job.py",
        "home_center/safe_auto_repair_adapter.py",
        "home_center/safe_auto_repair_verification.py",
        "home_center/safe_auto_repair_worker.py",
        "home_center/safe_auto_repair_job_store.py",
        "home_center/safe_auto_repair_job_migration.py",
        "home_center/safe_auto_repair_projection.py",
        "home_center/safe_auto_repair_read_api.py",
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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _member_is_safe(member: str) -> bool:
    path = PurePosixPath(member)
    return bool(member) and not path.is_absolute() and ".." not in path.parts and "\\" not in member


def _load_pyproject_version(root: Path) -> str:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(project["version"])


def _load_init_version(root: Path) -> str:
    tree = ast.parse((root / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__version__":
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        return node.value.value
    raise SystemExit("release artifact qualification blocked: __version__ is missing")


def _wheel_record(archive: zipfile.ZipFile) -> dict[str, bytes]:
    return {name: archive.read(name) for name in archive.namelist()}


def _metadata_version(record: dict[str, bytes]) -> str:
    candidates = [name for name in record if name.endswith(".dist-info/METADATA")]
    if len(candidates) != 1:
        raise SystemExit("release artifact qualification blocked: expected one METADATA file")
    message = BytesParser().parsebytes(record[candidates[0]])
    value = message.get("Version")
    if not value:
        raise SystemExit("release artifact qualification blocked: wheel metadata Version is missing")
    return value.strip()


def _normalized_payload_digest(record: dict[str, bytes]) -> str:
    digest = hashlib.sha256()
    for name in sorted(record):
        if name.endswith(".dist-info/RECORD"):
            continue
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(record[name])
        digest.update(b"\0")
    return digest.hexdigest()


def _qualify_wheel(path: Path, expected_version: str) -> dict[str, Any]:
    raw = path.read_bytes()
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        unsafe = sorted(name for name in names if not _member_is_safe(name))
        if unsafe:
            raise SystemExit(f"release artifact qualification blocked: unsafe archive members: {unsafe}")
        record = _wheel_record(archive)

    missing = sorted(REQUIRED_MEMBERS - record.keys())
    if missing:
        raise SystemExit(f"release artifact qualification blocked: missing required runtime members: {missing}")
    pycache = sorted(name for name in record if "__pycache__" in PurePosixPath(name).parts or name.endswith(".pyc"))
    if pycache:
        raise SystemExit(f"release artifact qualification blocked: generated bytecode present: {pycache}")

    metadata_version = _metadata_version(record)
    if metadata_version != expected_version:
        raise SystemExit(
            "release artifact qualification blocked: wheel metadata version mismatch "
            f"({metadata_version} != {expected_version})"
        )

    return {
        "name": path.name,
        "sha256": _sha256(raw),
        "payload_sha256": _normalized_payload_digest(record),
    }


def qualify(wheel_dir: Path, compare_wheel_dir: Path, root: Path) -> dict[str, Any]:
    version_file = (root / "VERSION").read_text(encoding="ascii").strip()
    pyproject_version = _load_pyproject_version(root)
    init_version = _load_init_version(root)
    versions = {version_file, pyproject_version, init_version}
    if len(versions) != 1:
        raise SystemExit(f"release artifact qualification blocked: source identity mismatch: {sorted(versions)}")

    wheels = sorted(wheel_dir.glob("*.whl"))
    compare_wheels = sorted(compare_wheel_dir.glob("*.whl"))
    if len(wheels) != 1 or len(compare_wheels) != 1:
        raise SystemExit("release artifact qualification blocked: expected exactly one wheel in each build directory")

    first = _qualify_wheel(wheels[0], version_file)
    second = _qualify_wheel(compare_wheels[0], version_file)
    if first["name"] != second["name"]:
        raise SystemExit("release artifact qualification blocked: wheel names differ between builds")
    if first["sha256"] != second["sha256"] or first["payload_sha256"] != second["payload_sha256"]:
        raise SystemExit("release artifact qualification blocked: wheel build is not reproducible")

    return {
        "schema": "home-center.release-artifact-qualification.v1",
        "release": version_file,
        "artifact": first["name"],
        "artifact_sha256": first["sha256"],
        "state": "qualified",
        "checks": {
            "archive_members_safe": True,
            "runtime_data_present": True,
            "identity_consistent": True,
            "reproducible_build": True,
            "generated_bytecode_absent": True,
        },
        "production_mutation_enabled": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", required=True, type=Path)
    parser.add_argument("--compare-wheel-dir", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = qualify(args.wheel_dir, args.compare_wheel_dir, args.root)
    print("RELEASE_ARTIFACT_QUALIFICATION=PASS")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
