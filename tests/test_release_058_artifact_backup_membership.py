from __future__ import annotations

import hashlib
import os
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from home_center.store import StateStore


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MEMBERS = {
    "home_center/device_management_enrollment_verification.py",
    "home_center/device_management_deenrollment.py",
}
CONTRACT_MEMBERS = {
    "contracts/devices/device-management-enrollment-post-condition-request.v1.schema.json",
    "contracts/devices/device-management-enrollment-post-condition-result.v1.schema.json",
    "contracts/devices/device-management-enrollment-post-condition-evidence.v1.schema.json",
    "contracts/devices/device-management-enrollment-post-condition-verification-receipt.v1.schema.json",
    "contracts/devices/device-management-deenrollment-confirmation.v1.schema.json",
    "contracts/devices/device-management-deenrollment-plan.v1.schema.json",
    "contracts/devices/device-management-deenrollment-readback-result.v1.schema.json",
    "contracts/devices/device-management-deenrollment-verification-receipt.v1.schema.json",
    "contracts/devices/device-management-failed-enrollment-cleanup-plan.v1.schema.json",
    "contracts/devices/device-management-failed-enrollment-cleanup-readback-result.v1.schema.json",
    "contracts/devices/device-management-failed-enrollment-cleanup-receipt.v1.schema.json",
}
RELEASE_059_RUNTIME_MEMBERS = {
    "home_center/api_v6.py",
    "home_center/api_v7.py",
    "home_center/api_v8.py",
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
}
RELEASE_059_CONTRACT_MEMBERS = {
    "contracts/household/household-policy-change-confirm-request.v1.schema.json",
    "contracts/household/household-policy-change-plan-request.v1.schema.json",
    "contracts/household/household-policy-change-plan.v1.schema.json",
    "contracts/household/household-policy-desired-state.v1.schema.json",
    "contracts/household/household-policy-actual-state-observation.v1.schema.json",
    "contracts/household/household-policy-backend-apply-request.v1.schema.json",
    "contracts/household/household-policy-effective-state.v1.schema.json",
    "contracts/household/household-policy-enforcement-admission.v1.schema.json",
    "contracts/household/household-policy-enforcement-confirm-request.v1.schema.json",
    "contracts/household/household-policy-enforcement-confirmation.v1.schema.json",
    "contracts/household/household-policy-enforcement-execute-request.v1.schema.json",
    "contracts/household/household-policy-enforcement-plan-request.v1.schema.json",
    "contracts/household/household-policy-enforcement-plan.v1.schema.json",
    "contracts/household/household-policy-enforcement-qualification-binding.v1.schema.json",
    "contracts/household/household-policy-enforcement-receipt.v1.schema.json",
    "contracts/household/household-policy-enforcement-reconciliation-snapshot.v1.schema.json",
    "contracts/household/household-policy-reconciliation-evidence.v1.schema.json",
    "contracts/household/household-policy-reconciliation-request.v1.schema.json",
    "contracts/household/household-policy-verification-transition-receipt.v1.schema.json",
    "contracts/household/household-policy-verification-transition-request.v1.schema.json",
    "contracts/household/household-policy-verified-desired-state.v1.schema.json",
    "contracts/openapi/home-center-household-policy-enforcement.v1.openapi.json",
    "contracts/releases/policy-backend-qualification.v1.schema.json",
    "contracts/releases/target-node-qualification.v1.schema.json",
    "contracts/releases/technical-stable-profile-decision.v1.schema.json",
}
RELEASE_059_WEB_MEMBERS = {
    "web/index.html",
    "web/policy-effective-state.js",
}


def _single(path: Path, pattern: str) -> Path:
    matches = sorted(path.glob(pattern))
    assert len(matches) == 1, matches
    return matches[0]


def _normalized(name: str) -> str:
    return name.removeprefix("./")


@pytest.mark.skipif(
    os.environ.get("GITHUB_ACTIONS") != "true" or sys.version_info[:2] != (3, 12),
    reason="deployment-artifact membership is qualified once on the hosted Python 3.12 leg",
)
def test_release_058_and_059_runtime_contracts_and_ui_are_in_qualified_artifacts(tmp_path: Path) -> None:
    """Prove inherited 0.58 and current 0.59 boundaries are carried by release artifacts.

    The normal CI build has already produced the wheel in dist/first. This test
    additionally builds the node deployment archive from the exact checked-out
    head and validates its sidecar plus per-member MANIFEST hashes. It does not
    publish an artifact or grant provider/production authority.
    """

    required_runtime = RUNTIME_MEMBERS | RELEASE_059_RUNTIME_MEMBERS
    required_contracts = CONTRACT_MEMBERS | RELEASE_059_CONTRACT_MEMBERS

    wheel = _single(ROOT / "dist" / "first", "*.whl")
    with zipfile.ZipFile(wheel) as bundle:
        wheel_members = set(bundle.namelist())
    assert required_runtime <= wheel_members

    output = tmp_path / "deployment-dist"
    subprocess_result = __import__("subprocess").run(
        ["bash", str(ROOT / "deploy/scripts/build-deployment-artifact.sh"), str(output)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    assert "DEPLOYMENT_ARTIFACT=" in subprocess_result.stdout

    artifact = _single(output, "home-center-*-linux-amd64.tar.gz")
    sidecar = Path(f"{artifact}.sha256")
    assert sidecar.is_file()
    expected_archive_sha = sidecar.read_text(encoding="ascii").split()[0]
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() == expected_archive_sha

    with tarfile.open(artifact, "r:gz") as bundle:
        files = {_normalized(member.name): member for member in bundle.getmembers() if member.isfile()}
        assert required_runtime <= set(files)
        assert required_contracts <= set(files)
        assert RELEASE_059_WEB_MEMBERS <= set(files)

        index_stream = bundle.extractfile(files["web/index.html"])
        assert index_stream is not None
        assert b'/static/policy-effective-state.js' in index_stream.read()

        manifest_member = files["MANIFEST.sha256"]
        manifest_stream = bundle.extractfile(manifest_member)
        assert manifest_stream is not None
        manifest: dict[str, str] = {}
        for line in manifest_stream.read().decode("ascii").splitlines():
            digest, raw_name = line.split(None, 1)
            name = _normalized(raw_name.strip().lstrip("*"))
            manifest[name] = digest

        required = required_runtime | required_contracts | RELEASE_059_WEB_MEMBERS
        assert required <= set(manifest)
        for name in sorted(required):
            stream = bundle.extractfile(files[name])
            assert stream is not None
            assert hashlib.sha256(stream.read()).hexdigest() == manifest[name]


def test_release_058_durable_evidence_survives_state_store_backup(tmp_path: Path) -> None:
    """The existing SQLite backup path must retain 0.58 durable evidence."""

    source_path = tmp_path / "source" / "state.sqlite3"
    snapshot_path = tmp_path / "snapshot" / "state.sqlite3"
    audit_key = b"release-058-backup-qualification-key"
    cluster_id = "qualification-058"
    durable_values = {
        "qualification:058:post-condition": {
            "schema": "home-center.device-management-enrollment-post-condition-verification-receipt.v1",
            "state": "verified",
            "evidence_sha256": "1" * 64,
            "managed_state_change_authorized": True,
        },
        "qualification:058:deenrollment": {
            "schema": "home-center.device-management-deenrollment-verification-receipt.v1",
            "state": "verified",
            "readback_sha256": "2" * 64,
            "managed_state_change_authorized": True,
        },
        "qualification:058:failed-cleanup": {
            "schema": "home-center.device-management-failed-enrollment-cleanup-receipt.v1",
            "state": "verified",
            "readback_sha256": "3" * 64,
            "transient_cleanup_authorized": True,
        },
    }

    source = StateStore(source_path, audit_key, cluster_id)
    try:
        for key, value in durable_values.items():
            source.set_meta(key, value)
        source.backup_to(snapshot_path)
    finally:
        source.close()

    restored = StateStore(snapshot_path, audit_key, cluster_id)
    try:
        for key, expected in durable_values.items():
            assert restored.get_meta(key) == expected
    finally:
        restored.close()
