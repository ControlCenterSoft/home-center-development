from __future__ import annotations

import json
from pathlib import Path

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


ROOT = Path(__file__).resolve().parents[1]


def test_release_058_release_notes_remain_historical_and_documented() -> None:
    notes = (ROOT / "docs/releases/0.58.0.md").read_text(encoding="utf-8")
    assert notes.startswith("# Home Center 0.58.0\n\nStatus: official release.")
    assert "`single-node-core`" in notes
    assert "multi-node HA / automatic failover" in notes
    assert "не заявлены" in notes
    assert "concrete provider execution" in notes
    assert "commercial launch clearance" in notes
    assert "Unknown, ambiguous, stale" in notes
    assert "0.57.0 → 0.58.0" in notes


def test_release_058_runtime_contracts_remain_packaged() -> None:
    assert {
        "home_center/api_v4.py",
        "home_center/api_v5.py",
        "home_center/device_management_enrollment_verification.py",
        "home_center/device_management_enrollment_post_condition_runtime.py",
        "home_center/device_management_deenrollment.py",
        "home_center/device_management_deenrollment_runtime.py",
        "home_center/device_management_deenrollment_execution_runtime.py",
        "home_center/device_management_failed_enrollment_cleanup_runtime.py",
        "home_center/device_management_failed_enrollment_cleanup_execution_runtime.py",
    } <= REQUIRED_MEMBERS


def test_release_058_openapi_preserves_fail_closed_authority_boundaries() -> None:
    document = json.loads(
        (ROOT / "contracts/openapi/home-center-device-management.v1.openapi.json").read_text(encoding="utf-8")
    )
    assert document["openapi"] == "3.1.0"
    paths = document["paths"]
    required = {
        "/api/v1/household/devices/enrollment/verification/plan",
        "/api/v1/household/devices/enrollment/verification/confirm",
        "/api/v1/household/devices/deenrollment/plan",
        "/api/v1/household/devices/deenrollment/confirm",
    }
    assert required <= set(paths)
    for path_item in paths.values():
        operation = path_item.get("post")
        if operation is None:
            continue
        boundary = operation.get("x-home-center-boundary", {})
        assert boundary.get("authenticated_session_required") is True
        assert boundary.get("same_origin_required") is True
        assert boundary.get("external_access_blocked") is True
        assert boundary.get("external_publication_authorized") is False


def test_release_ci_derives_candidate_artifact_name_from_version() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert 'version="$(tr -d \'[:space:]\' < VERSION)"' in workflow
    assert "HC_VERSION=$version" in workflow
    assert 'artifact="home-center-${HC_VERSION}-linux-amd64.tar.gz"' in workflow
    assert "home-center-0.57.0-deployment-candidate" not in workflow
