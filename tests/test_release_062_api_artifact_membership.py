from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MEMBERS = {
    "home_center/api_v9.py",
    "home_center/api_v10.py",
    "home_center/role_identity_provisioning_api_runtime.py",
    "home_center/role_identity_binding_api_runtime.py",
    "home_center/role_identity_binding_api_composition.py",
}
CONTRACT_MEMBERS = {
    "contracts/household/role-identity-provisioning-api-plan-request.v1.schema.json",
    "contracts/household/role-identity-provisioning-api-preflight-request.v1.schema.json",
    "contracts/household/role-identity-provisioning-api-execute-request.v1.schema.json",
    "contracts/household/role-identity-provisioning-api-bind-request.v1.schema.json",
}


def _single_wheel() -> Path:
    wheels = sorted((ROOT / "dist/first").glob("*.whl"))
    assert len(wheels) == 1, f"expected one qualified wheel, found {wheels}"
    return wheels[0]


def test_062_identity_api_runtime_is_present_in_qualified_wheel() -> None:
    with zipfile.ZipFile(_single_wheel()) as archive:
        members = set(archive.namelist())
    assert RUNTIME_MEMBERS <= members


def test_062_identity_api_runtime_and_contracts_are_present_in_node_candidate() -> None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        pytest.skip("deployment candidate membership is runner-qualified on Python 3.12")
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    archive_path = Path(runner_temp) / "deployment-candidate" / f"home-center-{version}-linux-amd64.tar.gz"
    if not archive_path.is_file():
        pytest.skip("deployment candidate is built only on the Python 3.12 CI leg")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = {name[2:] if name.startswith("./") else name for name in archive.getnames()}
    assert RUNTIME_MEMBERS <= members
    assert CONTRACT_MEMBERS <= members
