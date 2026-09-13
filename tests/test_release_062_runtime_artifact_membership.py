from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MEMBER = "home_center/role_identity_provisioning_runtime.py"
CONTRACT_MEMBER = "contracts/household/role-identity-provisioning-execution-receipt.v1.schema.json"


def test_062_identity_runtime_is_present_in_actual_qualified_wheel() -> None:
    wheels = sorted((ROOT / "dist/first").glob("*.whl"))
    assert len(wheels) == 1, f"expected one qualified wheel, found {wheels}"
    with zipfile.ZipFile(wheels[0]) as archive:
        assert RUNTIME_MEMBER in set(archive.namelist())


def test_062_identity_runtime_and_receipt_contract_are_present_in_node_candidate() -> None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        pytest.skip("deployment candidate membership is runner-qualified on the Python 3.12 leg")
    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    archive_path = Path(runner_temp) / "deployment-candidate" / f"home-center-{version}-linux-amd64.tar.gz"
    if not archive_path.is_file():
        pytest.skip("deployment candidate is built only on the Python 3.12 CI leg")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = {name[2:] if name.startswith("./") else name for name in archive.getnames()}
    assert RUNTIME_MEMBER in members
    assert CONTRACT_MEMBER in members
