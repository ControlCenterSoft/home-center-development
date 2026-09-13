from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
VPN_RUNTIME_MEMBERS = {
    "home_center/vpn_egress_policy.py",
    "home_center/vpn_egress_policy_api.py",
    "home_center/vpn_egress_policy_validation.py",
}
VPN_CONTRACT_MEMBERS = {
    "contracts/household/vpn-egress-observation.v1.schema.json",
    "contracts/household/vpn-egress-policy.v1.schema.json",
    "contracts/household/vpn-egress-provider-candidate.v1.schema.json",
    "contracts/household/vpn-egress-route-decision.v1.schema.json",
}


def _single_wheel() -> Path:
    wheels = sorted((ROOT / "dist/first").glob("*.whl"))
    assert len(wheels) == 1, f"expected one qualified wheel, found {wheels}"
    return wheels[0]


def test_061_vpn_runtime_is_present_in_actual_qualified_wheel() -> None:
    wheel = _single_wheel()
    with zipfile.ZipFile(wheel) as archive:
        members = set(archive.namelist())
    assert VPN_RUNTIME_MEMBERS <= members


def test_061_vpn_runtime_and_contracts_are_present_in_node_deployment_candidate() -> None:
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        pytest.skip("deployment candidate membership is runner-qualified on the Python 3.12 leg")

    version = (ROOT / "VERSION").read_text(encoding="ascii").strip()
    archive_path = Path(runner_temp) / "deployment-candidate" / f"home-center-{version}-linux-amd64.tar.gz"
    if not archive_path.is_file():
        pytest.skip("deployment candidate is built only on the Python 3.12 CI leg")

    with tarfile.open(archive_path, "r:gz") as archive:
        members = {
            name[2:] if name.startswith("./") else name
            for name in archive.getnames()
        }
    assert VPN_RUNTIME_MEMBERS <= members
    assert VPN_CONTRACT_MEMBERS <= members
