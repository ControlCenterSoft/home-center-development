from __future__ import annotations

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


def test_release_061_vpn_runtime_is_required_in_wheel() -> None:
    assert {
        "home_center/vpn_egress_policy.py",
        "home_center/vpn_egress_policy_api.py",
        "home_center/vpn_egress_policy_validation.py",
    } <= REQUIRED_MEMBERS
