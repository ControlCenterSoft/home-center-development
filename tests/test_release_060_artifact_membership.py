from __future__ import annotations

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


PARENTAL_060_RUNTIME_MEMBERS = {
    "home_center/parental_internet_policy.py",
    "home_center/parental_internet_policy_validation.py",
    "home_center/parental_internet_verified_base.py",
    "home_center/parental_internet_policy_runtime.py",
    "home_center/parental_internet_policy_change_api.py",
    "home_center/parental_internet_policy_api.py",
    "home_center/parental_internet_policy_adapter.py",
    "home_center/parental_internet_policy_reconciliation.py",
}


def test_release_artifact_requires_parental_060_runtime_modules() -> None:
    assert PARENTAL_060_RUNTIME_MEMBERS <= REQUIRED_MEMBERS
