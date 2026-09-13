from scripts.qualify_release_artifact import REQUIRED_MEMBERS


QR_RUNTIME_MEMBERS = {
    "home_center/qr_onboarding.py",
    "home_center/qr_onboarding_validation.py",
    "home_center/qr_onboarding_runtime.py",
    "home_center/qr_onboarding_api.py",
    "home_center/qr_onboarding_audit.py",
}


def test_release_063_qr_runtime_is_required_in_reproducible_wheel() -> None:
    assert QR_RUNTIME_MEMBERS <= REQUIRED_MEMBERS
