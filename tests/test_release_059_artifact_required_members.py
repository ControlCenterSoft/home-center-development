from __future__ import annotations

from scripts.qualify_release_artifact import REQUIRED_MEMBERS


def test_release_059_complete_runtime_is_required_in_release_artifact() -> None:
    assert {
        # Inherited 0.58 device-management runtime must remain in every later wheel.
        "home_center/device_management_enrollment_verification.py",
        "home_center/device_management_enrollment_post_condition_runtime.py",
        "home_center/device_management_deenrollment.py",
        "home_center/device_management_deenrollment_runtime.py",
        "home_center/device_management_deenrollment_execution_runtime.py",
        "home_center/device_management_failed_enrollment_cleanup_runtime.py",
        "home_center/device_management_failed_enrollment_cleanup_execution_runtime.py",
        "home_center/api_v4.py",
        "home_center/api_v5.py",
        # 0.59 Policy Composer, enforcement, reconciliation and verification runtime.
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
        # Release-evidence runtime used by the bounded technical Stable path.
        "home_center/release_promotion_gate.py",
        "home_center/target_node_qualification.py",
        "home_center/technical_stable_profile.py",
    } <= REQUIRED_MEMBERS
