from scripts.qualify_release_artifact import REQUIRED_MEMBERS


def test_release_064_safe_repair_runtime_is_required_in_artifact() -> None:
    assert {
        "home_center/api_v12.py",
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
    } <= REQUIRED_MEMBERS
