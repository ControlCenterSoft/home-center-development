from scripts.qualify_release_artifact import REQUIRED_MEMBERS


def test_release_064_requires_server_candidate_source_in_wheel() -> None:
    assert "home_center/safe_auto_repair_candidate_source.py" in REQUIRED_MEMBERS
