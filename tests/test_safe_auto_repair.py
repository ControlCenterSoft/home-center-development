from home_center import safe_auto_repair


def test_safe_auto_repair_schema_identity() -> None:
    assert safe_auto_repair.SAFE_REPAIR_RECOMMENDATION_SCHEMA == "home-center.safe-auto-repair-recommendation.v1"
