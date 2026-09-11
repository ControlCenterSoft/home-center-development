from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "product" / "web" / "static" / "app.js"


def test_cozy_family_renderer_consumes_canonical_household_shape() -> None:
    javascript = APP.read_text(encoding="utf-8")

    # FamilyMember.to_dict() exposes display_name/member_id and Household.to_dict()
    # exposes devices at the household level. Keep the Cozy read-only UI aligned
    # with that canonical domain shape while retaining compatibility fallbacks.
    assert "member.display_name || member.name" in javascript
    assert "household?.devices" in javascript
    assert "device.member_id" in javascript
    assert "deviceCounts.get(member.member_id)" in javascript


def test_cozy_family_mapping_remains_read_only() -> None:
    javascript = APP.read_text(encoding="utf-8")

    assert "fetch('/api/v1/infrastructure'" in javascript
    assert "method: 'POST'" not in javascript
    assert 'method: "POST"' not in javascript
