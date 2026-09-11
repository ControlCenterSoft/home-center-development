from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_V2 = ROOT / "product" / "control-plane" / "src" / "home_center" / "api_v2.py"
RUNTIME = ROOT / "product" / "control-plane" / "src" / "home_center" / "runtime.py"


def test_household_routes_are_on_authenticated_v2_handler() -> None:
    source = API_V2.read_text(encoding="utf-8")
    assert 'path == "/api/v1/household"' in source
    assert '"/api/v1/household/bootstrap"' in source
    assert '"/api/v1/household/intents/plan"' in source
    assert "self._require_actor(correlation_id)" in source
    assert "self._same_origin_post_allowed(context)" in source
    assert "self.runtime.household.bootstrap" in source
    assert "self.runtime.household.plan_intent" in source


def test_household_persisted_state_integrity_errors_are_service_unavailable() -> None:
    source = API_V2.read_text(encoding="utf-8")
    assert 'unavailable_codes = {"household_state_invalid", "household_state_evidence_mismatch"}' in source
    assert "elif exc.code in unavailable_codes:" in source
    assert "status = HTTPStatus.SERVICE_UNAVAILABLE" in source


def test_runtime_composes_household_service() -> None:
    source = RUNTIME.read_text(encoding="utf-8")
    assert "from .household_runtime import HouseholdRuntimeService" in source
    assert "self.household = HouseholdRuntimeService(self.store)" in source
