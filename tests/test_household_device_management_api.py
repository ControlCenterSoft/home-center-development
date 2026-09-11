from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
API_V3 = ROOT / "product" / "control-plane" / "src" / "home_center" / "api_v3.py"
SERVER = ROOT / "product" / "control-plane" / "src" / "home_center" / "server.py"


def test_management_status_route_is_authenticated_and_read_only() -> None:
    source = API_V3.read_text(encoding="utf-8")
    assert 'path != "/api/v1/household/devices/management"' in source
    assert "self._require_actor(correlation_id)" in source
    assert "self.runtime.household.status()" in source
    assert "management_report_from_runtime_status" in source
    assert "def do_POST" not in source


def test_server_uses_052_api_handler() -> None:
    source = SERVER.read_text(encoding="utf-8")
    assert "from .api_v3 import RuntimeRequestHandlerV3" in source
    assert "HomeCenterServer(config.web_bind, RuntimeRequestHandlerV3, runtime)" in source
