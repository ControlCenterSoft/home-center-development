from __future__ import annotations

from pathlib import Path

import pytest

from home_center.api_v6 import EFFECTIVE_STATE_PATH, _member_id_from_query


ROOT = Path(__file__).resolve().parents[1]


def test_effective_state_query_accepts_exact_single_member_id() -> None:
    assert (
        _member_id_from_query(
            "/api/v1/household/policy/effective-state?member_id=member-child"
        )
        == "member-child"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/household/policy/effective-state",
        "/api/v1/household/policy/effective-state?member_id=",
        "/api/v1/household/policy/effective-state?member_id=a&member_id=b",
        "/api/v1/household/policy/effective-state?member_id=a&debug=true",
        "/api/v1/household/policy/effective-state?unexpected=true",
        "/api/v1/household/policy/effective-state?broken",
    ],
)
def test_effective_state_query_rejects_ambiguous_or_extra_input(path: str) -> None:
    with pytest.raises(ValueError, match="invalid_household_policy_effective_state_query"):
        _member_id_from_query(path)


def test_api_route_is_read_only_and_wired_through_v7() -> None:
    api_v6 = (ROOT / "product/control-plane/src/home_center/api_v6.py").read_text(encoding="utf-8")
    api_v7 = (ROOT / "product/control-plane/src/home_center/api_v7.py").read_text(encoding="utf-8")
    server = (ROOT / "product/control-plane/src/home_center/server.py").read_text(encoding="utf-8")

    assert EFFECTIVE_STATE_PATH == "/api/v1/household/policy/effective-state"
    assert "class RuntimeRequestHandlerV6(RuntimeRequestHandlerV5)" in api_v6
    assert "def do_GET(self)" in api_v6
    assert "def do_POST(self)" not in api_v6
    assert "HouseholdPolicyEffectiveStateService(self.runtime.store).read" in api_v6
    assert "class RuntimeRequestHandlerV7(RuntimeRequestHandlerV6)" in api_v7
    assert "RuntimeRequestHandlerV7" in server
    assert "RuntimeRequestHandlerV5" not in server


def test_policy_state_ui_is_loaded_and_avoids_html_injection_sinks() -> None:
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    ui = (ROOT / "product/web/static/policy-effective-state.js").read_text(encoding="utf-8")

    assert 'src="/static/policy-effective-state.js"' in html
    assert "/api/v1/household/policy/effective-state" in ui
    assert "Правила применены" in ui
    assert "Ожидают проверки" in ui
    assert "По роли" in ui
    assert "textContent" in ui
    assert "innerHTML" not in ui
    assert "eval(" not in ui
    assert "credentials: 'same-origin'" in ui
    assert "cache: 'no-store'" in ui
    assert "external_publication_authorized" not in ui


def test_cozy_and_full_ui_share_one_policy_endpoint() -> None:
    ui = (ROOT / "product/web/static/policy-effective-state.js").read_text(encoding="utf-8")

    assert "family-policy-state-card" in ui
    assert "full-policy-state" in ui
    assert ui.count("POLICY_ENDPOINT") >= 2
    assert "state.state" in ui
    assert "state.technical_policy" in ui
