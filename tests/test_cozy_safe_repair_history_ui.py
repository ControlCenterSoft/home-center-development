from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _ui_source() -> str:
    return (ROOT / "product/web/static/policy-effective-state.js").read_text(encoding="utf-8")


def test_cozy_safe_repair_history_uses_authenticated_read_only_endpoint() -> None:
    ui = _ui_source()

    assert "'/api/v1/household/safe-repair/history'" in ui
    assert "method: 'GET'" in ui
    assert "credentials: 'same-origin'" in ui
    assert "cache: 'no-store'" in ui
    assert "method: 'POST'" not in ui
    assert "fetch(SAFE_REPAIR_HISTORY_ENDPOINT" not in ui
    assert "json(SAFE_REPAIR_HISTORY_ENDPOINT)" in ui


def test_cozy_safe_repair_history_never_maps_unverified_success_to_fixed() -> None:
    ui = _ui_source()

    assert "item.status === 'fixed'" in ui
    assert "item.repair_verified === true" in ui
    assert "SHA256.test(item.post_condition_evidence_sha256)" in ui
    assert "if (verifiedFixed(item)) return ['Исправлено', 'available'];" in ui
    assert "Статус «Исправлено» появляется только после подтверждённой проверки результата." in ui
    assert "verified=${verifiedFixed(item) ? 'true' : 'false'}" in ui


def test_cozy_safe_repair_history_is_accessible_and_injection_safe() -> None:
    ui = _ui_source()

    assert "cozy-safe-repair-history" in ui
    assert "full-safe-repair-history" in ui
    assert "aria-live" in ui
    assert "textContent" in ui
    assert "innerHTML" not in ui
    assert "eval(" not in ui
    assert "интерфейс не запускает и не повторяет исправления." in ui


def test_cozy_safe_repair_history_fails_closed_on_bad_or_unauthorized_response() -> None:
    ui = _ui_source()

    assert "SAFE_REPAIR_RESPONSE_SCHEMA" in ui
    assert "SAFE_REPAIR_ITEM_SCHEMA" in ui
    assert "result.response.status === 401" in ui
    assert "result.response.status === 403" in ui
    assert "result.response.status === 404" in ui
    assert "Ответ не прошёл безопасную проверку. Статус исправлений не изменён." in ui
    assert "История недоступна" in ui
