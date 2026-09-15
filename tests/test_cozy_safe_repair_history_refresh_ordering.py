from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _ui_source() -> str:
    return (ROOT / "product/web/static/policy-effective-state.js").read_text(encoding="utf-8")


def test_safe_repair_history_latest_refresh_owns_rendering() -> None:
    ui = _ui_source()

    assert "let safeRepairHistoryRefreshToken = 0;" in ui
    assert "const refreshToken = ++safeRepairHistoryRefreshToken;" in ui
    assert ui.count("refreshToken !== safeRepairHistoryRefreshToken") >= 2
    assert "refreshToken === safeRepairHistoryRefreshToken" in ui
    assert "result = await json(SAFE_REPAIR_HISTORY_ENDPOINT);" in ui


def test_safe_repair_history_busy_state_belongs_to_current_refresh() -> None:
    ui = _ui_source()

    assert "function setSafeRepairHistoryBusy(cozy, full, busy)" in ui
    assert "root.setAttribute('aria-busy', 'true')" in ui
    assert "root.removeAttribute('aria-busy')" in ui
    assert "setSafeRepairHistoryBusy(cozy, full, true);" in ui
    assert "setSafeRepairHistoryBusy(cozy, full, false);" in ui
    assert "finally" in ui


def test_safe_repair_history_refresh_remains_read_only_and_fail_closed() -> None:
    ui = _ui_source()

    assert "method: 'GET'" in ui
    assert "method: 'POST'" not in ui
    assert "item.status === 'fixed'" in ui
    assert "item.repair_verified === true" in ui
    assert "SHA256.test(item.post_condition_evidence_sha256)" in ui
    assert "Ответ не прошёл безопасную проверку. Статус исправлений не изменён." in ui
