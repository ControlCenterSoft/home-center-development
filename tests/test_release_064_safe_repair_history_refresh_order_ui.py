from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "product" / "web" / "static" / "policy-effective-state.js"


def _source() -> str:
    return UI.read_text(encoding="utf-8")


def test_safe_repair_history_refresh_is_latest_response_wins() -> None:
    source = _source()

    assert "let safeRepairHistoryRefreshSequence = 0;" in source
    assert "const refreshSequence = ++safeRepairHistoryRefreshSequence;" in source
    assert "const ownsRefresh = () => refreshSequence === safeRepairHistoryRefreshSequence;" in source
    assert source.count("if (!ownsRefresh()) return;") >= 2


def test_stale_safe_repair_errors_cannot_overwrite_newer_state() -> None:
    source = _source()
    refresh = source.split("async function refreshSafeRepairHistory() {", 1)[1].split("\n  async function refresh() {", 1)[0]

    catch_block = refresh.split("} catch (_) {", 1)[1].split("return;", 1)[0]
    assert "if (!ownsRefresh())" in catch_block
    assert catch_block.index("if (!ownsRefresh())") < catch_block.index("replaceChildren")


def test_safe_repair_history_busy_state_is_owned_by_current_refresh() -> None:
    source = _source()

    assert source.count("root.setAttribute('aria-busy', 'false');") >= 2
    assert "cozy.setAttribute('aria-busy', 'true');" in source
    assert "full.setAttribute('aria-busy', 'true');" in source
    assert "if (ownsRefresh()) {" in source
    assert "cozy.setAttribute('aria-busy', 'false');" in source
    assert "full.setAttribute('aria-busy', 'false');" in source


def test_safe_repair_history_remains_read_only_and_fail_closed() -> None:
    source = _source()

    assert "method: 'GET'" in source
    assert "credentials: 'same-origin'" in source
    assert "cache: 'no-store'" in source
    assert "verifiedFixed(item)" in source
    assert "post_condition_evidence_sha256" in source
    assert "fetch(SAFE_REPAIR_HISTORY_ENDPOINT" not in source
