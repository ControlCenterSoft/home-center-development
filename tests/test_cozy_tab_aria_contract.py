from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "product" / "web" / "static" / "index.html"


class _ElementCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, dict(attrs)))


def _document() -> _ElementCollector:
    parser = _ElementCollector()
    parser.feed(INDEX.read_text(encoding="utf-8"))
    return parser


def _by_id(document: _ElementCollector, element_id: str) -> dict[str, str | None]:
    matches = [attrs for _tag, attrs in document.elements if attrs.get("id") == element_id]
    assert len(matches) == 1, f"expected exactly one element #{element_id}, got {len(matches)}"
    return matches[0]


def _has_class(attrs: dict[str, str | None], class_name: str) -> bool:
    return class_name in (attrs.get("class") or "").split()


def _assert_tab_group(
    document: _ElementCollector,
    tab_ids: tuple[str, ...],
    panel_ids: tuple[str, ...],
) -> None:
    assert len(tab_ids) == len(panel_ids)

    selected = []
    for tab_id, panel_id in zip(tab_ids, panel_ids, strict=True):
        tab = _by_id(document, tab_id)
        panel = _by_id(document, panel_id)

        assert tab.get("role") == "tab"
        assert tab.get("aria-controls") == panel_id
        assert panel.get("role") == "tabpanel"
        assert tab_id in (panel.get("aria-labelledby") or "").split()

        is_selected = tab.get("aria-selected") == "true"
        selected.append(is_selected)
        if is_selected:
            assert tab.get("tabindex") in (None, "0")
        else:
            assert tab.get("aria-selected") == "false"
            assert tab.get("tabindex") == "-1"

    assert selected.count(True) == 1


def test_interface_mode_tabs_keep_bidirectional_aria_wiring() -> None:
    document = _document()
    mode_switch = _by_id(document, "mode-switch")
    assert mode_switch.get("role") == "tablist"
    assert mode_switch.get("aria-label") == "Режим интерфейса"

    _assert_tab_group(
        document,
        ("mode-cozy", "mode-full"),
        ("cozy-view", "full-view"),
    )


def test_cozy_navigation_tabs_keep_bidirectional_aria_wiring() -> None:
    document = _document()
    cozy_navs = [
        attrs
        for tag, attrs in document.elements
        if tag == "nav" and _has_class(attrs, "cozy-nav")
    ]
    assert len(cozy_navs) == 1
    assert cozy_navs[0].get("role") == "tablist"
    assert cozy_navs[0].get("aria-label") == "Разделы Уютного интерфейса"

    _assert_tab_group(
        document,
        ("cozy-tab-home", "cozy-tab-family", "cozy-tab-house"),
        ("cozy-home", "cozy-family", "cozy-house"),
    )
