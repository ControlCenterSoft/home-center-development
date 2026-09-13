from __future__ import annotations

import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.61.1"
BASE_SHA = "9376f16eaaf109085dc0e097e1a306cf6fa18468"


def _contract(name: str) -> dict[str, object]:
    return json.loads((ROOT / "contracts/household" / name).read_text(encoding="utf-8"))


def test_061_exact_release_identity_is_consistent() -> None:
    assert (ROOT / "VERSION").read_text(encoding="ascii").strip() == VERSION
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == VERSION
    runtime_init = (ROOT / "product/control-plane/src/home_center/__init__.py").read_text(encoding="utf-8")
    assert f'__version__ = "{VERSION}"' in runtime_init
    html = (ROOT / "product/web/static/index.html").read_text(encoding="utf-8")
    assert f'<small id="version">{VERSION}</small>' in html


def test_061_notes_are_official_bounded_and_truthful() -> None:
    notes = (ROOT / f"docs/releases/{VERSION}.md").read_text(encoding="utf-8")
    assert notes.startswith(f"# Home Center {VERSION}\n\nStatus: official release.")
    assert "Release profile: `single-node-core`." in notes
    assert "Provider selection is not VPN activation." in notes
    assert "Concrete production VPN adapter execution" in notes
    assert "Multi-node HA / automatic failover" in notes
    assert "commercial launch clearance" in notes
    assert "0.61.0 → 0.61.1" in notes
    assert "split-route direct egress" in notes
    assert "split_route_direct_not_authorized" in notes


def test_061_vpn_runtime_source_is_present() -> None:
    for relative in (
        "product/control-plane/src/home_center/vpn_egress_policy.py",
        "product/control-plane/src/home_center/vpn_egress_policy_api.py",
        "product/control-plane/src/home_center/vpn_egress_policy_validation.py",
    ):
        assert (ROOT / relative).is_file()


def test_061_contracts_are_closed_and_non_authorizing() -> None:
    for name in (
        "vpn-egress-provider-candidate.v1.schema.json",
        "vpn-egress-policy.v1.schema.json",
        "vpn-egress-observation.v1.schema.json",
        "vpn-egress-route-decision.v1.schema.json",
    ):
        schema = _contract(name)
        assert schema["additionalProperties"] is False
        props = schema["properties"]
        assert props["execution_authorized"] == {"const": False}
        assert props["infrastructure_mutation_authorized"] == {"const": False}
        assert props["external_publication_authorized"] == {"const": False}


def test_061_parental_precedence_and_kill_switch_are_explicit() -> None:
    policy = _contract("vpn-egress-policy.v1.schema.json")
    props = policy["properties"]
    assert props["parental_deny_has_priority"] == {"const": True}
    assert set(props["dns_strategy"]["enum"]) == {"provider", "parental", "system"}
    assert set(props["fallback_mode"]["enum"]) == {"deny", "direct"}
    serialized = json.dumps(policy, sort_keys=True)
    assert '"kill_switch"' in serialized
    assert '"fallback_mode"' in serialized


def test_061_architecture_keeps_execution_for_later_typed_boundary() -> None:
    architecture = (ROOT / "docs/architecture/0.61-vpn-egress-policy-foundation.md").read_text(
        encoding="utf-8"
    )
    assert "parental DENY has absolute precedence" in architecture
    assert "no generic shell" in architecture
    assert "post-condition read-back" in architecture


def test_061_upgrade_drills_bind_exact_current_stable_without_source_rewrite() -> None:
    for name in (
        "test_release_061_hosted_upgrade_drill.py",
        "test_release_061_hosted_systemd_upgrade.py",
    ):
        source = (ROOT / "tests" / name).read_text(encoding="utf-8")
        assert f'BASE_SHA = "{BASE_SHA}"' in source
        assert 'BASELINE_VERSION = "0.61.0"' in source
        assert 'CANDIDATE_VERSION = "0.61.1"' in source
        assert "SOURCE_VERSION" not in source
        assert "replace(source_marker" not in source


def test_061_ci_derives_deployment_candidate_from_exact_version() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert 'version="$(tr -d \'[:space:]\' < VERSION)"' in workflow
    assert "HC_VERSION=$version" in workflow
    assert 'artifact="home-center-${HC_VERSION}-linux-amd64.tar.gz"' in workflow
