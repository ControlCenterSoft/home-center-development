from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_fence_helper_is_python3_compilable_and_never_uses_shell_execution() -> None:
    helper = ROOT / "deploy/scripts/home-center-ha-fence.py"
    source = helper.read_text(encoding="utf-8")
    compile(source, str(helper), "exec")
    assert "shell=True" not in source
    assert "ROOT_REQUIRED" in source
    assert "resolve_firewall_binary" in source
    assert "IptablesFirewallAdapter" in source
    assert "execute_fence_command" in source


def test_fence_unit_runs_before_home_center_with_only_net_admin_capability() -> None:
    fence = (ROOT / "deploy/systemd/home-center-ha-fence.service").read_text(encoding="utf-8")
    service = (ROOT / "deploy/systemd/home-center.service").read_text(encoding="utf-8")

    assert "Before=home-center.service" in fence
    assert "ExecStart=/usr/bin/python3 -I /opt/home-center/current/deploy/home-center-ha-fence.py apply" in fence
    assert "User=root" in fence
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in fence
    assert "AmbientCapabilities=CAP_NET_ADMIN" in fence
    assert "ProtectSystem=strict" in fence
    assert "NoNewPrivileges=yes" in fence
    assert "RuntimeDirectory=home-center-locks" in fence
    assert "ReadWritePaths=/var/lib/home-center/ha-fence /run" in fence
    assert "ExecStop=" not in fence

    assert "Requires=home-center-ha-fence.service" in service
    assert "After=network-online.target time-sync.target home-center-ha-fence.service" in service
    assert "CapabilityBoundingSet=\n" in service
    assert "AmbientCapabilities=\n" in service


def test_deployment_artifact_contains_root_helper_unit_and_executable_bit_assignment() -> None:
    build = (ROOT / "deploy/scripts/build-deployment-artifact.sh").read_text(encoding="utf-8")
    assert '"$ROOT/deploy/scripts/home-center-ha-fence.py"' in build
    assert '"$ROOT/deploy/systemd/home-center-ha-fence.service"' in build
    assert '"$STAGE/deploy/home-center-ha-fence.py"' in build
    assert "DEPLOYMENT_ARTIFACT_PRIVACY_BOUNDARY_REJECTED" in build


def test_fence_design_has_no_unsafe_writer_override() -> None:
    control = (ROOT / "product/control-plane/src/home_center/ha_fence_control.py").read_text(encoding="utf-8")
    policy = (ROOT / "product/control-plane/src/home_center/ha_fence.py").read_text(encoding="utf-8")
    assert 'COMMANDS = frozenset({"apply", "status", "isolate", "standby", "auto"})' in control
    assert 'FENCE_OVERRIDES = frozenset({"standby", "isolated"})' in policy
    assert '"writer"' not in control.split("COMMANDS =", 1)[1].split("\n", 1)[0]
