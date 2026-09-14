"""Privileged network-fence execution primitives for manual HA.

The Home Center process never imports or invokes these primitives directly. A
separate root-only helper consumes the pure HAFencePolicy and applies it before
the unprivileged service starts.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import stat
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence

from .ha_fence import HAFencePolicy

MANAGED_CHAIN_PREFIX = "HC-HA-F-"
_CHAIN = re.compile(r"^HC-HA-F-[0-9a-f]{8}$")


class HAFenceRuntimeError(RuntimeError):
    """Firewall state could not be proven or changed safely."""


class FirewallAdapter(Protocol):
    def managed_chains(self) -> tuple[str, ...]: ...
    def create_chain(self, chain: str) -> None: ...
    def append_rule(self, chain: str, rule: Sequence[str]) -> None: ...
    def insert_jump(self, policy: HAFencePolicy, port: int, chain: str) -> None: ...
    def remove_jump(self, policy: HAFencePolicy, port: int, chain: str) -> None: ...
    def jump_exists(self, policy: HAFencePolicy, port: int, chain: str) -> bool: ...
    def rule_exists(self, chain: str, rule: Sequence[str]) -> bool: ...
    def rule_count(self, chain: str) -> int: ...
    def delete_chain(self, chain: str) -> None: ...


@dataclass(frozen=True, slots=True)
class FenceRuntimeStatus:
    mode: str
    active: bool
    active_chain: str | None
    managed_chains: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "home-center.ha-fence-runtime-status.v1",
            "mode": self.mode,
            "active": self.active,
            "active_chain": self.active_chain,
            "managed_chains": list(self.managed_chains),
        }


def address_prefix(address: str) -> str:
    parsed = ipaddress.ip_address(address)
    return f"{parsed}/{32 if parsed.version == 4 else 128}"


def expected_chain_rules(policy: HAFencePolicy) -> tuple[tuple[str, ...], ...]:
    if policy.mode == "writer":
        return ()
    target = ipaddress.ip_address(policy.target_address)
    rules: list[tuple[str, ...]] = [
        ("-i", "lo", "-j", "ACCEPT"),
        ("-s", address_prefix(policy.target_address), "-j", "ACCEPT"),
    ]
    if policy.mode == "standby":
        for peer_address in policy.peer_addresses:
            peer = ipaddress.ip_address(peer_address)
            if peer.version != target.version:
                raise HAFenceRuntimeError("ha_fence_peer_address_family_mismatch")
            for port in policy.peer_allowed_ports:
                rules.append(
                    (
                        "-s",
                        address_prefix(peer_address),
                        "-p",
                        "tcp",
                        "--dport",
                        str(port),
                        "-j",
                        "ACCEPT",
                    )
                )
    rules.append(("-j", "DROP"))
    return tuple(rules)


def new_chain_name() -> str:
    return MANAGED_CHAIN_PREFIX + uuid.uuid4().hex[:8]


def fence_runtime_status(policy: HAFencePolicy, firewall: FirewallAdapter) -> FenceRuntimeStatus:
    chains = firewall.managed_chains()
    if policy.mode == "writer":
        jumped = any(
            firewall.jump_exists(policy, port, chain)
            for chain in chains
            for port in policy.protected_ports
        )
        return FenceRuntimeStatus(
            mode="writer",
            active=not jumped and not chains,
            active_chain=None,
            managed_chains=chains,
        )

    expected = expected_chain_rules(policy)
    fully_active = [
        chain
        for chain in chains
        if all(firewall.jump_exists(policy, port, chain) for port in policy.protected_ports)
    ]
    if len(fully_active) != 1:
        return FenceRuntimeStatus(policy.mode, False, None, chains)
    chain = fully_active[0]
    rules_match = firewall.rule_count(chain) == len(expected) and all(
        firewall.rule_exists(chain, rule) for rule in expected
    )
    other_jumps = any(
        firewall.jump_exists(policy, port, other)
        for other in chains
        if other != chain
        for port in policy.protected_ports
    )
    return FenceRuntimeStatus(
        mode=policy.mode,
        active=rules_match and not other_jumps,
        active_chain=chain if rules_match else None,
        managed_chains=chains,
    )


def apply_fence_policy(
    policy: HAFencePolicy,
    firewall: FirewallAdapter,
    *,
    chain_factory: Callable[[], str] = new_chain_name,
) -> FenceRuntimeStatus:
    """Apply the desired policy, connecting a fully-built chain before old cleanup."""
    old_chains = firewall.managed_chains()
    if policy.mode == "writer":
        for chain in old_chains:
            for port in policy.protected_ports:
                firewall.remove_jump(policy, port, chain)
        for chain in old_chains:
            firewall.delete_chain(chain)
        result = fence_runtime_status(policy, firewall)
        if not result.active:
            raise HAFenceRuntimeError("ha_fence_writer_cleanup_unverified")
        return result

    expected = expected_chain_rules(policy)
    chain = chain_factory()
    if _CHAIN.fullmatch(chain) is None or chain in old_chains:
        raise HAFenceRuntimeError("ha_fence_chain_identity_rejected")
    firewall.create_chain(chain)
    connected = False
    try:
        for rule in expected:
            firewall.append_rule(chain, rule)
        if firewall.rule_count(chain) != len(expected) or not all(
            firewall.rule_exists(chain, rule) for rule in expected
        ):
            raise HAFenceRuntimeError("ha_fence_chain_build_unverified")

        # Each jump is inserted at the head of INPUT only after the new chain is
        # complete. Existing restrictive chains remain in place until both new
        # protected-port jumps have been verified.
        for port in policy.protected_ports:
            firewall.insert_jump(policy, port, chain)
        connected = True
        if not all(firewall.jump_exists(policy, port, chain) for port in policy.protected_ports):
            raise HAFenceRuntimeError("ha_fence_activation_unverified")

        for old in old_chains:
            for port in policy.protected_ports:
                firewall.remove_jump(policy, port, old)
        for old in old_chains:
            firewall.delete_chain(old)

        result = fence_runtime_status(policy, firewall)
        if not result.active or result.active_chain != chain:
            raise HAFenceRuntimeError("ha_fence_post_apply_unverified")
        return result
    except Exception:
        # If activation did not happen yet, removing the orphan is safe. Once a
        # new restrictive chain is connected, leave it in place on failure so a
        # retry starts from a fail-closed state.
        if not connected:
            try:
                firewall.delete_chain(chain)
            except Exception:
                pass
        raise


def resolve_firewall_binary(address: str) -> Path:
    family = ipaddress.ip_address(address).version
    name = "iptables" if family == 4 else "ip6tables"
    candidates = (Path("/usr/sbin") / name, Path("/sbin") / name)
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            info = resolved.stat()
        except OSError:
            continue
        if (
            stat.S_ISREG(info.st_mode)
            and info.st_uid == 0
            and info.st_mode & 0o111
            and not info.st_mode & 0o022
        ):
            # Keep the applet path (iptables/ip6tables) as argv[0]. Debian's
            # xtables-nft-multi dispatches behavior from that name; executing
            # the resolved multi-call binary directly would select no applet.
            return candidate
    raise HAFenceRuntimeError(f"ha_fence_firewall_binary_unavailable:{name}")


class IptablesFirewallAdapter:
    """Minimal no-shell adapter scoped to Home Center managed chains and jumps."""

    def __init__(
        self,
        executable: Path,
        *,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.executable = executable
        self._runner = runner

    def _run(self, args: Sequence[str], *, allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
        command = [str(self.executable), "-w", "5", *args]
        result = self._runner(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode not in allowed:
            detail = result.stderr.strip().replace("\n", " ")[:300]
            raise HAFenceRuntimeError(
                f"ha_fence_firewall_command_failed:{result.returncode}:{detail}"
            )
        return result

    @staticmethod
    def _jump_args(policy: HAFencePolicy, port: int, chain: str) -> tuple[str, ...]:
        if _CHAIN.fullmatch(chain) is None or port not in policy.protected_ports:
            raise HAFenceRuntimeError("ha_fence_jump_shape_rejected")
        return (
            "INPUT",
            "-d",
            address_prefix(policy.target_address),
            "-p",
            "tcp",
            "--dport",
            str(port),
            "-j",
            chain,
        )

    def managed_chains(self) -> tuple[str, ...]:
        result = self._run(("-S",))
        chains: set[str] = set()
        for raw_line in result.stdout.splitlines():
            try:
                parts = shlex.split(raw_line)
            except ValueError as exc:
                raise HAFenceRuntimeError("ha_fence_firewall_output_rejected") from exc
            if len(parts) == 2 and parts[0] == "-N" and _CHAIN.fullmatch(parts[1]):
                chains.add(parts[1])
        return tuple(sorted(chains))

    def create_chain(self, chain: str) -> None:
        if _CHAIN.fullmatch(chain) is None:
            raise HAFenceRuntimeError("ha_fence_chain_identity_rejected")
        self._run(("-N", chain))

    def append_rule(self, chain: str, rule: Sequence[str]) -> None:
        if _CHAIN.fullmatch(chain) is None:
            raise HAFenceRuntimeError("ha_fence_chain_identity_rejected")
        self._run(("-A", chain, *rule))

    def insert_jump(self, policy: HAFencePolicy, port: int, chain: str) -> None:
        args = self._jump_args(policy, port, chain)
        self._run(("-I", args[0], "1", *args[1:]))

    def remove_jump(self, policy: HAFencePolicy, port: int, chain: str) -> None:
        args = self._jump_args(policy, port, chain)
        while self._run(("-C", *args), allowed=(0, 1)).returncode == 0:
            self._run(("-D", *args))

    def jump_exists(self, policy: HAFencePolicy, port: int, chain: str) -> bool:
        args = self._jump_args(policy, port, chain)
        return self._run(("-C", *args), allowed=(0, 1)).returncode == 0

    def rule_exists(self, chain: str, rule: Sequence[str]) -> bool:
        if _CHAIN.fullmatch(chain) is None:
            raise HAFenceRuntimeError("ha_fence_chain_identity_rejected")
        return self._run(("-C", chain, *rule), allowed=(0, 1)).returncode == 0

    def rule_count(self, chain: str) -> int:
        if _CHAIN.fullmatch(chain) is None:
            raise HAFenceRuntimeError("ha_fence_chain_identity_rejected")
        result = self._run(("-S", chain))
        count = 0
        for raw_line in result.stdout.splitlines():
            try:
                parts = shlex.split(raw_line)
            except ValueError as exc:
                raise HAFenceRuntimeError("ha_fence_firewall_output_rejected") from exc
            if len(parts) >= 2 and parts[0] == "-A" and parts[1] == chain:
                count += 1
        return count

    def delete_chain(self, chain: str) -> None:
        if _CHAIN.fullmatch(chain) is None:
            raise HAFenceRuntimeError("ha_fence_chain_identity_rejected")
        listed = set(self.managed_chains())
        if chain not in listed:
            return
        self._run(("-F", chain))
        self._run(("-X", chain))
