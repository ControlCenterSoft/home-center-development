"""Composition root for API, state, auth, inventory and cluster health."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from . import __version__
from .actions import ActionRegistry
from .ad_auth import AdAuthenticator
from .auth import LoginRateLimiter, SessionManager
from .config import Config
from .external_access import ExternalAccessPolicy, ExternalRequestRateLimiter
from .local_admin_auth import LocalAdminCredentialStore
from .node_inventory_api import NodeInventoryService
from .reconcile import Reconciler
from .store import StateStore
from .util import sha256_file, utc_now


LOG = logging.getLogger("home_center.runtime")


class Runtime:
    def __init__(self, config: Config, *, local_admin_expected_uid: int = 0) -> None:
        self.config = config
        self.profile = self._load_profile(config.deployment_profile)
        self.store = StateStore(config.state_db, config.audit_key_file.read_bytes(), config.cluster_id)
        self.local_admin = LocalAdminCredentialStore(
            config.local_admin_credentials_file,
            expected_uid=local_admin_expected_uid,
            expected_gid=os.getegid(),
            expected_mode=0o640,
        )
        self.sessions = SessionManager(config.session_key_file)
        self.login_limiter = LoginRateLimiter()
        self.ad_auth = AdAuthenticator(config.ad_auth)
        self.external_access = ExternalAccessPolicy(
            configured_enabled=config.external_access.enabled,
            public_hostname=config.external_access.public_hostname,
            trusted_proxy_addresses=config.external_access.trusted_proxy_addresses,
            authentication_ready=True,
        )
        self.external_request_limiter = ExternalRequestRateLimiter()
        self.actions = ActionRegistry(config.node_id, self.store)
        self.node_inventory = NodeInventoryService(self.store, product_version=__version__)
        self.reconciler = Reconciler(config, self.store)

    def start(self) -> None:
        self.store.audit(
            actor="system:runtime",
            action="runtime.start",
            target=self.config.node_id,
            outcome="accepted",
            correlation_id=f"runtime-{self.config.node_id}",
            details={"version": __version__, "role": self.config.role},
        )
        self.reconciler.start()

    def stop(self) -> None:
        self.reconciler.stop()
        self.store.audit(
            actor="system:runtime",
            action="runtime.stop",
            target=self.config.node_id,
            outcome="accepted",
            correlation_id=f"runtime-{self.config.node_id}",
            details={"version": __version__},
        )
        self.store.close()

    def ready(self) -> tuple[bool, list[str]]:
        reasons: list[str] = []
        try:
            if not self.store.integrity_check():
                reasons.append("database_integrity")
            self.store.verify_audit_chain()
        except Exception:
            LOG.exception("readiness integrity validation failed")
            reasons.append("audit_integrity")
        if not self.reconciler.local_capability():
            reasons.append("inventory_unavailable")
        return not reasons, reasons

    def overview(self) -> dict[str, Any]:
        nodes = self.store.nodes()
        profile_name, profile_version, profile_nodes = self._profile_details(self.profile)
        expected_nodes = len(profile_nodes)
        ready_nodes = sum(node["status"] == "ready" for node in nodes)
        status = "healthy" if ready_nodes == expected_nodes and len(nodes) == expected_nodes else "degraded"
        return {
            "schema": "home-center.overview.v1",
            "observed_at": utc_now(),
            "version": __version__,
            "cluster": {
                "id": self.config.cluster_id,
                "status": status,
                "profile": profile_name,
                "profile_version": profile_version,
                "local_role": self.config.role,
                "ready_nodes": ready_nodes,
                "expected_nodes": expected_nodes,
                "automatic_failover": False,
                "split_brain_policy": "single-writer-manual-failover",
            },
            "nodes": nodes,
            "jobs": self.store.jobs(10),
            "audit_head": self.store.verify_audit_chain(),
        }

    def backup_inventory(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        if not self.config.backup_dir.exists():
            return items
        for manifest in sorted(self.config.backup_dir.glob("home-center-*.manifest.json"), reverse=True)[:100]:
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                data["manifest_sha256"] = sha256_file(manifest)
                items.append(data)
            except (OSError, json.JSONDecodeError):
                continue
        return items

    @staticmethod
    def _load_profile(path: Path) -> dict[str, Any]:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("deployment profile must be an object")
        if value.get("schema") not in {"home-center.deployment-profile.v1", "home-center.deployment-profile.v2"}:
            raise ValueError("unsupported deployment profile")
        Runtime._profile_details(value)
        return value

    @staticmethod
    def _profile_details(value: dict[str, Any]) -> tuple[str, str | int, list[dict[str, Any]]]:
        """Return the common runtime view for legacy v1 and portable v2 profiles."""

        if value.get("schema") == "home-center.deployment-profile.v2":
            profile_name = value.get("profile_id")
            profile_version: str | int = 2
            nodes = value.get("nodes")
        else:
            metadata = value.get("metadata")
            specification = value.get("spec")
            if not isinstance(metadata, dict) or not isinstance(specification, dict):
                raise ValueError("invalid v1 deployment profile shape")
            profile_name = metadata.get("name")
            profile_version = metadata.get("version")
            nodes = specification.get("nodes")

        if not isinstance(profile_name, str) or not profile_name.strip():
            raise ValueError("deployment profile name is required")
        if isinstance(profile_version, bool) or not isinstance(profile_version, (str, int)):
            raise ValueError("deployment profile version is required")
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= 64:
            raise ValueError("deployment profile node count must be between 1 and 64")
        if any(not isinstance(node, dict) for node in nodes):
            raise ValueError("deployment profile nodes must be objects")
        return profile_name, profile_version, nodes
