from __future__ import annotations

import inspect

from home_center.api_v11 import RuntimeRequestHandlerV11
from home_center.api_v12 import RuntimeRequestHandlerV12
from home_center.ha_admission import writer_admission
from home_center.ha_state import initialize_membership
from home_center.store import StateStore


def _membership(writer: str = "node-a") -> dict:
    return {
        "schema": "home-center.cluster-membership.v1",
        "cluster_id": "cluster-test",
        "generation": 1,
        "writer": writer,
        "members": [
            {"node_id": "node-a", "state": "ready", "roles": ["control-plane"]},
            {"node_id": "node-b", "state": "ready", "roles": ["control-plane"]},
        ],
        "quorum": {
            "mode": "single-writer-manual-failover",
            "automatic_failover": False,
            "witness_id": None,
        },
        "observed_at": "2026-09-14T12:00:00Z",
    }


def test_pre_ha_bootstrap_allows_leader_but_fails_closed_for_standby(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"a" * 32, "cluster-test")
    try:
        leader = writer_admission(store._connection, local_node_id="node-a", bootstrap_role="leader")
        standby = writer_admission(store._connection, local_node_id="node-b", bootstrap_role="standby")
        assert leader.allowed is True
        assert leader.reason == "single_node_or_pre_ha_bootstrap"
        assert standby.allowed is False
        assert standby.reason == "standby_without_writer_epoch"
    finally:
        store.close()


def test_durable_writer_epoch_rejects_stale_writer_and_reports_generation(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"a" * 32, "cluster-test")
    try:
        initialize_membership(store._connection, _membership("node-b"))
        active = writer_admission(store._connection, local_node_id="node-b", bootstrap_role="standby")
        stale = writer_admission(store._connection, local_node_id="node-a", bootstrap_role="leader")
        assert active.allowed is True
        assert active.writer_node_id == "node-b"
        assert active.generation == 1
        assert stale.allowed is False
        assert stale.reason == "local_node_is_not_writer"
        assert stale.writer_node_id == "node-b"
        assert stale.generation == 1
    finally:
        store.close()


def test_malformed_ha_state_fails_closed(tmp_path) -> None:
    store = StateStore(tmp_path / "state.db", b"a" * 32, "cluster-test")
    try:
        store.set_meta("ha.cluster-membership.v1", {"schema": "unexpected"})
        admission = writer_admission(store._connection, local_node_id="node-a", bootstrap_role="leader")
        assert admission.allowed is False
        assert admission.reason == "ha_state_invalid"
    finally:
        store.close()


def test_v12_wraps_all_authenticated_posts_with_writer_admission() -> None:
    assert issubclass(RuntimeRequestHandlerV12, RuntimeRequestHandlerV11)
    assert RuntimeRequestHandlerV12.SESSION_ONLY_POSTS == {
        "/api/v1/session",
        "/api/v1/session/logout",
        "/api/v1/session/reauth",
    }
    source = inspect.getsource(RuntimeRequestHandlerV12._require_actor)
    assert "writer_admission(" in source
    assert '"not_authoritative_writer"' in source
    assert 'getattr(self, "command", "GET") != "POST"' in source
