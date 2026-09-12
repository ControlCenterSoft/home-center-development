from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE = ROOT / "docs" / "architecture" / "household-policy-composer.md"


def test_policy_composer_architecture_keeps_fail_closed_authority_boundary() -> None:
    text = ARCHITECTURE.read_text(encoding="utf-8").lower()
    required = (
        "home center 0.59",
        "policy composer",
        "explicit confirmation",
        "optimistic concurrency",
        "provider/job/execution boundary",
        "external access",
        "append-only audit",
        "rollback",
        "single-node",
        "multi-node ha",
        "billing authority",
    )
    for marker in required:
        assert marker in text
    assert "infrastructure_mutation_authorized=false" in text
    assert "external_publication_authorized=false" in text
    assert "desired_state_write_authorized=false" in text


def test_policy_composer_architecture_does_not_creep_beyond_release_frontier() -> None:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    assert "0.60" not in text
    assert "Release Candidate" in text
    assert "не делает 0.59 Release Candidate или Stable" in text
