from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_official_release_skips_post_stable_product_development() -> None:
    workflow = (ROOT / ".github/workflows/publish-release.yml").read_text(encoding="utf-8")
    assert "POST_RELEASE_PRODUCT_DELTA_DETECTED" in workflow
    assert "POST_RELEASE_DEVELOPMENT_SKIP" in workflow
    assert 'echo "promote=false" >> "$GITHUB_OUTPUT"' in workflow
    assert "actions: write" in workflow


def test_deployment_publication_is_dispatched_only_by_eligible_release_flow() -> None:
    release = (ROOT / ".github/workflows/publish-release.yml").read_text(encoding="utf-8")
    deployment = (ROOT / ".github/workflows/publish-deployment-artifact.yml").read_text(encoding="utf-8")
    assert "gh workflow run publish-deployment-artifact.yml" in release
    assert "steps.publish.outputs.promote == 'true'" in release
    assert "workflow_run:" not in deployment
    assert "workflow_dispatch:" in deployment
    assert "confirmation must be PROMOTE" in deployment
