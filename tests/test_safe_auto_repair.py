from home_center.safe_auto_repair import (
    RepairAction,
    RepairBlocker,
    RepairCandidate,
    RepairRisk,
    SafeRepairPolicy,
    evaluate_safe_auto_repair,
)

DIGEST = "a" * 64
POLICY_DIGEST = "b" * 64


def candidate(**kwargs: object) -> RepairCandidate:
    return RepairCandidate(
        household_id="household-1",
        resource_id="derived-index-1",
        resource_generation=int(kwargs.get("generation", 1)),
        evidence_sha256=str(kwargs.get("evidence_sha256", DIGEST)),
        action=kwargs.get("action", RepairAction.REBUILD_DERIVED_INDEX),
        risk=kwargs.get("risk", RepairRisk.LOW),
        recovery_proven=bool(kwargs.get("recovery_proven", True)),
        post_condition_verifiable=bool(kwargs.get("post_condition_verifiable", True)),
        provider_execution_required=bool(kwargs.get("provider_execution_required", False)),
        infrastructure_mutation_required=bool(kwargs.get("infrastructure_mutation_required", False)),
        external_publication_required=bool(kwargs.get("external_publication_required", False)),
    )


def policy(*, digest: str = POLICY_DIGEST) -> SafeRepairPolicy:
    return SafeRepairPolicy(
        policy_id="policy-1",
        policy_sha256=digest,
        allowed_actions=frozenset({RepairAction.REBUILD_DERIVED_INDEX}),
        allowed_risks=frozenset({RepairRisk.LOW}),
    )


def test_safe_auto_repair_schema_identity() -> None:
    decision = evaluate_safe_auto_repair(candidate=candidate(), policy=policy())
    assert decision.schema == "home-center.safe-auto-repair-recommendation.v1"
    assert decision.eligible_for_auto_repair is True
    assert decision.blockers == ()


def test_policy_allowlist_and_risk_fail_closed() -> None:
    decision = evaluate_safe_auto_repair(
        candidate=candidate(action=RepairAction.REFRESH_LOCAL_READ_MODEL, risk=RepairRisk.MEDIUM),
        policy=policy(),
    )
    assert decision.eligible_for_auto_repair is False
    assert decision.blockers == (
        RepairBlocker.ACTION_NOT_ALLOWED,
        RepairBlocker.RISK_NOT_ALLOWED,
    )


def test_recovery_and_post_condition_evidence_are_required() -> None:
    no_recovery = evaluate_safe_auto_repair(
        candidate=candidate(recovery_proven=False), policy=policy()
    )
    no_verification = evaluate_safe_auto_repair(
        candidate=candidate(post_condition_verifiable=False), policy=policy()
    )
    assert RepairBlocker.RECOVERY_NOT_PROVEN in no_recovery.blockers
    assert RepairBlocker.POST_CONDITION_NOT_VERIFIABLE in no_verification.blockers


def test_recommendation_identity_changes_with_generation_and_policy() -> None:
    first = evaluate_safe_auto_repair(candidate=candidate(), policy=policy())
    replay = evaluate_safe_auto_repair(candidate=candidate(), policy=policy())
    newer = evaluate_safe_auto_repair(candidate=candidate(generation=2), policy=policy())
    other_policy = evaluate_safe_auto_repair(candidate=candidate(), policy=policy(digest="c" * 64))
    assert first.recommendation_id == replay.recommendation_id
    assert first.recommendation_id != newer.recommendation_id
    assert first.recommendation_id != other_policy.recommendation_id
