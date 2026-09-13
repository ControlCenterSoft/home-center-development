# Home Center 0.64 — safe repair admission, completion evidence and history

Status: source-only non-runner preparation. This document does not claim Release Candidate or Public Stable readiness.

## Purpose

The 0.64 Roadmap requires recommendations and safe auto-repair to stay bounded, typed, verifiable and recoverable. The first 0.64 source slice already defines exact recommendation evidence and deterministic repair plans. This continuation closes the next safety boundary before any executor is allowed to exist:

1. revalidate the exact plan immediately before durable Job admission;
2. distinguish explicit-confirmation work from low-risk automation candidates without granting execution authority;
3. require a durable Job, Audit, post-condition verification and recovery evidence for every future repair;
4. make false success structurally impossible in completion evidence;
5. provide a privacy-bounded Cozy/Full history projection that says what was fixed only after verification.

## Admission boundary

`SafeRepairAdmission` is content-addressed and bound to the exact plan, Household snapshot digest, recommendation evidence digest, actor, subject, target, action and risk.

For elevated repair classes, explicit confirmation is mandatory. For the current low-risk `compatibility-evidence-refresh` class, `automation_candidate=true` is only a classification signal. It does not authorize execution.

Every admission keeps these authority fields hard-false:

- `mutation_authorized=false`;
- `execution_authorized=false`;
- `automatic_execution_authorized=false`;
- `provider_execution_authorized=false`;
- `infrastructure_mutation_authorized=false`;
- `external_publication_authorized=false`.

A later runtime may consume an admission only through the normal Home Center chain: Identity/RBAC → Change/Job → typed execution → Actual State/read-back → post-condition verification → Audit/evidence → recovery.

## Freshness and stale-state handling

Admission calls the canonical recommendation planner again against the current Household and the original `RecommendationEvidence`. Any expired evidence, actor/subject state drift, managed-device state drift, target rebinding, plan drift or Household digest mismatch fails closed before a Job may be admitted.

## Completion evidence and false-success prevention

`SafeRepairCompletionEvidence` binds the durable Job to:

- the exact admission and plan;
- target and action;
- before/after evidence digests;
- post-condition evidence digest;
- recovery evidence digest;
- exact outcome and completion time.

`outcome=verified` is valid only with `post_condition_verified=true`. Failed or ambiguous/reconcile-required outcomes are forbidden from carrying `post_condition_verified=true` or `repair_verified=true`.

Completion transport reconstruction recomputes the content-addressed completion ID. A valid-looking but rebound completion ID is rejected. Runtime acceptance must additionally call `validate_completion_binding()` against the authoritative admission before durable persistence or user-visible projection.

## User-visible history

`SafeRepairHistoryEntry` is a bounded projection. It contains only target identity, recommendation class, durable Job identity, completion status and Russian operator/home-user text. It contains no provider payload, secret, credential, token, raw configuration or recovery location.

Only verified completion is shown as `Исправлено`. Ambiguous evidence is shown as `Требуется проверка`; failures are shown as `Не исправлено`.

## Single-node / HA

This source slice is topology-neutral and does not introduce a coordinator, leader election, failover or cross-node mutation path. The future executor must preserve the existing single-writer semantics and must not claim HA for repair execution until restart/failover/recovery behavior is separately qualified.

## Cozy / Full UI

The history projection is suitable for both interfaces. Cozy receives short household language. Full UI can additionally display exact Job/evidence identities from authoritative server-side state. Cozy never gets a separate mutation path.

## Security and commercial boundary

This slice adds no third-party runtime dependency, bundled external component, license redistribution obligation, external publication behavior, payment/licensing capability, or customer data export. It therefore does not broaden the commercial/legal surface. Commercial launch clearance is not claimed by this source preparation.

No GitHub workflow/check is required to create this source package. Runner qualification belongs to the later integration task after rebasing/transplanting onto the then-current canonical main.
