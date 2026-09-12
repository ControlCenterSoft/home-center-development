# Household policy presentation precondition (0.59)

## Purpose

Policy Composer already binds a proposal to an exact Household snapshot and an exact protected policy Desired State revision. The UI presentation boundary must preserve the same guarantee: Cozy and Full interfaces must never show an obsolete proposal as ready for confirmation after either Household state or the protected policy Desired State has changed.

## Fail-closed rule

After the durable plan is created and its stored proposal is rebuilt from exact evidence, the production workflow MUST re-read:

1. the current Household snapshot and actor binding;
2. the current policy Desired State revision for the proposal resource key.

The workflow then revalidates the original proposal against those fresh values. Any mismatch rejects the presentation with the existing stale/evidence error path. No replacement proposal is synthesized implicitly.

This prevents a plan created against Desired State generation N from being presented as current after another operation advances the same policy resource to generation N+1. It also prevents stale Household role/member evidence from reaching the confirmation UI.

## Authority boundary

The presentation guard is non-executing. It does not:

- materialize Desired State;
- execute a provider or device operation;
- change network, storage, domain or host configuration;
- enable external publication;
- weaken the explicit confirmation requirement.

The returned plan keeps `desired_state_materialized=false`, `provider_execution_authorized=false`, `infrastructure_mutation_authorized=false`, and `external_publication_authorized=false`.

## Runtime integration

`GuardedHouseholdPolicyWorkflowService` wraps the existing `HouseholdPolicyWorkflowService` and overrides only the plan/presentation boundary. The composition root selects the guarded service while confirmation, audit, history, rollback and recovery continue to use the established base implementation.

The second read does not replace the confirmation-time precondition. Confirmation/materialization must still revalidate exact evidence because state can change after presentation.

## Qualification handoff

Dedicated source tests cover:

- a current proposal is presented normally;
- a changed Desired State revision is rejected before presentation;
- changed Household evidence is rejected before presentation;
- no Desired State or provider/infrastructure mutation is performed by the guard.

This NR2 branch intentionally does not run GitHub Actions or open a pull request. Hosted qualification belongs to the runner-enabled release flow before integration.
