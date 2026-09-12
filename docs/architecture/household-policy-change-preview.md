# Household policy change preview (Home Center 0.59)

## Purpose

Before an authorized user confirms a Policy Composer proposal, Home Center should show what the proposal changes relative to the exact protected Policy Desired State revision that the plan observed. The preview is shared evidence for the «Уютный» confirmation flow and the technical/full interface; it is not a second planning or mutation path.

## Exact-state rule

The preview accepts only the already-built `PolicyCompositionProposal` and the current record for the same `desired_state_resource_key`.

It fails closed unless:

- an absent record corresponds to proposal precondition generation `0` and bundle `null`;
- an existing record has exactly the proposal's `expected_desired_state_generation` and `expected_desired_state_bundle_id`;
- the persisted bundle passes full semantic PolicyBundle verification for the exact resource key;
- every reported change can be explained by the bounded RolePreset/EffectivePolicy fields.

A bundle mismatch with no explainable policy-field delta is treated as evidence corruption, not as a cosmetic change.

## User-facing states

The contract `home-center.household-policy-change-preview.v1` exposes three states:

- `initial` — no policy Desired State exists yet for the member;
- `unchanged` — the verified current bundle is exactly the planned target;
- `changed` — one or more bounded policy fields differ.

`changed_fields` is limited to role-derived policy semantics: role, internet profile, VPN allowance, managed-device requirement, home files, smart-home control and Home Center administration. The «Уютный» summary uses short household language; the full interface can use the exact field list together with the existing technical policy inspector.

## Authority boundary

The preview always keeps:

- `confirmation_required=true`;
- `mutation_started=false`;
- `provider_execution_authorized=false`;
- `infrastructure_mutation_authorized=false`;
- `external_publication_authorized=false`.

It does not write Desired State, execute providers, create Jobs, change devices/network/storage/accounts or publish externally. Confirmation and materialization continue through the existing durable plan/confirm/Audit/recovery path.

## Integration and qualification

`GuardedHouseholdPolicyWorkflowService` builds the preview only after re-reading the Household and protected Desired State preconditions and revalidating the exact proposal. The plan-result contract permits the additional `change_preview` evidence while the base workflow remains compatible for staged qualification.

Source tests cover initial, unchanged, changed and forged-current-state cases plus guarded workflow integration. This non-runner branch intentionally does not run GitHub Actions, open a pull request or merge to `main`; runner-enabled qualification is deferred to the release flow.
