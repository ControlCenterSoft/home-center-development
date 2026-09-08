# Home Center Contracts

`contracts/` — canonical source для machine-readable границ Home Center. После допуска к разработке generated code может создаваться из contracts, но не должен становиться альтернативным источником истины.

## Планируемая структура

```text
contracts/
├── openapi/                  # Control Plane API
├── auth/                     # authentication credentials and login envelopes
├── agent/                    # Control Plane ↔ Node Agent protocol
├── capabilities/             # node capability schemas
├── inventory/                # authenticated node/infrastructure read models
├── automation/               # typed runbook planning schemas
├── actions/                  # typed action registry/request/result
├── desired-state/            # desired/actual state schemas
├── jobs/                     # Change/Job/action/result schemas
├── events/                   # audit/domain/health events
├── modules/                  # Module Manifest и lifecycle contracts
├── deployment-profiles/      # topology/role/placement declarations
├── health/                   # readiness/liveness/dependency schemas
├── backup/                   # backup/restore metadata contracts
└── releases/                 # signed channel, trust, checkpoint and verification
```

Каталоги создаются фактическими schema-файлами после утверждения соответствующего контракта; пустые placeholders не считаются контрактом.

## Обязательные правила

1. Каждый контракт имеет явную версию.
2. Breaking change требует ADR/migration/compatibility plan.
3. Неизвестные поля обрабатываются согласно явно зафиксированной forward-compatibility policy.
4. Security-sensitive поля маркируются и не должны автоматически попадать в logs/telemetry/evidence.
5. Privileged action описывается typed schema; generic shell command не является допустимым public product contract.
6. Compatibility опубликованных contract versions проверяется автоматическими contract tests.
7. Contract change в PR должен ссылаться на `HC-*` Requirement ID.

## Первый обязательный набор schemas

- `NodeCapability`;
- `NodeIdentity/Enrollment`;
- `DeploymentProfile`;
- `RolePlacementPolicy`;
- `DesiredState` / `ActualState`;
- `Change` / `Job` / `StepResult`;
- `HealthStatus`;
- `ModuleManifest`;
- `BackupContract` / `RestorePoint`;
- `ClusterMembership`;
- `DrainPlan` / `DrainResult`.

## Definition of done для контракта

Контракт считается готовым к реализации, когда определены:

- schema и semantic invariants;
- versioning;
- validation rules;
- compatibility behavior;
- security/data classification;
- positive/negative examples;
- migration/recovery semantics;
- тестовые fixtures.

## P2.1 active contracts

- `actions/action-registry.v1.schema.json` — immutable executable action catalog;
- `actions/action-request.v1.schema.json` — strict request envelope with local target and idempotency key;
- `actions/action-result.v1.schema.json` — persisted terminal job response;
- `jobs/job.v1.schema.json` — lifecycle, steps, evidence and recovery model.

P2.1 admits only `service.state.read.v1` for Home Center-owned allowlisted units. A registry entry without a matching certified executor fails startup.

## P2.4 signed release-channel contracts

- `releases/release-record.v1.schema.json` — immutable source/artifact/provenance/acceptance identity;
- `releases/release-ledger.v1.schema.json` — full append-only state snapshot and atomic transitions;
- `releases/dsse-envelope.v1.schema.json` — exact DSSE payload/signature envelope;
- `releases/release-trust-policy.v1.schema.json` — dedicated public P-256 keys and threshold;
- `releases/release-channel-checkpoint.v1.schema.json` — local anti-replay floor;
- `releases/release-verification-result.v1.schema.json` — non-secret verifier decision.

Schema validation is necessary but not sufficient: canonical-byte equality, DSSE PAE, cryptographic signatures, state folding, freshness, checkpoint monotonicity and artifact contents are enforced by `home_center.release_channel`. GDrive and issue metadata are evidence references, never release authority.

## Home Center 0.8 authentication contracts

- `auth/local-admin-credential.v1.schema.json` — persisted local administrator verifier envelope; it contains no plaintext or reversible password material and fixes the admitted scrypt parameters;
- `auth/local-admin-credential.v2.schema.json` — backward-compatible verifier state with an explicit one-time password-change requirement; clean installs create `admin`/`admin`, while an existing verifier is preserved byte-for-byte during upgrades;
- `auth/login-request.v1.schema.json` — frozen local-only login envelope from the first 0.8 increment;
- `auth/login-request.v2.schema.json` — closed provider/local-or-AD login envelope with a write-only password;
- `auth/ad-provider-config.v1.schema.json` — disabled-by-default Kerberos endpoints, bounded timeout and explicit AD administrator-group mapping; it contains no password or write authority;
- `openapi/home-center-auth.v2.openapi.json` — 0.8 authentication-surface OpenAPI contract using only the signed session cookie after login.

The bootstrap credential may authenticate only to the session, logout and password-change surfaces. All ordinary authenticated product operations fail closed until the local administrator sets a policy-compliant replacement password.

`openapi/home-center.v1.openapi.json` retains its published v1 identity for compatibility. It is not evidence that bootstrap Bearer authentication is accepted by the 0.8/0.9 runtime.

## Home Center 0.9 external-access contracts

- `external-access/external-access-status.v1.schema.json` — authenticated, non-secret configured/effective policy status;
- `external-access/external-health.v1.schema.json` — minimal public readiness result exposed only after exact trusted-gateway validation.

These contracts grant no router, NAT, DDNS, firewall, arbitrary listener or ambient network mutation authority. Gateway configuration remains an explicit operator-owned step.

## Home Center 0.9 release-candidate contracts

- `releases/release-candidate-acceptance.v1.schema.json` — closed evidence for exact 0.8→0.9 identity, node-b-first rollout, reverse rollback, backup/restore verification, two-node parity, preserved PKI/Domain SID/DRS and zero forbidden mutations;
- `releases/release-candidate-verification.v1.schema.json` — bounded non-secret verifier decision.

The acceptance document records observations and is not release authority. A separately verified threshold-signed stable-channel record remains mandatory before deployment.

## Home Center 0.15 inventory contracts

- `inventory/infrastructure-inventory-list.v1.schema.json` — closed, authenticated node and infrastructure inventory view over persisted capability facts;
- `openapi/home-center-inventory.v1.openapi.json` — read-only `/api/v1/infrastructure` endpoint.

The API omits the internal machine-identity fingerprint, rejects inconsistent node identity or capacity facts fail-closed, and grants no infrastructure mutation authority.

## Home Center 0.16 compute capacity contracts

- `compute/compute-provider-profile.v1.schema.json` — adapter capability profile; the built-in Proxmox profile is data, not a host or topology binding;
- `compute/compute-capacity-snapshot.v1.schema.json` — monotonically sequenced total, allocated and reserved capacity observation;
- `compute/compute-capacity-request.v1.schema.json` — closed planning input for VM, generic container or LXC workloads;
- `compute/compute-capacity-plan.v1.schema.json` — deterministic per-provider evaluation and selected placement;
- `openapi/home-center-compute.v1.openapi.json` — authenticated plan-only HTTP boundary.

The boundary accepts no endpoints, credentials, arbitrary provider settings, or execution commands. A successful plan has `production_mutation_enabled=false`; provider execution remains a separate, independently authorized lifecycle.
