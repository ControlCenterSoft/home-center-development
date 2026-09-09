# Home Center Contracts

## Home Center 0.19 home-service catalog

`market/home-service-profile.v1.schema.json` defines the closed, portable and
secret-free catalog surface for the accepted home-service families. Catalog
records declare requirements and lifecycle coverage only. They neither
authorize installation nor enable external publication.

`market/home-service-deployment-plan.v1.schema.json` defines the fail-closed
deployment preflight. Approval and execution authority remain separate, and
external publication requires both an explicit request and a matching node
capability.

`contracts/` — canonical source для machine-readable границ Home Center. После допуска к разработке generated code может создаваться из contracts, но не должен становиться альтернативным источником истины.

## Планируемая структура

```text
contracts/
├── openapi/                  # Control Plane API
├── auth/                     # authentication credentials and login envelopes
├── agent/                    # Control Plane ↔ Node Agent protocol
├── capabilities/             # node capability schemas
├── inventory/                # authenticated node/infrastructure read models
├── devices/                  # device inventory and provider pairing plans
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
- `releases/release-artifact-qualification.v1.schema.json` — deterministic wheel identity, content and reproducibility qualification result;
- `releases/release-ledger.v1.schema.json` — full append-only state snapshot and atomic transitions;
- `releases/dsse-envelope.v1.schema.json` — exact DSSE payload/signature envelope;
- `releases/release-trust-policy.v1.schema.json` — dedicated public P-256 keys and threshold;
- `releases/release-channel-checkpoint.v1.schema.json` — local anti-replay floor;
- `releases/release-verification-result.v1.schema.json` — non-secret verifier decision.

Schema validation is necessary but not sufficient: canonical-byte equality, DSSE PAE, cryptographic signatures, state folding, freshness, checkpoint monotonicity and artifact contents are enforced by `home_center.release_channel`. GDrive and issue metadata are evidence references, never release authority.

## Home Center 0.8 authentication contracts

- `auth/local-admin-credential.v1.schema.json` — persisted local administrator verifier envelope; it contains no plaintext or reversible password material and fixes the admitted scrypt parameters;
- `auth/login-request.v1.schema.json` — frozen local-only login envelope from the first 0.8 increment;
- `auth/login-request.v2.schema.json` — closed provider/local-or-AD login envelope with a write-only password;
- `auth/ad-provider-config.v1.schema.json` — disabled-by-default Kerberos endpoints, bounded timeout and explicit AD administrator-group mapping; it contains no password or write authority;
- `openapi/home-center-auth.v2.openapi.json` — 0.8 authentication-surface OpenAPI contract using only the signed session cookie after login.

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

## Home Center 0.16 compute contracts

- `compute/compute-plan.v1.schema.json` — provider-neutral, plan-only compute result;
- `compute/proxmox-discovery.v1.schema.json` — closed, read-only Proxmox inventory boundary without endpoints or credentials;
- `compute/resource-placement-plan.v1.schema.json` — deterministic provider placement decision;
- `compute/vm-lifecycle-plan.v1.schema.json` — VM lifecycle plan without execution authority;
- `compute/lxc-lifecycle-plan.v1.schema.json` — LXC lifecycle plan without execution authority.

Every 0.16 plan fixes `production_mutation_enabled` to `false`. Discovery data can authorize neither hypervisor access nor guest mutation; execution remains outside these contracts and requires a separately certified authorization boundary.

## Home Center 0.17 device and automation contracts

- `devices/device-registry.v1.schema.json` — closed, deterministic local device inventory without command authority;
- `devices/zigbee-pairing-plan.v1.schema.json` — provider-neutral Zigbee pairing plan without execution authority;
- `automation/automation-plan.v1.schema.json` — capability-gated device automation plan without execution authority;
- `automation/action-catalog.v1.schema.json` — allowlisted infrastructure runbook vocabulary;
- `automation/runbook-plan-request.v1.schema.json` — strict, typed runbook planning request;
- `automation/runbook-plan.v1.schema.json` — deterministic dependency-aware plan with explicit blockers;
- `openapi/home-center-automation.v1.openapi.json` — authenticated plan-only automation endpoints.

All 0.17 outputs fix `production_mutation_enabled` and `execution_authorized` to `false` where applicable. Device observations, provider discovery and plans do not grant command, pairing or infrastructure mutation authority.

## Home Center 0.18 authorization, certificate and remote-access contracts

- `authorization/authorization-policy.v1.schema.json` — closed, bounded RBAC policy with mandatory default deny and no mutation authority;
- `authorization/effective-access.v1.schema.json` — deterministic effective permissions and their role sources;
- `certificates/certificate-inventory.v1.schema.json` — secret-free certificate observations containing fingerprints and validity facts only;
- `certificates/certificate-renewal-batch.v1.schema.json` — deterministic, plan-only renewal batch with explicit blockers;
- `remote-access/remote-access-publication-plan.v1.schema.json` — readiness-derived publication plan with TLS, authentication, DNS/network and trusted-proxy blockers.

All 0.18 documents are closed and bounded. Every policy or plan fixes `production_mutation_enabled` to `false`; these contracts carry no private keys, passwords, provider endpoints, firewall/NAT authority or executable remote commands.
