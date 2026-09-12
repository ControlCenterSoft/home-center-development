# Device Management API boundary — Home Center 0.57–0.58

Статус: development contract. Документ не является Release Candidate/Public Stable evidence и не расширяет release claims.

## Назначение

Этот boundary фиксирует публичную HTTP-поверхность фактически реализованных слоёв 0.57 и 0.58: provider-backed enrollment execution, post-condition verification, de-enrollment, failed-enrollment cleanup и scoped step-up re-authentication. Канонический machine-readable контракт находится в `contracts/openapi/home-center-device-management.v1.openapi.json`.

Граница относится только к 0.57–0.58 и не проектирует функциональность следующих roadmap-релизов.

## Общие инварианты

Каждый endpoint этой поверхности работает только через штатный Home Center request fence:

- authenticated session обязателен;
- POST разрешён только same-origin;
- external-access path блокируется fail-closed;
- JSON body имеет жёсткий размерный предел: 8192 байта для device-management операций и 4096 байт для re-auth;
- неизвестный, stale, неоднозначный или неполный state не преобразуется в success;
- provider acceptance не означает успешный enrollment;
- значения credentials не входят в provider execution contract: передаются только `secret://` references;
- external publication authority не выдаётся ни одним endpoint этой группы;
- generic shell/command execution отсутствует.

## 0.57 — enrollment execution

`plan` формирует exact-bound execution plan и не разрешает provider execution. `start` требует отдельного подтверждения и durable Job/Audit. Даже если provider принял команду, receipt сохраняет `enrollment_completed=false`, `post_condition_verified=false` и `managed_state_change_authorized=false`.

`retry` допустим только когда предыдущий outcome доказанно безопасен для повтора. Timeout/ambiguous transport outcome не даёт automatic retry authority. `cancel` является отдельной типизированной операцией и также не изменяет managed state.

## 0.58 — post-condition verification

Verification отделён от provider acceptance. `verification/plan` формирует точную проверку, а `verification/confirm` дополнительно требует single-use scoped step-up grant.

Только свежий exact-bound provider read-back может дать verified evidence, после чего допустим guarded local managed-state transition с обязательным read-back. Failure/mismatch должен оставлять состояние fail-closed и не выдавать false success.

## 0.58 — de-enrollment

De-enrollment разделён на четыре шага:

1. `plan` — read-only exact-state planning;
2. `confirm` — scoped step-up и выдача ограниченной provider-mutation authority, без provider call;
3. `execute` — однократная typed provider mutation, затем обязательный fresh read-back; local `managed=false` применяется только после verified `unmanaged`/`absent`;
4. `reconcile` — read-only reconciliation для ambiguous outcome. Он не имеет права повторять provider mutation.

Если outcome неоднозначен, автоматический provider retry запрещён.

## 0.58 — failed-enrollment cleanup

Cleanup не является удалением устройства и не меняет Household/policy/managed/infrastructure state.

`cleanup/plan` допускается только для rejected post-condition evidence. `cleanup/verify` выполняет только provider read-back и может выдать bounded authority лишь при свежем exact-bound состоянии `unmanaged`/`absent`. `cleanup/execute` удаляет только transient single-use reference из всех durable копий Home Center и повторно проверяет отсутствие ссылки. Provider mutation в этом шаге запрещена.

## Step-up

`POST /api/v1/session/reauth` повторно проверяет credentials текущего actor и выдаёт короткоживущий single-use token только для server-validated scope. На 0.58 step-up используется для enrollment verification confirmation и de-enrollment confirmation. Token не является общей execution authority.

## Single-node / HA

API и durable state topology-neutral. Single-node остаётся полноценным режимом. Наличие этой HTTP-поверхности само по себе не является доказательством HA/provider certification. Неподтверждённые provider/HA capabilities должны оставаться fail-closed либо не заявляться как поддерживаемые в Stable profile.

## Drift protection

`tests/test_device_management_openapi_058.py` статически сопоставляет OpenAPI path set с точными route constants `RuntimeRequestHandlerV3/V4/V5`, проверяет closed request contracts, local `$ref`, same-origin/auth/external fences, step-up placement и ключевые no-false-success authority invariants. Тест предназначен для последующей штатной qualification; сам этот development slice не создаёт CI/runner evidence.
