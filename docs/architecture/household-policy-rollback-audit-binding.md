# Home Center 0.59 — exact Audit binding для Policy rollback

## Назначение

Policy Composer уже требует явного подтверждения, exact-state preconditions, monotonic Desired State generation, immutable history и post-condition verification. Для rollback дополнительно требуется доказать, что возвращаемый успешный receipt относится именно к тому Audit-событию, которое зафиксировало эту операцию.

Без этой границы корректное состояние Desired State могло совпасть с ожидаемым, но повреждённый или подменённый `audit_event_id` в durable rollback receipt не был бы отдельно доказан перед возвратом success.

## Production boundary

`GuardedHouseholdPolicyWorkflowService.rollback()` после существующей проверки Desired State/history вызывает отдельную fail-closed проверку Audit binding.

Для обычного rollback проверяются:

- exact actor;
- exact `rollback_id`, вычисленный из actor и закрытого rollback request;
- exact `resource_key`, current generation/bundle и target history generation/bundle;
- exact materialized policy value: current history обязан содержать тот же полный bundle value, что и выбранная target history revision, а не только совпадающий `bundle_id`;
- exact completion Audit event `household.policy.desired-state.rollback.complete`;
- ожидаемый outcome `succeeded` либо `already-current`;
- exact `history_evidence_sha256` фактически архивированной новой/current generation;
- запрет provider execution и infrastructure mutation authority;
- ссылка completion event на exact `rollback.begin` event;
- exact begin-event preconditions: исходные generation/bundle и выбранная history revision.

Для recovery после неоднозначного прерывания проверяется exact Audit event `household.policy.desired-state.rollback.recover` с outcome `finalized-existing-write`, тем же actor/resource/rollback id, фактической generation/bundle и history evidence. Exact materialized value проверяется одинаково для normal completion и recovery.

Idempotent replay `already-rolled-back` не создаёт новое доказательство: он обязан повторно пройти проверку исходного exact completion/recovery Audit event и той же materialized target value.

## Fail-closed semantics

Отсутствующее, повреждённое, чужое или не соответствующее request/state Audit evidence классифицируется существующим integrity-кодом `household_policy_rollback_evidence_mismatch`. На HTTP-границе он уже является `503 Service Unavailable`, поэтому повреждение локального evidence не маскируется под ошибку пользовательского запроса.

Проверка не добавляет новых mutation capabilities и не выдаёт provider execution, network/storage/account/device-management либо external publication authority.

## Qualification source

Подготовлены source-tests для:

- exact completion + begin Audit binding;
- exact equality materialized target/current history value, включая fail-closed случай одинакового `bundle_id` при отличающемся value;
- idempotent replay с тем же доказательством;
- отказа при ссылке receipt на постороннее Audit event;
- отказа при неверных preconditions в begin event;
- exact recovery Audit binding;
- no-op rollback с тем же exact value invariant.

Этот runner-free поток тесты не запускает. Фактическая qualification должна выполняться отдельным разрешённым runner/release-потоком до promotion 0.59.
