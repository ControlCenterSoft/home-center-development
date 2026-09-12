# Household Policy Composer — архитектура Home Center 0.59

## Назначение

Policy Composer переводит бытовую роль участника семьи (`RolePreset` / `EffectivePolicy`) в проверяемый `PolicyBundle`, который одинаково идентифицируется в интерфейсах «Уютный» и «Полный». Компонент не является механизмом исполнения инфраструктурных действий: его граница заканчивается на защищённом локальном Policy Desired State.

## Архитектурные инварианты

1. **Один policy evidence для двух интерфейсов.** «Уютный» показывает краткое объяснение, «Полный» — техническое содержимое, но оба используют один `proposal_id`, `bundle_id`, Household revision и Desired State precondition.
2. **Явное подтверждение обязательно.** `plan` никогда не выдаёт полномочия на запись. `confirm` принимается только с `confirmed=true`, повторно проверяет actor binding, Household snapshot и ранее наблюдавшуюся policy revision.
3. **Optimistic concurrency fail-closed.** Proposal фиксирует `expected_desired_state_generation` и `expected_desired_state_bundle_id`. Более новая policy revision не может быть тихо перезаписана старым proposal.
4. **Desired State не является execution authority.** Материализованный bundle содержит `desired_state_write_authorized=false`, `infrastructure_mutation_authorized=false` и `external_publication_authorized=false`. Provider/job/execution boundary не вызывается.
5. **Внешняя публикация запрещена.** Policy HTTP routes доступны только через существующую authenticated/same-origin внутреннюю HTTP boundary и отдельно отклоняют externally classified requests.
6. **История проверяема.** Каждая сохранённая policy revision связывается с SHA-256 evidence и keyed append-only Audit chain. Повреждение payload/evidence/audit трактуется как недоступность доверенного состояния, а не как пользовательская ошибка.
7. **Rollback — новая ревизия.** Откат не уменьшает generation. Ранее подтверждённый bundle материализуется как новая monotonic generation только после явного подтверждения и проверки exact current revision.
8. **Повторы идемпотентны.** Повтор подтверждения, apply и rollback не создаёт повторную мутацию и не увеличивает generation без изменения policy.
9. **Успех доказывается post-condition, а не receipt.** Перед успешным ответом apply/rollback orchestration связывает receipt с точным proposal/confirmation, immutable history и фактическим текущим Desired State. Несовпадение означает fail-closed integrity error.
10. **Persisted PolicyBundle проверяется семантически.** Помимо SHA-256/Audit evidence проверяются закрытая форма bundle, точное соответствие `RolePreset`, `EffectivePolicy`, `policy_id`, `bundle_id`, resource scope, бытового explanation и всех authority-флагов. Архивированный, но семантически подменённый bundle не считается доверенным.
11. **Resource identity не зависит от разделителя внутри ID.** Для обычных delimiter-safe Household/member ID сохраняется читаемый ключ `household-policy:<household>:<member>`. Если хотя бы один ID содержит `:`, точная пара Household/member связывается с SHA-256 suffix `hpk-*`; две разные пары идентификаторов не могут получить один Desired State key из-за неоднозначной конкатенации. Semantic evidence обязан заново вычислить тот же ключ, а не доверять persisted строке.

## Поток данных

`Household snapshot -> Policy Composer -> durable proposal -> presentation -> explicit confirmation -> protected Desired State writer -> immutable history/Audit`

После записи Policy Desired State дальнейшее применение к устройству, сети, VPN, аккаунту или внешнему provider остаётся отдельной capability boundary и не входит в 0.59.

## Состояния proposal

- `pending` — proposal построен и может быть подтверждён, пока все preconditions остаются точными;
- `confirming` — durable промежуточный marker; автоматическое продолжение запрещено, требуется recovery;
- `confirmed` — confirmation evidence зафиксировано; само по себе оно не разрешает произвольную запись или provider execution;
- `invalidated` — evidence/precondition больше нельзя доказать, повторное использование запрещено.

Confirmation recovery возвращает только доказуемо неизменившийся proposal в `pending`; stale или повреждённый proposal остаётся fail-closed.

## Crash consistency записи

Protected Desired State writer использует следующий порядок:

1. сохранить `applying` marker;
2. записать pre-write Audit evidence;
3. выполнить SQLite compare-and-set exact revision;
4. записать completion Audit evidence;
5. сохранить durable apply receipt.

Если процесс остановился после шага 3, replay обязан сначала доказать exact target bundle в Desired State. Только доказанный exact-state разрешает финализацию evidence без второй мутации. В противном случае операция остаётся fail-closed.

Rollback использует аналогичный durable `applying/applied/invalidated` протокол и exact current-state precondition. В исходном коде подготовлены fault-injection tests для потери процесса сразу после committed CAS, после completion Audit до durable `applied` marker и после rollback Desired State commit до history archive. Их фактическое выполнение относится к runner-dependent qualification и до неё не считается доказанным.

## HTTP boundary

Подготовленные routes:

- `POST /api/v1/household/policies/plan`;
- `POST /api/v1/household/policies/confirm`;
- `POST /api/v1/household/policies/recover`;
- `POST /api/v1/household/policies/rollback`;
- `GET /api/v1/household/policies/history?resource_key=...`.

Все POST routes наследуют аутентификацию, обязательную смену начального пароля и same-origin protection. Policy-specific external access дополнительно запрещён независимо от настроек внешней публикации других Home Center endpoints.

Классификация ошибок отделяет конфликт состояния (`409`), отсутствие/запрет доступа (`404/403`) и нарушения доверия к persisted evidence (`503`). Повреждение локального evidence не маскируется под `400 Bad Request`.

## Контракты

Публичная API-форма 0.59 использует закрытые JSON Schema (`additionalProperties=false`) для plan/confirm/recovery requests и результатов, presentation, confirmation/apply, history и rollback. Поля authority в результатах должны оставаться константно `false`; расширение capability требует отдельного архитектурного решения и нового qualification gate. `desired_state_resource_key` принимает только безопасную читаемую форму для ID без `:` либо collision-safe `hpk-*` форму для идентификаторов с разделителем; произвольная неоднозначная строка не является допустимым policy evidence.

## Single-node и HA

Policy state хранится через штатный StateStore/SQLite boundary и поэтому должен проходить те же backup/restart/replication требования, что и остальные критические состояния Home Center. До Release Candidate требуется доказать:

- single-node restart без потери proposal/confirmation/apply/history/rollback state;
- backup/restore с сохранением Audit evidence и идемпотентного replay;
- поддерживаемый multi-node HA/restart path без split-brain policy materialization;
- install/upgrade с сохранением Household, Policy Desired State, истории, пользовательских настроек и локальной аутентификации.

Наличие исходного кода без этих qualification evidence не делает 0.59 Release Candidate или Stable.

## Коммерческая и модульная граница

Policy Composer не должен скрыто активировать платную услугу, подписку, Market-модуль или внешний provider. Entitlement может ограничивать доступность отдельного модуля на более высоком уровне, но сам policy contract не получает billing authority и не выполняет покупку/активацию. Любая будущая коммерческая интеграция обязана быть явной, аудируемой и отделённой от локального policy evidence.

## Что не входит в 0.59

Не входят provider-specific provisioning, VPN/account/profile execution, детальные parental/proxy filtering rules, quotas и расписания, а также любые функции последующих релизных границ. Эти возможности нельзя добавлять в 0.59 обходным путём через Policy Composer.
