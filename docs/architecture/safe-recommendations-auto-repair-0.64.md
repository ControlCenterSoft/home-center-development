# Home Center 0.64 — рекомендации и безопасный auto-repair: plan-only foundation

Статус: source-only foundation; не Release Candidate и не Public Stable.

## Назначение

0.64 развивает фундамент `UserIntent` / `RecommendedAction` в сторону explainable
recommendations и безопасного auto-repair. Этот слой **не выполняет исправления** и
не создаёт обходной путь вокруг общего lifecycle Home Center.

Любая рекомендация строится только из типизированного evidence, привязанного к
точному Household snapshot. План имеет детерминированный content-addressed
`plan_id`, отдельную русскую бытовую формулировку для «Уютного» и техническую
причину для «Полного» интерфейса.

## Разрешённые классы foundation

- `managed-device-policy` — устройство члена семьи требует повторной проверки
  management policy;
- `household-policy-reconciliation` — требуется повторная сверка Household policy;
- `compatibility-evidence-refresh` — устаревшее read-only compatibility evidence
  может быть безопасно обновлено.

Список закрытый. Неизвестные классы не превращаются в generic command.

## Безопасность

План всегда сохраняет:

- `mutation_authorized=false`;
- `automatic_execution_authorized=false`;
- `provider_execution_authorized=false`;
- `infrastructure_mutation_authorized=false`;
- `external_publication_authorized=false`;
- `post_condition_verification_required=true`;
- `recovery_required=true`.

`automation_eligible=true` в foundation означает только, что класс может быть
рассмотрен будущим квалифицированным automation runtime. Это **не** разрешение
на исполнение. Сейчас таким низкорисковым классом является только read-only
refresh compatibility evidence.

Risk-bearing reconciliation требует явного подтверждения. Любая будущая
execution-реализация обязана идти через штатную цепочку
Identity/RBAC → exact plan/Desired State → Change/Job → typed execution →
Actual State/read-back → post-condition verification → Audit → rollback/recovery.

## Fail-closed boundaries

Планирование блокируется при:

- отключённом или не-parent actor;
- drift точного Household snapshot;
- future/expired evidence;
- неизвестном/выключенном subject member;
- несовпадении device/member;
- уже устранённой причине рекомендации;
- изменении content-addressed evidence или plan identity;
- попытке включить любую execution/mutation/publication authority в сохранённом
  или переданном плане.

## Release boundary

VERSION не повышается. API route, durable Job executor, provider adapter,
automatic repair executor и production mutation в этом slice отсутствуют.
Следующий 0.64 slice может добавлять admission/execution только для конкретного
allowlisted repair class после отдельной qualification; 0.65+ в эту работу не входит.
