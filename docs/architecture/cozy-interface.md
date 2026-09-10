# Home Center — интерфейс «Уютный» и Household/Intent Layer

Статус: принятое фундаментальное архитектурное решение.

## Назначение

«Уютный» — обязательный второй интерфейс Home Center. Это не отдельный продукт, не тема оформления и не урезанная редакция. Его задача — дать домашнему пользователю максимальный результат при минимальном количестве действий и скрыть инфраструктурные детали там, где они не нужны для бытового сценария.

Главное UX-правило: **Home Center знает, как устроена инфраструктура; пользователь указывает, чего он хочет.**

## Два уровня управления

Home Center имеет два взаимодополняющих интерфейса:

- **«Уютный»** — mobile-first интерфейс для повседневного домашнего управления: крупные элементы, короткие сценарии, готовые безопасные настройки и отсутствие прямых опасных операций;
- **«Полный»** — профессиональный интерфейс со всеми техническими параметрами, узлами, ролями, сетью, хранилищами, сервисами, политиками, журналами и диагностикой.

«Уютный» не является уменьшенной копией полного интерфейса. Он работает через бытовые намерения и доменные модели верхнего уровня.

## Пользовательские сущности

### «Домой»

Сводное состояние дома: домашние сервисы, семья, интернет/VPN, детские ограничения, умный дом, мультимедиа, игровые сервисы, резервные копии и только действительно важные уведомления.

### «Семья»

Человек является основной сущностью, а устройства и политики привязываются к нему. Базовые бытовые роли: `parent`, `child`, `guest`. Выбор роли применяет готовый RolePreset/PolicyBundle, а не только RBAC-права.

В зависимости от доступных providers RolePreset может включать identity/account, переносимый профиль и домашние каталоги, доступы к домашним ресурсам, internet/DNS policy, лимиты и расписания, VPN policy, managed-device policy, мультимедиа, игровые сервисы и разрешения умного дома.

### «Мой дом»

Бытовое представление домашней инфраструктуры: Интернет, Умный дом, Фильмы и музыка, Игры, Файлы, Сервер, Резервные копии и дополнительные домашние сервисы. Конкретные backend-технологии не должны без необходимости появляться в основном «Уютном» потоке.

## Архитектурная цепочка

`Cozy UI → Household/Intent API → Policy Composer → Core API / Desired State → Reconciler / Execution → Actual State → Post-condition verification`

«Уютный» не получает отдельный путь исполнения. Все изменения сохраняют общие гарантии Home Center: authorization, typed actions, idempotency, stale-state protection, Audit/evidence, post-condition verification и recovery/rollback semantics.

## Базовая доменная модель

Household/Intent foundation должна включать или семантически эквивалентно представлять:

- `Household`;
- `FamilyMember`;
- `HouseholdRole`;
- `ManagedDevice`;
- `RolePreset`;
- `PolicyBundle`;
- `EffectivePolicy`;
- `UserIntent`;
- `RecommendedAction`.

Точная физическая реализация может эволюционировать, но эти смысловые границы не должны растворяться в provider-specific конфигурации.

## Safety invariants

- safe-by-default и default deny для неподтверждённых privileged возможностей;
- destructive actions и raw network/storage/node operations не являются обычными бытовыми действиями;
- UserIntent сначала преобразуется в проверяемый plan/Desired State;
- автоматическое исправление допускается только для типизированных, проверяемых и recoverable сценариев;
- итоговый успех определяется Actual State и post-condition verification;
- EffectivePolicy должна быть объяснима уполномоченному пользователю;
- отказ provider не должен молча ослаблять child/security/network/VPN policy;
- внешняя публикация, NAT/port-forwarding и иные рискованные функции не включаются неявно.

## Mobile-first и onboarding

«Уютный» проектируется прежде всего для телефона: крупные touch targets, одна основная задача на экран, минимум полей, готовые пресеты, прогрессивное раскрытие деталей и бытовая терминология. Device/guest onboarding должен стремиться к минимальному числу действий и поддерживать безопасный QR/bootstrap flow там, где это уместно.

## Фактическая релизная граница

Опубликованный исходный релиз Home Center — `0.23.0`. «Уютный» не расширяет его durable service-transition scope.

Текущая подтверждённая кандидатная линия после него распределена так:

- `0.24.0` — read-back verification и audited apply boundary для durable transition;
- `0.25.0` — completion audit результата read-back verification;
- `0.26.0` — Household/Intent foundation: Household, FamilyMember, ManagedDevice, роли, RolePreset/EffectivePolicy и side-effect-free intent planning;
- `0.27.0` — versioned Household persistence с generation/resource-version и optimistic concurrency;
- `0.28.0` — exact-state Household/Intent proposal и stale-state revalidation;
- `0.29.0` — fail-closed compatibility admission для verified Module Manifest v2 artifacts;
- `0.30.0` — exact-state revalidation ранее сформированного module-admission decision;
- `0.31.0` — canonical runtime compatibility snapshot и привязка набора admission decisions к одному точному состоянию;
- `0.32.0` — batch exact-state revalidation полного module-admission set;
- `0.33.0` — cross-candidate compatibility evaluation набора module candidates на одном runtime snapshot;
- `0.34.0` — exact-state revalidation ранее оценённого module candidate set с обнаружением drift runtime state, membership, version/artifact binding и aggregate compatibility.

Контракты `0.29.0–0.34.0` являются evidence-only: они не разрешают installation, execution, external publication или production mutation.

Полноценный mobile-first UI «Домой»/«Семья»/«Мой дом», role-driven provisioning, рекомендации, QR-гости и безопасный auto-repair остаются следующими пользовательскими этапами. Их номера версий фиксируются только после появления соответствующего фактического состава кода; уже занятые версии `0.24.0–0.34.0` не переиспользуются.

## Правило для новых возможностей

Каждая новая пользовательская capability Home Center должна определить:

1. техническое представление в Full/Core API;
2. бытовое представление в Household/Intent API либо явное обоснование неприменимости;
3. mapping intent/policy → Desired State;
4. safety gates и permissions;
5. post-condition verification и recovery behavior.

## Non-goals

«Уютный» не должен становиться отдельным продуктом, иметь несовместимую с Core модель данных, обходить RBAC/Change/Job/Audit/Reconciler, скрывать критическую неисправность, автоматически включать внешнюю публикацию или заменять профессиональную RBAC-модель бытовыми ролями.
