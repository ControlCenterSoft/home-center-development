# Home Center — политика оркестрации разработки и выпуска

Статус: **CURRENT / NORMATIVE FOR DEVELOPMENT OPERATIONS**

Основной язык документации — русский. Английский используется только для API/идентификаторов, кода, команд, протоколов/стандартов, официальных названий внешних технологий и английской UI-локализации.

## 1. Ресурсная политика

Общий development/runner capacity: Control Center 60%, Home Center **30%**, Website / Client Portal / Admin Portal 10%. Свободная квота может временно заимствоваться, но возвращается Home Center на ближайшей 10-минутной точке при наличии готовой очереди.

## 2. Release-first и anti-drift

Для Home Center контролируются Code Drift, Release Drift, Production/Site Drift и Documentation Drift. Текущий development scope не должен накапливаться несколькими будущими release lines поверх невыпущенного текущего train.

Режимы: `NORMAL`, `DRIFT WARNING`, `RELEASE RESCUE`. При `RELEASE RESCUE` 70–80% собственной квоты Home Center направляется на integration, regression/security, qualification, Stable promotion, site sync и документационное выравнивание до сокращения release debt.

## 3. Definition of Done

Полная цепочка:

`актуальный RoadMap/ТЗ → implementation → tests/security → Gemini review → integration → GitHub docs sync → Google Drive docs sync → release qualification → Stable branch/release → site/LK sync при применимости → production verification`.

Merge в main или source release без применимых последующих стадий не означает `DONE`.

Gemini используется как независимый reviewer. После двух подряд технически невозможных попыток review фиксируется `SKIPPED_TECHNICAL_FAILURE`, и разработка продолжается. Реальные `BLOCKER`/`HIGH` findings должны быть устранены до соответствующего release gate.

Каждый начатый release train должен завершаться immutable Public Stable. Исторические tags/assets не переписываются задним числом.

## 4. UI/UX, Figma и RU/EN

Интерфейсы «Уютный» и «Полный» развиваются как единая современная, визуально цельная и отполированная система. Figma является рабочим design-source для design system, макетов и visual QA.

Обязательны mobile-first для «Уютного», responsive desktop/tablet/mobile, единые typography/grid/spacing/components/forms/tables/charts/icons, accessibility/keyboard navigation и явные loading/empty/error/unknown/stale/degraded состояния.

Пользовательский интерфейс поддерживает русский и английский языки через единый i18n-слой. Hardcoded RU/EN user-facing строки в новой или изменяемой реализации не считаются завершённой работой. UI не должен опережать реальные contracts/API/capabilities.

## 5. Документация

Каждый существенный slice до начала работы сверяет актуальные канонические документы, а после изменения architecture/API/UI/security/recovery/release status проверяет и при необходимости синхронизирует:

- канонический Google Drive RoadMap/ТЗ;
- repository-side architecture/contracts/release docs;
- Stable documentation;
- production-facing site claims.

Documentation Drift является дефектом и release blocker для затронутой capability. Документация ведётся максимально на русском языке.

## 6. Почасовая диспетчеризация

До 15 общих рабочих задач диспетчеризируются в `*:00`, `*:10`, `*:20`, `*:30`, `*:40`, `*:50`. Долгие операции не прерываются искусственно. В `*:00` формируется простой delta-отчёт: что изменилось, что приблизилось или вышло в Stable, изменения сайта, документация, Gemini, блокеры и следующий ожидаемый результат.
