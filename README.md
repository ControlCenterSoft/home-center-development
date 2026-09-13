# Home Center

Home Center — infrastructure-neutral локальная платформа управления домашней и малой серверной инфраструктурой через единый Web UI и API.

## Текущий статус

- Текущий официальный **PUBLIC STABLE — 0.63.0**, опубликованный в `ControlCenterSoft/home-center-stable` как `v0.63.0`.
- Текущая development-линия **0.64.0 — COMMITTED**: Recommendations и safe auto-repair. Реализуемые foundation-срезы не дают автоматическую mutation authority сами по себе; пользовательский успех допустим только после точной revalidation, типизированного исполнения и authoritative post-condition verification.
- Функции, разработанные после 0.63.0, не считаются доступными пользователю до собственной qualification и отдельной публикации соответствующего Stable release.

## Граница продукта

Home Center должен устанавливаться на новую или существующую поддерживаемую инфраструктуру без зависимости от конкретного deployment. Product source не должен содержать жёстко заданные реальные имена узлов, доменные имена, directory identifiers, сетевые адреса, credentials, сертификаты или topology конкретной среды оператора.

Runtime identity и topology задаются discovery, enrollment и deployment profiles. Directory integration является опциональной и настраивается администратором. Compute, storage, device, automation, certificate и remote-access providers выбираются через capabilities и provider profiles, а не через фиксированные hosts.

## Допустимое содержимое репозитория

- product source и Web UI;
- переносимая deployment/enrollment логика;
- schemas и API contracts;
- infrastructure-neutral tests и проверки качества;
- infrastructure-neutral документация и примеры;
- release и feature implementation, не содержащая данных конкретной операторской среды.

## Недопустимое содержимое

- credentials, private keys и production certificates;
- реальные deployment IP-адреса, host names, directory SIDs и private realms;
- operator-specific deployment overlays;
- production acceptance evidence с приватными деталями инфраструктуры;
- внутренние server-only operational данные.

Такие operational materials должны храниться вне публичной продуктовой документации и публичного product-development контента.

## Требования к документации

Пользовательская и продуктовая документация ведётся на русском языке и должна соответствовать фактически опубликованному Stable состоянию. Целевые и development-возможности обозначаются отдельно и не описываются как доступные пользователю до qualification/promotion.

Публичная документация не раскрывает внутреннюю методологию разработки и сборки, служебную инфраструктуру, внутренние адреса, секреты, рабочие репозитории/ветки, модели AI или иные внутренние сведения, не требующиеся пользователю и администратору Home Center.
