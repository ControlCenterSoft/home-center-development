# Home Center

Home Center — инфраструктурно-независимая платформа управления домашней и небольшой серверной инфраструктурой через единый Web UI и API.

## Текущий релизный статус

- Последний официальный canonical/source release в линии выпуска: **0.42.0**; фактическая canonical availability подтверждается только tag `v0.42.0` и официальным GitHub Release после завершения release governance.
- До завершения отдельного полноценного public export/release для 0.42.0 текущим подтверждённым **PUBLIC STABLE RELEASE** остаётся **0.41.0** в [`ControlCenterSoft/home-center-stable`](https://github.com/ControlCenterSoft/home-center-stable).
- Canonical и public stable используют раздельные подтверждённые release identities; sanitization/export может закономерно давать другой public commit SHA, поэтому соответствие фиксируется через version/digest/manifest mapping.
- Более новые development-возможности считаются доступными только после собственной release qualification и официальной публикации соответствующей release identity.

Home Center 0.42.0 добавляет canonical versioned requirement-set contract для точных Home Service/API contract revisions, требуемых модулю. Requirement-set evidence остаётся descriptive-only и не предоставляет authority на admission, installation, execution, production mutation или external publication.

## Архитектурная граница продукта

Home Center должен устанавливаться на новую или существующую поддерживаемую инфраструктуру без зависимости от конкретных имён узлов, доменов, адресов, directory identifiers, credentials, сертификатов или заранее заданной топологии.

Runtime identity и topology поступают через discovery, enrollment и deployment profiles. Directory integration является опциональной. Compute, storage, device, automation, certificate и remote-access возможности выбираются через типизированные capabilities и provider profiles.

## Интерфейсы

Home Center имеет два дополняющих уровня интерфейса: полный технический интерфейс и mobile-first интерфейс **«Уютный»**. «Уютный» — часть Home Center, а не отдельный продукт и не тема оформления.

Каноническая архитектурная граница «Уютного» описана в `docs/architecture/cozy-interface.md`. Пользователь формулирует бытовое намерение, а Home Center преобразует его в безопасный policy/desired-state plan через обычные Identity/RBAC, Change/Job, verification и recovery boundaries.

Household/Intent foundation формировался в development-линии начиная с версии 0.26.0 и входит в накопленную более позднюю исходную линию. Сам номер development-версии не означает наличие отдельного официального GitHub Release: пользовательская доступность определяется только фактически опубликованной release identity соответствующего канала.

## Основные требования безопасности

- deny-by-default Identity/RBAC;
- явное разделение Desired State и Actual State;
- типизированные операции вместо generic shell/root API;
- stale-state и tamper protection для подтверждений и evidence;
- обязательный post-condition verification для изменяющих state операций;
- Audit без credentials и секретов;
- backup/recovery semantics для stateful данных;
- infrastructure-neutral examples и deployment artifacts;
- внешняя публикация, routing/NAT и provider execution только через отдельные явно разрешённые границы.

## Первый вход

После чистой установки создаётся локальный пользователь `admin` с первоначальным паролем `admin`. При первом входе пароль необходимо сменить; до смены обычная работа запрещена. При обновлении установленный пользователем пароль сохраняется и не сбрасывается к первоначальному значению.

## Документация

Продуктовая документация должна соответствовать фактически опубликованному состоянию релизов. Планируемые возможности должны быть явно отделены от выпущенных.

В документации запрещено публиковать credentials, private keys, реальные deployment identifiers, внутренние адреса, приватную топологию, персональные данные и сведения о внутренней инфраструктуре или методологии разработки.
