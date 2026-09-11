# Home Center

Home Center — infrastructure-neutral и local-first платформа управления домашней и малой серверной инфраструктурой через единый Web UI и API.

## Текущий релизный статус

- Последний официальный canonical/source release: **0.47.0**.
- Полноценный **PUBLIC STABLE RELEASE 0.47.0** опубликован в [`ControlCenterSoft/home-center-stable`](https://github.com/ControlCenterSoft/home-center-stable) с tag `v0.47.0`, официальным GitHub Release, Linux/source artifacts, SHA256SUMS, acceptance/release manifests и SPDX SBOM.
- Более новые возможности не считаются доступными пользователю до собственной qualification и официальной публикации соответствующей release identity.

## Основные принципы

Home Center устанавливается на новую или существующую поддерживаемую инфраструктуру и не зависит от конкретных имён узлов, доменов, сетевых адресов или одной фиксированной топологии. Runtime identity и topology задаются через discovery, enrollment и deployment profiles. Directory integration является опциональной и настраивается администратором.

Single-node является полноценным режимом. Multi-node/HA расширяет продукт только там, где роли и providers имеют проверенные failure/recovery semantics. Опасные изменения проходят общий безопасный путь authorization → plan/Desired State → Change/Job → typed execution → Actual State → post-condition verification → Audit/evidence → recovery/rollback.

## Интерфейс 0.47

Home Center 0.47.0 завершает первый полный navigation boundary интерфейса «Уютный» и сохраняет профессиональный интерфейс «Полный».

- «Домой» показывает понятное состояние дома, серверов и доступных возможностей.
- «Семья» отображает household-oriented людей и роли; mutation/provisioning остаются за отдельными защищёнными границами последующих версий.
- «Мой дом» показывает только реально обнаруженные capabilities, а не заранее заявленный набор сервисов.
- На мобильных устройствах используется нижняя навигация с крупными touch targets; на desktop — компактная боковая навигация.
- Переключение «Уютный ↔ Полный» не создаёт отдельного execution path и не ослабляет RBAC, Audit, stale-state, recovery и post-condition проверки.

## Аутентификация после чистой установки

После чистой установки создаётся локальный пользователь `admin` с первоначальным паролем `admin`. При первом входе пароль требуется сменить; до смены обычная работа запрещена. При обновлении установленный пользователем пароль сохраняется и не сбрасывается к первоначальному значению.

## Публичная граница

Публичные материалы Home Center не должны содержать реальные deployment IP/host/domain/SID, credentials, private keys, production certificates, operator-specific overlays, внутреннюю инфраструктуру разработки, runner-инфраструктуру, названия внутренних AI/reviewer-процессов или иные сведения, не требующиеся пользователю продукта.

Технические инструкции и release notes должны соответствовать фактически опубликованной версии. Возможности последующих версий необходимо явно отделять от текущего Public Stable.
