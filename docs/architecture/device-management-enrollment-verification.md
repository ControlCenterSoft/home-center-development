# Проверка фактического подключения управляемого устройства

## Назначение

Home Center разделяет два разных факта:

1. провайдер **принял команду** подключения устройства;
2. устройство **фактически подключено** и это подтверждено отдельной проверкой состояния.

Первый факт сам по себе никогда не разрешает перевести устройство в `managed=true`. Такое изменение допускается только после второго факта и повторной проверки локального состояния Home Center.

## Граница доверия

Provider verification adapter считается источником наблюдения, а не источником полномочий. Он может подтвердить состояние внешней системы, но не может:

- менять Household state;
- присваивать `managed_state_change_authorized=true`;
- применять MDM, сетевые, файловые или иные политики;
- изменять инфраструктуру узлов;
- включать внешнюю публикацию сервисов.

Adapter регистрируется для verification только если явно объявляет read-only семантику. Полученный от него результат принимается только при точной связи с ранее сохранёнными `verification_id`, `provider_operation_id` и `device_id`.

## Последовательность

1. 0.57 execution должен находиться в состоянии `provider-accepted` и не иметь принятой команды отмены.
2. Home Center строит verification plan из exact execution plan/receipt и exact Household snapshot.
3. Пользователь явно подтверждает выполнение проверки.
4. Создаётся durable Job; до обращения к провайдеру `managed_state_change_authorized=false`.
5. Read-only adapter проверяет фактическое состояние провайдера.
6. Home Center принимает только результат с `enrollment_completed=true` и `post_condition_verified=true`, при этом сам provider result обязан сохранять `managed_state_change_authorized=false`.
7. Home Center повторно проверяет execution identity, actor binding и неизменность Household snapshot.
8. Ожидаемый новый Household snapshot вычисляется детерминированно: изменяется только `managed` целевого устройства.
9. Локальный commit выполняется compare-and-set относительно фактически прочитанного состояния. Конкурентное изменение Household приводит к отказу без перезаписи чужих данных.
10. После успешного commit durable Job получает evidence, а verification receipt фиксирует `managed_state_change_authorized=true`. Остальные mutation authorities остаются `false`.

## Fail-closed условия

Операция блокируется, если:

- execution отсутствует, отменён или не находится в `provider-accepted`;
- Household snapshot изменился после execution/verification plan;
- устройство уже `managed=true`;
- actor больше не связан с Household или не совпадает с actor исходного execution;
- provider operation/device binding не совпадает;
- провайдер пытается вернуть mutation authority;
- provider result не подтверждает завершение подключения;
- concurrent Household mutation обнаружена перед локальным commit;
- durable state, receipt или commit evidence имеют несогласованную identity.

## Повтор и восстановление

До локального commit подтверждённый provider result сохраняется в durable Job. После формирования `applying` состояния Home Center может завершить локальный commit без повторной команды подключения. Повтор после успешного commit возвращает ранее зафиксированный receipt только если текущий Household snapshot точно совпадает с ожидаемым результатом. Несовпадение после commit считается конфликтом состояния и не исправляется автоматически.

## Single-node и HA

Verification не создаёт отдельной модели владения кластером. Она использует существующую single-writer границу Home Center и durable StateStore. В multi-node конфигурации изменение Household state должно исполняться только на текущем авторитетном writer. Read-only provider observation не даёт standby-узлу права выполнять state mutation.

## Следующая граница

`managed=true` означает только подтверждённый факт подключения устройства к управлению. Он **не означает**, что MDM или другие политики уже применены. Применение политик должно иметь отдельные plan/confirm/execute/post-condition границы и собственные rollback/evidence правила.
