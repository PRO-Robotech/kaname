<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: снятие регистрации объекта снимает его выдачи

- **Статус:** DRAFT, редакция 2. Вердикта на эту редакцию нет, санкции на код нет (ban #1).
  Вердикт выносит `acceptance-reviewer`
- **Статическая форма:** DRAFT. Слово вписано автором и вердиктом не является. Действующее
  одобрение выводится из записи ревью по отпечатку редакции и из внешнего события, на которое
  запись ссылается (`change-graph.md` §3). После ревью слово DRAFT не правится
- **История ревью:** только дописывается строками вида «дата · круг · вердикт · SHA-256
  редакции · путь записи». Прежние строки не правятся и не удаляются. Записи кладутся в
  `docs/specs/reviews/unregistration-revokes-its-grants/<sha256>.yaml`
  - 2026-10-24 · круг 1 · ⛔ CHANGES_REQUESTED (CONSTRUCTIBILITY ×2, COVERAGE, SCOPE ×2) ·
    `12c38a0c07fcbbec232c817b4e0e683505367e66ba9f40247feb7764abaa97a5` ·
    `docs/specs/reviews/unregistration-revokes-its-grants/12c38a0c07fcbbec232c817b4e0e683505367e66ba9f40247feb7764abaa97a5.yaml`
  - 2026-10-24 · правка ПОСЛЕ вердикта `12c38a0c…` · редакция 2: закрыты пять блокирующих и
    четыре важных замечания круга 1 решениями диспетчера 1–5. Вердикт `12c38a0c…` относится к
    редакции 1 и на эту редакцию не переносится. Что закрыто — раздел «Редакция 2: что закрыто»
- **Дата:** 2026-10-24 · **редакция:** 2
- **Задача:** `PRO-Robotech/kaname#963`; связь — `PRO-Robotech/kaname#965` (манифест не
  ссылается на конкретные объекты)
- **Ревизия измерения:** kaname `318f793bb` (голова ветки `963`). Каждое число о дереве
  ниже снято на этой ревизии командой, приведённой рядом. Конструируемость «Дано» показана
  чтением писателя со строкой (раздел «Мир проб», таблица «Дано → писатель»); посева не было:
  стенда и слота у полосы нет
- **Решения диспетчера 2026-10-24** вписаны как принятые (§3, Р1–Р5; редакция 2 — Р6–Р8).
  Решения автора, выведенные из них и из одобренных соседей, помечены «Д» (§3, Д1–Д7)
- **Тип изменения:** контракт `.proto` (новое поле выхода `AccessBinding.revocation_reason`,
  правка комментариев), новая миграция (колонка причины, предикат индекса уникальности,
  ограничение `roles_permissions_valid`), поведение `InternalIAMService.UnregisterResource`,
  `AccessBindingService.Create`, `RoleService.Create`/`Update`, перерасчёта, структурных
  проверок выдачи
- **Сервис:** `kaname`

---

## §0. Перепись производителей — до сценариев

### 0.1. Кто снимает регистрацию объекта

```sh
git grep -n "func (uc \*RegisterResourceUseCase) Unregister" -- '*.go'
# → internal/apps/kaname/api/internal_iam/register_resource.go:533
git grep -c -i "accessbinding\|access_binding" -- internal/apps/kaname/api/internal_iam/register_resource.go
# → пусто (0)
```

Снятие (`Unregister`) удаляет строку зеркала объекта (`kaname.resource_mirror`), ставит в
журнал снятие кортежа запроса и остаточных кортежей объекта, со-коммитит событие перерасчёта
и после фиксации зовёт проход перерасчёта по объекту. Строку зеркала оно удаляет, только
если версия-надгробие запроса не старше хранимой версии регистрации. Снятие публикации
(`system_class:anonymous #v_get`, `isPureGrant`) идёт своей ветвью и строку зеркала не
трогает. Выдач (`kaname.access_bindings`) и ролей снятие не читает и не пишет — 0 упоминаний.

### 0.2. Кто переводит выдачу в REVOKED

Двумя предикатами:

```sh
# по написанию
git grep -n -E "SET status += 'REVOKED'" -- '*.go' ':!*_test.go'
# → 2: internal/repo/kaname/pg/access_binding_repo.go:857 (RevokeGuarded)
#      internal/repo/kaname/pg/reconcile_adapter.go:1462 (RevokeExpiredBinding)
# по предмету — вызовы писателей статуса в прод-коде
git grep -n -E "\.RevokeGuarded\(|\.RevokeExpiredBinding\(|\.TransitionStatus\(" -- '*.go' ':!*_test.go'
# → 2: internal/apps/kaname/api/access_binding/revoke.go:186 (глагол Revoke)
#      internal/apps/kaname/api/access_binding/reconcile/reconcile.go:793 (истечение срока)
```

Третий писатель `TransitionStatus` (`access_binding_repo.go:941`) пишет статус параметром,
поэтому первый предикат его не видит. Вызовов в прод-коде у него нет (второй предикат).
Итого путей отзыва сегодня два: глагол `Revoke` (`revoked_by_user_id` — вызывающий) и
истечение срока (`revoked_by_user_id` пуст). Физически выдачи снимают `Delete` и снос области
(`shared.RevokeBindingsInScope`, `internal/apps/kaname/shared/revoke_scope_bindings.go:93`).

### 0.3. Причина отзыва в модели выдачи

```sh
git grep -n "revocation_reason\|revoked_reason" -- internal/migrations/ proto/ | grep -ci access_binding
# → 0
```

Модель отзыва выдачи сегодня — `status = REVOKED`, `revoked_at`, `revoked_by_user_id`
(`proto/kaname/cloud/iam/v1/access_binding.proto:104`, `:107`; ограничение
`access_bindings_revoked_consistency_ck`, `internal/migrations/0001_initial.sql:1629`).
Поля причины нет. Причина отзыва есть у соседних записей: `token_families.revoked_reason`
(закрытый словарь, `20260920175117_authorization_code_is_our_record.sql:209`), `RoleLifecycle.retired_reason`
(`role.proto:369`).

### 0.4. Кто читает цель выдачи и названия правила роли

- ветвь выдач решения о доступе: `namedInTarget(...)` у правила верхнего уровня и у
  контейнера вложенного правила, ветвь `names` (`rs.resource_names`,
  `rs.container_resource_names`) — `internal/repo/kaname/pg/relverdict/grantarm.go:255-290`;
- материализатор: `MatchByIDs` — `internal/repo/kaname/pg/reconcile_adapter.go:472`;
  проходы `ReconcileBinding` (`reconcile/reconcile.go:617`) и `ReconcileObject` (`:676`);
- пустая цель читается как вся область: `AccessTarget.Digest` даёт `"all"` и для
  `allInScope`, и для пустого перечня (`internal/domain/access_binding_target.go:129-136`);
- пустой перечень названий правила — ветвь `anchor`, то есть все объекты типа в области
  (`role.proto:671-675`, ограничение `role_rule_selectors_arm_shape`, `0001_initial.sql`).

Две последние строки — причина Д3 и Д5: перечень, из которого вынули последний элемент,
хранить нельзя, он означал бы расширение доступа.

### 0.5. Уникальность и неизменяемость цели

- `access_bindings_active_grant_uniq (subject_id, subject_type, role_id, resource_type,
  resource_id, target_digest) WHERE revoked_at IS NULL` — `0001_initial.sql:4443`. Ключ берёт
  ПЕРВОГО субъекта выдачи (наследная пара `subject_type`/`subject_id`);
- отказ при совпадении — `ALREADY_EXISTS` «these permissions are already granted to %s on %s»
  (`internal/repo/kaname/pg/pgmaperr.go:455`);
- цель клиентом не меняется: `UpdateAccessBindingRequest` принимает только
  `deletion_protection` и `labels` (`access_binding_service.proto:534-536`).

### 0.6. Модель событий

- аудит: `kaname.audit_outbox`, словарь `event_type` — регулярное выражение
  `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$` (`0001_initial.sql:1728`), закрытого перечня нет.
  Типы выдачи в прод-коде:
  ```sh
  git grep -n '"iam\.access_binding\.[a-z_]*"' -- '*.go' ':!*_test.go'
  # → 4: granted, revoked (internal/repo/kaname/access_binding/iface.go:337, :339),
  #      orphan_scope_revoked (internal/apps/kaname/seed/orphan_scope_sweep.go:68),
  #      containment_rejected (internal/repo/kaname/pg/reconcile_adapter.go:1417)
  ```
  Отзыв жизненным циклом области уже имеет свой тип (`orphan_scope_revoked`), отдельный от
  отзыва глаголом (`revoked`). Р5 следует этому образцу;
- лента изменений: `kaname.resource_journal`, триггеры `AFTER UPDATE` на `kaname.access_bindings`
  и `kaname.roles` (`20260914090000_resource_journal_serves_the_subscription.sql:335`, `:327`).
  Каждый `UPDATE` строки выдачи или роли даёт событие `UPDATED`, отдельного вызова не нужно.

### 0.7. Объявления манифеста и роль без правил

```sh
# объявления манифестов канона, называющие ключ объекта
for f in services/{compute,nlb,registry,storage,vpc}/manifest.yaml; do
  git -C project/kacho show origin/main:$f | grep -cE 'resourceNames|^\s*target:\s*resources'; done
# → 0 0 0 0 0 (kacho @41d7edad9b)
grep -cE 'resourceNames|^\s*target:\s*resources' manifest.yaml internal/servicemanifest/manifest.embedded.yaml
# → 0 и 0
```

- **Посев.** Посев цель манифеста не переносит, поэтому выдачи посева на перечень объектов
  вне объёма — `PRO-Robotech/kaname#965` (§2).
- **Роли манифеста.** Схема допускает `resourceNames` у правила верхнего уровня
  (`schema/module-manifest.schema.json:338`) и у вложенного правила (`:385-389`). Через API
  вложенное правило на вход не принимается (ND-04 (ж) соседа
  `nested-rule-reaches-descendants-of-a-named-container.md`). Значит единственный сегодняшний
  производитель имён вложенного правила — применитель ролей манифеста: строка роли —
  `UpsertSystemRole` (`internal/repo/kaname/pg/role_repo.go:643`, вставка `:658`, столбец
  `rules`), строка отбора с собственными именами вложенного правила (`resource_names`) и именами
  контейнера (`container_resource_names`) — самолечение `SyncAllSystemRoleSelectors`
  (`internal/apps/kaname/seed/migrate_backfill.go:231`, вставка `:420`).
- **Роль без правил.** Ограничение `roles_permissions_valid`
  (`internal/migrations/0001_initial.sql:2510`):
  `(jsonb_array_length(permissions) = 0 AND jsonb_array_length(rules) > 0) OR iam_permissions_valid(permissions)`;
  `iam_permissions_valid` на пустом массиве даёт `false` (`:379`). Значит пара
  `rules = []`, `permissions = []` сегодня схемой запрещена.
  `git grep -l roles_permissions_valid -- internal/migrations` → только `0001_initial.sql`.
  Роль с `rules = []` код читает веткой «роль только с перечнем прав»: проверка 3a выдачи
  (`internal/apps/kaname/api/access_binding/structural_gates.go:107-121`) и кортежи уровня
  области (`internal/apps/kaname/api/access_binding/tuples.go:73-93`). Решение Р6 меняет и то,
  и другое.

### 0.8. Чтения, которыми судятся сценарии

- `AuthorizeService.Check` — дверь решения, которую спрашивает модуль;
- `AccessBindingService.ListSubjectPrivileges` — строки `REVOKED` не отдаёт
  (`ab.status <> 'REVOKED'`, `internal/repo/kaname/pg/access_binding_repo.go:459`);
- `AccessBindingService.ExpandAccess` — кто держит отношение на объекте;
- `AccessBindingService.Get`, `List` (`include_revoked`, `access_binding_service.proto:575-587`),
  `RoleService.Get`.

### 0.9. Посылка задачи

Признак `#963` — проба `internal/apps/kaname/api/access_binding/unregister_reregister_world_integration_test.go`,
`TestUnregister_GrantOnFormerObjectDoesNotReachReRegisteredKey` — красна @`318f793bb`, со слов
диспетчера (задание). Её близнец `TestUnregister_GrantMadeAfterReRegistrationReaches` —
там же. Прогон в этой полосе не выполнялся: машина владельца не для прогонов. Пробу и её
мир (`newURWorld`) эта приёмка берёт держателем URG-02 и URG-03 и фикстурой остальных.

---

## §1. Предмет

Снятие регистрации объекта с ключом X (пара «тип, id»), выполненное ПОСЛЕ выката `#963`,
снимает выдачи и ссылки правил ролей, называющие X и сделанные до этого снятия. Отзыв
происходит атомарно со снятием. Отозванная выдача видна вместе с причиной. Ключ X после
снятия свободен: повторная регистрация разрешена и не наследует ни одной выдачи, сделанной
до снятия. Перерасчёт снятого не восстанавливает.

Доводы о следствии нынешнего поведения — в теле задачи. Здесь они не пересказываются:
репозиторий публичен.

## §2. Что НЕ входит

| предмет | почему вне объёма | где живёт |
|---|---|---|
| запрет повторной регистрации снятого ключа | отвергнут решением Р2: повторную привязку реестра с сохранением данных делает registry-operator | — |
| выдачи на ключи, снятые ДО выката `#963` | отзыв к ним не применялся. Такая выдача неотличима от выдачи на свободный ключ по ATC-03: признака «ключ был снят» в строке нет, вывода из истории нет (тот же довод, что Д7). Они остаются действующими | ATC-03 соседа `access-target-names-live-catalog-types.md` |
| выдача на ключ, который сейчас не зарегистрирован | цель — «graceful-dangling», объект получает доступ при регистрации. Правило одобренного соседа, не меняется (Д6) | ATC-03 там же |
| ссылки на объекты в объявлениях манифеста: выдачи посева с `target: resources`, `resourceNames` правила верхнего уровня и правила-владельца в ролях манифеста | загрузчик будет отвергать такие ссылки (`PRO-Robotech/kaname#965`). Имена ВЛОЖЕННОГО правила остаются в объёме (Р7) | `PRO-Robotech/kaname#965` |
| снятие ТИПА из каталога | своё правило: выдача и цель переживают снятие типа | `module-withdrawal-is-described.md`, `plan-confirms-what-apply-withdraws.md`, ATC-14 |
| цель `allInScope` | называет область, а не ключ. Будущие объекты, в том числе повторно зарегистрированные, она покрывает по построению | — |
| запоздалое снятие регистрации и доступ владельца нового объекта (кортежи владельца при устаревшем надгробии) | порядок снятия кортежей владельца по версии — дефект, существовавший до `#963`, к предмету не относится. Утверждение о доступе владельца нового объекта из URG-30 снято | `PRO-Robotech/kaname#969` («Запоздалое снятие регистрации не трогает владельца нового объекта») |
| строки журнала намерений с версией владельца (публикация) | их порядок и след снятия — предмет соседа. Снятие публикации здесь — только близнец URG-31 | `relation-fact-remembers-its-removal.md` |
| обратное заполнение `revocation_reason` у строк, отозванных до миграции | причина не записывалась. Восстановить её можно было бы только выводом из `revoked_by_user_id`, а это вывод из истории писателей, а не факт | Д7 |
| комментарий `AccessTargetResources` | его переписывает и сосед (ветка `746`, Р6 соседа). Две правки одного комментария свести при посадке, чтобы ни одна не стёрла другую | DoD п.1 |
| сквозной случай «модуль снял объект» на стенде | снятие регистрации — метод `Internal*` только на `:9091` (ban #6), у края его нет. Сквозная проба через модуль — работа kacho, она стоит до посадки identity-own-2 (решение владельца 2026-10-23). Предикат снятия: в kacho заведена задача о сквозной пробе снятия реестра | §6 S2 — краевая часть поля причины |
| консоль, Terraform-провайдер | поле причины только выводится; показ — задача потребителя после пересборки края с пином kaname | — |

## §3. Решения

### Решения диспетчера (приняты, вписаны по смыслу)

**Р1. Снятие регистрации отзывает выдачи, называющие ключ.** Отзыв идёт в той же
транзакции, что снятие строки зеркала, либо атомарно с ней.

- (а) Выдача, цель которой — только X, отзывается: `status = REVOKED`, `revokedAt` выставлен,
  `revocationReason = REVOCATION_REASON_RESOURCE_UNREGISTERED` в `Get` и `List`
  (`includeRevoked = true`). `revokedByUserId` пуст, как у отзыва по сроку: отозвал не человек.
  Цель отозванной выдачи остаётся той, что была в момент отзыва.
- (б) Выдача с целью из нескольких объектов сужается: X убирается из
  `target.resources.resources`, порядок остальных сохраняется, выдача остаётся `ACTIVE`, её
  `id` не меняется. Опустевшая цель — отзыв как в (а), с последним удалённым ключом в цели.
- (в) `deletionProtection` отзыву по снятию регистрации не препятствует. Защита — от удаления
  и отзыва пользователем, а не от жизненного цикла объекта. Значение флага на строке не
  меняется.
- (г) Системные выдачи (`system = true`) — по тем же правилам. Производителя системной
  выдачи с перечнем объектов сегодня нет, и после `#965` не будет (§0.7, §2). Поэтому
  сценария у (г) нет: путь отзыва один и не различает выдачи по признаку `system`.
- (д) Ключ X, названный в ветви `names` правила роли (`rules[i].resourceNames`), из правила
  убирается. Правило, у которого названий не осталось, убирается из роли целиком (аналог
  (а)), правило с другими названиями сужается (аналог (б)). Имена вложенного правила — Р7.

**Р2. Повторная регистрация разрешена и начинается с пустого набора выдач, сделанных до
снятия.** Ни одна такая выдача и ни одно название правила к новому объекту не переходят.

**Р3. Такая же выдача после повторной регистрации — новая.** Отозванная запись слот
уникальности не занимает (`revoked_at IS NOT NULL`): `Create` возвращает `Operation` без
ошибки, а не `ALREADY_EXISTS`.

**Р4. Перерасчёт не восстанавливает доступ** отозванным и суженным выдачам и суженным ролям:
ни проход по объекту, ни проход по выдаче, ни периодический обход.

**Р5. Наблюдаемость — аудит и лента изменений.** Каждый отзыв, сужение выдачи и сужение
роли по снятию регистрации кладёт строку `kaname.audit_outbox` в транзакции изменения:

| что | `event_type` | поля полезной нагрузки сверх канонических (`actor`, `subject`, `resource`, `role_id`, `binding_id`) |
|---|---|---|
| отзыв выдачи (а) | `iam.access_binding.resource_unregistered_revoked` | `revocation_reason: "resource_unregistered"`, `unregistered_resource: {type, id}` |
| сужение выдачи (б) | `iam.access_binding.resource_unregistered_narrowed` | `unregistered_resource: {type, id}`, `remaining_resource_count: N` |
| сужение роли (д), Р7 | `iam.role.resource_unregistered_narrowed` | `role_id`, `unregistered_resource: {type, id}`, `removed_rule_count: N`, `remaining_rule_count: N` |

`actor` — проверенная личность вызывающего `UnregisterResource` (служебная учётка модуля).
Каждое изменение строки выдачи и роли попадает в ленту `kaname.resource_journal` событием
`UPDATED` существующим триггером (§0.6), с причиной в полном состоянии выдачи.

**Р6. Роль без правил остаётся и не даёт ничего.** Если снятие убрало последнее правило,
роль остаётся с `rules = []` и `permissions = []`. Форма в контракте и схеме:

- новая миграция `#963` с номером больше `20261024010000` меняет `roles_permissions_valid`:
  к прежним двум формам добавляется третья — `permissions = []` и `rules = []`. Вход
  `RoleService.Create`/`Update` по-прежнему требует 1..64 правил
  (`internal/apps/kaname/api/role/create.go:124`);
- структурные проверки выдачи (`structural_gates.go:107-121`, `tuples.go:73-93`) читают такую
  роль как «не даёт ничего», а не веткой «роль только с перечнем прав». Выдача на неё с целью
  `allInScope` принимается и кладёт только указатель на родителя выдачи, без кортежей уровня
  области. Выдача с перечнем объектов отвергается проверкой покрытия типа (текст ниже),
  а не текстом проверки 3a о «роли только с перечнем прав»;
- комментарий `Role.rules` правится: «на входе 1..64; на чтении 0..64, ноль — роль только с
  перечнем прав (`permissions` непуст) либо роль, все правила которой потеряли адресатов
  снятием регистрации (`permissions` пуст)».

Текст отказа выдачи с перечнем объектов на роль без правил — существующий текст проверки
покрытия, дословно (`structural_gates.go:131-133`):
`role <R> does not grant verbs on <T>; target type must be covered by role.rules`.

**Р7. Имена вложенного правила.** Снятый ключ объекта, названный в `resourceNames` вложенного
правила (`children[]`, `module-manifest.schema.json:385-389`; через API вложенное правило на
вход не принимается, ND-04 (ж) соседа), из имён убирается. Если убрано последнее имя,
вложенное правило снимается целиком, а не хранится пустым перечнем: пустой перечень — ветвь
`anchor`, все объекты вложенного типа под контейнером. Правило-владелец и остальные вложенные
правила при этом не меняются. Сегодня имена вложенного правила кладёт только применитель ролей
манифеста (§0.7). `#965` закрывает ссылки на объекты в манифестах; когда она сядет, у URG-35…37
не останется производителя «Дано», и эти сценарии снимаются её же изменением вместе с
производителем (ban #11, исход «снять вместе с подпираемым»).

**Р8. Гонка читается от момента приёма.** Гонка — выдача (роль), ПРИНЯТАЯ до снятия и
ЗАПИСАННАЯ после. Это согласуется с Д6 и ATC-03: выдача, принятая после фиксации снятия, —
выдача на свободный ключ.

### Решения автора, выведенные из Р1–Р8 и соседей

**Д1. Что такое «снятие регистрации».** Вызов `UnregisterResource`, который удалил строку
зеркала объекта X: надгробие не старше хранимой регистрации и снимается не публикация.
Только такой вызов отзывает и сужает. Не отзывают: снятие публикации (URG-31), устаревшее
надгробие (URG-30), снятие незарегистрированного ключа (URG-29), повтор уже применённого
снятия (URG-32). Ключ — пара «точечный тип цели, id». Тип модели прав (`registry_registry`)
и точечный тип цели (`registry.registries`) — одно и то же написание в разных словарях,
перевод делает служба. Тот же id другого типа ключом X не является (URG-05).

**Д2. Поле причины.** `AccessBinding.revocation_reason` — только вывод, новое поле тега 26,
перечисление `AccessBinding.RevocationReason`:

| значение | когда |
|---|---|
| `REVOCATION_REASON_UNSPECIFIED` (0) | выдача не отозвана; либо отозвана до заведения поля (Д7) |
| `REVOCATION_REASON_REVOKE` (1) | глагол `Revoke`; `revokedByUserId` — вызывающий |
| `REVOCATION_REASON_EXPIRED` (2) | истёк `expiresAt`, отозвал проход срока |
| `REVOCATION_REASON_RESOURCE_UNREGISTERED` (3) | снята регистрация объекта цели (Р1) |

Каждый путь, переводящий выдачу в `REVOKED`, пишет причину (оба пути §0.2 и новый).
Перечисление, а не строка: набор закрыт, и значение выразимо ровно одним способом. В JSON края
поле — `revocationReason`, значение по умолчанию proto3 JSON опускает.

**Д3. Цель никогда не хранится пустой.** Пустой перечень читается как вся область (§0.4).
Поэтому опустевшая цель — отзыв (Р1 (б)), а у отозванной выдачи в цели остаётся последний
удалённый ключ.

**Д4. Суженная выдача и уникальность.** Сужение не отказывает никогда и никогда не отзывает
выдачу, у которой цель не опустела. Если суженная цель совпала по ключу уникальности (§0.5)
с другой действующей выдачей, обе остаются `ACTIVE`: двойная выдача безвредна, а отзыв
лишил бы прочих субъектов суженной выдачи доступа к оставшимся объектам. Суженная выдача слот
уникальности не занимает, как отозванная (Р3): `Create` выдачи, совпадающей с суженной, —
новая выдача. `Create`, совпадающий с несуженной действующей выдачей, — `ALREADY_EXISTS`, как
прежде. Клиентом цель по-прежнему не меняется (§0.5).

**Д5. Правило и вложенное правило без имён не хранятся.** Пустой перечень имён — ветвь
`anchor` (§0.4): хранить его значило бы расширить доступ. Правило верхнего уровня без имён
снимается (Р1 (д)), вложенное — тоже (Р7), роль без правил — по Р6.

**Д6. Граница с одобренным соседом и гонка создания.** Цель — «graceful-dangling»
(ATC-03 `access-target-names-live-catalog-types.md`): выдача на ключ, который сейчас не
зарегистрирован, принимается и действует с ближайшей регистрации. Поэтому Р2 говорит о
выдачах, сделанных ДО снятия. Выдача, принятая ПОСЛЕ фиксации снятия, — выдача на свободный
ключ по ATC-03 (URG-25). Гонку определяет момент приёма (Р8). `Create`, принятый, пока X
зарегистрирован, и записанный после снятия, заканчивается одним из двух исходов: отказ
создания либо отзыв с причиной. Живой выдачи на снятый ключ такой `Create` не оставляет
(URG-24). То же для `RoleService.Create`/`Update`, называющих X в `resourceNames` (URG-26).

Тексты отказа — часть контракта (`api-error-tone`), `<T>` — точечный тип, `<ID>` — id:

- Т1, `Operation.error` выдачи, `FAILED_PRECONDITION`:
  `target resource <T> <ID> was unregistered before the access binding was written`;
- Т2, `Operation.error` роли, `FAILED_PRECONDITION`:
  `rules[<i>].resourceNames: resource <ID> was unregistered before the role was written`.

**Д7. Строки, отозванные до миграции,** несут `REVOCATION_REASON_UNSPECIFIED`. Это значит
«отозвана до заведения поля», а не «причину потеряли». Образец — `RoleLifecycle.retired_by`
и `role_grant_orphan.applied_by`, где пустое значение означает то же.

### Критерии продукта (ban #18)

- **производительность.** Снятие добавляет одно чтение выдач и ролей, называющих ключ, в
  транзакции снятия. Сегодня их ноль: снятие выдач не читает. Цена — число строк выдач и
  правил с этим ключом. Поиск по ключу обязан идти индексом, а не перебором выдач области:
  замер `EXPLAIN` на выдачах стенда — §6 S1 п.10;
- **безопасность.** Поверхность не расширяется. Новое поле — вывод, ввода нет. Снимается
  доступ, который пережил объект;
- **инновационность.** Отзыв по жизненному циклу объекта с причиной в ресурсе выдачи и в
  ленте изменений: администратор видит, почему доступ исчез, а не только что он исчез;
- **узнаваемость.** Причина отзыва — поле ресурса выдачи. Ближайший аналог у рынка — статус
  отзыва с причиной в записи привязки. Имя `revocationReason` следует нашему
  `revoked_reason` у семейства токенов;
- **перспективность.** Шаг обратим: новое поле аддитивно, ограничение роли только
  расширяется. Отозванная выдача остаётся строкой, повторная выдача — новой записью (Р3);
- **благо продукта, производственность.** Режима «только для стенда» нет.

---

## §4. Сценарии

### Мир проб

Мир У — `newURWorld` (проба `#963`, `unregister_reregister_world_integration_test.go`) поверх
П6 `newPCRWorld` (`public_container_read_world_integration_test.go:99`). Он даёт:

- аккаунт acc-A (владелец usr-A), проект prj-A, люди usr-B, usr-D; второй аккаунт acc-B
  (владелец usr-C);
- реестры X = `reg00000000000000001`, Y = `reg00000000000000002`, их репозитории `X/app`,
  `Y/app` (регистрация владельцем: указатель на проект или реестр, владелец объекта usr-A,
  цепь предков). Регистрация по `RegisterResourceRequest`:
  `{"subjectId":"project:<prj-A>","relation":"project","object":"registry_registry:<X>",
  "parentProjectId":"<prj-A>","parentAccountId":"<acc-A>","parentChain":["project:<prj-A>","account:<acc-A>"],
  "sourceVersion":"<v>"}` и вторым кортежем `owner`;
- роль rol-reg-get (аккаунт, правило `{"module":"registry","resources":["registries"],"verbs":["get"]}`)
  посевом `seedRole` так, как пишет `RoleService.Create`;
- выдачу A — rol-reg-get человеку usr-B на prj-A с целью
  `{"resources":{"resources":[{"type":"registry.registries","id":"<X>"}]}}` (`grantB` П6);
- снятие `withdrawX`: `UnregisterResourceRequest`
  `{"subjectId":"project:<prj-A>","relation":"project","object":"registry_registry:<X>","sourceVersion":"<v+1>"}`;
- повторную регистрацию `reRegisterX(usr-C)`: тот же ключ, владелец объекта usr-C, своя
  версия у каждого намерения;
- перерасчёт `recompute`: `ReconcileObject(registry.registries, X)` и `ReconcileBinding(<id>)`.

Дополнения мира, которые заводит автор проб (каждое строится существующими глаголами мира):

- реестр Z = `reg00000000000000003` в prj-A — `registerRegistry(Z)`;
- ключ Q = `reg00000000000000009` не регистрируется никогда;
- роль rol-reg-names-XY — `seedRole` с правилом
  `{"module":"registry","resources":["registries"],"verbs":["get"],"resourceNames":["<X>","<Y>"]}`,
  rol-reg-names-X — то же с `["<X>"]`, rol-reg-names-X-Y — два правила `["<X>"]` и `["<Y>"]`,
  rol-reg-names-Y — `["<Y>"]`;
- выдача ролью с названиями: человеку usr-B или usr-D на prj-A, цель `{"allInScope":{}}`;
- мир П3-У для вложенных имён (Р7) — `newP3UWorld`
  (`internal/apps/kaname/api/access_binding/unregister_nested_names_world_integration_test.go:83`)
  поверх мира У.
  **Принятое решение диспетчера (2026-10-24):** мир собран на типах registry вместо пробного
  модуля прошлой редакции — его типов нет в модели прав (решение по ним даёт отказ «тип не объявлен»). Контейнер —
  реестр X (`registry_registry`), вложенный тип — репозитории (`registry_repository`).
  Доставка — новая редакция манифеста registry П6 (`publicreadfixture.NewEditionFile`) с
  тремя дописанными ролями, загрузка `manifest.Load`, применение `applyDelivered`. Каждая
  роль — правило `{module: registry, resources: [registries], classes: [get, list]}` с одним
  вложенным правилом `{resources: [repositories], classes: [get, list], resourceNames: …}`:
  `registry.reader_t13` (`[t1, t3]`), `registry.reader_t1` (`[t1]`), `registry.reader_t3`
  (`[t3]`). Репозитории `t1`, `t3`, позже `t4` регистрирует `registerTag`: кортежи
  `{"subjectId":"registry_registry:<X>","relation":"parent","object":"registry_repository:<id>"}`
  и `owner` usr-A, `parentChain: ["registry_registry:<X>","project:<prj-A>","account:<acc-A>"]`,
  своя версия у каждого намерения. Снятие — `unregisterTag`: тот же кортеж `parent`, новая
  версия. Id репозиториев мира — непрозрачные `t1`, `t3`, `t4` без `/`: форма имени
  `^[a-zA-Z0-9_-]+$` им годна. Служба id не разбирает: регистрация принимает любой id формы
  `<type>:<id>` (`validateRelationString`, `register_resource.go`). Выдача — `grantNamedRole`:
  роль манифеста человеку usr-D на prj-A, цель `{"allInScope":{}}`, через `Create` от usr-A.
  Чтение роли — строка роли (`Roles().Get`, `roleRules` мира), `Check` — `ask` мира.

  | что в «Дано» мира П3-У | столбец | писатель, строка |
  |---|---|---|
  | роли `registry.reader_t1*` с вложенным правилом и именами | `roles.rules` | `internal/repo/kaname/pg/role_repo.go:643`, вставка `:658` (`UpsertSystemRole`) из `moduleroles.Applier.Apply` (`public_container_read_world_integration_test.go:292`) |
  | отбор вложенного правила | `role_rule_selectors.resource_names`, `container_type`, `container_resource_names` | `internal/apps/kaname/seed/migrate_backfill.go:420` (`SyncAllSystemRoleSelectors`, `public_container_read_world_integration_test.go:296`) |
  | репозитории `t1`, `t3`, `t4` под X | `resource_mirror`, `resource_parent_edge` | `internal/repo/kaname/pg/resource_mirror/emitter.go:197`, `:451` из `Register` (`registerTag`) |
  | выдача роли usr-D | `access_bindings.(role_id, target)` | `internal/repo/kaname/pg/access_binding_repo.go:696` из воркера `Create` (`create.go:324`) |

**Дано → писатель.** Каждый нетривиальный столбец «Дано» кладёт названный писатель:

| что в «Дано» | столбец | писатель, строка |
|---|---|---|
| объект зарегистрирован | `resource_mirror.(object_type, object_id, parent_project_id, source_version)` | `internal/repo/kaname/pg/resource_mirror/emitter.go:197` (вставка зеркала) из `RegisterResourceUseCase.Register` |
| предки объекта | `resource_parent_edge` | `emitter.go:451` |
| роль аккаунта с правилами и именами | `roles.rules`, `roles.permissions` | `internal/repo/kaname/pg/role_repo.go:573` (`roleWriter.Insert`) из `seedRole` |
| отбор роли аккаунта | `role_rule_selectors.resource_names` | `role_repo.go:1140` (`ReplaceRuleSelectors`) из `seedRole` |
| проекция глаголов | `role_verb` | `role_repo.go:954` (`ReplaceRoleVerbs`) из `seedRole` |
| роль манифеста с вложенным правилом | `roles.rules` (с `children`) | `role_repo.go:643`, вставка `:658` (`UpsertSystemRole`) из `moduleroles.Applier.Apply` (`public_container_read_world_integration_test.go:292`) |
| отбор вложенного правила | `role_rule_selectors.resource_names`, `container_type`, `container_resource_names` | `internal/apps/kaname/seed/migrate_backfill.go:420` (`SyncAllSystemRoleSelectors`, зов — `public_container_read_world_integration_test.go:296`) |
| выдача с целью, защитой, сроком | `access_bindings.(target, target_digest, deletion_protection, expires_at)` | `internal/repo/kaname/pg/access_binding_repo.go:696` (`Insert`) из воркера `Create` (`internal/apps/kaname/api/access_binding/create.go:324`) |
| отзыв по сроку (URG-34) | `access_bindings.(status, revoked_at)` | `internal/repo/kaname/pg/reconcile_adapter.go:1459` (`RevokeExpiredBinding`) из `ExpireBinding` (`reconcile/reconcile.go:770`) |
| строка, отозванная до миграции (URG-34) | `access_bindings.(status, revoked_at, revoked_by_user_id)` | SQL пробы на базе, накатанной до предыдущей головы, затем накат — образец поступенчатого наката `internal/migrations/family_revocation_vocabulary_narrows_integration_test.go` |

Чтения: `Check(субъект, v_get, тип, id)` — `AuthorizeService.Check` (`ask` мира);
`ListSubjectPrivileges` — `{"subjectType":"user","subjectId":"<usr>"}`; `ExpandAccess` —
`{"objectType":"registry_registry","objectId":"<X>","relation":"v_get"}` от имени usr-A
(владелец acc-A, право выдавать на объектах аккаунта). Каждая мутация края возвращает
`Operation`. Проба опрашивает `OperationService.Get` до `done = true` и читает `result`.

### Группа A — выдача на один объект (Р1 (а), Р2, Р3)

#### URG-01 · снятие регистрации отзывает выдачу на один объект

**Дано** мир У: выдача A действует (`Check(usr-B, v_get, registry_registry, X)` → allow)

**Когда** `withdrawX`

**Тогда** `Get(A)`: `status = REVOKED`, `revokedAt` выставлен,
`revocationReason = REVOCATION_REASON_RESOURCE_UNREGISTERED`, `revokedByUserId` пуст,
`target.resources.resources = [{registry.registries, X}]`
**И** `List(filter=subject="<usr-B>")` без `includeRevoked` A не содержит, с
`includeRevoked = true` — содержит с той же причиной
**И** `Check(usr-B, v_get, registry_registry, X)` → deny
**И** `ListSubjectPrivileges(usr-B)` строки с `bindingId = A` не содержит

Красна до кода: строка A остаётся `ACTIVE`, поля причины нет.

#### URG-02 · повторная регистрация не возвращает доступ прежней выдаче

**Дано** URG-01 исполнен
**И** `reRegisterX(usr-C)`: `Check(usr-C, v_get, registry_registry, X)` → allow (контроль живости)

**Когда** спрошено сразу после регистрации и после `recompute(A)`

**Тогда** `Check(usr-B, v_get, registry_registry, X)` → deny в обоих случаях
**И** `ExpandAccess(X, v_get)` среди `principals` usr-B не содержит
**И** `Get(A).status = REVOKED`

Красна @`318f793bb` (§0.9): прежняя выдача снова действует.

#### URG-03 · близнец 02: выдача после повторной регистрации действует

**Дано** то же, что в 02, до «Когда»
**И** `Check(usr-D, v_get, registry_registry, X)` → deny (контроль)

**Когда** usr-A создаёт выдачу rol-reg-get человеку usr-D на prj-A с целью
`{"resources":{"resources":[{"type":"registry.registries","id":"<X>"}]}}`

**Тогда** `Operation.done = true` без `error`
**И** `Check(usr-D, …, X)` → allow, и после `recompute(<новая>)` тоже
**И** `ListSubjectPrivileges(usr-D)` содержит строку новой выдачи
**И** `ExpandAccess(X, v_get)` содержит usr-D и не содержит usr-B

От 02 отличается одним фактом: выдача сделана после повторной регистрации.

#### URG-04 · такая же выдача после повторной регистрации — новая (Р3)

**Дано** URG-02 исполнен

**Когда** usr-A создаёт выдачу rol-reg-get человеку usr-B на prj-A с той же целью, что у A

**Тогда** `Operation.done = true` без `error` (не `ALREADY_EXISTS`), `id` новой ≠ A
**И** `Get(A).status = REVOKED`, причина та же
**И** `Check(usr-B, …, X)` → allow

#### URG-05 · близнец 01: тот же id другого типа ключом X не является

**Дано** мир У и выдача rol-reg-get человеку usr-D на prj-A с целью
`{"resources":{"resources":[{"type":"registry.repositories","id":"<X>"}]}}` (ключ не
зарегистрирован, ATC-03)

**Когда** `withdrawX`

**Тогда** `Get(выдачи usr-D)`: `status = ACTIVE`, `revocationReason` не задан, цель та же

От 01 отличается одним фактом: тип элемента цели.

### Группа B — выдача на несколько объектов (Р1 (б), Д3, Д4)

#### URG-06 · цель из нескольких объектов сужается

**Дано** мир У и выдача B2 — rol-reg-get человеку usr-D на prj-A с целью
`[{registry.registries, X}, {registry.registries, Y}]`

**Когда** `withdrawX`

**Тогда** `Get(B2)`: `status = ACTIVE`, `target.resources.resources = [{registry.registries, Y}]`,
`revokedAt` и `revocationReason` не заданы, `id` прежний
**И** `Check(usr-D, …, X)` → deny, `Check(usr-D, …, Y)` → allow
**И** `ListSubjectPrivileges(usr-D)` содержит B2
**И** после `reRegisterX(usr-C)` и `recompute(B2)`: `Check(usr-D, …, X)` → deny, `Y` → allow

#### URG-07 · опустевшая цель — отзыв, не пустой перечень

**Дано** выдача B2 из 06
**И** снята регистрация Y (`UnregisterResource` по Y с новой версией)

**Когда** `withdrawX`

**Тогда** `Get(B2)`: `status = REVOKED`, `revocationReason = REVOCATION_REASON_RESOURCE_UNREGISTERED`,
`target.resources.resources = [{registry.registries, X}]` (не `[]`, не `allInScope`)
**И** `Check(usr-D, …, Z)` → deny: реестр Z в prj-A, не названный целью, доступа не получил

Красна до кода: пустой перечень читался бы как вся область.

#### URG-08 · сужение до цели, совпавшей с действующей выдачей

**Дано** мир У, выдача B2 из 06 и выдача B3 — rol-reg-get человеку usr-D на prj-A с целью
`[{registry.registries, Y}]` (первый субъект, роль и область совпадают)

**Когда** `withdrawX`

**Тогда** `Get(B2)` и `Get(B3)` — оба `ACTIVE`, цель обоих `[{registry.registries, Y}]`
**И** `Check(usr-D, …, Y)` → allow

Красна на реализации, которая сужает записью под действующим индексом уникальности: снятие
падает отказом либо отзывает B2.

#### URG-09 · суженная выдача слот уникальности не занимает

**Дано** URG-06 исполнен (B2 сужена до `[Y]`, выдачи B3 нет)

**Когда** usr-A создаёт rol-reg-get человеку usr-D на prj-A с целью `[{registry.registries, Y}]`

**Тогда** `Operation.done = true` без `error`, новая выдача `ACTIVE`, B2 `ACTIVE`

#### URG-10 · близнец 09: совпадение с несуженной выдачей отвергается

**Дано** выдача B3 из 08, сужения не было

**Когда** тот же `Create`, что в 09

**Тогда** `Operation.error`: `ALREADY_EXISTS`, текст
`these permissions are already granted to <usr-D> on project:<prj-A>`

От 09 отличается одним фактом: совпавшая выдача не сужена.

### Группа C — защита от удаления (Р1 (в))

#### URG-11 · защищённая выдача отзывается снятием регистрации

**Дано** мир У и выдача P — rol-reg-get человеку usr-D на prj-A, цель `[{registry.registries, X}]`,
`"deletionProtection": true`

**Когда** `withdrawX`

**Тогда** `Get(P)`: `status = REVOKED`, `revocationReason = REVOCATION_REASON_RESOURCE_UNREGISTERED`,
`deletionProtection = true`
**И** `Check(usr-D, …, X)` → deny

#### URG-12 · близнец 11: отзыв глаголом защиту уважает

**Дано** выдача P из 11, X зарегистрирован

**Когда** usr-A вызывает `POST /iam/v1/accessBindings/<P>:revoke`

**Тогда** синхронно, без `Operation`: `FAILED_PRECONDITION`, текст
`access binding <P> has deletion_protection enabled; clear it via Update before revoke`
(`internal/apps/kaname/api/access_binding/revoke.go:113`)
**И** `Get(P).status = ACTIVE`

От 11 отличается одним фактом: кто отзывает.

### Группа D — системные выдачи (Р1 (г)) — снята в редакции 2

#### URG-13 · снят (решение диспетчера 2 редакции 2)

«Дано» не строится: применитель посева цель манифеста в строку выдачи не переносит (§0.7).
Ссылки на объекты в объявлениях манифеста — `PRO-Robotech/kaname#965` (§2). Правило Р1 (г)
действует без своего сценария: путь отзыва признак `system` не различает.

#### URG-14 · снят (решение диспетчера 2 редакции 2)

Повторное применение посева — предмет `#965` (§2).

### Группа E — вложенное правило по контейнеру (Р1 (д))

#### URG-15 · выдача на контейнер отзывается вместе с потомками

**Дано** мир У после `deliverNewEdition`; выдача N — роль `registry.reader` (правило над
`registries` с `children: [repositories]`) человеку usr-D на prj-A, цель
`[{registry.registries, X}]`; `Check(usr-D, v_get, registry_repository, X/app)` → allow

**Когда** `withdrawX`

**Тогда** `Get(N).status = REVOKED`, причина `REVOCATION_REASON_RESOURCE_UNREGISTERED`
**И** `Check(usr-D, v_get, registry_registry, X)` → deny, `Check(usr-D, v_get, registry_repository, X/app)` → deny

#### URG-16 · потомки повторно зарегистрированного контейнера прежней выдаче недоступны

**Дано** URG-15 исполнен, `reRegisterX(usr-C)`, репозиторий `X/late` зарегистрирован под X
(`registerRepository(X, "late")`)

**Когда** спрошено сразу и после `recompute(N)`

**Тогда** `Check(usr-D, v_get, registry_repository, X/late)` → deny и `… X/app` → deny

#### URG-17 · близнец 15: выдача на другой контейнер не тронута

**Дано** мир У после `deliverNewEdition`; выдача N2 — `registry.reader` человеку usr-D на prj-A,
цель `[{registry.registries, Y}]`

**Когда** `withdrawX`

**Тогда** `Get(N2).status = ACTIVE`
**И** `Check(usr-D, v_get, registry_repository, Y/app)` → allow

От 15 отличается одним фактом: контейнер цели.

#### URG-18 · снят (решение диспетчера 2 редакции 2)

`resourceNames` правила-владельца в роли манифеста — ссылка на объект в объявлении манифеста,
предмет `PRO-Robotech/kaname#965` (§2). Контейнер, названный ЦЕЛЬЮ выдачи, покрыт URG-15–17.

### Группа F — ветвь `names` правила роли (Р1 (д), Д5)

#### URG-19 · название убирается, остальные действуют

**Дано** мир У, роль rol-reg-names-XY, выдача человеку usr-D на prj-A, цель `allInScope`;
`Check(usr-D, …, X)` → allow, `… Y` → allow

**Когда** `withdrawX`

**Тогда** `RoleService.Get(rol-reg-names-XY).rules[0].resourceNames = ["<Y>"]`
**И** `Check(usr-D, …, X)` → deny, `… Y` → allow
**И** после `reRegisterX(usr-C)` и `recompute`: `Check(usr-D, …, X)` → deny

#### URG-20 · правило без названий убирается, роль без правил не даёт ничего (Р6)

**Дано** мир У, роль rol-reg-names-X, выдача человеку usr-D на prj-A, цель `allInScope`

**Когда** `withdrawX`

**Тогда** `RoleService.Get(rol-reg-names-X).rules = []`
**И** строка роли: `SELECT rules, permissions FROM kaname.roles WHERE id = <rol-reg-names-X>`
→ `[]`, `[]`
**И** `Check(usr-D, …, X)` → deny, `Check(usr-D, …, Z)` → deny, `Check(usr-D, …, Y)` → deny
**И** выдача `ACTIVE` (она называет роль, а не ключ)

Красна на реализации, которая оставляет `resourceNames: []`: правило стало бы ветвью
`anchor` и открыло бы Y и Z. Красна и на реализации, которая оставляет прежний
`permissions` при `rules = []`: роль читалась бы веткой «только с перечнем прав», и выдача
получила бы кортежи уровня области (инъекция I7). До миграции Р6 снятие падает на
`roles_permissions_valid`.

#### URG-21 · правило без названий убирается, остальные правила остаются

**Дано** мир У, роль rol-reg-names-X-Y (два правила), выдача человеку usr-D на prj-A, `allInScope`

**Когда** `withdrawX`

**Тогда** `RoleService.Get(...).rules` — одно правило с `resourceNames: ["<Y>"]`
**И** `Check(usr-D, …, Y)` → allow, `… X` → deny

#### URG-22 · близнец 19: роль, не называющая X, не тронута

**Дано** мир У, роль rol-reg-names-Y, выдача человеку usr-D на prj-A, `allInScope`

**Когда** `withdrawX`

**Тогда** `RoleService.Get(rol-reg-names-Y).rules` побайтово равны прежним
**И** `Check(usr-D, …, Y)` → allow
**И** в `kaname.audit_outbox` строки `iam.role.resource_unregistered_narrowed` с этим `role_id` нет

От 19 отличается одним фактом: в названиях роли нет X.

#### URG-23 · снят (решение диспетчера 2 редакции 2)

Названия в ролях манифеста и их восстановление применителем — предмет
`PRO-Robotech/kaname#965` (§2).

### Группа F2 — имена вложенного правила (Р7, Д5)

#### URG-35 · имя убирается из вложенного правила, остальные действуют

**Дано** мир П3-У, репозитории `t1`, `t3` под X, роль `registry.reader_t13`, выдача человеку
usr-D на prj-A, `allInScope`; `Check(usr-D, v_get, registry_repository, t1)` → allow,
`… t3` → allow (контроль фикстуры: без него красное ниже было бы о неработающих вложенных
именах, а не о снятии)

**Когда** `UnregisterResource` по `{"subjectId":"registry_registry:<X>","relation":"parent","object":"registry_repository:t1","sourceVersion":"<v+1>"}`

**Тогда** у роли `registry.reader_t13` одно правило, у него одно вложенное правило с
`resourceNames = ["t3"]`; `resources` и `verbs` правила-владельца не изменились
**И** `Check(usr-D, v_get, registry_repository, t1)` → deny, `… t3` → allow
**И** после повторной регистрации `t1` под X и перерасчёта — `… t1` → deny

#### URG-36 · последнее имя — вложенное правило снимается, а не хранится пустым

**Дано** мир П3-У, репозитории `t1`, `t3` под X, роль `registry.reader_t1`, выдача человеку
usr-D на prj-A, `allInScope`; `Check(usr-D, v_get, registry_repository, t1)` → allow,
`… t3` → deny (имена сужают)

**Когда** снята регистрация `t1`, как в 35

**Тогда** у роли `registry.reader_t1` одно правило, вложенных правил у него нет;
`resources = ["registries"]`
**И** `Check(usr-D, v_get, registry_repository, t3)` → deny и после регистрации репозитория
`t4` под X `… t4` → deny: пустой перечень не стал ветвью `anchor`
**И** `Check(usr-D, v_get, registry_registry, X)` → allow: правило-владелец действует

Красна на реализации, которая хранит `resourceNames: []` у вложенного правила: открылись бы
`t3` и `t4` (инъекция I8).

#### URG-37 · близнец 35: вложенное правило без снятого имени не тронуто

**Дано** мир П3-У, репозитории `t1`, `t3` под X, роль `registry.reader_t3`, выдача человеку
usr-D на prj-A, `allInScope`; `Check(usr-D, v_get, registry_repository, t3)` → allow

**Когда** снята регистрация `t1`, как в 35

**Тогда** правила роли `registry.reader_t3` равны прежним
**И** `Check(usr-D, v_get, registry_repository, t3)` → allow
**И** строки `iam.role.resource_unregistered_narrowed` с этим `role_id` нет

От 35 отличается одним фактом: в именах вложенного правила нет снятого ключа.

### Группа F3 — выдача на роль без правил (Р6)

#### URG-38 · выдача на роль без правил с целью «вся область» ничего не даёт

**Дано** URG-20 исполнен: rol-reg-names-X с `rules = []`, `permissions = []`

**Когда** usr-A создаёт выдачу rol-reg-names-X человеку usr-B на prj-A с целью `{"allInScope":{}}`

**Тогда** `Operation.done = true` без `error`, выдача `ACTIVE`
**И** `Check(usr-B, v_get, registry_registry, Y)` → deny, `… Z` → deny
**И** реестр выпущенных кортежей выдачи (`kaname.access_binding_emitted_tuples` по её `id`)
содержит только указатель на родителя выдачи — кортежей уровня области нет

Красна до миграции Р6: роль без правил не строится (URG-20 падает на ограничении).

#### URG-39 · близнец 38: роль с правилом даёт своё

**Дано** роль rol-reg-names-Y

**Когда** тот же `Create`, что в 38, с ролью rol-reg-names-Y

**Тогда** `Operation.done = true` без `error`; `Check(usr-B, …, Y)` → allow, `… Z` → deny

От 38 отличается одним фактом: у роли есть правило.

#### URG-40 · выдача с перечнем объектов на роль без правил отвергается проверкой покрытия

**Дано** URG-20 исполнен

**Когда** usr-A создаёт выдачу rol-reg-names-X человеку usr-B на prj-A с целью
`{"resources":{"resources":[{"type":"registry.registries","id":"<Y>"}]}}`

**Тогда** синхронно, без `Operation`: `FAILED_PRECONDITION`, текст
`role <rol-reg-names-X> does not grant verbs on registry.registries; target type must be covered by role.rules`
**И** не текст проверки 3a (`… has no rules; a per-object target requires a rules-role …`)

#### URG-41 · близнец 40: роль с правилом покрывает тип

**Дано** роль rol-reg-names-Y

**Когда** тот же `Create`, что в 40, с ролью rol-reg-names-Y

**Тогда** `Operation.done = true` без `error`

От 40 отличается одним фактом: у роли есть правило над типом цели.

### Группа G — конкуренция

#### URG-24 · выдача, принятая до снятия и записанная после, не остаётся живой (Р8)

**Дано** мир У. Точка удержания: обёртка порта `Repo` use-case создания выдачи, которую
ставит проба, держит вызов `Writer(ctx)` воркера операции
(`internal/apps/kaname/api/access_binding/create.go:300`, внутри `operations.Run`, `:269`) до
сигнала пробы

**Когда** 50 итераций, каждая на своём ключе итерации `K_i` (реестр в prj-A, зарегистрирован
`registerRegistry` перед итерацией): usr-A вызывает `Create` выдачи rol-reg-get человеку
usr-D с целью `[{registry.registries, K_i}]`; `Create` вернул `Operation` (приём, `K_i`
зарегистрирован). В чётных итерациях воркер держится в точке удержания, пока
`UnregisterResource` по `K_i` не вернул OK, затем отпускается. В нечётных снятие идёт
параллельно без удержания

**Тогда** каждая итерация заканчивается ровно одним исходом:
(i) `Operation.error` `FAILED_PRECONDITION` с текстом Т1 и строки выдачи нет, либо
(ii) выдача `REVOKED` с `revocationReason = REVOCATION_REASON_RESOURCE_UNREGISTERED`
**И** выдач `ACTIVE` с целью на снятый ключ — 0 из 50
**И** итераций, где запись выдачи начата после фиксации снятия, — не меньше 1 (все 25 чётных);
проба печатает их число и число исходов (i) и (ii)

Красна до кода: запись выдачи, зафиксированная после снятия, остаётся `ACTIVE`.

#### URG-25 · близнец 24: выдача, принятая после снятия, — выдача на свободный ключ

**Дано** мир У; `withdrawX` вернул OK

**Когда** usr-A создаёт выдачу rol-reg-get человеку usr-D с целью `[{registry.registries, X}]`,
затем `reRegisterX(usr-C)`

**Тогда** `Operation.done = true` без `error`, выдача `ACTIVE`
**И** после регистрации `Check(usr-D, …, X)` → allow (ATC-03)

От 24 отличается одним фактом: приём выдачи после фиксации снятия.

#### URG-26 · роль, принятая до снятия и записанная после, не называет снятый ключ

**Дано** мир У; X зарегистрирован; роль rol-reg-names-Y

**Когда** 50 итераций по образцу 24: `RoleService.Update` роли с `updateMask: ["rules"]` и
правилом `resourceNames: ["<ключ итерации>", "<Y>"]`, снятие ключа между приёмом и фиксацией;
и столько же итераций с `RoleService.Create` такой же роли

**Тогда** каждая итерация — ровно один исход: `Operation.error` `FAILED_PRECONDITION` с
текстом Т2, либо `RoleService.Get` роли не содержит ключа итерации
**И** ролей, называющих снятый ключ, — 0

Близнец — 25 в форме роли: `Update`, принятый после снятия, оставляет название (подтест 26б).

#### URG-27 · отзыв глаголом и снятие регистрации: ровно один отзыв

**Дано** мир У, выдача A

**Когда** параллельно: usr-A `POST /iam/v1/accessBindings/<A>:revoke` и `withdrawX`, 50 итераций
на свежей выдаче и ключе

**Тогда** в каждой итерации выдача `REVOKED` ровно один раз: либо
`revocationReason = REVOCATION_REASON_REVOKE` и `revokedByUserId = <usr-A>`, либо
`REVOCATION_REASON_RESOURCE_UNREGISTERED` и `revokedByUserId` пуст
**И** при втором исходе `Operation.error` отзыва — `FAILED_PRECONDITION`
`access binding <A> is not active (status REVOKED); cannot revoke`
**И** строк аудита отзыва этой выдачи (`revoked` или `resource_unregistered_revoked`) — ровно 1

#### URG-28 · два снятия одной цели параллельно

**Дано** выдача B2 из 06

**Когда** параллельно `withdrawX` и `UnregisterResource` по Y, 50 итераций на свежих ключах

**Тогда** B2 `REVOKED` с причиной `REVOCATION_REASON_RESOURCE_UNREGISTERED`
**И** ни в одной итерации B2 не осталась `ACTIVE` с целью, содержащей снятый ключ, или с
пустой целью

### Группа H — что снятием не является (Д1)

#### URG-29 · снятие незарегистрированного ключа выдачу на этот ключ не трогает

**Дано** мир У и выдача rol-reg-get человеку usr-D с целью `[{registry.registries, Q}]` (Q не
регистрировался)

**Когда** `UnregisterResource` по `registry_registry:Q`

**Тогда** gRPC OK (контракт идемпотентности); выдача `ACTIVE`, `revocationReason` не задан

Близнец 01: отличается одним фактом — строки зеркала у ключа не было.

#### URG-30 · устаревшее надгробие после повторной регистрации ничего не отзывает

**Дано** URG-03 исполнен: X зарегистрирован заново версией `v3`, выдача usr-D действует

**Когда** приходит снятие X с версией-надгробием `v2 < v3` (запоздалая доставка)

**Тогда** gRPC OK; выдача usr-D `ACTIVE`; `Check(usr-D, …, X)` → allow

Близнец 01: отличается одним фактом — версия надгробия.

#### URG-31 · снятие публикации — не снятие регистрации

**Дано** мир У после `deliverNewEdition`; объект X опубликован для анонимного чтения
(`RegisterResource` с `{"subjectId":"system_class:anonymous","relation":"v_get","object":"registry_registry:<X>"}`)

**Когда** `UnregisterResource` того же кортежа публикации

**Тогда** `Get(A).status = ACTIVE`; `Check(usr-B, …, X)` → allow

Близнец 01: отличается одним фактом — снимается публикация, а не объект.

#### URG-32 · повтор применённого снятия ничего не меняет

**Дано** URG-01 исполнен; `revokedAt` A запомнен; число строк аудита и ленты по A запомнено

**Когда** тот же `UnregisterResourceRequest` (та же версия) доставлен ещё раз

**Тогда** gRPC OK; `Get(A).revokedAt` прежний, причина прежняя
**И** новых строк `kaname.audit_outbox` и `kaname.resource_journal` по A — 0

### Группа I — наблюдаемость и причина на каждом пути (Р5, Д2, Д7)

#### URG-33 · аудит и лента каждого изменения

**Дано** мир У: выдача A (цель `[X]`), выдача B2 (цель `[X, Y]`), роль rol-reg-names-XY с
выдачей (группы A, B, F)

**Когда** `withdrawX` вызван служебной учёткой модуля

**Тогда** в `kaname.audit_outbox` ровно по одной строке:
`iam.access_binding.resource_unregistered_revoked` с `binding_id = A`,
`iam.access_binding.resource_unregistered_narrowed` с `binding_id = B2`,
`remaining_resource_count = 1`, `iam.role.resource_unregistered_narrowed` с `role_id` роли,
`removed_rule_count = 0`, `remaining_rule_count = 1`; у всех `unregistered_resource =
{"type":"registry.registries","id":"<X>"}`, `actor` — id служебной учётки
**И** в `kaname.resource_journal` по строке `UPDATED` для A, B2 и роли; полезная нагрузка A
несёт `status = REVOKED` и причину

#### URG-34 · причина пишется на каждом пути отзыва

**Дано** мир У: выдача R1 на `[Y]`; выдача R2 с `expiresAt` = сейчас + 2 с на `[Y]`; строка
R0, отозванная до миграции (посев строки `REVOKED` с `revoked_by_user_id` в базе на миграции
предыдущей головы, затем накат)

**Когда** usr-A отзывает R1 глаголом `Revoke`; срок R2 истекает и отрабатывает проход срока

**Тогда** `Get(R1).revocationReason = REVOCATION_REASON_REVOKE`, `revokedByUserId = <usr-A>`
**И** `Get(R2).revocationReason = REVOCATION_REASON_EXPIRED`, `revokedByUserId` пуст
**И** `Get(R0).revocationReason` не задан (`UNSPECIFIED`), `status = REVOKED`

### S2 — сквозной набор службы (`PRO-Robotech/kaname`, newman, собственный REST-фронт)

Снятие регистрации на крае недоступно (ban #6, §2), поэтому его следствия судятся
интеграцией (`testing-newman.md#edge-internal-consequence`). Край судит то, что через него
проходит: поле причины в теле ответа.

#### URG-E1 · причина отзыва видна на крае

**Дано** роль и выдача кейса созданы через фронт (`POST /iam/v1/accessBindings`, область
`iam.account`/`{{accountId}}`, цель `{"allInScope":{}}`), операция опрошена до `done = true`

**Когда** `POST /iam/v1/accessBindings/{{accessBindingId}}:revoke`, операция опрошена до `done`

**Тогда** `GET /iam/v1/accessBindings/{{accessBindingId}}` → HTTP 200,
`status = "REVOKED"`, `revocationReason = "REVOCATION_REASON_REVOKE"`
**И** `GET /iam/v1/accessBindings?filter=…&includeRevoked=true` содержит выдачу с тем же
`revocationReason`. Выдача и роль снимаются в уборке кейса

#### URG-E2 · близнец E1: у действующей выдачи причины нет

**Дано** то же, что в E1, до «Когда»

**Когда** `GET /iam/v1/accessBindings/{{accessBindingId}}` без отзыва

**Тогда** HTTP 200, `status = "ACTIVE"`, ключа `revocationReason` в теле нет

От E1 отличается одним фактом: отзыва не было.

---

## §5. Сценарий → производитель

Производителя в дереве у новых «Тогда» нет: это и есть предмет кода `#963`. Производитель
заказан реализацией задачи, его место названо, держатель — проба с утверждением.

| ID | что производит «Тогда» | координата производителя (место) и строка утверждения держателя | чем измерено |
|---|---|---|---|
| 01, 07, 11, 15 | отзыв в транзакции снятия, причина, флаг не трогается | заказан: `Unregister` (`register_resource.go:533`) в транзакции `uc.emit` — отзыв выдач по ключу, CAS `UPDATE … WHERE status = 'ACTIVE'` без условия на `deletion_protection`. Держатель — новый файл `unregister_revokes_grants_world_integration_test.go`: `require.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, got.GetRevocationReason(), "…")` | RED до кода — строка `ACTIVE` |
| 02 | прежняя выдача не достаёт до нового объекта | производитель — отзыв из строки выше. Держатель — `TestUnregister_GrantOnFormerObjectDoesNotReachReRegisteredKey`, `assert.False(… "kaname#963: выдача, сделанная на ПРЕЖНИЙ объект X, достаёт до объекта…")` | RED @`318f793bb`, со слов диспетчера |
| 03 | новая выдача действует | существующий путь `Create` + перерасчёт. Держатель — `TestUnregister_GrantMadeAfterReRegistrationReaches`, `w.pollAsk(usrD, … true, "kaname#963 близнец: …")` | существует |
| 04, 09 | `Create` после отзыва и после сужения — новая выдача | индекс `access_bindings_active_grant_uniq` (`0001_initial.sql:4443`) — для 04 без изменений (отозванная строка слот не занимает); для 09 заказан новый предикат индекса, исключающий суженные строки (миграция `#963`). Держатель — `require.NotEqual(t, A, newID, …)` и `require.Nil(t, op.GetError(), …)` | RED до кода: A не отозвана, и `Create` получает `ALREADY_EXISTS`; 09 — сужения нет |
| 05, 17, 22, 29, 30, 31, 37 | не тронуто | условие Д1 в том же месте, что строка 01 (ключ — пара «тип, id»; применённое снятие); для 22 и 37 — сужение роли трогает только правила с этим ключом. Держатели — подтесты близнецов: `require.Equal(t, iamv1.AccessBinding_ACTIVE, …)`, `require.Equal(t, before, role.GetRules(), …)` | зелены до кода и обязаны остаться зелены |
| 06, 07, 08, 28 | сужение, отзыв опустевшей, совпадение, параллельные снятия | заказан: сужение цели той же транзакцией под замком строки выдачи; опустевшая — отзыв (Д3); индекс уникальности не судит суженную (Д4). Держатель — `require.Equal(t, []*iamv1.ResourceRef{{Type: "registry.registries", Id: Y}}, got.GetTarget().GetResources().GetResources(), …)`, для 07 — `require.False(t, w.ask(usrD, "v_get", pcrRegType, pcrZ), …)` | RED до кода |
| 10 | `ALREADY_EXISTS` | `pgmaperr.go:455` (без изменений). Держатель — `require.Equal(t, codes.AlreadyExists, …)` и текст дословно | существует |
| 12 | защита уважается глаголом | `revoke.go:112-114` (без изменений) | существует |
| 16 | потомки нового контейнера | ветвь выдач и материализатор (`grantarm.go`, `reconcile_adapter.go:472`) читают уже отозванную выдачу. Держатель — `require.False(… X/late …)` | RED до кода |
| 19, 20, 21 | сужение роли, удаление правила, роль без правил | заказан: в той же транзакции снятия — правка `roles.rules` и `roles.permissions` (пересчёт `CompileRules`, `internal/domain/rule.go:402`) и трёх проекций (`role_rule_selectors`, `role_verb`, `role_rule_ref`) единственными писателями (`role_repo.ReplaceRuleSelectors` `:1091`, `ReplaceRoleVerbs` `:954`, `ReplaceRuleRefs` `:1000`); правило без названий не хранится (Д5); миграция Р6 — новая форма `roles_permissions_valid`. Держатель — `require.Equal(t, []string{Y}, role.GetRules()[0].GetResourceNames(), …)`, `require.Empty(t, role.GetRules(), …)`, для 20 — `SELECT rules, permissions` → `[]`, `[]` и `require.False(t, w.ask(usrD, "v_get", pcrRegType, pcrZ), …)` | RED до кода; 20 до миграции — отказ ограничения |
| 35, 36 | имена вложенного правила | заказан: то же место, что 19–21, для `rules[i].children[j].resourceNames`; вложенное правило без имён снимается (Р7); строка отбора вложенного правила переписывается тем же писателем, что кладёт её на старте (`migrate_backfill.go:420`) либо `ReplaceRuleSelectors` — один писатель, форма — замысел. Держатель — `unregister_nested_names_world_integration_test.go`, правила роли читаются `w.roleRules(role)` (строка роли через `Roles().Get`): `assert.Equal(t, []string{"t3"}, rules[0].Children[0].ResourceNames, "URG-35: имена вложенного правила не [t3]")`, `assert.False(t, w.tag("t1"), …)`; для 36 — `assert.Empty(t, rules[0].Children, "URG-36: вложенное правило без имён хранится")` и `assert.False(t, w.tag("t4"), "URG-36: пустой перечень стал ветвью anchor — t4 открыт")` | RED до кода |
| 38, 40 | роль без правил ничего не даёт; отказ текстом покрытия | заказан: `tuples.go:73-93` — ветвь «только с перечнем прав» лишь при непустом `permissions`; `structural_gates.go:107-121` — проверка 3a лишь при непустом `permissions`, проверка покрытия (`:128-135`) и при пустых правилах. Держатель 38 — по его «Тогда»: `SELECT relation, object FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1` → только указатель на родителя выдачи, и `require.False(t, w.ask(usrB, "v_get", pcrRegType, pcrY), …)`, `… pcrZ`; правку `tuples.go` держит инъекция I7 через URG-20. Для 40 — `require.Equal(t, codes.FailedPrecondition, …)` и текст дословно | RED до кода (38 — до миграции роль не строится; 40 — текст 3a) |
| 39, 41 | роль с правилом | существующий путь. Держатель — `require.True(t, w.ask(usrB, …, Y), …)`, `require.Nil(t, op.GetError(), …)` | зелены до кода |
| 24, 26 | отказ Т1/Т2 либо отзыв/сужение | заказан: запись выдачи и роли судит регистрацию названных ключей под замком, согласованным со снятием (форма — замысел). Держатель — счётчик итераций, `require.Zero(t, liveOnUnregistered, …)`, `require.GreaterOrEqual(t, writtenAfterUnregister, 1, …)`; точка удержания — обёртка порта `Repo` у `create.go:300` | RED до кода |
| 25 | выдача на свободный ключ | существующее поведение ATC-03 | зелен до кода |
| 27 | ровно один отзыв | CAS `WHERE status = 'ACTIVE'` у обоих писателей (`access_binding_repo.go:857` и новый) | RED до кода (у снятия писателя нет) |
| 32 | идемпотентность | Д1: повтор не удаляет строку зеркала → отзыва нет. Держатель — `require.Equal(t, before, after, …)` по `revokedAt` и числу строк | RED на реализации, отзывающей по любому снятию |
| 33 | аудит, лента | заказан: `EmitAuditEvent` (`internal/repo/kaname/access_binding/iface.go`) с новыми типами; лента — триггеры `20260914090000_…:335`, `:327`, функция полезной нагрузки дополняется полем причины. Держатель — `SELECT event_type, event_payload FROM kaname.audit_outbox WHERE …` | RED до кода |
| 34 | причина на каждом пути | заказан: `RevokeGuarded` (`access_binding_repo.go:847`) и `RevokeExpiredBinding` (`reconcile_adapter.go:1459`) пишут причину; миграция — колонка и проекция в `dto/toproto/access_binding.go`. Держатель — подтесты по пути | RED до кода |
| E1, E2 | поле в теле края | проекция `toproto` + пересборка фронта. Держатель — новый кейс `tests/newman/cases/iam-access-binding-revocation-reason.py`, `pm.expect(body.revocationReason).to.eql("REVOCATION_REASON_REVOKE")`, близнец — `pm.expect(body).to.not.have.property("revocationReason")` | RED до кода |

Сценариев без производителя — **ноль**: у каждого «Тогда» производитель есть в дереве либо
заказан кодом `#963` с названным местом. URG-13, 14, 18, 23 сняты решением диспетчера 2
(§2, `#965`).

---

## §6. Признак готовности (DoD)

### S1 — `PRO-Robotech/kaname`

1. **Контракт.** `AccessBinding.revocation_reason = 26` с перечислением
   `AccessBinding.RevocationReason` (Д2); комментарии `AccessBinding.target`,
   `AccessTargetResources` (цель сужается снятием регистрации; правка сводится при посадке с
   правкой соседа из ветки `746`, §2), `Role.rules` (Р6), `Rule.children` и `Rule.resource_names`
   (имена снимаются снятием регистрации, Р1 (д), Р7), `UnregisterResource` (отзыв и сужение по
   Р1). Изменение аддитивно: `buf lint` и `buf breaking` против ствола зелёные.
2. **Миграция новая** (ban #5), номер больше `20261024010000`:
   `git diff --name-status <база>...HEAD -- 'internal/migrations/*.sql'` даёт ровно одну
   строку `A`. В ней: колонка причины с закрытым `CHECK`, согласованным с
   `access_bindings_revoked_consistency_ck`; предикат индекса уникальности по Д4; новая форма
   `roles_permissions_valid` — допустимо `permissions = []` и `rules = []` (Р6); раздел отката
   восстанавливает прежние определения дословно. `TestNewMigrationOutranksEveryAppliedOne`
   зелёный. Шапка миграции называет санкцией эту приёмку: путь, редакцию и отпечаток одобренной
   редакции.
3. **Структурные проверки выдачи** правлены по Р6: `structural_gates.go:107-121` (проверка 3a
   — лишь роль с непустым `permissions`), `tuples.go:73-93` (кортежи уровня области — лишь
   при непустом `permissions`). Пару `rules = []`, `permissions = []` отвергает и
   `domain.Role.Validate` (`internal/domain/role.go:151-157`: роль без правил обязана нести
   хотя бы одно право) — он правится тем же изменением. Держатели — URG-38, URG-40; близнецы
   URG-39, URG-41 зелены.
4. **Пробы — до правки** (ban #12): на дереве с пробами и без кода красны 01, 02, 04, 06, 07,
   08, 09, 11, 15, 16, 19, 20, 21, 24, 26, 27, 28, 32, 33, 34, 35, 36, 38, 40. Зелены близнецы
   03, 05, 10, 12, 17, 22, 25, 29, 30, 31, 37, 39, 41 и контроли фикстуры П3-У (35, 36 до
   «Когда»). Красное прочитано по тексту утверждения.
5. **Все действующие URG-01…URG-41 (кроме снятых 13, 14, 18, 23) зелены одновременно на
   голове:** пакеты `internal/apps/kaname/api/access_binding`,
   `internal/apps/kaname/api/internal_iam`, `internal/apps/kaname/api/role`,
   `internal/repo/kaname/pg` — `ok`, FAIL 0. Конкурентные 24, 26, 27, 28 печатают число
   итераций (50) и число исходов каждого вида; 24 — ещё число итераций с записью после снятия
   (≥ 1).
6. **Способность упасть показана инъекциями,** по одному факту на инъекцию:
   - I1 — снятие не отзывает: красны 01, 02, 33; близнецы 29–31 зелены;
   - I2 — опустевшая цель хранится пустой: красна 07 (утверждение по Z);
   - I3 — отзыв по снятию с условием `deletion_protection = false`: красна 11, 12 зелена;
   - I4 — отзыв на любом снятии без проверки удалённой строки зеркала: красны 29, 30, 32;
   - I5 — правило без названий хранится с `resourceNames: []`: красна 20 (утверждение по Y и Z);
   - I6 — запись выдачи не судит регистрацию названного ключа: красна 24, 25 зелена;
   - I7 — при `rules = []` оставлен прежний `permissions`: красна 20 (утверждения по Y, Z и
     форме строки), близнец 22 зелен;
   - I8 — вложенное правило без имён хранится с `resourceNames: []`: красна 36 (утверждения по
     `t3`, `t4`), близнец 37 зелен.

   Красное другого подтеста или сбой прогона — дефект постановки инъекции, а не её исход.
7. **Отзыв в транзакции снятия:** проба 01 с инъекцией отказа после отзыва и до фиксации
   (`Unregister` возвращает ошибку) — строка зеркала на месте, выдача `ACTIVE`, строк аудита 0.
8. **Причина на каждом пути** — перепись §0.2 повторена на голове: писателей `REVOKED` три
   (глагол, срок, снятие), у каждого держатель в 34 или 01.
9. **Уборка:** каждая проба снимает созданное (`t.Cleanup`), census
   `scripts/residue-census/census.sh` до и после — 0.
10. **Цена снятия названа числом:** `EXPLAIN (ANALYZE)` поиска выдач и правил по ключу на
    базе стенда — индексный доступ, время в мс и число строк записаны в `DoD-proof` задачи.

### S2 — `PRO-Robotech/kaname`, сквозной набор

11. Кейс `tests/newman/cases/iam-access-binding-revocation-reason.py` (E1, E2) заведён и
    зарегистрирован по правилам kaname: строка `run_one "iam-access-binding-revocation-reason"`
    в `tests/newman/scripts/run.sh` (образец — `run.sh:497`) и строка
    `--service iam-access-binding-revocation-reason` в `.github/workflows/e2e-newman.yml`
    (образец — `:992`). Прогон набора на внешнем кластере против стенда службы в боевой
    посадке — E1, E2 зелены, пара «HTTP-статус и `code`» утверждается
    (`api-case-asserts-pair`).
12. Полный набор newman службы и полный CI зелёные на голове ветки (порядок —
    `CLAUDE.md` «Перепись — потом массово»).

---

## Редакция 2: что закрыто

| замечание круга 1 | род | что сделано | где |
|---|---|---|---|
| роль с `rules = []` схемой запрещена | CONSTRUCTIBILITY | Р6: форма `rules = []`, `permissions = []`, миграция ограничения, правка проверок; инъекция I7; URG-38…41 | §0.7, §3 Р6, URG-20, F3, §6 п.2, 3, 6 |
| выдачу посева с перечнем объектов не строит применитель | CONSTRUCTIBILITY | группа D, URG-18, URG-23 и Д8 сняты; ссылки на объекты в манифестах — `#965` | §0.7, §2, §3 Р1 (г), группа D |
| имена вложенного правила не покрыты | COVERAGE | Р7; URG-35 (одно из нескольких), URG-36 (последнее), близнец URG-37; инъекция I8 | §3 Р7, Д5, группа F2 |
| выдачи на ключи, снятые до выката | SCOPE | строка §2; §1 сужен до снятий после выката | §1, §2 |
| решение о манифестах не вписано | SCOPE | строка §2 со ссылкой на `#965` | §2 |
| регистрация набора — оснастка kacho | DoD | `run_one` и `--service` по правилам kaname | §6 п.11 |
| окно гонки не обязано быть задето | FORMAT | точка удержания `create.go:300`; итераций с записью после снятия ≥ 1 | URG-24 |
| комментарий `AccessTargetResources` правит и сосед | CONVENTION | строка §2 «свести при посадке» | §2, §6 п.1 |
| документ не закоммичен | FORMAT | коммит — шаг исполнителя полосы; отпечаток закоммиченной редакции обязан совпасть с одобренным | — |

Формулировка гонки закреплена решением Р8: выдача принята до снятия, записана после.

---

## Опора: одобренные соседи

| сосед (путь · отпечаток) | что закреплено | стык |
|---|---|---|
| `access-target-names-live-catalog-types.md` · `18360285461ee74e59c92a0445fcff9d313e8c2e3ed99bb56b4efce209ff9bd9` (ветка `746`, APPROVED, круг 2) | цель — «graceful-dangling» (ATC-03); снятие типа выдачу не трогает (ATC-14, Р5) | Д6 читает Р2 через ATC-03: выдача, принятая после снятия, — выдача на свободный ключ (URG-25). Р5 соседа — о снятии ТИПА и чтении; здесь цель переписывается ЗАПИСЬЮ при снятии ОБЪЕКТА, чтение не фильтрует |
| `relation-fact-remembers-its-removal.md` · `f5b979630f087295e8b8038a0ac4dbe43936c9522a920cfe1d9b96a3600b9304` (ветка `636`, APPROVED, круг 2) | след снятия судит только строки с версией владельца; строки выдачи упорядочены меткой журнала (Р4 соседа) | отзыв и сужение выдачи снимают кортежи строками без версии владельца — след соседа их не судит. Снятие публикации в URG-31 — путь соседа, без изменения |
| `nested-rule-reaches-descendants-of-a-named-container.md` · `f12395ae242f85e1120346123286318b3027d87e53f6973f4b8a21ac1bd6d9f6` (APPROVED, запись `docs/specs/reviews/nested-rule-reaches-descendants-of-a-named-container/f12395ae…yaml`) | вложенное правило достаёт до потомков контейнера, выбранного целью или правилом-владельцем | URG-15–17: контейнер X, снятый с регистрации, снимается из цели. Имена правила-владельца в ролях манифеста — `#965` (§2); имена вложенного правила — URG-35–37 (Р7). Мир — П3-У на типах registry: репозитории под X с id без `/` (`t1`, `t3`, `t4`), которым форма имени `^[a-zA-Z0-9_-]+$` годна. Реальный registry таких id не создаёт (его id репозитория несёт `/`, Р2 соседа), и предмет держится на уровне контракта kaname, где id непрозрачен |
