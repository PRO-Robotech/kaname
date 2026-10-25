<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: делегированные выдачи не выходят за делегирование

- **Статус:** DRAFT, редакция 3. Вердикта на эту редакцию нет, санкции на код нет (ban #1).
  Вердикт выносит `acceptance-reviewer`
- **Статическая форма:** DRAFT. Слово вписано автором и вердиктом не является. Действующее
  одобрение выводится из записи ревью по отпечатку редакции и из внешнего события, на которое
  запись ссылается (`change-graph.md` §3). После ревью слово DRAFT не правится
- **История ревью:** только дописывается строками вида «дата · круг · вердикт · SHA-256
  редакции · путь записи». Прежние строки не правятся и не удаляются. Записи кладутся в
  `docs/specs/reviews/delegated-grants-stay-within-the-delegation/<sha256>.yaml`
  - 2026-10-25 · круг 1 · CHANGES_REQUESTED (блокирующих 4: PRODUCER ×3, COVERAGE ×1) ·
    `51da4ac879859f6a11b5f92a72a62bc8372f434b7492507962ecb0252fe68165` ·
    `docs/specs/reviews/delegated-grants-stay-within-the-delegation/51da4ac879859f6a11b5f92a72a62bc8372f434b7492507962ecb0252fe68165.yaml`
  - 2026-10-25 · круг 2 · APPROVED (блокирующих 0) ·
    `43622b181b782b8ee969d77de33412a9adc12dfbe17f39a25de5f652c3df37c1` ·
    `docs/specs/reviews/delegated-grants-stay-within-the-delegation/43622b181b782b8ee969d77de33412a9adc12dfbe17f39a25de5f652c3df37c1.yaml`
- **Дата:** 2026-10-25 · **редакция:** 3. Что изменено против редакции 1 — §10, против
  редакции 2 — §11
- **Задача:** `PRO-Robotech/kaname#986`. Связь: `#1003` (служебная учётка модуля без прав на
  проект, группу и роль), `#982` (родителя объекта выводит kaname), `#983` (привязка объекта к
  проекту переживает снятие регистрации), `#984` (перечень методов на личность модуля), `#987`
  (Check модуля в пределах домена), `#988` (признание модуля по выпустившему УЦ), `#963`
  (снятие регистрации снимает выдачи, посажено)
- **Потребитель:** приёмка svc-registry «единственный писатель IAM и выдача токенов»
  (дом — `docs/acceptance/registry-iam-and-tokens.md` репозитория svc-registry), редакция 3,
  SHA-256 `2717077568f0057fa3205069807b4cc1b5fa72ec00ecda50eadfad0967b22dc7`, статус DRAFT.
  Её группа F (учётные данные) и сценарий SRI-111 опираются на механизм этой приёмки (§3а
  строка «делегирование» там). Соответствие строк — §5.3
- **Ревизия измерения:** kaname `5c6b7c078` (голова `origin/955`). Каждое число о дереве ниже
  снято на этой ревизии командой рядом. Посева и прогона не было: «Дано» показано чтением
  писателя со строкой (§4.1, §5.2)
- **Тип изменения:** контракт `.proto` (новая служба `GrantDelegationService`, новое сообщение
  `GrantDelegation`, новое поле вывода `AccessBinding.delegation_id`, новое значение
  `AccessBinding.RevocationReason`; аннотация права `AccessBindingService.Revoke` и `Delete`
  меняется с `v_delete` на `<exempt>` · `HANDLER_DECIDES`, Р1а); новая миграция (таблица
  делегирований, ссылка выдачи на делегирование); поведение `AccessBindingService.Create`,
  `Revoke`, `Delete`, `ServiceAccountService.Delete`; новые типы аудита
- **Сервис:** `kaname`

---

## §0. Перепись производителей — до сценариев

### 0.1. Кто сегодня вправе выдавать

```sh
git grep -n -E 'Path [0-2]' -- internal/apps/kaname/api/access_binding/helpers.go
# → 156 (Path 0), 238 (Path 1), 243 (Path 2)
```

Право выдавать спрашивает одна функция `requireGrantAuthority`
(`internal/apps/kaname/api/access_binding/helpers.go:155`). Путей три: администратор облака
(`:170`), владелец аккаунта области (`:239`), отношение `admin` на объекте области (`:320`,
`relations.Check(ctx, subject, "admin", …)`). Отказ — `PERMISSION_DENIED` `permission denied`
(`internal/authzguard/authzguard.go:63-64`), неполадка хранилища прав —
`UNAVAILABLE` `authz backend unavailable` (`:86-87`).

Отзыв и удаление выдачи спрашивают ту же функцию на области выдачи
(`revoke.go:105`, `delete.go:125`). Несуществующая выдача отвечает `PERMISSION_DENIED`, а не
`NOT_FOUND`: так скрывается существование (`revoke.go:94-98`, `get.go:66-72`).

**До обработчика вызов проходит дверь слушателя.** На арендаторском слушателе каждое
обращение сперва судит собственная дверь kaname (`authzguard.NewOwnDoor`,
`cmd/kaname/serve.go:885`); её карта выводится из аннотаций контракта
(`internal/authzguard/own_door.go`, шапка «Карта ВЫВОДИТСЯ»). Аннотации глаголов выдачи:

```sh
grep -n -E 'rpc (Create|Delete|Update|Revoke) |exempt_reason|required_relation' \
  proto/kaname/cloud/iam/v1/access_binding_service.proto
# → Create :39 — "<exempt>", HANDLER_DECIDES (:55-56)
#   Delete :61 — v_delete на iam_access_binding (:67-68)
#   Update :83 — v_update на iam_access_binding (:89-90)
#   Revoke :413 — v_delete на iam_access_binding (:419-420)
```

У объекта выдачи `v_delete` и `v_update` — прямые кортежи либо `super_admin` от области
(`internal/authzmodel/fga_model.fga:927-942`). Тот, у кого на объекте выдачи нет ни того ни
другого, получает отказ двери до use-case. Обработчик решает только у `Create`.

### 0.2. Делегирования права выдавать нет

```sh
git grep -c -i -E 'grant.?option|grant_?delegation|GrantDelegation' -- internal proto | wc -l
# → 0 (файлов с совпадением нет)
git grep -n -E '^service ' -- 'proto/kaname/cloud/iam/v1/*.proto' | wc -l
# → 24 службы
git grep -n -E '^service .*Delegat' -- proto | wc -l
# → 0
```

Первый предикат — по написанию, второй и третий — по предмету: среди 24 служб домена нет ни
одной о делегировании.

### 0.3. Цель выдачи сужает, ЧТО выдано, но не КТО вправе выдать

- область выдачи — только `iam.cluster`, `iam.account`, `iam.project`
  (`internal/domain/access_binding_scope.go:19-22`, `:51-53`);
- цель — `resources` (закрытый перечень `ResourceRef{type,id}`) либо `allInScope`
  (`proto/kaname/cloud/iam/v1/access_binding.proto:279-287`);
- право выдавать проверяется на ОБЛАСТИ (`create.go:268`), цели оно не читает.

### 0.4. Порядок проверок `AccessBindingService.Create`

`create.go:192-300`: живость типа цели (`:198`) → аутентификация → разбор субъектов
(`INVALID_ARGUMENT`) → форма идентификатора области → `Validate` → нижняя граница срока →
**право выдавать** (`:268`) → структурные ворота (назначаемость роли, покрытие типа) → ворота
системного класса → правило кластера. Структурные ворота стоят после права: отказ в праве не
раскрывает, есть ли роль и проект (`structural_gates.go:20-30`). Окно свежести сессии при выдаче
системному классу спрашивается только у человека (`system_class_gates.go:220-224`).

### 0.5. Субъект выдачи и аккаунт области

```sh
grep -n -i -E 'subject.{0,30}(account|foreign|cross)' \
  internal/apps/kaname/api/access_binding/create.go \
  internal/apps/kaname/api/access_binding/structural_gates.go internal/domain/access_binding*.go
# → пусто (0)
```

Сверки «субъект принадлежит аккаунту области» на пути выдачи нет. Для делегированного пути она
вводится этой приёмкой (Д6).

### 0.6. Причина отзыва и аудит

- `AccessBinding.RevocationReason` — 0…3: не отозвана · `REVOKE` · `EXPIRED` ·
  `RESOURCE_UNREGISTERED` (`access_binding.proto:254-266`, посажено `#963`);
- типы аудита выдачи в прод-коде:
  ```sh
  git grep -n -E '"iam\.access_binding\.[a-z_]*"' -- '*.go' ':!*_test.go' | wc -l
  # → 6: granted, revoked (internal/repo/kaname/access_binding/iface.go:334, :336),
  #      resource_unregistered_revoked, resource_unregistered_narrowed
  #      (internal/apps/kaname/api/access_binding/unregistered_key.go:50-51),
  #      orphan_scope_revoked (internal/apps/kaname/seed/orphan_scope_sweep.go:68),
  #      containment_rejected (internal/repo/kaname/pg/reconcile_adapter.go:1413)
  ```
  Приёмник — `kaname.audit_outbox`; RPC чтения аудита нет. Держатель аудита — чтение этой таблицы.

### 0.7. Роли модуля

- правило роли называет ровно один модуль (`proto/kaname/cloud/iam/v1/role.proto:117`);
- роли модуля объявляет манифест модуля и доставляет загрузчик: идентификатор роли выводится
  (`rolb1325b011aa17211d` у `registry.public.read`,
  `internal/testsupport/publicreadfixture/publicreadfixture.go:61-62`), имя — идентификатор из
  манифеста;
- роли модуля `iam` объявлены встроенным манифестом службы: `iam.project.admin`,
  `iam.group.admin`, `iam.role.admin` и т.д. (`manifest.yaml:865-1045`);
- роли `registry.puller`, `registry.pusher`, `registry.admin` объявляет манифест svc-registry, в
  дереве kaname их нет:
  ```sh
  git grep -c -E 'registry\.(puller|pusher)' | wc -l
  # → 0
  ```
  Мир проб заводит их своей редакцией манифеста registry (§4.1).

### 0.8. Права на проект, группу, роль, служебную учётку

`ProjectService.Create`, `GroupService.Create`, `RoleService.Create`,
`ServiceAccountService.Create` требуют `editor` на аккаунте
(`project_service.proto:59-66`, `group_service.proto:59-66`, `role_service.proto:76-83`,
`service_account_service.proto:60-67`); `GroupService.AddMember` — `v_update` на группе
(`group_service.proto:109-116`). Делегирование этих отношений давать не должно (Р3).

### 0.9. Право модуля писать регистрации — на кластере

`cluster#fga_writer` (`internal/authzmodel/fga_model.fga:284-307`): право модуля писать
кортежи объявлено на кластере. Предмет 2 задачи `#986` («на аккаунте родителя») этой
приёмкой не решается — §2 п.1, вопрос В3.

### 0.10. Каталог префиксов идентификаторов

Префиксы kaname перечислены литералами в фундаменте: `ids/ids.go:245` corelib `origin/main`
(`"acc", "prj", "usr", "sva", "grp", "rol", "acb", …`); kaname закрепляет corelib `v1.15.0`
(`go.mod`). Префикс нового ресурса заводится там (§7, В7).

### 0.10а. Принадлежность субъекта аккаунту: где лежит факт

- **учётка** — `kaname.service_accounts.account_id` (посев мира: `seedServiceAccount`,
  `system_class_world_integration_test.go:157`);
- **группа** — `kaname.groups.account_id` (`seedGroup`, `system_class_world_integration_test.go:168`);
- **человек** — строка `kaname.memberships` пары «человек × аккаунт», уникальной полностью;
  состояние `PENDING` (приглашён) или `ACTIVE` (`proto/kaname/cloud/iam/v1/membership.proto:142-148`,
  `membership_service.proto:68` — `MembershipService`). Читатель пары уже есть:
  `UserReader.Membership` (`internal/repo/kaname/pg/user_repo.go:158`), `MembershipExists`
  (`:144`) состояние не читает. У типа `account` модели прав отношения членства нет
  (`fga_model.fga`, `type account`): источник — таблица, а не модель.

### 0.10б. Кто записывается отозвавшим

`revoke.go:119`: `actor := authzguard.PrincipalUserID(ctx)`. `PrincipalUserID` отдаёт
идентификатор принципала для типов `user`, `service_account`, `system`
(`internal/authzguard/principal.go:72-74`). Подстановка `GrantedByUserID` и затем
`"system:revoke"` (`revoke.go:189-194`) срабатывает только при ПУСТОМ `actor`, то есть у
анонимного или безличного контекста; до неё анонимный не доходит
(`authzguard.RequireAuthenticated`, `revoke.go:82`). Поэтому отзыв учёткой пишет в
`revoked_by_user_id` идентификатор учётки — как и записано в контракте перечисления:
«`REVOKE` — `revoked_by_user_id` — вызывающий» (`access_binding.proto:258`). Удаление — тот же
порядок (`delete.go:141`, `:320-322`).

### 0.10в. Отказ формы пагинации: два производителя, два текста

| производитель | вход | `message` | `field_violations[0]` |
|---|---|---|---|
| `shared.ValidateRawPagination` (`internal/apps/kaname/shared/pagination.go:86`) → corelib `validate.PageSize` (v1.15.0, `validate.go:250-253`) | `page_size` вне [0..1000] | `invalid argument` (corelib `errors.go`, `InvalidArgument()`) | `{field: "page_size", description: "page_size must be in [0..1000] (0 means default)"}` |
| тот же → `shared.ValidatePageToken` (`pagination.go:30-31`) → `shared.InvalidArg` (`errdetails.go:21`) | мусорный `page_token` | `Illegal argument page_token` | `{field: "page_token", description: "Illegal argument page_token"}` |

`shared.ValidatePagination` (`pagination.go:60-62`, `Illegal argument page_size`) и
репозиторий (`internal/repo/kaname/pg/helpers.go:28`, `page_size must be in …` в `message`)
этой приёмкой производителями не называются. Сырой формой (`ValidateRawPagination`) проверяют
списки выдач (`handler.go:346`, `:362`, `:378`, `:403`, `:445`).

### 0.10г. Имя поля в отказе формы

```sh
git grep -h -o -E 'InvalidArg\(\s*"[^"]+"' -- internal ':!*_test.go' | grep -c -E '"[a-z0-9]+_[a-z]'
# → 31 (snake_case)
git grep -h -o -E 'InvalidArg\(\s*"[^"]+"' -- internal ':!*_test.go' | grep -c -E '"[a-z]+[A-Z]'
# → 4 (camelCase)
```

Второй предикат — по предмету: `InvalidArg` — единственный писатель `field_violations` в kaname
(`errdetails.go:21`). Форма kaname — имя поля `.proto` в snake_case; ей следует эта приёмка (Р6).
Тело JSON края остаётся camelCase (`naming-json-camel`).

### 0.11. Посылка задачи

| посылка | исход | чем проверено |
|---|---|---|
| в kaname нет делегирования права выдавать | **подтверждена** | §0.2, три предиката |
| право выдавать дают три пути | **подтверждена** | §0.1 |
| цель сужает выданное, но не выдающего | **подтверждена** | §0.3 |
| право писателя модуля — на кластере | **подтверждена** | §0.9 |
| правки обработчика `revoke.go`/`delete.go` хватит, чтобы делегат отзывал (допущение редакции 1) | **опровергнута** | §0.1: дверь слушателя судит `v_delete` до обработчика; закрыто Р1а |
| «правило R4» называет типы, разрешённые модулю | **не найдена** | `git grep -n -E '(правил[оа]\|rule) ?R4'` по kaname @`5c6b7c078`, по приёмке svc-registry и по воркспейсу — 0 совпадений по предмету. Принято допущение А1 (§3), вопрос В2 |

---

## §1. Предмет

Модуль выдаёт и отзывает права на объекты своего модуля от имени того, кто его к этому
допустил. Для этого вводится **делегирование права выдавать** — запись kaname, которую заводит
держатель права выдавать на аккаунте и которая ограничена четырьмя осями:

1. **набор ролей** — роли, объявленные манифестом одного модуля;
2. **типы цели** — типы объектов того же модуля;
3. **типы субъекта** — кому делегат вправе выдавать;
4. **область** — один аккаунт.

Выдача делегатом, выходящая за любую ось, за область, за права делегирующего или за
зарегистрированные объекты аккаунта, отвергается. Делегирование не даёт делегату ни прав на
проекты, группы, роли и служебные учётки, ни доступа к данным, ни права делегировать дальше.
Делегат отзывает только выданное по своему делегированию. Отзыв делегирования отзывает всё,
что по нему выдано. Каждый шаг пишет аудит.

---

## §2. Что НЕ входит

1. **Право модуля писать регистрации на аккаунте, а не на кластере** (`#986` предмет 2, §0.9).
   Меняет `InternalIAMService.RegisterResource` и место права `fga_writer`; связано с `#982`
   (родителя выводит kaname) и `#983`. Предикат снятия: одобрена приёмка, решающая предмет 2,
   либо диспетчер решил В3 иначе. Пока он не решён, `#986` этой приёмкой целиком не закрывается:
   задача входит в PR как `Refs`
2. **Право заводить служебные учётки и ключи без прав на проект, группу и роль** — `#1003`.
   Здесь утверждается только, что делегирование таких прав НЕ даёт (группа D)
3. **Правка осей действующего делегирования** (`Update`). Оси неизменяемы; расширение —
   вопрос В5
4. **Срок делегирования** (`expiresAt`). Делегирование действует до отзыва
5. **Поток изменений делегирований** (подписка). Чтение — `Get` и `List` поллом
6. **Перенос делегирования между аккаунтами, удаление аккаунта с действующими делегированиями** —
   поведение удаления аккаунта не меняется. Предикат снятия — приёмка уборки аккаунта,
   называющая делегирования
7. **Выдача делегатом с целью `allInScope`, системному классу `authenticated`, на область
   кластера** — отвергаются (группа B), а не откладываются
8. **Пределы числа делегирований и делегированных выдач в kaname** — их нет по решению
   владельца (§3 Р-В7); границы размера запроса (`roleIds` ≤ 16 и т.п.) — проверка формы, а не
   предел числа ресурсов
9. **Край kacho, консоль, публикация kaname наружу** — не трогаются (Р-В5)
10. **Правка `docs/specs/*`, сайта документации, README**

---

## §3. Решения

### Решения владельца (не переоткрываются)

Переданы заданием диспетчера 2026-10-25; дословные формулировки — §1 приёмки svc-registry
(отпечаток выше):

- **Р-В1.** «Таплы и токены создает svc-registry-mng». Kaname не заводит ни служебных учёток,
  ни выдач по своей инициативе: выдачи пишет делегат;
- **Р-В3.** «через канаме только авторизация токенов на пуш пул». Kaname только авторизует:
  делегирование — механизм авторизации записи выдач. Единственная запись kaname от себя — отзыв
  выдач при отзыве делегирования, который требует предмет задачи;
- **Р-В7.** «лимиты на кол-во ресурсов только в svc-registry». Kaname не ограничивает число
  делегированных выдач и делегирований;
- **Р-В5.** «интернал апи опубликовать не можем»: kaname наружу не публикуется. Новая служба
  монтируется на арендаторском слушателе kaname внутри кластера; новой публикации нет.

### Решение диспетчера (не переоткрывается)

- **Д-A6** (2026-10-24, дословно из `#986`): «постоянного admin на аккаунт у сервисов registry
  нет; выдачи на новый проект создаёт svc-registry через делегирование, ограниченное ролями
  модуля registry и целями типа registry (нужен механизм kaname)».

### Решения автора

**Р1. Форма контракта.** Новая служба `kaname.cloud.iam.v1.GrantDelegationService`, ресурс
`GrantDelegation`, идентификатор `gdl` + 17 знаков crockford-base32 (`ids.NewID`). Методы:

| метод | REST | ответ | право | аннотация права |
|---|---|---|---|---|
| `Create` | `POST /iam/v1/grantDelegations` | `Operation` | право выдавать на аккаунте области (три пути §0.1) | `<exempt>`, `HANDLER_DECIDES`, `required_acr_min = "2"` |
| `Get` | `GET /iam/v1/grantDelegations/{grantDelegationId}` | `GrantDelegation` | право выдавать на аккаунте области либо вызывающий — делегат | `<exempt>`, `HANDLER_DECIDES`, `required_acr_min = "1"` |
| `List` | `GET /iam/v1/grantDelegations?accountId=…&pageSize=…&pageToken=…` | `ListGrantDelegationsResponse` | право выдавать на аккаунте | `<exempt>`, `HANDLER_DECIDES`, `required_acr_min = "1"` |
| `Revoke` | `POST /iam/v1/grantDelegations/{grantDelegationId}:revoke` | `Operation` | право выдавать на аккаунте области | `<exempt>`, `HANDLER_DECIDES`, `required_acr_min = "2"` |

Почему не статическое отношение. Право выдавать — три пути, и путь владельца аккаунта —
предикат по `accounts.owner_user_id`, а не отношение модели (§0.1, `helpers.go:239`); у `Get`
к нему добавляется «вызывающий — делегат», факт строки делегирования. Статическим
`required_relation` ни то ни другое не выражается, поэтому решает обработчик — как у
`AccessBindingService.Create` (`access_binding_service.proto:45-56`). Причина `HANDLER_DECIDES`
в закрытом словаре — «владение решается предикатом у владельца ресурса»
(`proto/corelib/authz/v1/authz_options.proto:231-232`). Порог уровня входа: мутации — «2», как у
мутаций выдачи; чтения — «1», как у `AccessBindingService.Get` (`:33`).

`Update` и `Delete` нет: оси неизменяемы (§2 п.3), отозванная запись остаётся для аудита.

**Р1а. `AccessBindingService.Revoke` и `Delete` решает обработчик.** Аннотация права обоих
глаголов меняется: `required_relation = "v_delete"` с `scope_extractor` на `iam_access_binding`
→ `permission = "<exempt>"`, `exempt_reason = "HANDLER_DECIDES"`; `required_acr_min = "2"` не
меняется. Причина: у делегата на объекте выдачи нет ни одного отношения (Р3), поэтому дверь
слушателя (§0.1) отвергла бы его отзыв до обработчика. Выдать делегату `v_delete` на объекте
его выдачи — значит завести отношение модели, которого Р3 не допускает, и окно материализации на
пути отзыва; это отвергнуто.

Чтобы снятие двери не расширило прежний путь, вопрос двери ПЕРЕЕЗЖАЕТ в обработчик дословно:
прежние пути отзыва и удаления требуют, как и сегодня, `v_delete` на `iam_access_binding:<id>`
(тем же портом и с тем же надзором администратора облака, что у двери) И права выдавать на
области выдачи (`revoke.go:105`, `delete.go:125`). Несуществующая выдача — `PERMISSION_DENIED`
`permission denied` до любого вопроса (`revoke.go:94-98`), побайтово как отказ в праве.
`AccessBindingService.Update` остаётся за дверью с `v_update` (GD-22).

Цена названа в критерии «безопасность» ниже: в пакете освобождённых двери методов становится на
шесть больше (четыре метода новой службы и два глагола выдачи); у каждого гейт дерева требует
живую координату решающего кода (`authz_options.proto`, абзац «Три причины из четырёх»).

Поля `GrantDelegation` (JSON края):

| поле | вход `Create` | смысл |
|---|---|---|
| `id` | нет | `gdl…` |
| `accountId` | обязательно | область — один аккаунт |
| `delegate` | обязательно | `Subject`, только `SUBJECT_TYPE_SERVICE_ACCOUNT`; учётка может жить в другом аккаунте |
| `roleIds` | 1…16, без повторов | роли, объявленные манифестом одного модуля |
| `targetTypes` | 1…16, без повторов | точечные типы каталога того же модуля (`registry.registries`, `registry.repositories`) |
| `subjectTypes` | 1…4, без повторов, без `SUBJECT_TYPE_UNSPECIFIED` | кому делегат вправе выдавать |
| `module` | нет | модуль ролей и типов (выводится) |
| `status` | нет | `ACTIVE` · `REVOKED` |
| `delegatedBy` | нет | `{type, id}` принципала, заведшего делегирование |
| `createdAt`, `revokedAt` | нет | усечены до секунды |
| `revokedBy` | нет | `{type, id}` отозвавшего; задано только у `REVOKED` |

Порядок `roleIds`, `targetTypes`, `subjectTypes` — набор: чтение возвращает их по возрастанию
строки, порядок входа не хранится (`api-repeated-order`).

**Р2. Делегированный путь права выдавать.** Четвёртый путь `requireGrantAuthority` — только для
`AccessBindingService.Create` и для `Revoke`/`Delete` выдач этого делегирования.

**Порядок путей.** Сперва — прежние пути (§0.1; у `Revoke`/`Delete` — ещё и прежний вопрос
двери, Р1а). Делегированный путь спрашивается, только когда прежние отказали. Поле
`delegationId` выдаче ставит только делегированный путь: учётка, которая держит право выдавать
сама и при этом делегат, выдаёт прежним путём, и её выдача `delegationId` не несёт (GD-62 b).

**Выдача** делегатом принимается, только если ВСЁ верно:

- у вызывающего есть действующее делегирование на аккаунт области выдачи (делегирование
  выбирается по паре «аккаунт, делегат», в запросе выдачи оно не называется);
- область выдачи — этот аккаунт или проект в нём (кластер — нет);
- роль выдачи ∈ `roleIds`;
- цель — `resources` (не `allInScope`), тип каждого объекта ∈ `targetTypes`, каждый объект
  зарегистрирован и его проект лежит в аккаунте делегирования;
- тип каждого субъекта ∈ `subjectTypes`; субъект принадлежит аккаунту делегирования по Д6;
  системный класс — только `anonymous` (Д5); субъект не равен делегату (Д4);
- делегирующий (`delegatedBy`) сейчас держит право выдавать на этом аккаунте (Д3).

**Отзыв и удаление** делегатом принимаются, только если выдача несёт `delegationId`
действующего делегирования, делегат которого — вызывающий. Права делегирующего на отзыве не
спрашиваются: отзыв сужает доступ, а не расширяет его, и делегат, потерявший опору, должен
мочь убрать выданное им (GD-31; против выдачи — GD-20). Защита от удаления после права
работает как прежде (GD-41 a).

Иначе — `PERMISSION_DENIED` `permission denied`, побайтово тот же отказ, что у вызывающего без
права (§0.1). Делегированный путь стоит на месте права выдавать — до структурных ворот (§0.4) и
до проверки защиты от удаления, поэтому отказ ничего не говорит о роли, объекте и защите.
Структурные ворота и ворота системного класса после него работают как прежде.

**Р3. Делегирование ничего не даёт сверх выдачи.** Ни одного отношения модели прав (`admin`,
`editor`, `viewer`, `v_*`) делегат от делегирования не получает. Права на проект, группу, роль и
служебную учётку не появляются (группа D). Делегат не заводит делегирований (группа C). Выдачу
делегата правит (`Update`) только держатель права выдавать: `Update` делегированный путь не
покрывает.

**Р4. Отзыв делегирования.** `Revoke` в одной транзакции переводит делегирование в `REVOKED` и
каждую действующую выдачу с `delegationId` этого делегирования — в `REVOKED` с причиной
`REVOCATION_REASON_DELEGATION_REVOKED` (4). Защита выдачи от удаления отзыву делегирования не
мешает — так же, как снятию регистрации (`#963`, URG-11). `revokedByUserId` выдачи —
вызывающий `GrantDelegationService.Revoke`, тем же писателем, что у `REVOKE`
(`authzguard.PrincipalUserID`, §0.10б): человек или учётка. Комментарий значения в контракте:
«`revoked_by_user_id` — отозвавший делегирование».
Доступ исчезает после материализации — тем же окном, что у отзыва глаголом.

**Р5. Аудит** — в той же транзакции, что изменение:

| что | `event_type` | полезная нагрузка сверх канонических (`actor`, `tenant_account_id`) |
|---|---|---|
| заведение делегирования | `iam.grant_delegation.created` | `delegation_id`, `account_id`, `delegate`, `module`, `role_ids`, `target_types`, `subject_types` |
| отзыв делегирования | `iam.grant_delegation.revoked` | `delegation_id`, `revoked_binding_count` |
| выдача делегатом | `iam.access_binding.granted` (есть) | + `delegation_id` |
| отзыв или удаление выдачи, несущей `delegationId`, кем угодно | `iam.access_binding.revoked` (есть) | + `delegation_id` |
| отзыв выдачи отзывом делегирования | `iam.access_binding.delegation_revoked` | `delegation_id`, `revocation_reason: "delegation_revoked"` |

`delegation_id` в строке отзыва — факт о выдаче, а не о том, кто отозвал: его несёт и отзыв
делегатом, и отзыв обычным держателем права (GD-70, шаги 3 и 4). Отказанная выдача аудита не
пишет — как сегодня.

`tenant_account_id` у строк выдачи с `delegationId` и её отзыва или удаления (кем угодно, в
том числе отзывом делегирования) — аккаунт делегирования, при любой области выдачи. Это новый
писатель: существующий (`auditTenantAccountID`, `helpers.go:36-41`) ставит аккаунт только
выдаче с областью `account`, у области `project` — NULL. Строки выдач без `delegationId` и
`accountId` в метаданных операции — прежним писателем, как сегодня (GD-70, пара B14/Bo).

**Р6. Тексты отказов** — часть контракта (`api-error-tone`). Имя поля в тексте и в
`field_violations` — имя поля `.proto` в snake_case, форма kaname (§0.10г). Отказ формы с
именем поля пишет `shared.InvalidArg(field, text)` (`errdetails.go:21`): `message` = текст,
`field_violations[0]` = `{field, description: текст}`. Отказ формы идентификатора пишет
`shared.ValidateResourceID` (`ids.go:47-59`) — `status.Errorf` без `field_violations`, как у
всех идентификаторов kaname.

| код | текст | `field_violations[0].field` | где |
|---|---|---|---|
| `INVALID_ARGUMENT` | `account_id: required` | `account_id` | `Create`, `List`, синхронно |
| `INVALID_ARGUMENT` | `invalid account id '<x>'` | — | `Create`, `List` |
| `INVALID_ARGUMENT` | `delegate.type: only SUBJECT_TYPE_SERVICE_ACCOUNT can hold a grant delegation` | `delegate.type` | `Create` |
| `INVALID_ARGUMENT` | `invalid service account id '<x>'` | — | `Create` |
| `INVALID_ARGUMENT` | `role_ids: required` · `role_ids: at most 16 roles` · `role_ids: role <id> is listed twice` | `role_ids` | `Create` |
| `INVALID_ARGUMENT` | `target_types: required` · `target_types: at most 16 types` · `target_types: type <t> is listed twice` | `target_types` | `Create` |
| `INVALID_ARGUMENT` | `Illegal argument target_types[] "<t>" (not a live entry of the platform resource catalog; grantable types are published by <domain.CatalogEndpoint>)` | `target_types` | `Create`; форма — та же, что у цели выдачи (`create.go:136-139`) |
| `INVALID_ARGUMENT` | `subject_types: required` · `subject_types: SUBJECT_TYPE_UNSPECIFIED is not a subject type` · `subject_types: type <t> is listed twice` | `subject_types` | `Create` |
| `INVALID_ARGUMENT` | `invalid grant delegation id '<x>'` | — | `Get`, `Revoke` |
| `INVALID_ARGUMENT` | `invalid argument` (размер страницы) · `Illegal argument page_token` | `page_size` · `page_token` | `List`, §0.10в |
| `PERMISSION_DENIED` | `permission denied` | — | все отказы в праве, в том числе несуществующее делегирование (скрытие существования, как у выдачи §0.1) |
| `FAILED_PRECONDITION` | `Role <id> not found` | — | `Create`, после права |
| `FAILED_PRECONDITION` | `ServiceAccount <id> not found` | — | `Create`, после права |
| `FAILED_PRECONDITION` | `role <id> is not declared by a module manifest` | — | `Create` |
| `FAILED_PRECONDITION` | `role_ids and target_types must belong to one module; found <m1>, <m2>` | — | `Create` |
| `FAILED_PRECONDITION` | `module iam cannot be delegated` | — | `Create` |
| `FAILED_PRECONDITION` | `grant delegation <id> is already revoked` | — | `Revoke` |
| `FAILED_PRECONDITION` | `service account <id> holds an active grant delegation <gdl>; revoke it first` | — | `Operation.error` `ServiceAccountService.Delete` (удаление учётки асинхронно, `service_account/delete.go:70`) |
| `ALREADY_EXISTS` | `an active grant delegation to service account <id> in account <acc> already exists` | — | `Operation.error` `Create` |
| `FAILED_PRECONDITION` | Т-D1: `grant delegation <id> was revoked before the access binding was written` | — | `Operation.error` выдачи (гонка, GD-51) |

**Д1. Одно действующее делегирование на пару «аккаунт, делегат»** — уникальностью в базе
(частичная, по действующим). Второе — `ALREADY_EXISTS` (GD-07); после отзыва новое заводится.
Поэтому выдача делегатом однозначно знает своё делегирование.

**Д2. Модуль делегирования.** Все роли `roleIds` объявлены манифестом одного модуля M, и все
правила этих ролей называют M; все `targetTypes` — типы M; M ≠ `iam`. Своя роль аккаунта с
правилами на M — не роль модуля: отказ (GD-06 f). Это и есть «типы, разрешённые модулю»
(допущение А1).

**Д3. Права делегирующего — в момент выдачи.** «Не шире прав делегирующего» проверяется на
каждой выдаче делегатом: делегирующий, потерявший право выдавать на аккаунте, больше ничего
выдать через делегата не может (GD-20). Выдачи, сделанные раньше, остаются — как остаются выдачи
администратора, потерявшего право (вопрос В4).

**Д4. Себе не выдаёт.** Субъект выдачи, равный делегату, — отказ (GD-11 k): право писать выдачи
не даёт права на данные (строка SRI-90 приёмки svc-registry).

**Д5. Из системных классов — только `anonymous`.** `SUBJECT_TYPE_SYSTEM_CLASS` в
`subjectTypes` разрешает выдачу классу `anonymous` (публичный режим реестра, SRI-71) и не
разрешает `authenticated`: «любой вошедший» шире аккаунта (вопрос В6).

**Д6. Субъект — из аккаунта делегирования.** Источник факта — §0.10а:

- служебная учётка — `service_accounts.account_id` = аккаунт делегирования;
- группа — `groups.account_id` = аккаунт делегирования;
- человек — **участник** аккаунта: строка `kaname.memberships` пары «человек, аккаунт
  делегирования» в состоянии `ACTIVE`. Приглашённый (`PENDING`) участником не считается: он
  ещё не принял членство, и выдача ему от имени модуля шире, чем разрешил аккаунт.
  Читатель — существующий `UserReader.Membership` (`user_repo.go:158`); модель прав членства
  в аккаунте не знает и не спрашивается.

Основание — допущение A4 приёмки svc-registry (учётка клиента — в аккаунте регистрации).
Держатели — GD-16 (человек и группа) и пара GD-10 a / GD-11 i (учётка).

**Д7. Объект — зарегистрирован и в аккаунте.** Делегат выдаёт только на зарегистрированные
объекты, чей проект лежит в аккаунте делегирования. Выдача на свободный ключ (ATC-03 соседа)
делегированным путём не принимается: делегат не вправе выдавать на то, что в аккаунте ещё не
существует.

**Д8. Удаление служебной учётки-делегата** отвергается, пока у неё есть действующее
делегирование (GD-45) — тот же порядок «сперва отозвать права», что держит триггер
`membership_carrying_rights_is_kept` для членства. Удаление учётки асинхронно
(`service_account/delete.go:70`), поэтому отказ приходит в `Operation.error`.

**Допущение А1.** «Правило R4» в задании прочитано как Д2: делегирование покрывает только типы,
объявленные манифестом одного модуля, и не модуль `iam`. Источник R4 в деревьях не найден
(§0.11); вопрос В2.

### Критерии продукта (ban #18)

- **производительность.** Выдача делегатом добавляет к пути права выдавать: одно чтение
  делегирования по уникальному индексу «аккаунт, делегат»; один вопрос о праве делегирующего
  (та же цена, что Путь 1 или 2); одно чтение регистрации на каждый объект цели; одно чтение
  принадлежности на каждого субъекта (учётка и группа — по первичному ключу, человек — по
  уникальной паре `memberships(user_id, account_id)`). Делегированный путь спрашивается только
  после отказа прежних, поэтому прежним держателям права он не стоит ничего. Отзыв
  делегирования — один `UPDATE` выдач по индексу `delegation_id`. Замер — `EXPLAIN` обоих
  запросов на базе мира проб, DoD S1 п.9; перебора выдач аккаунта быть не должно;
- **безопасность.** Поверхность расширяется, и это названо:
  1. новая служба из четырёх методов на арендаторском слушателе;
  2. четвёртый путь права выдавать — в `AccessBindingService.Create`, `Revoke`, `Delete`;
  3. **дверь слушателя больше не судит `AccessBindingService.Revoke` и `Delete`** (Р1а), а
     четыре метода новой службы освобождены от неё с рождения. Освобождённых методов в пакете
     становится на шесть больше. Решение переходит в код обработчика, и пропуск вопроса там
     уже никто не подстрахует. Это держится так: прежний вопрос двери (`v_delete` на объекте
     выдачи) переезжает в обработчик дословно; отрицания идут через слушатель (GD-32, GD-E5);
     постороннему отказ приходит побайтово тот же, что от двери (GD-30 f); гейт дерева требует
     координату решающего кода у каждого освобождённого метода.

  Делегированный путь уже трёх прежних: он не даёт ни одного отношения модели прав и ограничен
  осями, областью, принадлежностью субъекта аккаунту и правами делегирующего. Право писать
  выдачи у служб registry перестаёт требовать `admin` на аккаунт (Д-A6);
- **инновационность.** Право выдавать, ограниченное ролями, типами, субъектами и аккаунтом, с
  проверкой прав делегирующего на каждой выдаче и отзывом всех выданных выдач с причиной;
- **узнаваемость.** Ближайший аналог — `WITH GRANT OPTION` стандарта SQL (право передавать
  привилегию) и делегированное администрирование с границей прав. Имя `GrantDelegation`
  называет предмет. Отличие нашего варианта: четыре оси, выдачи только на объекты, отзыв
  делегирования отзывает выданное;
- **перспективность.** Шаг обратим: новая таблица, новое поле вывода, новое значение
  перечисления аддитивны. Миграции данных арендатора нет. Внешне адресуемые координаты не
  меняются;
- **благо продукта, производственность.** Режима «только для стенда» нет.

---

## §4. Сценарии

### 4.1. Мир проб

**Мир Д** — `newGDWorld` (заказан, `internal/apps/kaname/api/access_binding/`) поверх мира П6
`newPCRWorld` (`public_container_read_world_integration_test.go:99`), который поверх
`newSCWorld` (`system_class_world_integration_test.go:88`). Уже даёт:

- аккаунт acc-A (владелец usr-A), проект prj-A, человек usr-B без выдач и без членства в acc-A,
  учётка sva-A и группа grp-A в acc-A; аккаунт acc-B (владелец usr-C, членства в acc-A нет),
  учётка sva-B;
- реестры X = `reg00000000000000001`, Y = `reg00000000000000002` в prj-A и их репозитории `app`
  (`registerRegistry`, `registerRepository`, `:178`, `:193`);
- роль аккаунта rol-reg-get с правилом `{module: registry, resources: [registries], verbs: [get]}`
  (`seedRole`, `:151`) — своя роль аккаунта, не роль модуля;
- живую сессию человека usr-A (`seedLiveHumanSession`, `system_class_s2_integration_test.go:228`).

Дополнения (каждое — существующим глаголом или посевом мира):

- **роли модуля registry** — новая редакция манифеста registry (фикстура
  `internal/manifest/testdata/registry.delegation-fixture.yaml`, заказана), доставленная путём
  `deliverNewEdition` (`:230`: `manifest.Load` и `applyDelivered`). Роли уровня кластера:
  `registry.puller` — `{registries: [get, list]}` с вложенным `{repositories: [get, list]}`;
  `registry.pusher` — то же плюс `update` на репозиториях; `registry.admin` — то же плюс
  `delete`. Идентификаторы ролей проба читает `RoleService.List` по имени;
- **роль другого модуля** — `vpc.address_pool_admin` из `internal/manifest/testdata/vpc.resources-fixture.yaml:159`,
  доставка тем же путём;
- **роль модуля iam** — `iam.project.admin` встроенного манифеста (`manifest.yaml:955`), посев
  ролей модуля при старте (`internal/apps/kaname/moduleseed`);
- **каноническая роль** `admin` — системная роль каталога (`internal/domain/role_catalog.go:26`);
- **аккаунт службы** acc-S (владелец usr-S) и в нём учётки sva-iss (делегат), sva-iss2 (второй
  делегат), sva-other — `seedAccountByOwner`, `seedServiceAccount`
  (`testhelpers_assignable_test.go:113`, `system_class_world_integration_test.go:157`);
- **учётки** sva-A2, sva-A3 в acc-A — `seedServiceAccount`;
- **группа** grp-B в acc-B — `seedGroup` (`system_class_world_integration_test.go:168`);
- **люди** usr-M и usr-P — `mustSeedUser` (`testhelpers_assignable_test.go:80`; своя строка аккаунта у каждого), адрес подтверждён тем же `verifyAddresses`
  (`system_class_world_integration_test.go:150`); членство в acc-A: usr-M — `ACTIVE`, usr-P —
  `PENDING`. Писатель — посев строки `kaname.memberships` тем же выражением идентификатора, что
  у зеркала и бэкфилла (`kaname.membership_mirror_id`; образец `seedMembership`,
  `internal/repo/kaname/pg/membership_is_the_account_source_integration_test.go:77`), — помощник
  в пакете мира заказан. Контроль посева: `UserReader.Membership(usr-M, acc-A).State = ACTIVE`,
  `(usr-P, acc-A) = PENDING`, `(usr-C, acc-A)` — строки нет;
- **проект** prj-A2 в acc-A, проект prj-C в acc-B — `seedProjectInAccount`
  (`testhelpers_assignable_test.go:125`);
- **реестр** Z = `reg00000000000000003` в prj-C (цепь prj-C, acc-B) — `registerRegistry` с
  проектом prj-C (вариант глагола, заказан); **ключ** Q = `reg00000000000000009` не
  регистрируется никогда;
- **администратор аккаунта** usr-E: выдача канонической роли `admin` человеку usr-E, область
  `iam.account` acc-A, цель `{"allInScope":{}}`, вызов `AccessBindingService.Create` от usr-A
  (`createDone`, `system_class_world_integration_test.go:212`). Контроль: usr-E проходит Путь 2;
- **вызов от учётки** — `operations.WithPrincipal(ctx, Principal{Type: "service_account", ID: …})`
  (образец `system_class_s2_integration_test.go:334`);
- **вопрос о доступе** — `pollAsk` (`public_container_read_world_integration_test.go:353`):
  `AuthorizeService.Check` с повтором в ограниченном окне.

**Тело делегирования D1** (вызов от usr-A):

```json
{"accountId":"<acc-A>",
 "delegate":{"type":"SUBJECT_TYPE_SERVICE_ACCOUNT","id":"<sva-iss>"},
 "roleIds":["<id registry.puller>","<id registry.pusher>","<id registry.admin>"],
 "targetTypes":["registry.registries","registry.repositories"],
 "subjectTypes":["SUBJECT_TYPE_SERVICE_ACCOUNT","SUBJECT_TYPE_SYSTEM_CLASS"]}
```

**D2** — то же с делегатом sva-iss2 и `"targetTypes":["registry.registries"]`. **D-E** — то же,
что D1, с делегатом sva-iss2, вызов от usr-E. **D-U** — то же, что D1, с делегатом sva-iss2 и
`"subjectTypes":["SUBJECT_TYPE_GROUP","SUBJECT_TYPE_SERVICE_ACCOUNT","SUBJECT_TYPE_SYSTEM_CLASS","SUBJECT_TYPE_USER"]`,
вызов от usr-A. D2, D-E и D-U в одном прогоне не встречаются (Д1).

**Тело выдачи делегатом V** (вызов от sva-iss): область `iam.project` prj-A, роль
`registry.pusher`, субъект `{"type":"SUBJECT_TYPE_SERVICE_ACCOUNT","id":"<sva-A>"}`, цель
`{"resources":{"resources":[{"type":"registry.registries","id":"<X>"}]}}`. Строки отказов ниже
отличаются от V ровно одним полем.

### Группа A — заведение делегирования

#### GD-01 · владелец аккаунта заводит делегирование

**Given** мир Д; делегирований в acc-A нет
**When** usr-A вызывает `GrantDelegationService.Create` с телом D1; проба поллит
`OperationService.Get` до `done`
**Then** `done = true`, `error` пуст; `GrantDelegationService.Get` возвращает `id` с префиксом
`gdl`, `accountId = acc-A`, `delegate = {SUBJECT_TYPE_SERVICE_ACCOUNT, sva-iss}`, три `roleIds`,
два `targetTypes`, два `subjectTypes` — каждое поле по возрастанию строки; `module = "registry"`;
`status = ACTIVE`; `delegatedBy = {user, usr-A}`; `createdAt` усечён до секунды; ключей
`revokedAt` и `revokedBy` в теле нет
**And** у sva-iss нет новых выдач (`ListBySubject` sva-iss → 0) и Check(sva-iss, `admin`,
`account:acc-A`) — false.

#### GD-02 · администратор аккаунта заводит делегирование

**Given** мир Д с usr-E
**When** usr-E вызывает `Create` с телом D-E
**Then** `done`, `error` пуст; `delegatedBy = {user, usr-E}`
**And** близнец GD-03: отличается вызывающим.

#### GD-03 · без права выдавать делегирование не заводится

**Given** мир Д; usr-B выдач в acc-A не держит
**When** usr-B вызывает `Create` с телом D1
**Then** `PERMISSION_DENIED` `permission denied`, синхронно, операции нет; делегирований в acc-A — 0
**And** то же от usr-C (владелец acc-B) и от sva-iss
**And** GD-01 — близнец: отличается вызывающим.

#### GD-04 · форма запроса проверяется синхронно

**Given** мир Д; вызывающий usr-A
| пример | отличие от D1 | исход |
|---|---|---|
| a | `accountId` пуст | `INVALID_ARGUMENT` `account_id: required`; `field_violations[0].field = "account_id"` |
| b | `accountId: "acc!!"` | `INVALID_ARGUMENT` `invalid account id 'acc!!'`; `field_violations` нет |
| c | `delegate.type: SUBJECT_TYPE_USER`, `id: <usr-B>` | `INVALID_ARGUMENT` `delegate.type: only SUBJECT_TYPE_SERVICE_ACCOUNT can hold a grant delegation`; поле `delegate.type` |
| d | `delegate.id: "sva!!"` | `INVALID_ARGUMENT` `invalid service account id 'sva!!'`; `field_violations` нет |
| e | `roleIds: []` | `INVALID_ARGUMENT` `role_ids: required`; поле `role_ids` |
| f | `roleIds` — puller дважды | `INVALID_ARGUMENT` `role_ids: role <id> is listed twice`; поле `role_ids` |
| g | `roleIds` — 17 элементов | `INVALID_ARGUMENT` `role_ids: at most 16 roles`; поле `role_ids` |
| h | `targetTypes: []` | `INVALID_ARGUMENT` `target_types: required`; поле `target_types` |
| i | `targetTypes: ["registry.nope"]` | `INVALID_ARGUMENT` — текст Р6 с `"registry.nope"` дословно; поле `target_types` |
| j | `subjectTypes: []` | `INVALID_ARGUMENT` `subject_types: required`; поле `subject_types` |
| k | `subjectTypes: ["SUBJECT_TYPE_UNSPECIFIED"]` | `INVALID_ARGUMENT` `subject_types: SUBJECT_TYPE_UNSPECIFIED is not a subject type`; поле `subject_types` |
**When** `Create`
**Then** как в таблице: `message` дословно и `field_violations[0]` (`field`, `description` = `message`)
там, где поле названо; операции нет; делегирований в acc-A — 0
**And** GD-01 — близнец каждой строки.

#### GD-05 · форма проверяется до права, состав — после

**Given** мир Д
**When** usr-B (без права) вызывает `Create` a) с телом GD-04 b; b) с телом GD-06 a
**Then** a) `INVALID_ARGUMENT` `invalid account id 'acc!!'`; b) `PERMISSION_DENIED` `permission denied`
**And** близнец b — GD-06 a (тот же запрос от usr-A даёт текст о составе): отказ в праве не
раскрывает, есть ли роль и чья она.

#### GD-06 · состав делегирования: роли и типы одного модуля, не iam

**Given** мир Д; вызывающий usr-A
| пример | отличие от D1 | исход |
|---|---|---|
| a | `roleIds` + `<id vpc.address_pool_admin>` | `FAILED_PRECONDITION` `role_ids and target_types must belong to one module; found registry, vpc` |
| b | `roleIds` + `<id admin>` (каноническая) | `FAILED_PRECONDITION` `role <id admin> is not declared by a module manifest` |
| c | `roleIds: [<id iam.project.admin>]`, `targetTypes: ["iam.project"]` (`internal/authzmap/tables_gen.go:91`) | `FAILED_PRECONDITION` `module iam cannot be delegated` |
| d | `targetTypes` + `vpc.addressPool` | `FAILED_PRECONDITION` `role_ids and target_types must belong to one module; found registry, vpc` |
| e | `roleIds` + `rol00000000000000099` (нет такой) | `FAILED_PRECONDITION` `Role rol00000000000000099 not found` |
| f | `roleIds` + `<rol-reg-get>` (своя роль acc-A) | `FAILED_PRECONDITION` `role <rol-reg-get> is not declared by a module manifest` |
| g | `delegate.id: sva00000000000000099` (нет такой) | `FAILED_PRECONDITION` `ServiceAccount sva00000000000000099 not found` |
**When** `Create`
**Then** как в таблице, синхронно; операции нет; делегирований в acc-A — 0
**And** GD-01 — близнец каждой строки (отличие — одна роль, один тип или делегат).

#### GD-07 · одно действующее делегирование на пару «аккаунт, делегат»

**Given** мир Д; GD-01 выполнен (D1 `ACTIVE`)
**When** a) usr-A вызывает `Create` с телом D1 ещё раз; b) usr-A отзывает D1 (`Revoke`, `done`),
затем `Create` с телом D1
**Then** a) `Operation.error` `ALREADY_EXISTS` `an active grant delegation to service account <sva-iss> in account <acc-A> already exists`;
действующих делегирований пары — 1
**And** b) `done`, новый `id` ≠ id D1; D1 — `REVOKED`; действующих делегирований пары — 1
**And** b — близнец a: отличается тем, что прежнее делегирование отозвано.

### Группа B — выдача делегатом в пределах делегирования (SRI-111)

#### GD-10 · делегат выдаёт роль модуля на объект модуля учётке аккаунта

**Given** мир Д; D1 заведён (GD-01)
| пример | отличие от V | исход |
|---|---|---|
| a | — | создана |
| b | область `iam.account` acc-A | создана |
**When** sva-iss вызывает `AccessBindingService.Create`; проба поллит операцию
**Then** `done`, `error` пуст; `AccessBindingService.Get` выдачи от usr-A (у делегата `v_get` на
объекте выдачи нет, Р3): роль `registry.pusher`, субъект sva-A, цель X, `delegationId` = id D1,
`status = ACTIVE`, ключа `grantedByUserId` нет
**And** `pollAsk(service_account:<sva-A>, v_get, registry_registry, X, true)` — истина в окне
материализации
**And** a — близнец каждой строки GD-11.

#### GD-11 · выдача за пределами делегирования отвергается

**Given** мир Д; D1 заведён
| пример | отличие от V | ось |
|---|---|---|
| a | роль rol-reg-get (своя роль acc-A) | набор ролей |
| b | роль `admin` (каноническая), область `iam.account` acc-A | набор ролей (SRI-111 b) |
| c | роль `registry.puller`, цель `{"allInScope":{}}` | вид цели (SRI-111 c) |
| d | субъект `{SUBJECT_TYPE_USER, usr-B}` | тип субъекта (SRI-111 d) |
| e | субъект `{SUBJECT_TYPE_GROUP, grp-A}` | тип субъекта |
| f | область `iam.project` prj-C, цель Z | область |
| g | цель Z (проект prj-C в acc-B) при области prj-A | объект вне аккаунта |
| h | цель Q (не зарегистрирован) | объект не существует (Д7) |
| i | субъект sva-B (учётка acc-B) | субъект вне аккаунта (Д6) |
| j | субъект sva-iss (сам делегат) | себе (Д4) |
| k | область `iam.cluster` `cluster_root` | область |
| l | роль `registry.puller`, субъект `{SUBJECT_TYPE_SYSTEM_CLASS, authenticated}` | системный класс (Д5) |
**When** sva-iss вызывает `AccessBindingService.Create`
**Then** каждая строка — `PERMISSION_DENIED` `permission denied`, синхронно, операции нет
**And** выдач с `delegationId` = id D1 — столько же, сколько до вызова; строк аудита
`iam.access_binding.granted` от sva-iss не прибавилось
**And** GD-10 a — близнец каждой строки (одно поле).

#### GD-12 · ось типов цели

**Given** мир Д; D2 заведён usr-A (делегат sva-iss2, `targetTypes: ["registry.registries"]`)
**When** sva-iss2 выдаёт `registry.puller` учётке sva-A с целью a) `{registry.repositories, X/app}`;
b) `{registry.registries, X}`
**Then** a) `PERMISSION_DENIED` `permission denied`; b) `done`; `AccessBindingService.Get` выдачи
от usr-A — `ACTIVE`, `delegationId` = id D2
**And** b — близнец a: отличается типом объекта цели.

#### GD-13 · публичный режим: выдача классу anonymous (SRI-111 e, SRI-71)

**Given** мир Д; D1 заведён
**When** sva-iss выдаёт `registry.puller`, субъект `{SUBJECT_TYPE_SYSTEM_CLASS, anonymous}`, цель X,
область prj-A
**Then** `done`, `error` пуст; `AccessBindingService.Get` выдачи от usr-A — `ACTIVE`,
`delegationId` = id D1
**And** `pollAsk(system_class:anonymous, v_get, registry_registry, X, true)` — истина в окне
**And** близнец — GD-11 l: отличается именем класса.

#### GD-14 · выдача на несколько объектов (SRI-86)

**Given** мир Д; D1 заведён
**When** sva-iss выдаёт `registry.pusher` учётке sva-A2, область prj-A, цель a)
`[{registry.repositories, X/app}, {registry.repositories, Y/app}]`; b)
`[{registry.repositories, X/app}, {registry.repositories, Q/app}]`
**Then** a) `done`; цель выдачи — оба объекта; `pollAsk` sva-A2 `v_update` на
`registry_repository:X/app` и `…:Y/app` — истина; b) `PERMISSION_DENIED` `permission denied`
**And** a — близнец b: отличается одним объектом цели (незарегистрированный).

#### GD-15 · делегирование не даёт доступа к данным

**Given** мир Д; D1 заведён; GD-10 a выполнен
**When** проба спрашивает Check(sva-iss, `v_get`, `registry_registry:X`) и
`AccessBindingService.ListBySubject` для sva-iss
**Then** Check — false; выдач с субъектом sva-iss — 0
**And** близнец — sva-A по GD-10 a: Check истина (отличается субъектом вопроса).

#### GD-16 · человек и группа — только из аккаунта делегирования (Д6)

**Given** мир Д; D-U заведён usr-A (делегат sva-iss2; `subjectTypes` — все четыре типа);
членства в acc-A: usr-M `ACTIVE`, usr-P `PENDING`, usr-C — нет (§4.1)
| пример | отличие от V (вызов от sva-iss2, роль `registry.puller`) | исход |
|---|---|---|
| a | субъект `{SUBJECT_TYPE_GROUP, grp-A}` (группа acc-A) | `done`; `Get` от usr-A — `ACTIVE`, `delegationId` = id D-U |
| b | субъект `{SUBJECT_TYPE_GROUP, grp-B}` (группа acc-B) | `PERMISSION_DENIED` `permission denied`, синхронно |
| c | субъект `{SUBJECT_TYPE_USER, usr-M}` (участник acc-A, `ACTIVE`) | `done`; `Get` от usr-A — `ACTIVE`, `delegationId` = id D-U |
| d | субъект `{SUBJECT_TYPE_USER, usr-C}` (членства в acc-A нет) | `PERMISSION_DENIED` `permission denied`, синхронно |
| e | субъект `{SUBJECT_TYPE_USER, usr-P}` (членство `PENDING`) | `PERMISSION_DENIED` `permission denied`, синхронно |
**When** sva-iss2 вызывает `AccessBindingService.Create`; на `done` проба поллит операцию
**Then** как в таблице; в отказах выдач с `delegationId` = id D-U — столько же, сколько до вызова
**And** в c `pollAsk(user:<usr-M>, v_get, registry_registry, X, true)` — истина в окне
**And** близнецы, отличные ровно одним фактом: a — b (аккаунт группы); c — d (есть ли членство);
c — e (состояние членства). Каждая строка — на свежем мире.
**And** пара для учётки — GD-10 a (sva-A из acc-A) и GD-11 i (sva-B из acc-B).

### Группа C — не шире прав делегирующего

#### GD-20 · делегирующий потерял право — делегат больше не выдаёт

**Given** мир Д с usr-E; D-E заведён usr-E (делегат sva-iss2); D1 заведён usr-A (делегат
sva-iss; пары разные, Д1 не мешает); sva-iss2 выдал V' (= V от sva-iss2) — выдача B-E `ACTIVE`
**When** usr-A отзывает выдачу `admin` человеку usr-E (`AccessBindingService.Revoke`, `done`);
затем a) sva-iss2 выдаёт `registry.puller` учётке sva-A2 на X; b) sva-iss выдаёт то же
**Then** a) `PERMISSION_DENIED` `permission denied`; операции нет; b) `done`
**And** B-E по-прежнему `ACTIVE` (Д3); D-E `ACTIVE`
**And** b — близнец a: отличается тем, держит ли делегирующий право выдавать сейчас (usr-A —
владелец, usr-E — уже нет).

#### GD-21 · делегат не делегирует дальше

**Given** мир Д; D1 заведён
**When** a) sva-iss вызывает `GrantDelegationService.Create` в acc-A с делегатом sva-other,
`roleIds: [<id registry.puller>]`, `targetTypes: ["registry.registries"]`,
`subjectTypes: ["SUBJECT_TYPE_SERVICE_ACCOUNT"]`; b) тот же запрос от usr-A
**Then** a) `PERMISSION_DENIED` `permission denied`; делегирований sva-other — 0; b) `done`
**And** b — близнец a: отличается вызывающим.

#### GD-22 · делегат не правит выдачу

**Given** мир Д; D1 заведён; выдача B10 по GD-10 a
**When** a) sva-iss вызывает `AccessBindingService.Update` B10 с `updateMask: ["labels"]`,
`labels: {"k":"v"}`; b) тот же вызов от usr-A
**Then** a) `PERMISSION_DENIED` `permission denied`; метки B10 прежние; b) `done`, метки `{"k":"v"}`
**And** b — близнец a: отличается вызывающим.

### Группа D — без прав на проект, группу, роль, учётку (#1003)

#### GD-25 · делегат не трогает проекты, группы, роли и учётки

**Given** мир Д; D1 заведён
| пример | вызов | от sva-iss | близнец: от usr-A |
|---|---|---|---|
| a | `ProjectService.Create` в acc-A | `PERMISSION_DENIED` | `done` |
| b | `ProjectService.Update` prj-A2, `labels` | `PERMISSION_DENIED` | `done` |
| c | `ProjectService.Delete` prj-A2 | `PERMISSION_DENIED` | `done` |
| d | `GroupService.Create` в acc-A | `PERMISSION_DENIED` | `done` |
| e | `GroupService.AddMember` grp-A, участник usr-B | `PERMISSION_DENIED` | `done` |
| f | `RoleService.Create` в acc-A | `PERMISSION_DENIED` | `done` |
| g | `ServiceAccountService.Create` в acc-A | `PERMISSION_DENIED` | `done` |
**When** вызов
**Then** как в таблице; при отказе объект не появился и не изменился (перепись проектов, групп,
ролей и учёток acc-A до и после равна)
**And** правый столбец — близнец левого (отличается вызывающим); строки b и c от usr-A идут
каждая на свежем мире.

#### GD-26 · делегирование не даёт отношений модели прав

**Given** мир Д; D1 заведён
**When** проба спрашивает Check(sva-iss, r, o) для r ∈ {`admin`, `editor`, `viewer`, `v_get`},
o ∈ {`account:acc-A`, `project:prj-A`}
**Then** все восемь — false
**And** близнец: Check(usr-E, `admin`, `account:acc-A`) — истина (отличается субъектом).

### Группа E — отзыв выданного делегатом

#### GD-30 · делегат отзывает и удаляет только выданное по своему делегированию

**Given** мир Д; D1 заведён; B10 — выдача по GD-10 a; B10' — выдача по GD-10 b; Bo — выдача
usr-A роли `registry.puller` учётке sva-A3, область `iam.project` prj-A, цель X (обычный
путь, `delegationId` нет). Каждая
строка — на свежем мире
| пример | вызывающий и вызов | исход |
|---|---|---|
| a | sva-iss: `AccessBindingService.Revoke` B10 | `done`; `Get` B10 от usr-A: `status = REVOKED`, `revocationReason: REVOCATION_REASON_REVOKE`, `revokedByUserId` = sva-iss (§0.10б); `pollAsk(service_account:<sva-A>, v_get, registry_registry, X, false)` в окне |
| b | sva-iss: `Revoke` Bo | `PERMISSION_DENIED` `permission denied`, синхронно; Bo `ACTIVE` |
| c | sva-iss: `AccessBindingService.Delete` B10' | `done`; `Get` B10' от usr-A → `PERMISSION_DENIED` `permission denied` (выдачи нет, скрытие существования) |
| d | sva-iss: `Delete` Bo | `PERMISSION_DENIED` `permission denied`; Bo `ACTIVE` |
| e | sva-iss: `Revoke` `acb00000000000000099` (нет такой) | `PERMISSION_DENIED` `permission denied` |
| f | usr-B (ни права, ни делегирования): `Revoke` B10 | `PERMISSION_DENIED` `permission denied`; B10 `ACTIVE` |
| g | usr-A (владелец, прежний путь): `Revoke` Bo | `done`; Bo `REVOKED`, `revokedByUserId` = usr-A |
**When** вызов. Интеграционная проба зовёт use-case; что дверь слушателя этот вызов до
use-case пропускает, держит GD-32, весь путь через слушатель — GD-E5. Одна интеграционная проба
зелёной при неработающем глаголе на слушателе быть не может: GD-32 и GD-E5 — её обязательная
пара в том же DoD
**Then** как в таблице
**And** близнецы: a — b и c — d (отличается выдачей: своя по делегированию или чужая); f — a
(отличается вызывающим: посторонний или делегат); g — b (отличается вызывающим: держатель права
или делегат); e, f побайтово равны b.

#### GD-31 · делегат убирает выданное и тогда, когда делегирующий потерял право

**Given** мир GD-20 до шага When: D-E заведён usr-E, B-E выдана sva-iss2 по D-E; usr-A отозвал
выдачу `admin` человеку usr-E (`done`)
**When** a) sva-iss2 вызывает `AccessBindingService.Revoke` B-E; b) sva-iss2 вызывает
`AccessBindingService.Create` с телом V' (новый субъект sva-A2)
**Then** a) `done`; B-E `REVOKED`, `revocationReason: REVOCATION_REASON_REVOKE`,
`revokedByUserId` = sva-iss2; b) `PERMISSION_DENIED` `permission denied`
**And** a — близнец b: отличается глаголом (отзыв сужает доступ и права делегирующего не
спрашивает, выдача — спрашивает, Р2).

#### GD-32 · дверь слушателя пропускает отзыв и удаление к обработчику, правку — нет

**Given** дверь, собранная тем же конструктором, что в композиционном корне
(`authzguard.NewOwnDoor`, карта выведена из влинкованных дескрипторов; образец сборки —
`doorUnder`, `internal/authzguard/own_door_test.go:65-72`); хранилище отношений, в котором у
учётки sva-iss нет ни одного отношения на `iam_access_binding:<B10>`
| пример | метод (`FullMethod`) | исход |
|---|---|---|
| a | `/kaname.cloud.iam.v1.AccessBindingService/Revoke` | обработчик достигнут; модель о `v_delete` дверью не спрошена |
| b | `/kaname.cloud.iam.v1.AccessBindingService/Delete` | обработчик достигнут |
| c | `/kaname.cloud.iam.v1.AccessBindingService/Update` | обработчик НЕ достигнут; `PERMISSION_DENIED`; модель спрошена о `v_update` на `iam_access_binding:<B10>` |
| d | `/kaname.cloud.iam.v1.GrantDelegationService/Revoke` | обработчик достигнут |
**When** вызов от `Principal{Type: "service_account", ID: <sva-iss>}`
**Then** как в таблице
**And** c — близнец a: отличается методом (аннотация `v_update` остаётся, Р1а)
**And** проба печатает число методов пакета, освобождённых дверью. Первый (красный) прогон на
`5c6b7c078` снимает прежнее число, зелёный — новое; разница — 6 (Р1а), иначе проба красная.

### Группа F — отзыв делегирования

#### GD-40 · отзыв делегирования отзывает всё выданное по нему

**Given** мир Д; D1 заведён; по D1 выданы B10 (GD-10 a), B13 (GD-13), B14 (GD-14 a) — `ACTIVE`;
B30 — выдача по D1, уже отозванная делегатом (`REVOKE`); Bo — выдача usr-A (GD-30)
**When** usr-A вызывает `GrantDelegationService.Revoke` D1 `{}`; проба поллит операцию
**Then** `done`, `error` пуст; D1: `status = REVOKED`, `revokedAt` задан, `revokedBy = {user, usr-A}`
**And** B10, B13, B14 — `REVOKED`, `revocationReason: REVOCATION_REASON_DELEGATION_REVOKED`,
`revokedByUserId = usr-A`
**And** B30 — `REVOKED` с прежней причиной `REVOCATION_REASON_REVOKE` и прежним `revokedAt`
**And** `pollAsk` в окне: sva-A `v_get` X — false; anonymous `v_get` X — false; sva-A2 `v_update`
`X/app` — false
**And** Bo — `ACTIVE`, `pollAsk(service_account:<sva-A3>, v_get, registry_registry, X, true)`
**And** Bo — близнец B10: отличается тем, что выдан не по делегированию.

#### GD-41 · защита от удаления отзыву делегирования не мешает

**Given** свежий мир Д; D1 заведён; Bp — выдача sva-iss по V с `deletionProtection: true`
**When** a) sva-iss вызывает `AccessBindingService.Revoke` Bp; b) usr-A отзывает D1
**Then** a) `FAILED_PRECONDITION` `access binding <Bp> has deletion_protection enabled; clear it via Update before revoke`
(текст `revoke.go:114-115`), синхронно, Bp `ACTIVE`. Этот текст достижим только после права
(`revoke.go:102-107`): делегат доходит до него делегированным путём Р2, а дверь его не
останавливает (Р1а, GD-32 a); b) Bp `REVOKED`, причина `REVOCATION_REASON_DELEGATION_REVOKED`
**And** a — близнец b: отличается путём отзыва
**And** через слушатель — GD-E5 d.

#### GD-42 · после отзыва делегат не выдаёт

**Given** мир Д; D1 заведён и отозван (GD-40)
**When** sva-iss вызывает `AccessBindingService.Create` с телом V
**Then** `PERMISSION_DENIED` `permission denied`
**And** близнец — GD-10 a (отличается тем, что D1 действует).

#### GD-43 · повторный отзыв и отзыв несуществующего

**Given** мир Д; D1 отозван
**When** usr-A вызывает `Revoke` a) D1; b) `gdl00000000000000099`; c) `gdl!!`
**Then** a) `FAILED_PRECONDITION` `grant delegation <D1> is already revoked`; b)
`PERMISSION_DENIED` `permission denied`; c) `INVALID_ARGUMENT` `invalid grant delegation id 'gdl!!'`
**And** близнец a — GD-40 (отличается тем, что D1 действует).

#### GD-44 · кто вправе отозвать

**Given** мир Д с usr-E; D1 заведён
| пример | вызывающий `Revoke` D1 | исход |
|---|---|---|
| a | usr-E (администратор acc-A) | `done`; `revokedBy = {user, usr-E}` |
| b | usr-B | `PERMISSION_DENIED`; D1 `ACTIVE` |
| c | sva-iss (делегат) | `PERMISSION_DENIED`; D1 `ACTIVE` |
| d | usr-C (владелец acc-B) | `PERMISSION_DENIED`; D1 `ACTIVE` |
**When** вызов
**Then** как в таблице; b–d побайтово равны GD-43 b
**And** a — близнец b, c, d (отличается вызывающим); каждая строка — на свежем мире.

#### GD-45 · учётку-делегата нельзя удалить при действующем делегировании

**Given** мир Д; D1 заведён (делегат sva-iss в acc-S)
**When** usr-S вызывает `ServiceAccountService.Delete` sva-iss a) при `ACTIVE` D1; b) после
отзыва D1; проба поллит операцию (удаление асинхронно, `service_account/delete.go:70`)
**Then** a) `Operation.done`, `Operation.error` — `FAILED_PRECONDITION`
`service account <sva-iss> holds an active grant delegation <D1>; revoke it first`; sva-iss на
месте; b) `done`, `error` пуст, учётки нет
**And** b — близнец a: отличается состоянием делегирования.

### Группа G — конкуренция

#### GD-50 · два одновременных заведения одной пары

**Given** мир Д; делегирований пары (acc-A, sva-iss) нет
**When** 8 горутин одновременно вызывают `Create` с телом D1 от usr-A; проба поллит все операции
**Then** ровно одна `done` без ошибки; остальные семь — `Operation.error` `ALREADY_EXISTS` текстом
Р6; действующих делегирований пары — 1
**And** близнец — GD-01 (один вызов).

#### GD-51 · выдача делегатом во время отзыва делегирования

**Given** мир Д; D1 заведён
**When** 20 раз: на свежем D1 горутина 1 — sva-iss `AccessBindingService.Create` с телом V и
новым субъектом; горутина 2 — usr-A `Revoke` D1; обе стартуют одним барьером; проба поллит обе
операции
**Then** после каждого раунда выдач `ACTIVE` с `delegationId` отозванного D1 — 0
**And** каждая выдача раунда кончается одним из трёх исходов: синхронный `PERMISSION_DENIED`;
`Operation.error` `FAILED_PRECONDITION` Т-D1; выдача `REVOKED` с причиной
`REVOCATION_REASON_DELEGATION_REVOKED`
**And** проба печатает распределение трёх исходов; исход «выдача `ACTIVE`» — 0
**And** близнец — GD-10 a без отзыва (выдача `ACTIVE`).

### Группа H — чтение

#### GD-60 · Get

**Given** мир Д с usr-E; D1 заведён
| пример | вызывающий, id | исход |
|---|---|---|
| a | usr-A, D1 | тело D1 (GD-01) |
| b | usr-E, D1 | то же тело |
| c | sva-iss, D1 | то же тело |
| d | usr-B, D1 | `PERMISSION_DENIED` `permission denied` |
| e | sva-other, D1 | `PERMISSION_DENIED` |
| f | usr-A, `gdl00000000000000099` | `PERMISSION_DENIED`, побайтово как d |
| g | usr-A, `gdl!!` | `INVALID_ARGUMENT` `invalid grant delegation id 'gdl!!'` |
**When** `GrantDelegationService.Get`
**Then** как в таблице
**And** c — близнец e (отличается тем, делегат ли вызывающий); a — близнец d.

#### GD-61 · List по аккаунту

**Given** мир Д; в acc-A три делегирования от usr-A: D1 (sva-iss), D2 (sva-iss2), D3 (делегат
sva-other, тело D1); D3 отозван
**When** a) usr-A `List` `accountId=acc-A` `pageSize=2`, затем со следующим `pageToken`; b)
`pageToken=garbage`; c) `pageSize=1001`; d) usr-C `List` `accountId=acc-A`
**Then** a) первая страница — два, вторая — одно; вместе — три делегирования, порядок
`(createdAt, id)` по возрастанию; D3 — со `status: REVOKED`; `nextPageToken` второй страницы пуст
**And** b) `INVALID_ARGUMENT`, `message` `Illegal argument page_token`, `field_violations[0]` =
`{field: "page_token", description: "Illegal argument page_token"}`; c) `INVALID_ARGUMENT`,
`message` `invalid argument`, `field_violations[0]` =
`{field: "page_size", description: "page_size must be in [0..1000] (0 means default)"}`.
Производитель обоих — один: `shared.ValidateRawPagination` (§0.10в) первым оператором `List`, до
права; d) `PERMISSION_DENIED` `permission denied`
**And** b и c от usr-C (без права) — те же ответы, что от usr-A: форма судится до права
**And** a — близнец b, c, d.

#### GD-62 · выдача несёт ссылку на делегирование

**Given** мир Д; B10 (GD-10 a), Bo (GD-30)
**When** a) `AccessBindingService.Get` B10 и Bo от usr-A; b) на свежем мире: D1 заведён, usr-A
выдаёт учётке sva-iss каноническую `admin` на `iam.account` acc-A (цель `allInScope`, `done`),
затем (контроль: sva-iss проходит Путь 2, как usr-E в мире Д) sva-iss выдаёт по телу V, проба поллит операцию и читает выдачу от usr-A
**Then** a) у B10 `delegationId` = id D1; у Bo ключа `delegationId` в теле нет; b) `done`;
ключа `delegationId` нет — учётка прошла прежний путь (Путь 2), делегированный не спрашивался
(Р2 «Порядок путей»)
**And** Bo — близнец B10; b — близнец GD-10 a (отличается тем, держит ли делегат право выдавать
сам).

### Группа I — аудит

#### GD-70 · аудит каждого шага

**Given** свежий мир Д
**When** шаги по порядку, каждый — до `done`:
1. usr-A заводит D1 (тело GD-01);
2. sva-iss выдаёт B10 (тело V), B13 (тело GD-13) и B14 (тело GD-14 a);
3. sva-iss отзывает B10 (`AccessBindingService.Revoke`);
4. usr-A отзывает B14 (`AccessBindingService.Revoke`, прежний путь); затем usr-A выдаёт Bo
   (тело GD-30, обычный путь) и отзывает её;
5. sva-iss пытается выдать по телу GD-11 a (отказ);
6. usr-A отзывает D1 (`GrantDelegationService.Revoke`);

затем проба читает `SELECT event_type, event_payload, tenant_account_id FROM kaname.audit_outbox`
за интервал прогона
**Then** есть строки (Р5):
- `iam.grant_delegation.created` — `delegation_id` D1, `delegate` sva-iss, `module: "registry"`, `actor` usr-A (шаг 1);
- `iam.access_binding.granted` — по строке на B10, B13, B14, у каждой `delegation_id` D1, `actor` sva-iss (шаг 2);
- `iam.access_binding.revoked` — `binding_id` B10, `delegation_id` D1, `actor` sva-iss (шаг 3);
- `iam.access_binding.revoked` — `binding_id` B14, `delegation_id` D1, `actor` usr-A (шаг 4: отзыв обычным держателем права тоже несёт `delegation_id`);
- `iam.access_binding.revoked` — `binding_id` Bo, `actor` usr-A, ключа `delegation_id` нет (шаг 4);
- `iam.access_binding.delegation_revoked` — `binding_id` B13, `delegation_id` D1, `revocation_reason: "delegation_revoked"` (шаг 6);
- `iam.grant_delegation.revoked` — `delegation_id` D1, `revoked_binding_count: 1` (шаг 6: действовала одна B13)
**And** строк `iam.access_binding.granted` с `actor` sva-iss — ровно три: шаг 5 строки не добавил
**And** `tenant_account_id = acc-A` — у строк делегирования (`iam.grant_delegation.*`) и у
строк выдач с `delegation_id` D1 (B10, B13, B14: выдача, отзыв, отзыв делегированием), хотя
область этих выдач — prj-A (Р5); у строк Bo (выдача и отзыв, шаг 4) — NULL, как сегодня
**And** проба печатает число прочитанных строк; 0 прочитанных — «не выполнилось»
**And** близнецы: шаг 5 против шага 2 (отказанная выдача против принятой — строки нет / строка
есть); строка отзыва B14 против строки отзыва Bo (шаг 4: тот же вызывающий, тот же глагол) —
у B14 `delegation_id` D1 и `tenant_account_id = acc-A`, у Bo ключа `delegation_id` в полезной
нагрузке нет и `tenant_account_id` NULL (обе выдачи на prj-A).

### S2 — сквозной набор службы (`PRO-Robotech/kaname`, newman, собственный REST-фронт)

Мир — посев набора (`tests/newman/cases/`, образец `iam-rbac-scope-grant.py`): аккаунт с
владельцем, учётка-делегат в отдельном аккаунте с ключом доступа, зарегистрированный объект типа
registry в проекте аккаунта. Утверждается пара: HTTP-статус и `code` из тела.

#### GD-E1 · делегирование заводится и отзывается через край

**Given** посев набора; владелец вошёл
**When** `POST /iam/v1/grantDelegations` с телом D1; полл `GET /iam/v1/operations/{id}`; `GET
/iam/v1/grantDelegations/{id}`; `POST /iam/v1/grantDelegations/{id}:revoke` `{}`; полл
**Then** 200 на каждом шаге; тело `GET` — поля GD-01; после отзыва `status: "REVOKED"`.

#### GD-E2 · близнец E1: делегат не заводит делегирований

**Given** посев набора; делегат вошёл ключом
**When** `POST /iam/v1/grantDelegations` с тем же телом
**Then** 403, `code: 7` (`PERMISSION_DENIED`), `message: "permission denied"`.

#### GD-E3 · выдача делегатом через край

**Given** E1 до отзыва; делегат вошёл ключом
**When** `POST /iam/v1/accessBindings` с телом V; полл операции; `GET /iam/v1/accessBindings/{id}`
**Then** 200; операция `done` без ошибки; тело выдачи несёт `delegationId`.

#### GD-E4 · близнец E3: роль вне делегирования

**Given** как E3
**When** то же с ролью `admin` (каноническая), областью `iam.account`
**Then** 403, `code: 7`, `message: "permission denied"`.

#### GD-E5 · отзыв и удаление делегатом проходят слушатель (держатель GD-30, GD-41 a)

**Given** E3 выполнен — выдача Bd по делегированию, вторая выдача Bd' тем же телом с другим
субъектом, третья Bp с `deletionProtection: true`; Bo — выдача владельца без делегирования;
делегат вошёл ключом
| пример | вызов делегата | исход |
|---|---|---|
| a | `POST /iam/v1/accessBindings/{Bd}:revoke` `{}`; полл операции | 200; операция `done` без ошибки; `GET` Bd от владельца — `status: "REVOKED"` |
| b | `POST /iam/v1/accessBindings/{Bo}:revoke` `{}` | 403, `code: 7`, `message: "permission denied"` |
| c | `DELETE /iam/v1/accessBindings/{Bd'}`; полл операции | 200; операция `done` без ошибки |
| d | `POST /iam/v1/accessBindings/{Bp}:revoke` `{}` | 400, `code: 9` (`FAILED_PRECONDITION`), `message` — текст GD-41 a |
| e | `PATCH /iam/v1/accessBindings/{Bp}` `{"updateMask":"deletionProtection","deletionProtection":false}` | 403, `code: 7`, `message: "permission denied"` (дверь, `v_update`); `GET` Bp от владельца — `deletionProtection: true`, `status: "ACTIVE"` |
**When** вызов через собственный REST-фронт kaname и арендаторский слушатель с дверью, строки
по порядку a…e
**Then** как в таблице
**And** близнецы: a — b (своя выдача против чужой); d — a (защита от удаления — единственное
отличие); e — d (тот же объект Bp, другой глагол: отзыв доходит до обработчика, правка
остаётся за дверью). Утверждается пара «статус, `code`».

---

## §5. Сценарий → производитель

### 5.1. Таблица

Производитель «заказан» — его заводит реализация; держатель — проба с именем
`Test<Предмет>_GD<NN>_…` в `internal/apps/kaname/api/access_binding/` (интеграционные, testcontainers),
сквозные — `tests/newman/cases/iam-grant-delegation.py`.

| ID | что производит «Тогда» | держатель: строка утверждения | чем измерено |
|---|---|---|---|
| GD-01 | заказан: `GrantDelegationService.Create` и `Get` (новый use-case, writer-транзакция, отпечаток полей) | равенство тела `Get` полям D1; `module == "registry"`; `ListBySubject(sva-iss)` → 0 | статус и тело gRPC, Check |
| GD-02 | заказан: Путь 2 в праве на `Create` (переиспользует `fgaHoldsScopeAdminE`, `helpers.go:312`) | `delegatedBy == {user, usr-E}` | тело |
| GD-03 | заказан: право выдавать на аккаунте в `Create`; текст — `authzguard.PermissionDenied` (`authzguard.go:63`) | код `PermissionDenied`, текст `permission denied`, `count(*)` делегирований acc-A = 0 | статус, SQL |
| GD-04 | заказан: проверка формы первым оператором; отказ с полем — `shared.InvalidArg` (`errdetails.go:21`), форма id — `shared.ValidateResourceID` (`ids.go:47`) | код, `message` дословно и `field_violations[0]` (`field`, `description`) каждой строки; у b, d — `field_violations` нет | статус, детали `BadRequest` |
| GD-05 | заказан: порядок форма → право → состав | пара кодов a/b | статус |
| GD-06 | заказан: проверка состава после права (роль объявлена манифестом, один модуль, не iam, существование) | код и текст каждой строки | статус |
| GD-07 | заказан: частичная уникальность «аккаунт, делегат» по действующим, маппинг 23505 → `ALREADY_EXISTS` | `Operation.error` код и текст; `count` действующих = 1 | операция, SQL |
| GD-10 | заказан: четвёртый путь `requireGrantAuthority`; `AccessBinding.delegation_id` на записи | `delegationId == D1`; `pollAsk` истина | тело, Check |
| GD-11 | заказан: проверки Р2 в четвёртом пути | код и текст каждой строки; `count` выдач D1 до = после; строк аудита до = после | статус, SQL |
| GD-12 | заказан: ось типов цели | пара a/b | статус, тело |
| GD-13 | заказан: Д5 в четвёртом пути; ворота класса — `system_class_gates.go` (окно свежести у учётки не спрашивается, `:221-224`) | `pollAsk(anonymous)` истина | Check |
| GD-14 | заказан: проверка каждого объекта цели (Д7) | цель из двух объектов; пара a/b | тело, Check |
| GD-15 | есть: модель прав не выводит доступа без выдачи (`relverdict`); утверждается, что заказанный путь его не добавляет | Check false; `ListBySubject` → 0 | Check |
| GD-16 | заказан: Д6 в четвёртом пути — `groups.account_id`, `service_accounts.account_id`, членство `ACTIVE` через существующий `UserReader.Membership` (`user_repo.go:158`); помощник посева членства в мире заказан | пять строк: `done`/`PERMISSION_DENIED`, `delegationId`, `pollAsk(usr-M)` истина; `count` выдач D-U до = после в отказах | статус, тело, SQL, Check |
| GD-20 | заказан: вопрос о праве делегирующего на каждой выдаче (Д3) | пара a/b; B-E `ACTIVE` | статус, тело |
| GD-21 | заказан: делегирование не путь права для `GrantDelegationService.Create` | пара a/b | статус |
| GD-22 | есть: `Update` выдачи гейтит `v_update` (`access_binding_service.proto:89-90`); заказано — делегированный путь его не покрывает | пара a/b; метки | статус, тело |
| GD-25 | есть: аннотации `editor`/`v_update` (§0.8) и проверка на слушателе; заказано — делегирование не пишет отношений | семь пар | статус, перепись SQL |
| GD-26 | есть: `relverdict`; заказано — Р3 | восемь вопросов false; близнец истина | Check |
| GD-30 | заказан: Р1а — аннотация `Revoke`/`Delete` → `<exempt>` · `HANDLER_DECIDES`, прежний вопрос двери (`v_delete`) переезжает в обработчик; делегированный путь в `Revoke`/`Delete` (`revoke.go:105`, `delete.go:125`) — только выдачи с `delegationId` своего делегирования. Есть: `revokedByUserId` = вызывающий (`revoke.go:119`, `principal.go:72-74`) | семь строк; в a `revokedByUserId == <sva-iss>`; f побайтово равна b | статус, тело, Check |
| GD-31 | заказан: на отзыве делегированный путь права делегирующего не спрашивает (Р2) | пара a/b | статус, тело |
| GD-32 | заказан: аннотации Р1а; есть: дверь `authzguard.NewOwnDoor` с картой из дескрипторов (`own_door.go`) | достигнут ли обработчик в a–d; какой вопрос задан модели в c; число освобождённых методов +6. Держатель — `internal/authzguard/` (проба двери, без базы) | флаг достижения, журнал вопросов хранилища |
| GD-40 | заказан: `GrantDelegationService.Revoke` — одна транзакция: делегирование и выдачи по `delegation_id`; `REVOCATION_REASON_DELEGATION_REVOKED = 4` | статусы и причины пяти выдач; `pollAsk` | тело, Check |
| GD-41 | есть: защита при отзыве глаголом (`revoke.go:114-115`), достижимая только после права; заказан: делегат проходит право делегированным путём через обработчик (Р1а, Р2), отзыв делегирования защиту не спрашивает | пара a/b; текст a дословно; через слушатель — GD-E5 d | статус, тело |
| GD-42 | заказан: четвёртый путь читает статус делегирования | код | статус |
| GD-43 | заказан: CAS `UPDATE … WHERE status = 'ACTIVE'`, 0 строк → `FAILED_PRECONDITION` | три кода | статус |
| GD-44 | заказан: право выдавать на аккаунте в `Revoke` | четыре строки | статус, тело |
| GD-45 | заказан: ограничение в базе (ссылка делегирования на учётку `ON DELETE RESTRICT`), маппинг 23503 → `FAILED_PRECONDITION` с текстом Р6 в обработчике операции удаления учётки (асинхронно, `service_account/delete.go:70`) | пара a/b: `Operation.error` код и текст; учётка на месте / нет | операция, SQL |
| GD-50 | заказан тем же, что GD-07 (уникальность в базе) | ровно одна `done`; `count` = 1 | операции, SQL |
| GD-51 | заказан: блокировка строки делегирования в транзакции записи выдачи и в транзакции отзыва; Т-D1 | `count` `ACTIVE` с отозванным D1 = 0 в каждом раунде; распределение исходов | SQL, операции |
| GD-60 | заказан: `Get` с правом «право выдавать или делегат»; скрытие существования | семь строк | статус, тело |
| GD-61 | заказан: `List` курсором `(created_at, id)`; есть: `shared.ValidateRawPagination` (`pagination.go:86`) первым оператором, до права — единственный производитель отказов b, c (§0.10в) | страницы; в b, c — код, `message` и `field_violations[0]` дословно, от usr-A и от usr-C одинаково | тело, статус, детали `BadRequest` |
| GD-62 | заказан: проекция `delegation_id` на `Get`/`List` выдачи; порядок путей Р2 (делегированный — после прежних) | a: ключ есть / ключа нет; b: ключа нет | тело JSON |
| GD-70 | заказан: `EmitAuditEvent` (`internal/repo/kaname/access_binding/iface.go`) с новыми типами; `delegation_id` в строке отзыва — по выдаче, кем бы она ни отзывалась; `tenant_account_id` строк выдачи с `delegation_id` и их отзыва — аккаунт делегирования (Р5). Есть: строки Bo — `auditTenantAccountID` (`helpers.go:36-41`), у области `project` NULL | `SELECT … FROM kaname.audit_outbox` — девять строк по списку, `granted` от sva-iss — три, `tenant_account_id` по строке, число прочитанных | SQL |
| GD-E1 | заказан: регистрация службы на REST-фронте kaname | 200 и поля | newman |
| GD-E2 | то же | 403 + `code` 7 | newman |
| GD-E3 | то же | 200, `delegationId` | newman |
| GD-E4 | то же | 403 + `code` 7 | newman |
| GD-E5 | заказан: Р1а и делегированный путь в `Revoke`/`Delete`; есть: дверь слушателя и `v_update` у `Update` | пять пар «статус, `code`»; `status`/`deletionProtection` по `GET` | newman |

Сценариев: **39** (`grep -c '^#### GD-'` = 39; строк таблицы `grep -c '^| GD-'` = 39) —
интеграционных 33 (GD-01…07 — 7, 10…16 — 7, 20…22 — 3, 25, 26 — 2, 30, 31 — 2, 40…45 — 6,
50, 51 — 2, 60…62 — 3, 70 — 1), проба двери 1 (GD-32, `internal/authzguard/`, без базы),
сквозных 5 (GD-E1…E5). Производитель назван у всех 39.

### 5.2. Дано → писатель

| «Дано» | писатель | координата |
|---|---|---|
| аккаунты, проекты, люди, учётки, группа мира П6 | посев мира | `system_class_world_integration_test.go:88-142` |
| X, Y и репозитории `app` | `InternalIAMService.RegisterResource` (use-case мира) | `public_container_read_world_integration_test.go:178`, `:193` |
| Z в prj-C | тот же глагол с проектом prj-C | заказан вариант `registerRegistry` |
| роли `registry.puller/pusher/admin` | загрузчик манифеста `manifest.Load` + `applyDelivered` | путь `deliverNewEdition` (`:230`); фикстура заказана |
| `vpc.address_pool_admin` | тот же путь | `vpc.resources-fixture.yaml:159` |
| `iam.project.admin` | посев ролей модуля при старте | `manifest.yaml:955`, `internal/apps/kaname/moduleseed` |
| rol-reg-get | `seedRole` тремя сторонами, как `RoleService.Create` | `public_container_read_world_integration_test.go:151` |
| usr-E — администратор acc-A | `AccessBindingService.Create` от владельца | `createDone`, `system_class_world_integration_test.go:212` |
| grp-B в acc-B | посев мира `seedGroup` | `system_class_world_integration_test.go:168` |
| usr-M, usr-P | посев мира `mustSeedUser` + `verifyAddresses` | `testhelpers_assignable_test.go:80`, `system_class_world_integration_test.go:150` |
| членство usr-M `ACTIVE`, usr-P `PENDING` в acc-A | посев строки `kaname.memberships` выражением `kaname.membership_mirror_id` — тем же, что у зеркала и бэкфилла; помощник в пакете мира заказан; контроль посева — `UserReader.Membership` | образец `internal/repo/kaname/pg/membership_is_the_account_source_integration_test.go:77` |
| D1, D2, D-E, D-U, D3 | `GrantDelegationService.Create` (GD-01) | заказан |
| B10, B10', B13, B14, Bp, B30, B-E | `AccessBindingService.Create` делегатом (GD-10) | заказан |
| Bo | `AccessBindingService.Create` от usr-A | есть |
| отзыв выдачи usr-E | `AccessBindingService.Revoke` | есть, `revoke.go:80` |
| вызов от учётки | `operations.WithPrincipal` | `system_class_s2_integration_test.go:334` |
| посев S2 | сценарий набора | `tests/newman/cases/iam-rbac-scope-grant.py` (образец) |

Каждое «Дано» строится либо существующим писателем, либо глаголом, чей положительный путь —
отдельный сценарий этой приёмки (GD-01, GD-10). Посева мимо глагола для делегирований и
делегированных выдач нет. Членство — посев мира, как и прочие строки мира (люди, аккаунты,
учётки); глагол `MembershipService.Create` для мира не годится: он заводит членство
приглашением по почте, и состояние `PENDING` против `ACTIVE` зависит от почтовой ветки, а не от
Given.

**Конструируемость отзыва делегатом** (замечание круга 1 о GD-30 a, c и GD-41 a). Выдачи B10,
B10', Bp строятся GD-10; отзыв и удаление делегатом достигают use-case, потому что дверь их
больше не судит (Р1а, держатель GD-32), а use-case пропускает делегата делегированным путём
(Р2). Текст защиты от удаления в GD-41 a достижим после права (`revoke.go:102-115`).

### 5.3. Строки потребителя → сценарии

| строка приёмки svc-registry | сценарий здесь |
|---|---|
| SRI-111 a — pusher на `registry_registry`, субъект SA → создано | GD-10 a |
| SRI-111 b — роль вне манифеста модуля на аккаунт | GD-11 b (и a, f группы A) |
| SRI-111 c — `allInScope` на проект | GD-11 c |
| SRI-111 d — субъект-человек | GD-11 d |
| SRI-111 e — `system_class:anonymous` → создано | GD-13 |
| SRI-111 f — `ProjectService/Create` | GD-25 a |
| SRI-111 g — группа, `RoleService/Create` | GD-25 d–f |
| SRI-111 «привязок admin/owner на аккаунт у учёток svc-registry — 0» | GD-26 (свойство kaname); перепись привязок стенда — держатель svc-registry |
| SRI-60 — выдача на реестр учётке клиента в аккаунте регистрации | GD-10, GD-16, Д6 |
| SRI-65, SRI-67 — отзыв ключа, удаление учётных данных (снятие выдачи) | GD-30 a, c; через слушатель — GD-32, GD-E5 a, c |
| SRI-71 — публичный режим и возврат в приватный | GD-13, GD-30 a; через слушатель — GD-E5 a |
| SRI-86 — выдача на перечисленные репозитории | GD-14 |

Заведение SA и ключей выпускающим (SRI-60, SRI-66, SRI-67) — `#1003`, не здесь (§2 п.2).

---

## §6. Признак готовности (DoD)

### S1 — `PRO-Robotech/kaname`

1. `proto/kaname/cloud/iam/v1/grant_delegation.proto`, `grant_delegation_service.proto`:
   служба и сообщение по Р1; аннотация права каждого из четырёх методов — по столбцу
   «аннотация права» Р1. `access_binding_service.proto`: `Revoke` и `Delete` — `<exempt>`,
   `HANDLER_DECIDES`, `required_acr_min = "2"` (Р1а). `AccessBinding.delegation_id`
   (вывод, новый тег), `RevocationReason.REVOCATION_REASON_DELEGATION_REVOKED = 4` с
   комментарием Р4. Встроенный каталог прав (`internal/apps/kaname/seed/embedded/permission_catalog.json`)
   перевыведен из аннотаций. Гейт дерева освобождённых методов зелёный: у каждого из шести —
   живая координата решающего кода. `buf lint`, `buf breaking`, перегенерация — зелёные
2. Новая миграция: таблица делегирований (`CHECK` на `status`, частичная уникальность
   «аккаунт, делегат» по действующим, ссылка на учётку `ON DELETE RESTRICT`), колонка
   `delegation_id` выдачи со ссылкой и индексом. Применённые миграции не правятся (ban #5)
3. Префикс `gdl` — в каталоге corelib и в закреплённой версии (§7)
4. Use-case `Create`, `Get`, `List`, `Revoke` службы; четвёртый путь права выдавать (Р2) в
   `Create`, `Revoke`, `Delete` выдачи — после прежних путей; прежний вопрос двери `v_delete`
   — в обработчике `Revoke`/`Delete` (Р1а); принадлежность субъекта (Д6); отказ удаления
   учётки (Д8)
5. Аудит по Р5 в той же транзакции
6. Интеграционные пробы GD-01…GD-70 (33) и проба двери GD-32 — сперва красные на
   `5c6b7c078` (ban #12), затем зелёные; обе стороны каждой пары — в одном наборе, на одной
   ревизии. GD-30 и GD-41 a зелёными без GD-32 и GD-E5 не считаются
7. Ни одна прежняя проба домена доступа не ослаблена; набор домена доступа зелёный целиком
8. Регистрация службы на обоих путях монтирования (gRPC и REST-фронт), гейт паритета
   монтирования зелёный
9. `EXPLAIN` запроса чтения делегирования (по паре «аккаунт, делегат») и запроса отзыва выдач (по
   `delegation_id`) — по индексу, без перебора выдач аккаунта; вывод — в комментарии `DoD-proof`
10. Комментарий `DoD-proof @<sha>` в `#986`: команда, сырой итог, код возврата

### S2 — `PRO-Robotech/kaname`, сквозной набор

1. `tests/newman/cases/iam-grant-delegation.py` и порождённая коллекция: GD-E1…GD-E5, пара
   «статус, `code`» в каждом отрицательном
2. Прогон на внешнем кластере в боевой посадке, своё пространство, снятие в той же задаче,
   перепись остатков после — 0

---

## §7. Внешние зависимости

| что | где | зачем | признак готовности |
|---|---|---|---|
| префикс `gdl` в `domainStringPrefixes` | `PRO-Robotech/corelib` `ids/ids.go:245`; выпуск и закрепление в `go.mod` kaname | классификация id ресурса (`corevalidate.ResourceID`, маршрутизация операций) | `grep -c '"gdl"' "$(go list -m -f '{{.Dir}}' github.com/PRO-Robotech/corelib)/ids/ids.go"` в копии kaname = 1 — путь берётся из версии, закреплённой в `go.mod`, поэтому единица означает и выпуск, и закрепление (на `5c6b7c078`, corelib v1.15.0 — 0) |
| роли `registry.puller`, `registry.pusher`, `registry.admin` в манифесте svc-registry | svc-registry (Д3 приёмки svc-registry) | делегирование на стенде и в боевой посадке; в пробах kaname — своя фикстура | SRI-92 приёмки svc-registry зелёный |
| кто заводит делегирование для registry на аккаунт | решение В1 | без делегирования группа F svc-registry на настоящем kaname — «не выполнилось» | В1 решён; шаг заведения назван в приёмке потребителя |
| каталог прав у края kacho | `PRO-Robotech/kacho`, закрепление версии kaname | край kacho судит по каталогу прав (`own_door.go`, шапка «Предмет»), выведенному из аннотаций закреплённой у него версии kaname. До перезакрепления он по-прежнему требует `v_delete` у `Revoke`/`Delete` выдачи: отказ делегату через край kacho — уже, а не шире (fail-closed). svc-registry ходит к kaname напрямую, на арендаторский слушатель (Р-В5), край kacho в его пути не стоит | перезакрепление — после kaname (порядок «сначала kaname»), отдельной задачей kacho; этой приёмкой не требуется |

---

## §8. Открытые вопросы

**В1. Кто заводит делегирование для registry в боевой посадке.** Kaname наружу не публикуется
(Р-В5), владелец аккаунта к нему не ходит.
- (а) платформа при включении registry для аккаунта: шаг выдачи от администратора облака.
  Цена — шаг и личность платформы; делегирующий — администратор облака, делегирование —
  на один аккаунт;
- (б) владелец аккаунта через каталог компании и мост к kaname. Цена — новый путь до kaname
  вопреки Р-В5;
- (в) манифест модуля объявляет шаблон, kaname заводит делегирование на каждый аккаунт сам.
  Цена — возвращает право уровня кластера, «от имени пользователя» теряет смысл.
**Рекомендация — (а).** Механизм приёмки не зависит от выбора: любой из трёх создаёт
делегирование тем же `Create`.

**В2. Что такое «правило R4».** В деревьях не найдено (§0.11). Принято А1 (= Д2). Если R4
означает иное (например, перечень типов из манифеста модуля, отличный от его ролей) — правится
только Д2 и GD-06, остальное не зависит. Рекомендация — подтвердить А1.

**В3. Предмет 2 задачи `#986` — право писать регистрации на аккаунте.**
- (а) отдельная приёмка вместе с `#982`. Цена — второй круг ревью; `#986` закрывается двумя PR;
- (б) расширить делегирование правом регистрации типов модуля. Цена — делегатом становится и
  личность регистратора, новая ось «регистрация», `RegisterResource` меняется в этой же полосе.
**Рекомендация — (а).** Предмет 2 отделить в свою задачу, `#986` закрывать после обоих.

**В4. Выдачи делегата, когда делегирующий потерял право.** Принято: остаются (Д3, GD-20),
как выдачи администратора, потерявшего право. Альтернатива — отзывать их при потере права
делегирующим. Цена — kaname следит за правом каждого делегирующего и отзывает по событию.
Рекомендация — как принято; отзыв — отзывом делегирования.

**В5. Правка осей.** Принято: правки нет; расширение — новое делегирование после отзыва
прежнего, что отзывает выданное. Альтернатива — `Update`, только расширяющий оси, отдельной
приёмкой. Цена — оператору registry придётся перевыдать учётные данные при смене набора ролей.
Рекомендация — завести `Update` расширения следующей задачей, если набор ролей registry
изменится.

**В6. Класс `authenticated` через делегирование.** Принято: нет (Д5). Альтернатива — отдельное
значение оси. Рекомендация — как принято: registry нужен только `anonymous`.

**В7. Префикс `gdl`.** Нужен выпуск corelib (§7). Альтернатива — нет: префикс без каталога не
классифицируется (`api-hyphen-prefix`). Рекомендация — выпуск corelib первым шагом полосы.

**В8. Как делегат проходит дверь слушателя на `Revoke`/`Delete` выдачи** (круг 1, B1).
Принято Р1а — вариант (а).
- (а) решает обработчик: аннотация `<exempt>` · `HANDLER_DECIDES`, прежний вопрос двери
  переезжает в обработчик дословно. Цена — шесть освобождённых методов вместо прежних, их
  держат отрицания через слушатель (GD-32, GD-E5) и гейт координат;
- (б) делегату — `v_delete` на объекте каждой его выдачи (кортеж при выдаче, снятие при отзыве
  делегирования). Цена — противоречит Р3, вводит окно материализации на пути отзыва и второй
  производитель кортежей у выдачи.
**Рекомендация — (а)**, совпадает с рекомендацией рецензента.

---

## §9. Опора: соседи

| приёмка | отпечаток, состояние | что берётся |
|---|---|---|
| `unregistration-revokes-its-grants.md` (`#963`) | на `5c6b7c078`, редакция в линии | причина отзыва, образец Р5 аудита, защита от удаления при отзыве не глаголом (URG-11), мир У |
| `anonymous-and-authenticated-are-subject-classes.md` | на `5c6b7c078` | ворота системного класса, окно свежести у человека |
| `access-target-names-live-catalog-types.md` | на `5c6b7c078` | выдача на свободный ключ (ATC-03); Д7 сужает её для делегата |
| `module-manifest-roles-and-seed-grants.md` | на `5c6b7c078` | роли модуля объявляет манифест |
| приёмка svc-registry, редакция 3 | `2717077568f0057fa3205069807b4cc1b5fa72ec00ecda50eadfad0967b22dc7`, DRAFT | потребитель: SRI-111, группа F, Д-A6, Д11 |

Опора svc-registry — DRAFT. Если её отпечаток сменится до ревью этой приёмки, рецензент сверяет
таблицу §5.3 с новой редакцией (fa-b7). К редакции 2 автор опору заново не сверил: копии файла
на машине нет, чтение через API GitHub ответило 404. Отпечаток выше — снятый к редакции 1;
таблица §5.3 правилась только в сторону новых держателей (GD-16, GD-32, GD-E5), состав строк
SRI не менялся.

---

## §10. Что изменено против редакции 1 (`51da4ac8…`)

| замечание круга 1 | где закрыто |
|---|---|
| B1 PRODUCER — делегат не проходит дверь на `Revoke`/`Delete` | §0.1 (дверь в переписи), Р1а, Р2 (порядок путей, условие отзыва), критерий «безопасность» п.3, В8; держатели GD-30 (строки f, g), GD-32, GD-E5; DoD S1 пп. 1, 4, 6 |
| B2 PRODUCER — `revokedByUserId` в GD-30 a | §0.10б — существующий писатель пишет вызывающего, в том числе учётку (`principal.go:72-74`); GD-30 a утверждает `revokedByUserId = <sva-iss>`. Довод рецензента о `"system:revoke"` не подтвердился: подстановка срабатывает только при пустом вызывающем. Р4 приведён к тому же писателю |
| B3 PRODUCER — производитель и текст GD-61 c | §0.10в — один производитель `shared.ValidateRawPagination`; GD-61 b, c утверждают `message` и `field_violations[0]` |
| B4 COVERAGE — Д6 для группы и человека | §0.10а (источник членства), Д6 (участник = `ACTIVE`), D-U, GD-16 (пять строк, три пары по одному факту) |
| сценарий GD-45 асинхронно | GD-45, Р6, Д8 |
| вызывающий `Get` в GD-10, 12, 13 | usr-A |
| аннотации четырёх методов | Р1, столбец «аннотация права»; DoD S1 п.1 |
| порядок путей | Р2 «Порядок путей»; держатель — GD-62 b (делегат, держащий право сам, выдаёт без `delegationId`) |
| сценарий GD-06 c — точная строка типа | `iam.project` |
| имя поля в `field_violations` | §0.10г, Р6: snake_case, тексты GD-04 |
| сценарий GD-70 — противоречивое составное Given | шаги When 1–6 |
| сценарий GD-20 — нет D1 в Given | Given и пара a/b |
| Р5 — `delegation_id` при отзыве обычным держателем | Р5, GD-70 шаг 4 и пара B14/Bo |
| опора svc-registry | §9 |
| новый сценарий GD-31 | следствие условия отзыва Р2 (права делегирующего на отзыве не спрашиваются) |

---

## §11. Что изменено против редакции 2 (`43622b18…`)

Правка узкая: сценариев не прибавилось и не убыло, наблюдаемое поведение прочих не тронуто.

| основание | где закрыто |
|---|---|
| разбор классов, «вернуть в приёмку»: `tenant_account_id = acc-A` у всех строк GD-70 существующий писатель не даёт — выдачи на prj-A получают NULL (`helpers.go:36-41`) | Р5 — абзац о `tenant_account_id` строк выдачи с `delegationId` (новый писатель; прочее — как сегодня); GD-70 — утверждение сужено: acc-A у строк делегирования и выдач с `delegation_id`, у Bo — NULL; пара B14/Bo дополнена этим фактом; строка GD-70 в «сценарий → производитель» |
| область Bo в Given GD-30 не названа | GD-30 Given: `iam.project` prj-A, цель X |
| предикат §7 «префикс `gdl`» шёл по пути `ids/ids.go`, которого в дереве kaname нет | §7: путь берётся из закреплённой версии (`go list -m -f '{{.Dir}}'`), единица означает выпуск и закрепление сразу |
