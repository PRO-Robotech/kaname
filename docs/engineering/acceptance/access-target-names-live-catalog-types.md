<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: цель выдачи принимает типы живого каталога, включая типы модулей

- **Статус:** DRAFT — вердикта нет; санкции на код нет (ban #1). Слово в этой строке —
  статическая форма: действующее одобрение выводится из записи ревью, привязанной к
  отпечатку редакции, и внешнего события, а не из шапки (`change-graph.md` §3)
- **Статическая форма:** DRAFT
- **История review:** (только дописывается строкой «дата · круг · вердикт · SHA-256
  редакции · путь записи»)
  - 2026-10-19 · круг 1 · RETURNED (B1, род DoD: стадия S2 адресована в kacho) ·
    `6a8b134fc5d7ba8310c83d91675dc1db056aad0e0d30d25fe489dc915679046f` ·
    `docs/changes/kn-904/reviews/acceptance/6a8b134fc5d7ba8310c83d91675dc1db056aad0e0d30d25fe489dc915679046f.yaml`
- **Дата:** 2026-10-19 · **редакция:** 2 (дельта к редакции 1 — только замечания круга 1:
  B1 и N1–N3; сценарии S1, решения Р1–Р6 и тексты Т1/Т2 не менялись)
- **Задача:** `PRO-Robotech/kaname#904` (эпик `#746`; связь: `#866` — замер, давший
  признак; `#874` — вложенное правило, чья проба П3 обходила вход API строкой выдачи)
- **Решение диспетчера 2026-10-19:** исход (а) — открыть цель API для типов, живых в
  каталоге. Довод: выдача на объекты модулей обязана идти тем же API, что и на
  канонические, иначе модули — второго сорта. Условие безопасности: тип живой в каталоге
  на момент записи; выдача на тип, снятый из каталога, — по существующему правилу снятия
- **Ревизия замера:** kaname `b800272d5341` (ветка `904` от `origin/746`). Каждое число о
  дереве ниже — предикатом на этой ревизии

## Обзор

`AccessBindingService.Create` принимает пообъектную цель `target.resources[{type,id}]`
только для типов из закрытого перечня, выписанного в коде
(`internal/domain/feed_registry.go`, `materializableTypes`). Тип, заведённый
манифестом модуля в живом каталоге, вход отвергает. Поэтому выдачу на объект модуля
сегодня можно получить только ролью на всю область (`allInScope`) — то есть шире, чем
просили, — либо строкой выдачи в обход API.

Изменение делает источником ответа «может ли выдача назвать этот тип» **живую строку
каталога** — тот же источник, которым уже судятся правило роли
(`internal/apps/kaname/api/role/rules_catalog.go`) и приём объекта в зеркало
(`internal/repo/kaname/pg/resource_mirror/emitter.go`, отказ
`is not a live entry of the platform resource catalog`). Проверка выполняется дважды:
синхронно до `Operation` и повторно в транзакции записи выдачи, так что тип, снятый между
ними, выдачи не получает.

## Что НЕ входит

1. **Судьба уже записанной выдачи при снятии её типа.** Снятие типа из каталога выдачу не
   отвергает и цель не переписывает; доступ по объектам снятого типа живёт по
   существующему правилу снятия (`module-withdrawal-is-described.md`,
   `plan-confirms-what-apply-withdraws.md`). Это изменение правило не трогает: оно
   добавляет запрет **новой** записи на неживой тип (ATC-06, ATC-09, ATC-10) и закрепляет,
   что лежащая выдача читается как была (ATC-14).
2. **Проверка существования объекта цели.** Цель — «graceful-dangling»
   (`access_binding.proto`, комментарий `AccessTargetResources`): `id` у владельца не
   проверяется, объект, зарегистрированный позже, получает доступ при регистрации. Для
   типов модулей это поведение то же, что для канонических (ATC-03).
3. **Перечень грантуемых типов как отдельная витрина.** Его уже отдаёт
   `GET /iam/v1/permissionCatalog` из того же снимка (`list_catalog.go`); новое поле
   «годен для цели» не вводится: годен ровно тот тип, который витрина перечисляет.
4. **Консоль и Terraform-провайдер.** Оба передают тип цели свободной строкой без
   закрытого перечня (замер в разделе «Замер»): правка не нужна.
5. **Правило роли, `children`, ворота системного класса.** Их семантика не меняется;
   ATC-11 и ATC-13 утверждают, что они применяются к типам модулей через API так же, как
   к каноническим.

## Замер посылок

Все величины — на kaname `b800272d5341`.

**П1. Закрытый перечень цели — 26 типов, живых строк каталога в посеве — 27, перечень
целиком внутри живых, разность — `vpc.addressPool`.** Двумя предикатами:

- по написанию — строки посева каталога в базовой миграции:
  `grep -c "INSERT INTO kaname.catalog_resource" internal/migrations/0001_initial.sql` → 30
  (из них `live = true` — 27, `false` — 3: `compute.disk`, `compute.image`,
  `compute.snapshot`);
- по предмету — проба-overlay ниже, вывод:
  `closedSet=26 liveSeedResources=27 closedNotLive=[] liveOutsideClosed=[vpc.addressPool]`.

Следствие: перевод на живой каталог **не сужает** ни один канонический тип посева и
расширяет набор на `vpc.addressPool` (тип грантуем правилом роли уже сегодня —
`list_catalog.go`, комментарий поля `LabelSelectable`) и на типы, заведённые манифестами
модулей.

**П2. Вход отвергает тип модуля, живой в каталоге, в двух местах.** Проба-overlay
(в дерево не кладётся; запуск — `go test -short -overlay <карта> -run '^TestProbe904$'
./internal/apps/kaname/api/access_binding/`), исходник:

```go
// Каталог: живые строки посева + probemod.boxes (тот же способ, что у
// factsWithAppliedType в internal/apps/kaname/api/role/).
rows := seed.LiteralRows()
rows.Modules = append(rows.Modules, "probemod")
rows.Resources = append(rows.Resources, catalog.ResourceRow{Module: "probemod", Resource: "boxes", ObjectType: "probemod_box"})
// + глаголы get/list/update/delete
f, _ := catalog.NewFacts(catalog.Halves{Live: rows})
for _, ty := range types {
    _, live := f.FGAObjectType(ty)
    _, perr := targetFromProto(resources(ty, "b1"))            // вход ручки
    dv := domain.AccessTarget{Resources: ...}.Validate()       // домен
    t.Logf(...)
}
```

Вывод (сокращён до кода и текста):

| тип | живой в каталоге | `targetFromProto` | `AccessTarget.Validate` |
|---|---|---|---|
| `probemod.boxes` | да | `InvalidArgument` `Illegal argument target.resources[].type "probemod.boxes"` | отказ |
| `vpc.addressPool` | да | `InvalidArgument`, тот же текст | отказ |
| `compute.instance` | да | `OK` | `nil` |
| `compute.disk` (снят) | нет | `InvalidArgument` | отказ |
| `probemod.nope`, `*`, `probemod.*`, `vpc.address_pool` | нет | `InvalidArgument` | отказ |

Посылка задачи подтверждена: отказ даёт и вход ручки
(`internal/apps/kaname/api/access_binding/delta_input.go`, `targetFromProto`), и домен
(`internal/domain/access_binding.go`, `AccessBinding.Validate` → `Target.Validate` →
`ValidTargetType`). Снять нужно оба.

**П3. Зеркало принимает объект только живого типа — значит, объект типа, живого в
каталоге, до сравнения с целью доходит.** `emitter.go` отвергает регистрацию при
`!typeLive` в той же транзакции, что и запись; регистрация объекта типа модуля доходит до
зеркала — `TestRegisterResource_AppliedTypeReachesTheMirror`. Материализатор сравнивает
цель с типом из зеркала точным совпадением (`reconcile.go`, `filterMatchedToTarget`,
`desiredMembersForObject`) и для типа модуля уже работает —
`TestRuleObjectTuples_SC65_DeclaredContainerGetsPublicReader` (цель
`[probemod.boxes …]`, построенная строкой). Довод закрытого перечня — «тип, который лента
никогда не произведёт, принимается и не даёт ничего»
(`internal/domain/access_binding_target_vocabulary_test.go`, шапка) — сохраняется
дословно: множество типов, которые лента **может** произвести, и есть живой каталог.

**П4. Потребители закрытого перечня не держат.**

- Клиенты в `PRO-Robotech/kacho` @ `fd9f1793e7`: Terraform-провайдер судит лишь форму
  (`validateTargetResources`: отвергает `*` и тип без точки); консоль
  (`AccessBindingCreateForm.tsx`) передаёт `{type,id}` как ввёл человек.
- Сквозной набор — в kaname, не в kacho:
  `git -C <kacho> ls-tree --name-only fd9f1793e7 tests/newman/cases/` → пусто (0 строк).
  Кейс `IAM-ACB-RD-CR-TARGET-UNKNOWN-TYPE-NEG` лежит в kaname
  `tests/newman/cases/iam-access-binding-redesign.py` @ `b800272d5341` (id — строка 243),
  его утверждение — **вхождение** префикса `Illegal argument target.resources[].type`
  (строка 263); продление текста (Р3) его не ломает. Заголовок кейса и комментарии модуля
  называют закрытый перечень (`closed-table`, `closed type-registry`, «закрытого
  type-registry» — строки 14, 57, 177, 213, 244–245, 249): это текст, а не утверждение, и
  он приводится к Р1 (DoD S2 п. 3).

**П5. Окно отставания снимка каталога — 15 с** (`cmd/kaname/catalog_snapshot_wiring.go`,
`catalogSnapshotRefreshDefault`, ручка `KANAME_CATALOG_SNAPSHOT_REFRESH_INTERVAL_MS`).

## Решения

**Р1. Источник ответа — живая строка каталога.** Тип годен для цели тогда и только тогда,
когда у него есть строка каталога с `live = true`. Закрытый перечень в коде источником
ответа для цели перестаёт быть. Тот же источник уже у правила роли и у зеркала: выдача,
роль и объект судятся одним множеством.

**Р2. Две проверки, одна санкция.**

- **Синхронно**, до `Operation`, по снимку каталога — тому же, которым судится правило
  роли. Отказ — `INVALID_ARGUMENT`, ни `Operation`, ни строки выдачи. Порядок
  относительно права выдавать не меняется (проверка типа стоит до него, как сейчас):
  перечень живых типов публичен (`GET /iam/v1/permissionCatalog`), отказ не сообщает
  ничего, чего вызывающий не мог бы прочесть.
- **В транзакции записи выдачи** — по строке каталога в базе, под замком, согласованным с
  применением манифеста (применитель берёт замки на строки ресурсов модуля,
  `CatalogWriter.LockModuleResources`). Снятие, зафиксированное до записи, даёт
  `Operation.error` `FAILED_PRECONDITION` и строки выдачи нет. Снятие, начатое, но не
  зафиксированное, запись дожидается и судит по его исходу (ATC-10). Форма замка —
  предмет замысла.

**Р3. Тексты отказа — часть контракта (`api-error-tone`).** `<T>` — тип дословно, как
пришёл:

- Т1, синхронно, `INVALID_ARGUMENT`:
  `Illegal argument target.resources[].type "<T>" (not a live entry of the platform resource catalog; grantable types are published by GET /iam/v1/permissionCatalog)`.
  Префикс до `(` — нынешний текст побайтово; продление называет, где брать перечень,
  тем же адресом, что отказ правила роли (`domain.CatalogEndpoint`);
- Т2, в `Operation.error`, `FAILED_PRECONDITION`:
  `target type <T> is not a live entry of the platform resource catalog; grantable types are published by GET /iam/v1/permissionCatalog`.

Перечень с несколькими неживыми типами отвергается целиком; Т1 называет **первый**
неживой тип в порядке перечня.

**Р4. Снятый тип — тот же отказ, что неизвестный.** Строка `live = false` годной для цели
не делает. Отдельного текста «снят» у цели нет: преемник снятого публикуется тем же
адресом, что назван в Т1.

**Р5. Чтение лежащей выдачи от каталога не зависит.** `Get`/`List` отдают цель дословно
и после снятия её типа; ни одна ветвь чтения тип с каталогом не сверяет.

**Р6. Контракт `.proto` — только комментарий.** Комментарий `AccessTargetResources`
(«`type` is dotted from the closed type-registry») переписывается: тип — точечное имя
типа, живого в каталоге платформы, перечень — `GET /iam/v1/permissionCatalog`. Поле,
номер, форма — без изменений; ломающего изменения нет.

### Критерии продукта (ban #18)

| критерий | ответ |
|---|---|
| производительность | синхронно — поиск в снимке, ≤ 256 обращений к карте на запрос (`MaxTargetResourcesPerBinding`); в транзакции — одно чтение строк каталога по ключу `dotted` для ≤ 256 различных типов одним оператором. Замер — DoD S1 п. 6 |
| безопасность | поверхность **расширяется**, и это названо: множество типов цели — с 26 закрытых до всех живых в каталоге. Новых ответов-оракулов нет (перечень публичен). Ворота роли (`RoleCoversType`), области (`IsContainedIn`) и системного класса применяются к новым типам без изменений (ATC-11…13). Запись на неживой тип закрыта и в окне гонки (ATC-09, ATC-10) |
| инновационность | модуль платформы получает пообъектную выдачу на свои объекты наравне с каноническими, без правки кода службы доступа |
| узнаваемость относительно рынка | новых имён нет: поле, ресурс и метод существуют |
| перспективность | обратимо без миграции данных: возврат к закрытому перечню отвергал бы лишь новые записи |
| благо продукта | выигрыш — продуктовый: без изменения выдача на объект модуля доступна только всей областью (шире запрошенного) |
| производственность | режима «только для стенда» нет; обе проверки — в боевом пути |

## Мир проб

- **М1 (unit).** Каталожный факт = живые строки посева (`seed.LiteralRows()`) плюс строки
  фикстуры `internal/manifest/testdata/probemod.public-read-fixture.yaml`: `probemod.boxes`
  (`probemod_box`, указатель на проект, `publicReadToChildren`) и `probemod.items`
  (`probemod_item`, указатель `box`). Построение — как `factsWithAppliedType`
  (`applied_type_reaches_the_rule_gate_test.go`) и `sc65Facts`
  (`reconcile/public_reader_sc65_test.go`); конструируемость показана пробой П2.
- **М2 (integration, testcontainers).** Мир `pcrWorld`
  (`internal/apps/kaname/api/access_binding/public_container_read_world_integration_test.go`):
  аккаунт `acc-A`, проекты `prj-A` и `prj-B` (второй — `seedProjectInAccount`, как
  первый), владелец `usr-A`, получатели `usr-D` и `usr-E` (`mustSeedUser`). Доставка
  фикстуры М1 — `applyDelivered`.
  Объекты `probemod_box:b1`, `probemod_box:b2` в `prj-A` (до выдачи, если сценарий не
  говорит иного) — регистрацией службой-владельцем
  (`RegisterResource`, две строки `project` и `owner`, цепь
  `["project:prj-A", "account:acc-A"]`) тем же способом, что `registerRegistry`. Роли —
  `seedRole` аккаунта `acc-A`:
  - `rol-box-get` — `{probemod, [boxes], [get]}`;
  - `rol-box-read` — `{probemod, [boxes], [get, list]}`;
  - `rol-box-upd` — `{probemod, [boxes], [get, update]}`;
  - `rol-item-get` — `{probemod, [items], [get]}`;
  - `rol-pool-get` — `{vpc, [addressPool], [get]}`;
  - `rol-inst-get` — `{compute, [instance], [get]}`;
  - `rol-inst-box` — `{compute, [instance], [get]}` и `{probemod, [boxes], [get]}`.
  «Выдача В(получатель, роль, область, цель)» — `Create` через ручку от `usr-A`; «доходит»
  — опрос `Operation` до `done = true`; «опрос `Check`» — `AuthorizeService.Check` раз в
  200 мс с пределом 30 с (окно соседа `nested-rule-reaches-descendants-of-a-named-container.md`).
- **М3 (снятие).** «Снятие `probemod.items`» — применение той же фикстуры без ресурса
  `items` через `modulecatalog.NewApplier(...).ApplyAll`. «Снимок не обновлён» — ручка
  мира М2 остаётся на факте, построенном до снятия (как снимок в окне П5).
- **М4 (сквозной набор kaname).** Автономный стенд службы — задание `stand`
  `.github/workflows/e2e-newman.yml` (своя база и свой УЦ, без платформы); шаги модуля
  `iam-access-binding-redesign` адресованы собственному публичному REST-фронту службы
  (`address_own_front` в конце модуля; гейт `scripts/own_front_env_test.py`). Посев набора
  даёт `accountAId`, `userNOBId`, `jwtAccountAdminA`. Роль заводит помощник модуля
  `_seed_role` (`POST /iam/v1/roles`, уровень `iam.account`/`accountAId`) с правилом
  `{vpc, [addressPool], [get]}`; тело выдачи — `_acb_body` (область
  `iam.account`/`accountAId`, получатель `userNOBId`); уборка — `_cleanup_binding`,
  `_cleanup_role`. Строка `vpc.addressPool` живая в посеве каталога стенда (П1).

## Сценарии

### S1 — служба доступа (`PRO-Robotech/kaname`)

#### ATC-01 — тип модуля, живой в каталоге, принимается целью

**Дано** М2. **Когда** В(`usr-D`, `rol-box-get`, `iam.project`/`prj-A`,
`{"resources":{"resources":[{"type":"probemod.boxes","id":"b1"}]}}`).
**Тогда** ответ — `Operation` без ошибки; опрос доходит до `done = true` без `error`.
**И** `GET /iam/v1/accessBindings/{id}` отдаёт `target.resources` =
`[{"type":"probemod.boxes","id":"b1"}]` дословно.
**Близнец:** ATC-02. Отличие — один факт: тип есть в каталоге.

#### ATC-02 — тип, которого в каталоге нет, отвергается синхронно с именем типа

**Дано** М2. **Когда** та же выдача, тип `probemod.nope` (модуль `probemod` живой,
ресурса `nope` нет). **Тогда** синхронно `INVALID_ARGUMENT`, текст Т1 с
`<T> = probemod.nope`; `Operation` не заведена; выдач у `usr-D` в `prj-A` — 0
(`List` с `filter=subject="usr-D"`).
**Близнец:** ATC-01.

#### ATC-03 — выдача на тип модуля материализуется ровно на названный объект

**Дано** выдача ATC-01, `done = true` без `error`; объекты `b1`, `b2` к моменту выдачи
**не** зарегистрированы (сценарий отменяет умолчание М2).
**Когда** служба-владелец регистрирует `b1`, затем `b2`.
**Тогда** опрос `Check(user:usr-D, v_get, probemod_box:b1)` доходит до `allowed = true`.
**И** `Check(user:usr-D, v_get, probemod_box:b2)` → `allowed = false` (после того как
вопрос по `b1` дал `true`).
**Близнец:** `b2` против `b1` — отличие один факт: объект назван целью.

#### ATC-04 — канонический живой тип вне прежнего перечня принимается

**Дано** М2. **Когда** В(`usr-D`, `rol-pool-get`, `iam.project`/`prj-A`,
`[{"type":"vpc.addressPool","id":"ap1"}]`).
**Тогда** `Operation` доходит до `done = true` без `error`; `GET` отдаёт цель дословно.
**Близнец:** тот же вход с типом `vpc.address_pool` → синхронно `INVALID_ARGUMENT`, Т1 с
`<T> = vpc.address_pool`. Отличие — один факт: написание типа.

#### ATC-05 — канонический тип прежнего перечня принимается как сегодня

**Дано** М2. **Когда** В(`usr-D`, `rol-inst-get`, `iam.project`/`prj-A`,
`[{"type":"compute.instance","id":"i1"}]`). **Тогда** `Operation`
доходит до `done = true` без `error`; `GET` отдаёт цель дословно.
**Близнец:** ATC-06 (а). Отличие — один факт: строка каталога живая.

#### ATC-06 — неживой тип отвергается тем же текстом

- (а) **Дано** М2 (строка `compute.disk` в посеве с `live = false`). **Когда** выдача с
  ролью `rol-inst-get` и целью `[{"type":"compute.disk","id":"d1"}]`. **Тогда**
  синхронно `INVALID_ARGUMENT`, Т1 с `<T> = compute.disk`; выдачи нет.
- (б) **Дано** М2, затем М3 (снятие `probemod.items`) и ручка, пересобранная на факте
  после снятия. **Когда** выдача с ролью `rol-item-get` и целью
  `[{"type":"probemod.items","id":"i1"}]`. **Тогда** синхронно `INVALID_ARGUMENT`, Т1 с
  `<T> = probemod.items`.
  **Близнец (б):** тот же вход **до** снятия → `done = true` без `error`. Отличие — один
  факт: строка снята.

#### ATC-07 — подстановочный и не-точечный тип отвергаются

**Дано** М2. **Когда** выдача с ролью `rol-box-get` и целью из одного элемента, тип —
по очереди `*`, `probemod.*`, `probemod`. **Тогда** каждый — синхронно
`INVALID_ARGUMENT`, Т1 с соответствующим `<T>`; выдачи нет.
**Близнец:** ATC-01 (`probemod.boxes`). Отличие — один факт: тип.

#### ATC-08 — перечень с одним неживым типом отвергается целиком

**Дано** М2. **Когда** В(`usr-D`, `rol-inst-box`, `iam.project`/`prj-A`,
`[{"type":"compute.instance","id":"i1"},{"type":"probemod.nope","id":"x"}]`).
**Тогда** синхронно `INVALID_ARGUMENT`, Т1 с `<T> = probemod.nope`; выдачи нет.
**Близнец:** второй элемент `{"type":"probemod.boxes","id":"b1"}` → `done = true` без
`error`; `GET` отдаёт оба элемента в присланном порядке. Отличие — один факт: тип второго
элемента.

#### ATC-09 — снятие, зафиксированное после синхронной проверки, записи не даёт

**Дано** М2 и М3: строка `probemod.items` снята в базе, снимок ручки не обновлён (в нём
`probemod.items` живой). **Когда** В(`usr-D`, `rol-item-get`, `iam.project`/`prj-A`,
`[{"type":"probemod.items","id":"i1"}]`).
**Тогда** синхронный ответ — `Operation`; опрос доходит до `done = true` с `error.code` =
`FAILED_PRECONDITION` и `error.message` = Т2 с `<T> = probemod.items`; выдач у `usr-D` в
`prj-A` — 0.
**Близнец:** то же без шага снятия → `done = true` без `error`, выдача есть. Отличие —
один факт: строка каталога в базе.

#### ATC-10 — незафиксированное снятие решает исход записи

**Дано** М2. Применение М3 выполнило свои операторы и
удерживает транзакцию открытой (обёртка порта `modulecatalog.TxRunner` в пробе: функция
транзакции отработала, возврат — по сигналу пробы).
**Когда** В(`usr-D`, `rol-item-get`, `iam.project`/`prj-A`,
`[{"type":"probemod.items","id":"i1"}]`) — синхронно `Operation`; затем проба отпускает
применение, и оно **фиксируется**.
**Тогда** опрос доходит до `done = true` с `FAILED_PRECONDITION`, Т2; выдачи нет.
**Близнец:** применение отпускается с **откатом** → `done = true` без `error`, выдача есть,
её `GET` отдаёт цель дословно. Отличие — один факт: исход транзакции снятия. Близнец
отличает запись, ждущую исхода снятия, от записи, читающей прежнюю версию строки (та
дала бы выдачу в обоих исходах), и от записи, отказывающей на занятой строке сразу (та
дала бы отказ в обоих).

#### ATC-11 — ворота роли действуют на тип модуля

**Дано** М2. **Когда** В(`usr-D`, `rol-inst-get`, `iam.project`/`prj-A`,
`[{"type":"probemod.boxes","id":"b1"}]`) — роль правил над `boxes` не имеет.
**Тогда** синхронно `FAILED_PRECONDITION`, текст существующий:
`role <rol-inst-get> does not grant verbs on probemod.boxes; target type must be covered by role.rules`.
**Близнец:** ATC-01 (роль `rol-box-get`). Отличие — один факт: роль покрывает тип.

#### ATC-12 — цель вне области выдачи не даёт доступа

**Дано** М2, `b1` зарегистрирован в `prj-A`. **Когда** В(`usr-D`, `rol-box-get`,
`iam.project`/`prj-B`, `[{"type":"probemod.boxes","id":"b1"}]`); `done = true` без `error`.
**Тогда** `Check(user:usr-D, v_get, probemod_box:b1)` → `allowed = false` после того, как
выдача-контроль ниже дала `true`.
**Близнец:** та же выдача с областью `prj-A` получателю `usr-E` → опрос
`Check(user:usr-E, v_get, probemod_box:b1)` доходит до `true`. Отличие по предмету — один
факт: область выдачи. Получатель другой по устройству мира, а не как второй фактор: оба
исхода наблюдаются в одном мире, и отрицательный ответ берётся после положительного (иначе
«`false`» неотличим от «материализация ещё не дошла»); выдача `prj-A` тому же `usr-D`
сделала бы отрицательный исход ненаблюдаемым. `usr-D` и `usr-E` симметричны: оба заведены
`mustSeedUser`, других выдач у них нет.

#### ATC-13 — ворота системного класса действуют на тип модуля

**Дано** М2; `usr-A` — человеческая сессия в окне свежести (`ClassGrantFreshness`).
**Когда** В(`system_class:anonymous`, `rol-box-read`, `iam.project`/`prj-A`,
`[{"type":"probemod.boxes","id":"b1"}]`). **Тогда** `done = true` без `error`; опрос
`Check(system_class:anonymous, v_get, probemod_box:b1)` доходит до `true`;
`Check(system_class:anonymous, v_get, probemod_box:b2)` → `false`.
**Близнец:** роль `rol-box-upd` → синхронно `FAILED_PRECONDITION`, текст существующий
`Role <rol-box-upd> grants verbs beyond get and list; a system class subject accepts read-only roles`.
Отличие — один факт: роль только читает.

#### ATC-14 — лежащая выдача читается после снятия её типа

**Дано** ATC-01 для цели `[{"type":"probemod.items","id":"i1"}]` с ролью `rol-item-get`,
`done = true` без `error`. **Когда** М3 (снятие `probemod.items`).
**Тогда** `GET` выдачи отдаёт `target.resources` = `[{"type":"probemod.items","id":"i1"}]`
дословно, ответ без ошибки; `List` с `filter=subject="usr-D"` содержит эту выдачу.
**Близнец:** тот же `GET` до снятия — тот же ответ. Отличие — один факт: строка снята.

### S2 — сквозной набор службы (`PRO-Robotech/kaname`, newman, собственный REST-фронт)

Стадия идёт той же веткой, что S1, и судит развёрнутую службу через её публичный
REST-фронт (второй эшелон, `ban12-second-echelon`).

#### ATC-E1 — `vpc.addressPool` принимается фронтом

**Дано** М4. **Когда** `POST /iam/v1/accessBindings` с ролью М4, областью
`iam.account`/`accountAId`, получателем `userNOBId`, целью
`{"resources":{"resources":[{"type":"vpc.addressPool","id":"ap1"}]}}`.
**Тогда** HTTP 200, тело — `Operation`; опрос операции доходит до `done = true` без
`error`; `GET /iam/v1/accessBindings/{accessBindingId}` отдаёт цель
дословно. Выдача и роль снимаются в уборке кейса.
**Близнец:** ATC-E2.

#### ATC-E2 — опечатка в типе отвергается фронтом с адресом перечня

**Дано** М4. **Когда** тот же запрос с типом `vpc.address_pool`. **Тогда** HTTP 400,
`code` = 3; `message` = Т1 с `<T> = vpc.address_pool` дословно (пара статус-код —
`api-case-asserts-pair`).
**Близнец:** ATC-E1. Отличие — один факт: написание типа.

## Сценарий → производитель

«Есть» — производитель в дереве на `b800272d5341` и это изменение его не меняет;
«меняется» — производитель есть и правится этим изменением; «заказан» — пишется этим
изменением.

| ID | что производит «Тогда» | координата | статус |
|---|---|---|---|
| ATC-01, -04, -05 | приём цели по живой строке | `internal/apps/kaname/api/access_binding/delta_input.go` (`targetFromProto`); `internal/domain/access_binding_target.go` (`Validate`, `ValidTargetType`) | меняется: источник — снимок каталога (`catalog.Source`, как у `CreateRoleUseCase`) |
| ATC-01, -04, -05, -14 | `GET` цели дословно | `internal/dto/toproto/access_binding.go` (`domainTargetToProto`); `internal/repo/kaname/pg/relverdict/target.go` (разбор формы) | есть |
| ATC-02, -04 близнец, -06, -07, -08 | Т1 синхронно | `delta_input.go` | меняется (текст Р3) |
| ATC-03, -12, -13 | материализация по цели и области | `reconcile/reconcile.go` (`filterMatchedToTarget`, `desiredMembersForObject`, `IsContainedIn`); регистрация — `internal/apps/kaname/api/internal_iam/` (`RegisterResourceUseCase`) | есть |
| ATC-03, -12, -13 | `Check` | `internal/repo/kaname/pg/relverdict/` (ветвь выдач) | есть |
| ATC-09, -10 | Т2 в `Operation.error`, выдачи нет | `internal/apps/kaname/api/access_binding/create.go` (`doCreate`, транзакция записи) и чтение строк каталога в ней в адаптере `internal/repo/kaname/pg/` | заказан |
| ATC-11 | отказ покрытия | `internal/apps/kaname/api/access_binding/structural_gates.go` (Gate 3) | есть |
| ATC-13 | ворота класса | `internal/apps/kaname/api/access_binding/system_class_gates.go` | есть |
| ATC-E1, -E2 | ответ собственного REST-фронта службы: HTTP-статус и `code` | `internal/restfront/` (маршрутизатор фронта, отображение кода в статус) поверх того же `targetFromProto` и `doCreate` | есть (фронт); тело ответа — по строкам ATC-01/-02 и ATC-09 выше |

Ни одного «Тогда» без производителя.

## Пробы-держатели

| ID | проба | слой | статус |
|---|---|---|---|
| ATC-01, -02, -04, -05, -06 (а), -07, -08 | вход ручки на каталожном факте М1: каждый тип ATC — исход и текст дословно | unit, `internal/apps/kaname/api/access_binding/` | заказана; заменяет утверждения закрытого перечня в `TestAB_IAM_1_23_ValidTargetType`, `TestTargetParse_RetiredBlockStorageIsRefused`, `TestTargetParse_MisspelledTypeIsRefusedNotSilentlyStored` |
| ATC-01…-08 (домен) | `AccessTarget.Validate` не судит членство в перечне | unit, `internal/domain/` | заказана; `TestTargetTypeRegistryIsTheMaterializationFeed` и `TestTargetTypeRegistryRefusesTypesTheFeedNeverProduces` переводятся с `AllMaterializableTypes` на живой каталог (довод шапки сохраняется, П3) |
| ATC-01, -02, -03, -04, -05, -06 (б), -09, -10, -11, -12, -13, -14 | мир М2 через ручку (ATC-02 — «выдач у `usr-D` в `prj-A` 0» читается `List`) | integration, testcontainers, `internal/apps/kaname/api/access_binding/` | заказана; `TestAB_IAM_1_23_UnknownTargetType_InvalidArgument` остаётся зелёным без правки (вхождение префикса) |
| ATC-E1, -E2 | кейсы сквозного набора, пара статус-код | newman, kaname `tests/newman/cases/iam-access-binding-redesign.py` (тот же модуль, что `IAM-ACB-RD-CR-TARGET-UNKNOWN-TYPE-NEG`), задание `stand` `e2e-newman.yml` | заказаны; соседний NEG-кейс остаётся зелёным без правки утверждения |

Каждая заказанная проба красная на `b800272d5341` по исходу, а не по сборке: ATC-01 и
ATC-E1 — `INVALID_ARGUMENT` (у ATC-E1 — HTTP 400) вместо `Operation` (П2), ATC-09/-10 —
`done` без ошибки вместо Т2 (проверки в транзакции нет), Т1 и ATC-E2 — текст без
продления.

## DoD

### S1 — `PRO-Robotech/kaname`

1. Пробы-держатели S1 из таблицы — красные до правки кода (вывод прогона в комментарии
   задачи), зелёные после; утверждения о закрытом перечне в названных пробах заменены, а
   не удалены без замены.
2. Integration-прогон мира М2 (ATC-01, -03, -04, -05, -06 (б), -09…-14) — зелёный во
   внешнем кластере слотом `heavy-slot.sh`; ATC-10 — оба исхода, по 20 повторов без
   расхождения.
3. `AccessBinding.Create` на неизвестном и снятом типе даёт Т1 побайтово; в транзакции —
   Т2 побайтово (ATC-02, -06, -09, -10).
4. Комментарий `AccessTargetResources` в `proto/kaname/cloud/iam/v1/access_binding.proto`
   переписан по Р6; `buf lint` и `buf breaking` против базы — зелёные; порождённый код
   пересобран.
5. Шапки, утверждающие закрытый перечень цели, приведены к Р1:
   `internal/domain/access_binding_target.go` (`ValidTargetType`),
   `internal/domain/feed_registry.go` (`materializableTypes`, если остаётся у другого
   потребителя — с его именем), `delta_input.go`, `handler.go` (комментарий
   «closed-table»). Предикат: `git grep -n 'closed type-registry\|closed-table' --
   internal/apps/kaname/api/access_binding internal/domain proto` — каждое попадание
   либо снято, либо говорит о другом предмете (вывод в комментарии задачи).
6. Цена проверки в транзакции замерена: время `Create` при цели из 256 элементов разных
   типов против цели из 1 элемента — число в мс с медианой по 20 прогонам и ревизией.
   Фикстура: манифест модуля `probeperf` с ресурсами `r000`…`r255`, порождённый пробой и
   доставленный `applyDelivered` в мир М2 (предела числа ресурсов в манифесте нет:
   `grep -rn -i 'max.*resource\|cardinality' internal/manifest/*.go` без `_test` → 0
   @`b800272d5341`); роль `rol-perf` аккаунта — 16 правил `{probeperf, [16 ресурсов],
   [get]}`. Подстановочный `*` в ресурсах собственной роли запрещён
   (`internal/domain/rule.go`, шапка: «custom roles reject `*` in module/resource»), поэтому
   ресурсы перечислены: 16 на правило и до 64 правил (`maxRuleElems`, `MaxRules`),
   256 скомпилированных разрешений при пределе 1024 (`MaxCompiledPermissions`).
7. Полный хук отправки на закоммиченной голове — отказов 0; комментарий `DoD-proof @<sha>`
   в `kaname#904`.

### S2 — `PRO-Robotech/kaname`, сквозной набор

1. Кейсы ATC-E1, ATC-E2 — в `tests/newman/cases/iam-access-binding-redesign.py` (тот же
   модуль, что `IAM-ACB-RD-CR-TARGET-UNKNOWN-TYPE-NEG`); пара статус-код в каждом. Коллекция
   не новая — записи ведомости производителя не нужно; коллекция перегенерирована
   `scripts/gen.py` (шаг «коллекции воспроизводятся генератором побайтово»), каталог
   `tests/newman/docs/CASES-INDEX.md` сходится (`scripts/validate-cases.py`).
2. Задание `stand` `.github/workflows/e2e-newman.yml` на голове ветки — зелёное, в шаге
   «коллекции собственного REST-фронта гоняются» `iam-access-binding-redesign` исполнен с
   ATC-E1, ATC-E2; до правки кода оба красные по исходу (вывод — в комментарии задачи).
   Уборка кейса снимает выдачу и роль.
3. `IAM-ACB-RD-CR-TARGET-UNKNOWN-TYPE-NEG` — зелёный, утверждение не правится; заголовок
   кейса и комментарии модуля, называющие закрытый перечень, приведены к Р1. Предикат:
   `git grep -n 'closed-table\|closed type-registry\|closed target type-registry\|закрытого type-registry' -- tests/newman/cases/iam-access-binding-redesign.py`
   — каждое попадание снято либо говорит о другом предмете (вывод в комментарии задачи).

S2 идёт той же веткой и тем же запросом, что S1: контракт меняется лишь комментарием (Р6),
фронт собирается с той же головы, ребра в kacho и пересборки чужого края нет.
