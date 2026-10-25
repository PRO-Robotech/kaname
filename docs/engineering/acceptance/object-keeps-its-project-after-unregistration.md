<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: объект модуля остаётся привязан к проекту и после снятия регистрации

- **Статус:** DRAFT, редакция 2. Вердикта на эту редакцию нет, санкции на код нет (ban #1).
  Вердикт выносит `acceptance-reviewer`
- **Статическая форма:** DRAFT. Слово вписано автором и вердиктом не является. Действующее
  одобрение выводится из записи ревью по отпечатку редакции и из внешнего события, на которое
  запись ссылается (`change-graph.md` §3). После ревью слово DRAFT не правится
- **История ревью:** только дописывается строками вида «дата · круг · вердикт · SHA-256
  редакции · путь записи». Прежние строки не правятся и не удаляются. Записи кладутся в
  `docs/specs/reviews/object-keeps-its-project-after-unregistration/<sha256>.yaml`
  - 2026-10-25 · круг 1 · CHANGES_REQUESTED · `1864ef496efa810811281da7c1c90a90c62bfbf72c9d039f2263782eb61387ab` ·
    `docs/specs/reviews/object-keeps-its-project-after-unregistration/1864ef496efa810811281da7c1c90a90c62bfbf72c9d039f2263782eb61387ab.yaml`
  - 2026-10-25 · круг 2 · APPROVED · `1d308bbd5d5bb6cee79994a67f7cf3664e475f504c65f323b983948139b26a72` ·
    `docs/specs/reviews/object-keeps-its-project-after-unregistration/1d308bbd5d5bb6cee79994a67f7cf3664e475f504c65f323b983948139b26a72.yaml`
  - 2026-10-25 · круг 3 (правка одобренной, §11) · CHANGES_REQUESTED · `4265bf69e5bdb6193867781de8440e975cd853ee5d9548943b31b0e6e44522d8` ·
    `docs/specs/reviews/object-keeps-its-project-after-unregistration/4265bf69e5bdb6193867781de8440e975cd853ee5d9548943b31b0e6e44522d8.yaml`
  - 2026-10-25 · круг 4 (правка одобренной, §11) · APPROVED · `69280aba687b7b3cb87b71a40c675b6ff8204405fd8550cfe98574d037fdbbd0` ·
    `docs/specs/reviews/object-keeps-its-project-after-unregistration/69280aba687b7b3cb87b71a40c675b6ff8204405fd8550cfe98574d037fdbbd0.yaml`
  - 2026-10-25 · правка ПОСЛЕ вердикта круга 4: предикат §6 S1 п.1 получает путь миграции от
    диффа полосы, а не заготовкой. Вердикта на эту редакцию нет, вердикт круга 4 остаётся
    вердиктом о редакции `69280aba…bbd0`. Что изменено — §11.1
- **Дата:** 2026-10-25 · **редакция:** 2 (что изменено против редакции 1 — §10)
- **Задача:** `PRO-Robotech/kaname#983` (эпик `#980`, вторая волна registry). Связь: `#982`
  (родителя регистрируемого объекта выводит kaname, закрытая политика записи модуля), `#963`
  (снятие регистрации снимает выдачи, посажено), `#981` (публикация манифеста модулем),
  `#986` (делегирование права выдавать)
- **Потребитель:** приёмка svc-registry «единственный писатель IAM и выдача токенов», редакция 3,
  SHA-256 `2717077568f0057fa3205069807b4cc1b5fa72ec00ecda50eadfad0967b22dc7`, DRAFT (сверено
  `sha256sum` по копии документа из дома svc-registry, `docs/acceptance/registry-iam-and-tokens.md`).
  Её §3а строка «привязка id объекта к проекту переживает снятие регистрации (Д-A2)» и сценарий
  SRI-23 опираются на эту приёмку. Соответствие строк — §5.3
- **Ревизия измерения:** kaname `5c6b7c078` (голова `origin/955`). Каждое число о дереве ниже
  снято на этой ревизии командой рядом. Посева и прогона не было: «Дано» показано чтением
  писателя со строкой (§4.1, §5.2)
- **Тип изменения:** новая миграция (хранилище привязок объекта к проекту, ограничения базы,
  колонка признака у строки каталога ресурсов); новый ключ манифеста модуля
  `permanentProject`; поведение `InternalIAMService.RegisterResource` (новый отказ
  `FAILED_PRECONDITION` с машинной причиной, два новых отказа формы `INVALID_ARGUMENT`) и
  применения каталога модуля; комментарий контракта
  `RegisterResource` в `.proto` (новых полей нет)
- **Сервис:** `kaname`

---

## §0. Перепись производителей — до сценариев

### 0.1. Где сегодня живёт проект регистрации

```sh
awk '/^CREATE TABLE/{t=$3} /object_id text/{print t}' internal/migrations/0001_initial.sql | sort -u
# → access_binding_target_members, relation_fact, resource_mirror,
#   resource_parent_edge, resource_reconcile_outbox  (5 таблиц)
git grep -l 'CREATE TABLE' -- 'internal/migrations/2026*.sql' | xargs grep -l object_id
# → 20260916020000_public_read_publication_is_ordered_by_its_owner.sql (публикация, без проекта)
```

Проект регистрации объекта несёт ровно одна колонка: `kaname.resource_mirror.parent_project_id`
(`internal/migrations/0001_initial.sql:2387`), ключ строки — `(object_type, object_id)` (`:4265`).
Цепь предков — `kaname.resource_parent_edge` (`:2402`). Ни одна другая таблица проекта объекта
не хранит; публикация (`public_read_publication`) хранит только признак и версию.

Писатель проекта — `RegisterResourceUseCase.Register` (`internal/apps/kaname/api/internal_iam/register_resource.go:377`)
→ `resource_mirror.UpsertTx` (`internal/repo/kaname/pg/resource_mirror/emitter.go:277`). Поле
запроса — `RegisterResourceRequest.parent_project_id` (`proto/kaname/cloud/iam/v1/internal_iam_service.proto:407`),
переносится в строку дословно (`register_resource.go:399`).

### 0.2. Повторная регистрация в другом проекте сегодня применяется

Оператор вставки `StmtInsertOrSupersede` (`emitter.go:188-213`) на конфликте ключа заменяет
`parent_project_id` и цепь при строго новой версии (`:201-207`). Регистрация того же объекта с
другим проектом и новой версией применяется молча; отказа «объект в другом проекте» в пути
регистрации нет:

```sh
git grep -n -i 'another project\|other project\|bound to' -- internal/apps/kaname/api/internal_iam/ internal/repo/kaname/pg/resource_mirror/ ':!*_test.go'
# → 0
```

### 0.3. Снятие регистрации удаляет единственное место проекта

`Unregister` (`register_resource.go:556`) → `resource_mirror.DeleteTx` (`emitter.go:526`):
`DELETE FROM kaname.resource_mirror … AND source_version <= $3` (`:531`) и снятие цепи (`:554`).
После снятия у объекта не остаётся строки, называющей его проект (§0.1). Снятие выдач объекта —
`keyWithdrawal.WithdrawTx` той же транзакции (`register_resource.go:905`, `#963`).

### 0.4. Писатели строки зеркала — все пути

Предикат по написанию:

```sh
git grep -c -E '(INSERT INTO|UPDATE|DELETE FROM)\s+(kaname\.)?resource_mirror\b' -- 'internal/**/*.go' 'cmd/**/*.go' ':!*_test.go'
# → backfill_adapter.go:2, orphan_mirror_adapter.go:1, resource_mirror/emitter.go:3
```

Предикат по предмету (кто шлёт операторы зеркала, не называя таблицу):

```sh
git grep -n -E 'StmtInsertOrSupersede|StmtVersionOnlyBump|resource_mirror\.(UpsertTx|DeleteTx)\(' -- '*.go' ':!*_test.go' | grep -v resource_mirror/emitter.go
# → resource_mirror_emitter.go:35, :49 (порт use-case), scalegrid/seed.go:223, :225 (посевщик сетки замера)
```

Итого писателей строки зеркала в не-тестовом дереве — **четыре пути**: регистрация
(`emitter.go` через `resource_mirror_emitter.go`), дымовой посев проверки готовности
(`backfill_adapter.go:231`, `SeedSmokeMirrorObject`), починка пустого проекта из цепи
(`orphan_mirror_adapter.go:183`, `RepairMirrorParentFromChain`) и посевщик сетки замера
(`scalegrid/seed.go:223-225`). Вне `internal/` — стенд замера `tools/authzformbench/relational.go`
(4 оператора, не прод). Инвариант, выраженный только в use-case регистрации, три из четырёх
путей не видели бы — отсюда Р9 (механизм базы).

### 0.5. Кто вызывает регистрацию

```sh
git grep -n -E 'registrar\.(Register|Unregister)\(' -- '*.go' ':!*_test.go'
# → internal/apps/kaname/api/internal_iam/handler.go:205, :230
```

Единственный вход — `InternalIAMService.RegisterResource` / `UnregisterResource` внутреннего
слушателя (`internal_iam_service.proto:185`, `:207`, аннотация `<exempt>` · `INTERNAL_LISTENER`;
`google.api.http` нет). Отказ use-case уходит единственным переводчиком `shared.MapRepoErr`
(`handler.go:211`); `ErrFailedPrecondition` → `codes.FailedPrecondition` с текстом без
приставки (`internal/apps/kaname/shared/errors.go:114-115`). Машинная причина в
`ErrorInfo` — образец `referenceRefusal` (`internal/apps/kaname/shared/reference_refusal.go:68-76`,
домен `refusaldomain.For(refusaldomain.ServiceIAM)`).

### 0.6. Кто переносит объекты между проектами повторной регистрацией

```sh
git grep -n 'rpc Move' -- 'proto/**/*.proto'   # в PRO-Robotech/kacho @fd9f1793e7
# → loadbalancer/v1/network_load_balancer_service.proto:107, target_group_service.proto:103
```

Перенос балансировщика в другой проект (`MoveNetworkLoadBalancerRequest.destination_project_id`)
исполняется снятием регистрации в прежнем проекте и регистрацией в новом той же транзакцией
владельца (`project/kacho` `services/nlb/internal/apps/kacho/api/loadbalancer/move.go:252-278`,
@`fd9f1793e7`). Правило «повторная регистрация в другом проекте отвергается» для ВСЕХ типов
сломало бы законный перенос: регистрация назначения была бы отвергнута после применённого снятия,
и ресурс остался бы без проекции. Отсюда Р1 (правило — для объявленных типов).

### 0.7. Признаки типа в каталоге и манифесте

Признак типа манифестом уже переносится в строку каталога дословно: `publicReadToChildren`
(`internal/manifest/resources.go:470`, проверка значения `:1225-1240`) → `catalog.ResourceRow.PublicReadToChildren`
(`internal/apps/kaname/modulecatalog/rows.go:136`) → колонка `catalog_resource.public_read_to_children`
(`internal/migrations/20261017020000_container_passes_public_read_to_its_children.sql:96`).
Применение — `modulecatalog.Applier.ApplyAll` (`internal/apps/kaname/modulecatalog/applyall.go:176`).
Гейт паритета посева каталога перечисляет колонки строки (`internal/check/catalog_seed_parity.go:745`).
Ключ `permanentProject` идёт тем же путём (Р7).

Манифест registry в фикстурах kaname: `resources[registries].parents: [project]`,
`resources[repositories].parents: [{name: parent, type: registry_registry}]`
(`internal/manifest/testdata/registry.public-read-fixture.yaml:38`, `:76-77`).

### 0.8. Удаление проекта читает только живые регистрации

`projectDeleteQ` (`internal/repo/kaname/pg/project_repo.go:263-285`): охрана непустоты —
`NOT EXISTS` по `resource_mirror … parent_project_id = $1` и по `roles`. Новое хранилище привязок
этой охраной не читается и не должно (Р3, PB-21).

### 0.9. Посылка задачи

«Задача требует приёмку из-за миграции» — **подтверждена**:

```sh
scripts/lane-tier.sh --paths-file <пути: internal/migrations/…sql, internal_iam/register_resource.go, internal_iam_service.proto> --repo kaname
# → tier: R2; acceptance: yes; reason: R2 миграция …; R2 вход и права …; R2 публичный контракт …
```

### 0.10. Читатели проекта на пути решения и писатели цепи

Решение о доступе берёт область объекта **из цепи**, а не из `parent_project_id`:

```sh
git grep -n -E 'FROM kaname\.resource_(scope|parent)_edge' -- 'internal/repo/kaname/pg/relverdict/*.go' ':!*_test.go'
# → expand.go:110, grantarm.go:276, list.go:239, query.go:286, :864, subjects.go:98
git grep -c 'parent_project_id' -- 'internal/repo/kaname/pg/relverdict/*.go' ':!*_test.go'
# → 0 (ни одного файла); контроль — тот же предикат без ':!*_test.go' по каталогу пакета
#   находит 3 файла проб, то есть написание распознаётся
```

`kaname.resource_scope_edge` — представление над `resource_parent_edge` плюс выводимые звенья
(`0001_initial.sql:2581`). Обход области (`query.go:279-291`) рекурсивен: он читает рёбра объекта,
затем рёбра каждого достигнутого предка. Значит, проект, на который действуют выдачи, — это звено
`project` присланной цепи (и звенья цепей предков, названных в ней), а `parent_project_id` читают
охрана удаления проекта (§0.8) и починка пустого проекта из цепи (§0.4). Поле и цепь присылаются
независимо (`register_resource.go:396`, `:398` — оба переносятся дословно); сверки между ними нет —
признак `#982`. Неизменность проекта, выраженная только над полем, решение не держала бы — отсюда
Р4 и Р9 над обоими носителями (решение диспетчера 2026-10-25, §3).

Писатели цепи в не-тестовом дереве:

```sh
git grep -n -E '(INSERT INTO|UPDATE|DELETE FROM)\s+(kaname\.)?resource_parent_edge\b' -- 'internal/**/*.go' 'cmd/**/*.go' ':!*_test.go'
# → resource_mirror/emitter.go:429, :451, :554; scalegrid/seed.go:232, :243;
#   check/census_fixture_producer.go:55 — строковая константа гейта, не оператор
git grep -n 'upsertParentEdges(' -- '*.go' ':!*_test.go'
# → emitter.go:381 (вызов из UpsertTx), :427 (объявление)
```

Пути записи цепи — два: регистрация (`UpsertTx` → `upsertParentEdges`, снятие — `DeleteTx`) и
посевщик сетки замера. Р9 держит инвариант и на них.

---

## §1. Предмет

Модуль регистрирует свои объекты в kaname и снимает регистрацию. Для типов, чей манифест
объявляет `permanentProject: true`, kaname запоминает проект, в котором объект зарегистрирован
впервые, и держит эту привязку **после снятия регистрации**. Проект регистрации несут два
носителя — поле `parentProjectId` и звенья `project` цепи предков, из которой решение о доступе
берёт область (§0.10); сверяются оба. Регистрация того же объекта, у которой любой из носителей
называет другой проект, — пока регистрация действует или после её снятия — отвергается
`FAILED_PRECONDITION` с машинной причиной, и ничего не записывается. Регистрация под тем же
проектом проходит; после снятия она начинается с пустого набора выдач (`#963`). Объекты,
зарегистрированные до объявления, привязываются в момент доставки объявления. Инвариант
«проект строки зеркала и каждое звено `project` цепи зарегистрированного объекта равны проекту
его привязки; привязка не меняется и не удаляется» держит база на каждом пути записи зеркала и
цепи. Для необъявленных типов поведение не меняется.

---

## §2. Что НЕ входит

1. **Метка проекта пространства имён и запрет арендатору её писать** (Д-A2, сторона площадки;
   SRI-112 e приёмки svc-registry). Kaname этой метки не видит
2. **Неверный проект НОВОГО объекта при скомпрометированном модуле** — остаток, названный в
   `#983`. По Д-A2 его держит метка пространства. Здесь — только неизменность проекта уже
   привязанного объекта
3. **Вывод родителя и проекта kaname и закрытая политика записи модуля** — `#982`. Здесь НЕ
   судятся: принадлежность проекта цепи аккаунту цепи (SRI-110 e приёмки svc-registry —
   держатель `#982`); совпадение проекта ребёнка с проектом контейнера, названного в его цепи
   (проект контейнера — носитель регистрации контейнера, а не ребёнка; контейнер объявленного
   типа держит свою привязку сам). Здесь судится: оба носителя проекта
   регистрации самого объекта — `parentProjectId` и каждое звено `project` его цепи — против
   привязки (Р4, Р9). Эта приёмка от `#982` не зависит и садится без него (решение диспетчера
   2026-10-25); после `#982` у ребёнка проект равен проекту родителя
4. **Привязка ребёнка к конкретному родителю.** Перенос ребёнка под другой контейнер ТОГО ЖЕ
   проекта остаётся законным (ND-09 одобренной приёмки
   `nested-rule-reaches-descendants-of-a-named-container.md`). Вопрос В2
5. **Освобождение привязки** (снятие привязки ключа). Пути нет ни у модуля, ни у администратора.
   Предикат снятия пункта: решение диспетчера или владельца, что освобождение нужно, и отдельная
   приёмка его глагола
6. **Кто вправе снять объявление ключа новой редакцией манифеста и как это видно в плане
   публикации** — `#981`. Здесь утверждается только, что снятие объявления существующих привязок
   не снимает (PB-23)
7. **Удаление, перенос проекта между аккаунтами, удаление аккаунта** — поведение не меняется.
   Здесь утверждается только, что привязка снятого объекта удаление проекта не блокирует (PB-21)
8. **Объявление ключа в манифестах модулей `PRO-Robotech/kacho`** (vpc, compute, nlb, storage,
   registry платформы). Не трогаются (порядок «сначала kaname»); перенос балансировщика и
   целевой группы не затронут (§0.6)
9. **Пределы числа привязок** — их нет по решению владельца (Р-В7)
10. **Край, консоль, сквозной набор newman.** Глаголы регистрации живут только на внутреннем
    слушателе без `google.api.http` (§0.5); край их не видит, kaname наружу не публикуется
    (Р-В5). Сквозную проверку держит потребитель: SRI-23 на `F-SR-KANAME` (§5.3)
11. **Правка `docs/specs/*`, сайта документации, README**

---

## §3. Решения

### Решения владельца (не переоткрываются)

Переданы заданием диспетчера 2026-10-25 (те же, что у соседа `delegated-grants-stay-within-the-delegation.md` §3):

- **Р-В1.** Токены и кортежи пишет svc-registry. Привязка — не кортеж и не токен: её заводит
  регистрация, присланная модулем (той же транзакцией), либо объявление `permanentProject`,
  доставленное манифестом модуля (транзакцией применения каталога, Р8); по своей инициативе
  kaname её не заводит;
- **Р-В3.** Kaname только авторизует. Привязка — проверка входа регистрации, а не новая запись
  прав;
- **Р-В7.** Лимиты — в svc-registry. Kaname не ограничивает число привязок;
- **Р-В5.** Kaname наружу не публикуется. Предмет целиком на внутреннем слушателе.

### Решения диспетчера (не переоткрываются)

- **Д-A2** (2026-10-24, дословно из `#983`): «проект Registry берётся только из метки namespace,
  выставленной платформой; арендатор писать её не может; привязка id к проекту в kaname
  сохраняется после снятия регистрации, повторная регистрация с другим проектом отвергается.»
- **Д-983-1** (2026-10-25, по блокирующему COVERAGE круга 1, вариант (а), дословно из задания):
  «сверять и parentProjectId, и ближайший project: цепи предков (resource_parent_edge); сценарий
  с близнецом. Посадка не зависит от #982.» Применено в Р2, Р4, Р9, PB-24, PB-25.

### Решения автора

**Р1. Правило — для объявленных типов.** Привязка заводится и судится для типа, чей ресурс
манифеста объявляет `permanentProject: true`. Для прочих типов регистрация, снятие и
перерегистрация в другом проекте ведут себя как сегодня (§0.2). Довод — §0.6: глобальное правило
ломает перенос балансировщика и целевой группы платформы. **Допущение** до ответа на В1: так и
принято, сценарии написаны под него.

**Р2. Проект регистрации — `parentProjectId` и звено `project` цепи.** Для объявленного типа
оба носителя обязательны; проверка формы синхронна, до транзакции, ничего не записано:
- пустое поле → `INVALID_ARGUMENT` `parent_project_id: required for object type <модельный тип> with a permanent project`,
  `field_violations[0].field = "parent_project_id"`;
- в `parentChain` нет ни одного звена `project:<id>` → `INVALID_ARGUMENT`
  `parent_chain: must name the project for object type <модельный тип> with a permanent project`,
  `field_violations[0].field = "parent_chain"`. Без звена второй носитель проекта сверять с
  привязкой нечем, и правило Р4 по цепи было бы пустым (§0.10).

Поле проверяется первым: при обоих нарушениях отказ называет `parent_project_id`. Регистрация
публикации (`system_class:anonymous` / `user:*` с `v_get`) проектом не адресуется и этим правилом
не судится (`register_resource.go:390-395`).

**Р3. Привязка.** Заводится первой принятой регистрацией объекта объявленного типа (либо
применением объявления к уже зарегистрированному объекту, Р8); проект привязки — проект строки
зеркала этой регистрации (`parentProjectId`). Заводит её уровень записи зеркала, а не use-case
(Р9): регистрация через `resource_mirror.UpsertTx` без use-case тоже заводит привязку (PB-18).
Ключ — `(модельный тип, id)`.
Проект привязки не меняется и привязка не удаляется ни снятием регистрации, ни иным путём.
Ссылки на проект у привязки нет: удаление проекта она не блокирует и при нём не исчезает (PB-21).
Объект, чей проект удалён, повторно зарегистрировать нельзя нигде — это и есть утверждение Д-A2.

**Р4. Отказ.** Регистрация объекта, привязанного к проекту P (привязкой, заведённой раньше, либо
заводимой этой же регистрацией из `parentProjectId`, Р3), у которой `parentProjectId` ≠ P **или**
хотя бы одно звено `project:<id>` цепи называет id ≠ P. Сверяется каждое звено `project`, а не
только ближайшее: обход области читает все рёбра объекта (§0.10), и звено глубже ближайшего
действовало бы так же; ближайшее — частный случай (Д-983-1). Отказ:
`FAILED_PRECONDITION`, `message` = `<object> is bound to another project`, где `<object>` —
значение поля `object` запроса дословно (например `registry_registry:e12813c6a/abc123`).
`ErrorInfo`: `reason = "OBJECT_BOUND_TO_OTHER_PROJECT"`, `domain` — `refusaldomain.For("iam")`
(тот же, что у `REFERENCE_*`), `metadata = {resource_type: <модельный тип>, resource_id: <id>}`.
Проект привязки в ответе не называется ни текстом, ни метаданными. Ответ одинаков, действует ли
регистрация сейчас или снята и каким носителем назван другой проект. Ничего не записывается: ни строки зеркала, ни цепи, ни факта
отношения, ни события перерасчёта. Повтор того же запроса — тот же отказ.

**Р5. Тот же проект.** Регистрация под проектом привязки проходит как сегодня. После снятия она
заводит объект заново, без выдач прежнего (`#963`, URG-02 соседа держит это и здесь не
повторяется; PB-03 утверждает один контроль).

**Р6. Ребёнок.** Ребёнок объявленного типа (репозиторий реестра) привязывается к проекту своей
регистрации, как любой объявленный объект. Перенос под другой контейнер того же проекта проходит
(ND-09); регистрация под контейнером другого проекта отвергается Р4 — и пока регистрация
действует, и после снятия. Проект ребёнка выводит из родителя `#982`; эта приёмка от вывода не
зависит: она сверяет оба носителя проекта регистрации с привязкой. Совпадение проекта
контейнера с проектом ребёнка — `#982` (§2 п.3).

**Р7. Ключ манифеста.** `resources[i].permanentProject` — ключ, объявляемый автором
(`producer` его не порождает, как `publicReadToChildren`). Значение выражается одним способом:
ключ отсутствует либо равен `true`. Загрузка манифеста отвергает:
- `permanentProject: false` — `manifest.ErrPermanentProjectFalse`, координата
  `resources[i].permanentProject`;
- тип, у которого нет пути к проекту: среди `parents` нет якоря `project` и нет типизированного
  указателя — `manifest.ErrPermanentProjectWithoutProject`;
- тип, чей типизированный указатель называет тип того же документа без ключа —
  `manifest.ErrPermanentProjectParentUnbound` (иначе родитель мог бы сменить проект, а ребёнок —
  нет).
Признак переносится в строку каталога ресурсов колонкой (имя — замысел) тем же путём, что
`publicReadToChildren` (§0.7); гейт паритета посева каталога её знает.

**Р8. Объявление действует и на зарегистрированное до него.** Применение каталога, впервые
выставившее признак типу, в той же транзакции привязывает каждый объект этого типа, у которого
есть строка зеркала с непустым проектом, к этому проекту. Объект, снятый до доставки
объявления, привязки не получает (строки нет — проекта взять неоткуда; PB-09 — остаток, названный
вслух). Объект с пустым проектом в зеркале привязывается своей следующей регистрацией (Р2 требует
проект). Объект, у которого до объявления звено `project` цепи расходилось с проектом строки
зеркала, привязывается к проекту строки зеркала; его цепь применение не переписывает (kaname
по своей инициативе цепь не пишет), а следующая принятая запись обязана нести оба носителя,
равные привязке (Р4, Р9) — остаток, названный вслух. Регистрация, конкурирующая с применением
объявления, привязывается в любом порядке коммитов (PB-18).

**Р8а. Снятие объявления привязок не снимает.** Суд Р4 опирается на привязку, а не на текущий
признак типа: редакция без ключа перестаёт заводить привязки новым объектам, а заведённые
продолжают действовать (PB-23).

**Р9. Механизм базы.** Утверждения «проект строки зеркала объекта, у которого есть привязка,
равен проекту привязки», «каждое звено `project` цепи объекта, у которого есть привязка, называет
проект привязки», «проект привязки не меняется», «привязка не удаляется» держат ограничения и
триггеры базы — на каждой записи после заведения привязки, на всех четырёх путях записи зеркала
(§0.4) и обоих путях записи цепи (§0.10), а не проверка в use-case (ban #10); расхождение,
лежавшее до объявления, — остаток Р8. Заведение привязки первой регистрацией и сверка живут на
уровне записи зеркала и цепи (оператор либо триггер той же транзакции; форма — замысел), а не в
`emit`: путь `resource_mirror.UpsertTx` без use-case (PB-18) обязан и заводить, и сверять;
use-case только переводит отказ. Прямой оператор, нарушающий любое из четырёх, отвергается базой
с SQLSTATE класса `23` (нарушение ограничения целостности; конкретный код — замысел) и ничего не
меняет (PB-19, PB-20). Две одновременные первые регистрации одного объекта в разных проектах:
проходит ровно одна (PB-17). Отказ базы — немедленный или пришедший из коммита — use-case
переводит в отказ Р4, а не в `INTERNAL` (`sqlstate-to-grpc`, `no-pgx-leak`,
`api-gotcha-deferrable-fk`).

**Р10. Контракт.** `.proto`: комментарий `RegisterResource` (`internal_iam_service.proto:167-184`)
называет новый отказ (код, причина, когда), комментарий `RegisterResourceRequest.parent_project_id`
(`:404-407`) — обязательность для объявленного типа. Новых полей и номеров нет;
`buf breaking` зелёный.

### Критерии продукта (ban #18)

- **Производительность.** Цена — на регистрацию объявленного типа: +1 поиск по первичному ключу
  привязки и ≤ 1 вставка строки (два текстовых поля и проект, порядка 100 байт); сверка звеньев
  цепи — сравнение с уже прочитанной строкой привязки, 0 обращений сверх того (звеньев у
  объекта ≤ 4, предел `resource_parent_edge_depth_bounded`); на регистрацию
  необъявленного типа — 0 обращений к привязкам сверх чтения признака той же строки каталога,
  которую оператор вставки уже читает (`emitter.go:188-200`). Объём хранилища — число различных
  объектов объявленных типов, когда-либо зарегистрированных. Замер — DoD S1 п.8;
- **Безопасность.** Поверхность не расширяется: новых методов, слушателей и полей нет; новый
  отказ не раскрывает проект привязки (Р4). Закрывается обход неизменности проекта снятием и
  повторной регистрацией — по обоим носителям проекта регистрации объекта: полю, которое читают
  охрана удаления проекта и починка зеркала, и звеньям `project` цепи, из которой область берёт
  решение о доступе (§0.10; Р4, Р9; PB-24 — смена проекта одной цепью при совпавшем поле).
  Закрытие не зависит от посадки `#982`. Остатки названы и закрытием не объявлены: неверный
  проект нового объекта (§2 п.2); согласованность ребёнка с проектом контейнера и проекта с
  аккаунтом цепи (§2 п.3, `#982`);
- **Инновационность.** Новое свойство: модуль объявляет неизменность проекта своего типа
  данными манифеста, и её держит база служба доступа, а не модуль;
- **Узнаваемость относительно рынка.** Аналога «привязка идентификатора к проекту, переживающая
  удаление объекта» нет: обычно идентификатор после удаления свободен. Наш вариант лучше для
  ключей, выводимых из внешнего имени (ключ реестра — из пространства имён), где повтор имени —
  штатный, а не исключение;
- **Перспективность.** Шаг обратим для новых объектов (снятие ключа, Р8а) и аддитивен в
  контракте; внешне адресуемая координата (id) не меняется;
- **Благо продукта и производственность.** Режимов «только для стенда» нет; инвариант на всех
  путях записи (Р9).

---

## §4. Сценарии

### 4.1. Мир проб

**Мир ПП** — `newPPWorld` (заказан, `internal/apps/kaname/api/access_binding/`) поверх мира П6
`newPCRWorld` (`public_container_read_world_integration_test.go:99`), который поверх
`newSCWorld` (`system_class_world_integration_test.go:88`). Уже даёт:

- аккаунт acc-A (владелец usr-A), проект prj-A, человек usr-B; аккаунт acc-B (владелец usr-C)
  (`system_class_world_integration_test.go:121-127`);
- манифест registry прежней редакции, доставленный путём старта (`deliverPriorEdition`, `:260`) —
  ключа `permanentProject` в нём нет;
- реестры X = `reg00000000000000001`, Y = `reg00000000000000002` в prj-A и их репозитории
  `X/app`, `Y/app` (`registerRegistry` `:178`, `registerRepository` `:193`);
- роль аккаунта rol-reg-get `{module: registry, resources: [registries], verbs: [get]}` (`seedRole`, `:151`);
- вопрос о доступе `ask` (`:324`), выдача `createDone` (`system_class_world_integration_test.go:212`).

Дополнения (каждое — существующим глаголом или посевом мира):

- **проекты** prj-A2 в acc-A и prj-C в acc-B — `seedProjectInAccount`
  (`testhelpers_assignable_test.go:125`);
- **доставка D-K** — новая редакция манифеста registry, фикстура
  `internal/manifest/testdata/registry.permanent-project-fixture.yaml` (заказана): фикстура П6
  новой редакции (`registry.public-read-fixture.yaml`) плюс `permanentProject: true` на ресурсах
  `registries` и `repositories`. Доставка — `manifest.Load` и `applyDelivered` (`:272`). Варианты
  фикстуры для PB-22 и PB-23 — правкой одного ключа того же документа в пробе;
- **регистрация** `regIn(obj, prj, acc)` — запрос `registerRegistry` (`:178`) с проектом и
  аккаунтом параметрами (вариант заказан):

  ```json
  {"subjectId":"project:<prj>","relation":"project","object":"registry_registry:<id>",
   "parentProjectId":"<prj>","parentAccountId":"<acc>",
   "parentChain":["project:<prj>","account:<acc>"],"sourceVersion":"<следующая версия>"}
  ```

  и вторым кортежем `{"subjectId":"user:<usr-A>","relation":"owner",…}` с теми же полями
  области. **Ребёнок** `regRepoIn(registry, name, prj, acc)` — запрос `registerRepository`
  (`:193`): `{"subjectId":"registry_registry:<registry>","relation":"parent","object":"registry_repository:<registry>/<name>",
  "parentProjectId":"<prj>","parentAccountId":"<acc>","parentChain":["registry_registry:<registry>","project:<prj>","account:<acc>"],…}`;
- **снятие** `unreg(obj, prj)` — запрос `withdrawX` мира У (`unregister_reregister_world_integration_test.go:87`)
  с объектом параметром: `{"subjectId":"project:<prj>","relation":"project","object":"<obj>","sourceVersion":"<следующая версия>"}`;
  у ребёнка — кортеж `parent`;
- **ключи** (форма ключа потребителя, с `/`): Q = `e12813c6a/abc123`, Q2 = `e12813c6a/q2`,
  Q3 = `e12813c6a/q3`, Z = `93124b19b/abc123`, K<n> = `race<n>/k` (n = 1…40). До «Когда»
  каждый из них не регистрировался, если «Дано» не говорит иного;
- **версии** — монотонные у каждого намерения (`nextVersion` мира У, `:79`);
- **чтения** — SQL пробы на базе мира: строка зеркала
  `SELECT parent_project_id, labels, source_version FROM kaname.resource_mirror WHERE object_type = 'registry.registries' AND object_id = $1`
  (у ребёнка — `registry.repositories`); цепь — `SELECT parent_type||':'||parent_id FROM kaname.resource_parent_edge WHERE object_type = $1 AND object_id = $2 ORDER BY depth`
  (образец `readParentChain`, `internal/repo/kaname/pg/resource_mirror/parent_edge_integration_test.go:46`);
  факты — `SELECT count(*) FROM kaname.relation_fact WHERE object_type = $1 AND object_id = $2`;
  события перерасчёта — `SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type = $1 AND object_id = $2`.
  **Снимок С(obj)** — четвёрка этих чтений.

**Тело отказа Р4** (ссылка «Р4-отказ(obj)» ниже): `FAILED_PRECONDITION`; `message` =
`<obj> is bound to another project`; ровно одна деталь `ErrorInfo` с `reason =
"OBJECT_BOUND_TO_OTHER_PROJECT"`, `domain = refusaldomain.For("iam")`,
`metadata = {"resource_type":"<модельный тип>","resource_id":"<id>"}`; ни `message`, ни
`metadata` не содержат строки проекта привязки.

### Группа A — объявленный тип: тройка задачи (Р3, Р4, Р5)

#### PB-01 · регистрация в другом проекте при действующей регистрации отвергается

**Given** мир ПП после D-K; `regIn(registry_registry:Q, prj-A, acc-A)` прошла; снимок С(Q) запомнен
**When** `regIn(registry_registry:Q, prj-C, acc-B)` с `labels = {"env":"prod"}`, версия новее
**Then** Р4-отказ(`registry_registry:e12813c6a/abc123`), синхронно
**And** С(Q) равен запомненному: `parent_project_id = prj-A`, цепь `[project:prj-A, account:acc-A]`,
число фактов и событий перерасчёта прежнее
**And** повтор того же запроса — тот же отказ, С(Q) прежний
**And** близнец — PB-04 (отличается проектом).

Красна @`5c6b7c078`: регистрация применяется, проект становится prj-C (§0.2).

#### PB-02 · регистрация в другом проекте после снятия отвергается

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)`, затем `unreg(registry_registry:Q, prj-A)` — оба OK;
строки зеркала у Q нет
**When** `regIn(registry_registry:Q, prj-C, acc-B)`
**Then** Р4-отказ(`registry_registry:e12813c6a/abc123`) — побайтово тот же `message` и та же
деталь, что в PB-01
**And** строки зеркала у Q нет, цепи нет, фактов `registry_registry`/Q — 0, событий перерасчёта не прибавилось
**And** близнец — PB-03 (отличается проектом).

Красна @`5c6b7c078`: регистрация проходит (§0.3).

#### PB-03 · регистрация в том же проекте после снятия проходит и начинается без выдач

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)`; usr-A выдал rol-reg-get человеку usr-B на prj-A
с целью `{"resources":{"resources":[{"type":"registry.registries","id":"e12813c6a/abc123"}]}}`
(`createDone`), `ask(user:<usr-B>, v_get, registry_registry, Q)` → истина; затем `unreg(Q, prj-A)`
**When** `regIn(registry_registry:Q, prj-A, acc-A)`
**Then** gRPC OK (оба кортежа)
**And** строка зеркала: `parent_project_id = prj-A`; цепь `[project:prj-A, account:acc-A]`
**And** `ask(user:<usr-B>, v_get, registry_registry, Q)` → ложь (выдача снята снятием регистрации, `#963`)
**And** близнец PB-02: отличается только проектом.

#### PB-04 · регистрация в том же проекте при действующей регистрации проходит

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)` прошла
**When** регистрация Q с `parentProjectId = prj-A`, `labels = {"env":"prod"}`, версия новее
**Then** gRPC OK; строка зеркала `parent_project_id = prj-A`, `labels = {"env":"prod"}`, версия — новая
**And** близнец PB-01: отличается только проектом.

#### PB-05 · другой проект того же аккаунта — тоже другой проект

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)`, `unreg(Q, prj-A)`
**When** `regIn(registry_registry:Q, prj-A2, acc-A)`
**Then** Р4-отказ(`registry_registry:e12813c6a/abc123`); строки зеркала у Q нет
**And** близнец — PB-03 (отличается проектом; аккаунт тот же).

### Группа A2 — второй носитель проекта: цепь (Р2, Р4, Д-983-1)

#### PB-24 · другой проект в цепи при совпавшем поле отвергается

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)` прошла; снимок С(Q) запомнен
| пример | перед «Когда» | запрос «Когда» (кортеж `project`, `parentAccountId` — из цепи) |
|---|---|---|
| a | ничего (регистрация действует) | регистрация Q: `"parentProjectId":"<prj-A>"`, `"parentChain":["project:<prj-C>","account:<acc-B>"]`, `labels = {"env":"prod"}`, версия новее |
| b | `unreg(Q, prj-A)` | тот же запрос, что a |
| c | ничего; Q2 не регистрировался | первая регистрация Q2: `"parentProjectId":"<prj-A>"`, `"parentChain":["project:<prj-C>","account:<acc-B>"]` |
| d | ничего | регистрация Q: `"parentProjectId":"<prj-A>"`, `"parentChain":["project:<prj-A>","project:<prj-C>","account:<acc-A>"]` — ближайшее звено совпадает, следующее нет |
| e | ничего | тот же запрос, что a, с `"parentChain":["project:<prj-A>","account:<acc-A>"]` |

**When** запрос из таблицы
**Then** a), b), c), d) — Р4-отказ (a, b, d — `registry_registry:e12813c6a/abc123`; c —
`registry_registry:e12813c6a/q2`), побайтово та же форма `message` и детали, что в PB-01
**And** a), d) — С(Q) равен запомненному: `parent_project_id = prj-A`, цепь
`[project:prj-A, account:acc-A]`, число фактов и событий перерасчёта прежнее; b) строки зеркала
и цепи у Q нет; c) строки зеркала, цепи и фактов у Q2 нет, привязки не заведено — последующая
`regIn(registry_registry:Q2, prj-C, acc-B)` проходит
**And** e) gRPC OK; строка зеркала Q — `prj-A`, `labels = {"env":"prod"}`; цепь `[project:prj-A, account:acc-A]`
**And** близнецы, каждый отличается одним фактом: e — a (проект в цепи); e — d (звена
`project:prj-C` нет); PB-03 — b (проект в цепи); для c — последующая `regIn(Q2, prj-C, acc-B)`
(проект в поле).

Красна @`5c6b7c078`: a, d применяются (§0.2), b, c проходят (§0.3) — у цепи сверки нет (§0.10).

#### PB-25 · объявленный тип без звена `project` в цепи отвергается

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)` прошла; объект
`registry_repository:e12813c6a/abc123/team/app` и ключ Q2 не регистрировались
| пример | мир | запрос «Когда» |
|---|---|---|
| a | после D-K | первая регистрация Q2: `"parentProjectId":"<prj-A>"`, `"parentChain":["account:<acc-A>"]` |
| b | после D-K | регистрация ребёнка `{"subjectId":"registry_registry:e12813c6a/abc123","relation":"parent","object":"registry_repository:e12813c6a/abc123/team/app","parentProjectId":"<prj-A>","parentAccountId":"<acc-A>","parentChain":["registry_registry:e12813c6a/abc123"],…}` |
| c | после D-K | запрос a с `"parentProjectId":""` |
| d | **без** D-K | запрос a |
| e | после D-K | запрос b с `"parentChain":["registry_registry:e12813c6a/abc123","project:<prj-A>","account:<acc-A>"]` |

**When** запрос из таблицы
**Then** a), b) — `INVALID_ARGUMENT`, `message` =
`parent_chain: must name the project for object type <тип> with a permanent project` (a —
`registry_registry`, b — `registry_repository`); `BadRequest.field_violations[0].field = "parent_chain"`,
`description` = `message`; строки зеркала, цепи и фактов у объекта нет; после a привязки не
заведено — последующая `regIn(registry_registry:Q2, prj-C, acc-B)` проходит
**And** c) — отказ PB-12: `field_violations[0].field = "parent_project_id"` (поле проверяется первым, Р2)
**And** d) gRPC OK, строка зеркала Q2 с `parent_project_id = prj-A`, цепь `[account:acc-A]` (как сегодня)
**And** e) gRPC OK, строка зеркала ребёнка — `prj-A`, цепь `[registry_registry:e12813c6a/abc123, project:prj-A, account:acc-A]`
**And** близнецы, каждый отличается одним фактом: d — a (объявление); e — b (звено `project` в цепи).

Красна @`5c6b7c078`: a, b проходят — формы цепи для объявленного типа нет.

### Группа B — необъявленный тип: поведение прежнее (Р1)

#### PB-06 · без объявления перерегистрация в другом проекте после снятия проходит

**Given** мир ПП **без** D-K (действует прежняя редакция, ключа нет); `regIn(Q, prj-A, acc-A)`, `unreg(Q, prj-A)`
**When** `regIn(registry_registry:Q, prj-C, acc-B)`
**Then** gRPC OK; строка зеркала `parent_project_id = prj-C`; цепь `[project:prj-C, account:acc-B]`
**And** близнец PB-02: отличается одним фактом — объявление не доставлено.

#### PB-07 · без объявления регистрация в другом проекте заменяет проект

**Given** мир ПП без D-K; `regIn(Q, prj-A, acc-A)`
**When** `regIn(registry_registry:Q, prj-C, acc-B)` с `labels = {"env":"prod"}`, версия новее (тот же запрос, что в PB-01)
**Then** gRPC OK; `parent_project_id = prj-C`; цепь `[project:prj-C, account:acc-B]` (как сегодня, §0.2)
**And** близнец PB-01: отличается одним фактом — объявление не доставлено.

### Группа C — объявление и уже зарегистрированное (Р8)

#### PB-08 · объект, зарегистрированный до объявления, привязывается доставкой

**Given** мир ПП: X зарегистрирован в prj-A до D-K (мир); затем D-K доставлена
**When** a) `regIn(registry_registry:X, prj-C, acc-B)`; b) `unreg(X, prj-A)`, затем `regIn(registry_registry:X, prj-C, acc-B)`
**Then** a) и b) — Р4-отказ(`registry_registry:reg00000000000000001`); в a) строка зеркала X — prj-A, в b) — строки нет
**And** близнец — PB-09 (отличается одним фактом: был ли X зарегистрирован в момент доставки).

#### PB-09 · объект, снятый до объявления, не привязан (остаток Р8)

**Given** мир ПП: `unreg(X, prj-A)` **до** D-K; затем D-K доставлена
**When** `regIn(registry_registry:X, prj-C, acc-B)`
**Then** gRPC OK; `parent_project_id = prj-C`
**And** повторная регистрация X в prj-A после этого — Р4-отказ (привязка заведена этой
регистрацией, PB-01 для нового проекта)
**And** близнец PB-08 b.

### Группа D — ребёнок (Р6)

#### PB-10 · ребёнок под контейнером другого проекта отвергается

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)`, `regIn(Z, prj-C, acc-B)`;
`regRepoIn(Q, team/app, prj-A, acc-A)` прошла — объект `registry_repository:e12813c6a/abc123/team/app`
| пример | перед «Когда» |
|---|---|
| a | ничего (регистрация действует) |
| b | `unreg(registry_repository:e12813c6a/abc123/team/app, …)` — кортеж `parent` под Q |

**When** регистрация того же объекта: `{"subjectId":"registry_registry:93124b19b/abc123","relation":"parent","object":"registry_repository:e12813c6a/abc123/team/app","parentProjectId":"<prj-C>","parentAccountId":"<acc-B>","parentChain":["registry_registry:93124b19b/abc123","project:<prj-C>","account:<acc-B>"],"sourceVersion":"<новее>"}`
**Then** a), b) — Р4-отказ(`registry_repository:e12813c6a/abc123/team/app`), `metadata.resource_type = "registry_repository"`
**And** a) строка зеркала ребёнка — prj-A, цепь `[registry_registry:e12813c6a/abc123, project:prj-A, account:acc-A]`; b) строки нет
**And** близнец — PB-11 (отличается контейнером и его проектом).

#### PB-11 · ребёнок под другим контейнером того же проекта проходит (ND-09 сохранён)

**Given** мир ПП после D-K (Y в prj-A привязан доставкой, PB-08); `regIn(Q, prj-A, acc-A)`;
`regRepoIn(Q, team/app, prj-A, acc-A)`
| пример | перед «Когда» |
|---|---|
| a | ничего |
| b | снятие ребёнка, как PB-10 b |

**When** регистрация того же объекта с `"subjectId":"registry_registry:reg00000000000000002"`,
`parentProjectId = prj-A`, цепь `["registry_registry:reg00000000000000002","project:<prj-A>","account:<acc-A>"]`, версия новее
**Then** gRPC OK; строка зеркала ребёнка — prj-A; цепь `[registry_registry:reg00000000000000002, project:prj-A, account:acc-A]`
**And** близнец PB-10: отличается контейнером (Y в prj-A против Z в prj-C).

### Группа E — форма регистрации объявленного типа (Р2)

#### PB-12 · регистрация объявленного типа без проекта отвергается

**Given** мир ПП после D-K
**When** `regIn`-запрос для Q с `"parentProjectId":""` (цепь `["project:<prj-A>","account:<acc-A>"]`, прочее как обычно)
**Then** `INVALID_ARGUMENT`, `message` = `parent_project_id: required for object type registry_registry with a permanent project`;
`BadRequest.field_violations[0].field = "parent_project_id"`, `description` = `message`
**And** строки зеркала у Q нет; цепи и фактов нет; привязки не заведено — последующая
`regIn(Q, prj-C, acc-B)` проходит
**And** близнецы — PB-13 a и b.

#### PB-13 · близнецы PB-12

**Given** a) мир ПП **без** D-K; b) мир ПП после D-K и `regIn(Q, prj-A, acc-A)`
**When** a) тот же запрос, что в PB-12; b) публикация Q:
`{"subjectId":"system_class:anonymous","relation":"v_get","object":"registry_registry:e12813c6a/abc123","sourceVersion":"<новее>"}` (полей области нет)
**Then** a) gRPC OK, строка зеркала Q с `parent_project_id = ''` (как сегодня); b) gRPC OK,
`ask(system_class:anonymous, v_get, registry_registry, Q)` → истина в окне материализации (`pollAsk`, `:353`)
**And** a отличается от PB-12 объявлением; b — видом регистрации (публикация не адресуется проектом).

### Группа F — конкуренция и механизм базы (Р8, Р9)

#### PB-17 · две одновременные первые регистрации в разных проектах — проходит ровно одна

**Given** мир ПП после D-K; ключи K1…K20 не регистрировались
**When** для каждого Kn — две горутины одновременно (общий барьер старта): `regIn(registry_registry:Kn, prj-A, acc-A)` и `regIn(registry_registry:Kn, prj-C, acc-B)` (только кортеж `project`)
**Then** для каждого Kn ровно один вызов — OK, второй — Р4-отказ(`registry_registry:Kn`); ни одного
`INTERNAL` и ни одного `UNAVAILABLE`
**And** строка зеркала Kn несёт проект выигравшего вызова; регистрация Kn в проекте проигравшего — Р4-отказ, в проекте выигравшего — OK
**And** близнец: ключи K21…K40 тем же способом, но обе горутины — в prj-A: оба вызова каждой
пары OK, строка зеркала — prj-A (отличается одним фактом — проект второго вызова).

#### PB-18 · регистрация во время доставки объявления привязывается в любом порядке

**Given** база мира с прежней редакцией registry; оператор объявления признака типа вместе с
привязкой зарегистрированного (Р8) исполняется в транзакции T1, регистрация нового объекта Q3 в
prj-A через `resource_mirror.UpsertTx` — в транзакции T2 (порт транзакционного вызова оператора
объявления заказан; держатель — интеграционная проба пакета `resource_mirror` или каталога)
| пример | порядок |
|---|---|
| a | T1 исполнил оператор и держит транзакцию; T2 стартует; коммит T1, затем T2 |
| b | T2 исполнил вставку и держит транзакцию; T1 стартует; коммит T2, затем T1 |

**When** обе транзакции закоммичены
**Then** a), b): после коммитов регистрация Q3 в prj-C — Р4-отказ; в prj-A — OK
**And** обе транзакции закоммичены без ошибки (ожидание замка допустимо)
**And** близнец — PB-09 (объект, которого в момент объявления нет, не привязан): там регистрация
после объявления заводит привязку сама.

#### PB-19 · прямой оператор не меняет проект привязанного объекта

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)` (Q привязан); объект необъявленного типа —
строка зеркала `vpc.network`/`net00000000000000099` с `parent_project_id = prj-A` и цепью
`[project:prj-A, account:acc-A]`, положенная `resource_mirror.UpsertTx` при доставленном
манифесте vpc (`internal/manifest/testdata/vpc.resources-fixture.yaml`, путь `applyDelivered`)
**When** проба исполняет на базе мира прямой оператор
a) `UPDATE kaname.resource_mirror SET parent_project_id = '<prj-C>' WHERE object_type = 'registry.registries' AND object_id = 'e12813c6a/abc123'`;
b) тот же оператор для `vpc.network`/`net00000000000000099`;
c) `UPDATE kaname.resource_parent_edge SET parent_id = '<prj-C>' WHERE object_type = 'registry_registry' AND object_id = 'e12813c6a/abc123' AND parent_type = 'project'`;
d) тот же оператор для `vpc_network`/`net00000000000000099`
**Then** a), c) — отказ базы с SQLSTATE класса `23`; строка зеркала Q прежняя (`prj-A`), цепь Q
прежняя (`[project:prj-A, account:acc-A]`)
**And** b), d) — оператор принят; b) строка несёт `prj-C`; d) звено `project` цепи — `prj-C`
**And** b — близнец a, d — близнец c: отличаются одним фактом — у объекта нет привязки.

#### PB-20 · привязку нельзя изменить и удалить прямым оператором

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)`
**When** проба исполняет на базе мира прямой оператор хранилища привязок (имя таблицы — замысел):
a) смена проекта привязки Q на prj-C; b) удаление привязки Q; c) `TRUNCATE` хранилища привязок
**Then** a), b), c) — отказ базы с SQLSTATE класса `23`; у c — отказ триггера `BEFORE TRUNCATE`
хранилища привязок (проба исполняется под владельцем схемы, поэтому исход — триггер, а не
привилегия); привязка прежняя: `regIn(Q, prj-C, acc-B)` — Р4-отказ
**And** близнец — PB-02 (снятие регистрации удаляет строку зеркала и принимается; привязка остаётся).

### Группа G — следствия

#### PB-21 · привязка снятого объекта удаление проекта не блокирует

**Given** мир ПП после D-K; `regIn(Q2, prj-A2, acc-A)`, `unreg(Q2, prj-A2)`; других регистраций и
ролей у prj-A2 нет
| пример | перед «Когда» |
|---|---|
| a | ничего |
| b | `regIn(Q3, prj-A2, acc-A)` — регистрация действует |

**When** удаление проекта prj-A2 оператором писателя: `w.ProjectsW().Delete(ctx, prj-A2)` и
коммит (`internal/repo/kaname/pg/project_repo.go:306`, образец `deleteProject`,
`project_delete_nonempty_integration_test.go:64`)
**Then** a) `Delete` вернул `nil`, коммит прошёл: строки `projects` с id prj-A2 нет; затем
`regIn(Q2, prj-A, acc-A)` — Р4-отказ (привязка пережила проект)
**And** b) `Delete` вернул ошибку уровня писателя (gRPC-кода на этом уровне нет):
`errors.Is(err, iamerr.ErrReferenceInUse)`; `iamerr.StripSentinel(err)` =
`Project <prj-A2> is not empty (registry.registries: 1)` (`project_repo.go:328`, форма — как у
`IAM-PNE-1-10`, `project_delete_nonempty_integration_test.go:145`); проект на месте
**And** b — близнец a: отличается действующей регистрацией.

#### PB-22 · загрузка манифеста проверяет ключ

**Given** фикстура D-K; варианты — правка одного ключа документа в пробе
| пример | правка | исход `manifest.Load` |
|---|---|---|
| a | `registries.permanentProject: false` | `errors.Is(err, manifest.ErrPermanentProjectFalse)`, координата `resources[0].permanentProject` |
| b | у `registries` `parents: [account]` (якоря `project` нет) | `manifest.ErrPermanentProjectWithoutProject`, координата `resources[0].permanentProject` |
| c | ключ снят у `registries`, оставлен у `repositories` | `manifest.ErrPermanentProjectParentUnbound`, координата `resources[1].permanentProject` |
| d | без правки | загружен; у обеих строк каталога признак выставлен после `applyDelivered` |

**When** загрузка
**Then** как в таблице; при отказе ни одной строки каталога не применено (каталог прежний)
**And** d — близнец a, b, c (одна правка).

#### PB-23 · снятие объявления заведённых привязок не снимает

**Given** мир ПП после D-K; `regIn(Q, prj-A, acc-A)`, `unreg(Q, prj-A)`; затем доставлена редакция
D-K без ключа на обоих ресурсах (вариант фикстуры, путь `applyDelivered`)
**When** a) `regIn(registry_registry:Q, prj-C, acc-B)`; b) `regIn(registry_registry:Q2, prj-A, acc-A)`,
`unreg(Q2, prj-A)`, `regIn(registry_registry:Q2, prj-C, acc-B)`
**Then** a) Р4-отказ(`registry_registry:e12813c6a/abc123`)
**And** b) все три вызова OK; строка зеркала Q2 — prj-C
**And** b — близнец a: отличается одним фактом — объект зарегистрирован после снятия объявления.

---

## §5. Сценарий → производитель

### 5.1. Таблица

Производитель «заказан» — его заводит реализация. Держатель — интеграционная проба
`TestPermanentProject_PB<NN>_…` (testcontainers) в `internal/apps/kaname/api/access_binding/`,
PB-18 и PB-19, PB-20 — там же либо в `internal/repo/kaname/pg/resource_mirror/`, PB-22 — в
`internal/manifest/`.

| ID | что производит «Тогда» | держатель: строка утверждения | чем измерено |
|---|---|---|---|
| PB-01 | заказан: сверка проекта регистрации с привязкой на уровне записи зеркала и цепи (оператор либо триггер транзакции `UpsertTx`, `emitter.go:277`, Р9), не в `emit`; перевод отказа базы — новый отказ рядом с `referenceRefusal` (`reference_refusal.go:68`) через `MapRepoErr` (`handler.go:211`) | `status.Code == FailedPrecondition`; `message == "registry_registry:e12813c6a/abc123 is bound to another project"`; `ErrorInfo.Reason == "OBJECT_BOUND_TO_OTHER_PROJECT"`; С(Q) до == после | статус и детали gRPC, SQL |
| PB-02 | заказан: привязка переживает `DeleteTx` (`emitter.go:526`) — хранилище вне строки зеркала | тот же код, `message`, деталь; `count(resource_mirror) == 0`, `count(relation_fact) == 0` у Q | статус, SQL |
| PB-03 | есть: путь регистрации (`Register`, `:377`) при совпавшем проекте; снятие выдач — `#963` (`WithdrawTx`, `:905`) | `err == nil`; `parent_project_id == prj-A`; `ask(usr-B, v_get, Q) == false` | gRPC, SQL, Check |
| PB-04 | есть: `StmtInsertOrSupersede` (`emitter.go:188`) при совпавшем проекте | `err == nil`; `labels == {"env":"prod"}` | gRPC, SQL |
| PB-05 | заказан: тот же, что PB-01 (сверка по проекту, не по аккаунту) | Р4-отказ при `prj-A2` | статус |
| PB-24 | заказан: тот же уровень записи, что PB-01, сверяет каждое звено `project` цепи (вставка рёбер `upsertParentEdges`, `emitter.go:451`) с привязкой — заведённой ранее либо этой же регистрацией | a–d: `status.Code == FailedPrecondition`, `ErrorInfo.Reason == "OBJECT_BOUND_TO_OTHER_PROJECT"`, `message` дословно; a, d: С(Q) до == после; b, c: `count(resource_mirror) == 0`; c: затем `regIn(Q2, prj-C)` `err == nil`; e: `err == nil`, `labels == {"env":"prod"}` | статус и детали gRPC, SQL |
| PB-25 | заказан: проверка формы цепи до транзакции (рядом с проверкой Р2 PB-12, `validateTuple`, `register_resource.go:719`) через `shared.InvalidArg` (`errdetails.go:21`) | a, b: `Code == InvalidArgument`, `message` дословно, `field_violations[0].field == "parent_chain"`, `count(resource_mirror) == 0`; c: `field == "parent_project_id"`; d, e: `err == nil`, цепь как в «Тогда» | статус, детали `BadRequest`, SQL |
| PB-06 | есть: путь `Register` без привязки (тип не объявлен) | `err == nil`; `parent_project_id == prj-C` | gRPC, SQL |
| PB-07 | есть: `StmtInsertOrSupersede` (`emitter.go:201-207`) | `parent_project_id == prj-C`; цепь `[project:prj-C, account:acc-B]` | SQL |
| PB-08 | заказан: привязка зарегистрированных объектов при применении признака (`modulecatalog.Applier.ApplyAll`, `applyall.go:176`, та же транзакция) | Р4-отказ в a и b; a: `parent_project_id == prj-A` | статус, SQL |
| PB-09 | заказан: тот же оператор привязки не находит строки снятого объекта; привязку заводит регистрация (PB-01) | `err == nil`, `prj-C`; затем Р4-отказ в prj-A | gRPC, SQL |
| PB-10 | заказан: тот же, что PB-01, на типе `registry_repository` | Р4-отказ; `metadata["resource_type"] == "registry_repository"`; a: цепь прежняя | статус, детали, SQL |
| PB-11 | есть: замена цепи при совпавшем проекте (`upsertParentEdges`, `emitter.go:427`; ND-09 `parent_edge_move_integration_test.go`) | `err == nil`; цепь `[registry_registry:reg…02, project:prj-A, account:acc-A]` | gRPC, SQL |
| PB-12 | заказан: проверка формы до транзакции (рядом с `validateTuple`, `register_resource.go:719`); отказ с полем — `shared.InvalidArg` | `Code == InvalidArgument`; `message` дословно; `field_violations[0].field == "parent_project_id"`; `count(resource_mirror) == 0` | статус, детали `BadRequest`, SQL |
| PB-13 | есть: a — путь `Register` необъявленного типа; b — путь публикации `publish` (`register_resource.go:390-395`, `:790`) | a: `parent_project_id == ''`; b: `pollAsk(anonymous, v_get, Q, true)` | gRPC, SQL, Check |
| PB-17 | заказан: первичный ключ хранилища привязок; заведение и сверка на уровне записи зеркала одним оператором либо триггером (без чтения-и-действия, ban #10) | по каждому Kn `ok == 1 && refused == 1`, `internal == 0`, `unavailable == 0` | статус, SQL |
| PB-18 | заказан: замок строки каталога между объявлением и вставкой зеркала; привязку в T2 заводит уровень записи зеркала, а не `emit` (Р8, Р9) | по a и b: Р4-отказ в prj-C, OK в prj-A | статус |
| PB-19 | заказан: ограничение или триггер базы на `resource_mirror` и `resource_parent_edge` для объекта с привязкой | a, c: `pgconn.PgError.Code[:2] == "23"`, `parent_project_id == prj-A`, цепь прежняя; b: `err == nil`, `prj-C`; d: `err == nil`, звено `project` — `prj-C` | SQL |
| PB-20 | заказан: ограничения и триггеры хранилища привязок (неизменность проекта, запрет удаления, триггер `BEFORE TRUNCATE`) | `Code[:2] == "23"` у a, b, c; затем Р4-отказ | SQL, статус |
| PB-21 | есть: `projectDeleteQ` (`project_repo.go:263`) хранилище привязок не читает; отказ непустоты — `projectWriter.Delete` (`:328`) | a: `err == nil`, `projectExists == false`, затем Р4-отказ; b: `errors.Is(err, iamerr.ErrReferenceInUse)`, `StripSentinel(err) == "Project <prj-A2> is not empty (registry.registries: 1)"`, `projectExists == true` | ошибка писателя, SQL, статус |
| PB-22 | заказан: проверка ключа в загрузчике (рядом с `validateResourcePublicRead`, `resources.go:1225`) | `errors.Is` по каждой строке; координата; d: признак у двух строк каталога | ошибка загрузчика, SQL |
| PB-23 | заказан: суд Р4 читает привязку, а не текущий признак типа (Р8а) | a: Р4-отказ; b: три `err == nil`, `prj-C` | статус, SQL |

Номера PB-14…PB-16 не заняты (сведены в Then PB-01, PB-02); PB-24, PB-25 добавлены редакцией 2.

### 5.2. Дано → писатель

| что в «Дано» | столбец | писатель, строка |
|---|---|---|
| аккаунты, проект prj-A, люди мира | `accounts`, `projects`, `users` | посев мира, `system_class_world_integration_test.go:121-127` |
| prj-A2 в acc-A, prj-C в acc-B | `projects` | `seedProjectInAccount`, `testhelpers_assignable_test.go:125` |
| X, Y, `X/app`, `Y/app` в prj-A | `resource_mirror`, `resource_parent_edge`, `relation_fact` | `InternalIAMService.RegisterResource` (use-case мира), `public_container_read_world_integration_test.go:178`, `:193` → `emitter.go:197`, `:451` |
| Q, Q2, Q3, Z, Kn в названном проекте; ребёнок `…/team/app` | те же | тот же глагол с проектом параметром (`regIn`, `regRepoIn` — варианты заказаны) |
| запросы PB-24, PB-25 с полем и цепью порознь (в том числе цепь без звена `project` и с двумя звеньями `project`) | — (отвергаются; e и d — те же столбцы, что выше) | тот же глагол, тело запроса пробы; форму цепи сегодня не проверяет никто (§0.10), две вершины `project` на глубинах 1 и 2 допускает ключ `resource_parent_edge_pkey (object_type, object_id, depth)` (`0001_initial.sql:4273`) |
| снятие регистрации | удаление строк зеркала и цепи | `UnregisterResource` (`unreg` — вариант `withdrawX`, `unregister_reregister_world_integration_test.go:87`) → `emitter.go:531`, `:554` |
| прежняя редакция registry | `catalog_resource` | `deliverPriorEdition`, `:260` |
| D-K и её варианты | `catalog_resource` + колонка признака; привязки зарегистрированных | `manifest.Load` + `applyDelivered` (`:272`) → `modulecatalog.Applier.ApplyAll` (`applyall.go:176`); фикстура и колонка заказаны |
| манифест vpc и `vpc.network`/`net…99` с цепью `[project:prj-A, account:acc-A]` (PB-19 b, d) | `catalog_resource`, `resource_mirror`, `resource_parent_edge` | `vpc.resources-fixture.yaml` (ресурс `network`, `objectType: vpc_network`) + `applyDelivered`; `resource_mirror.UpsertTx` (`emitter.go:277`) → `upsertParentEdges` (`:381`) |
| выдача usr-B на Q (PB-03) | `access_bindings` | `AccessBindingService.Create` от usr-A (`createDone`, `system_class_world_integration_test.go:212`) |
| T1/T2 (PB-18) | `catalog_resource`, `resource_mirror` | порт транзакционного вызова оператора объявления — заказан; `resource_mirror.UpsertTx` |
| прямые операторы (PB-19, PB-20) | — | `pool.Exec` пробы на базе мира |
| удаление проекта (PB-21) | `projects` | `projectWriter.Delete`, `project_repo.go:306` |

Каждое «Дано» строится существующим писателем либо глаголом, положительный путь которого —
сценарий этой приёмки (PB-03, PB-04, PB-22 d). Посева мимо глагола для привязок нет: привязку
заводит только регистрация или применение объявления. Посев не ставился (testcontainers — тяжёлый
класс, только слотом внешнего кластера; задание посева не назвало); конструируемость показана
писателями и ограничениями схемы на `5c6b7c078`: `resource_mirror_id_nonempty` и
`relation_fact_object_id_nonempty` (`0001_initial.sql:2392`, `:2364`) допускают id с `/`;
`resource_parent_edge_depth_bounded` (`:2410`) допускает цепь глубины 3 у ребёнка.

### 5.3. Строки потребителя → сценарии

Опора — приёмка svc-registry, SHA-256 `2717077568…22dc7`.

| строка приёмки svc-registry | сценарий здесь |
|---|---|
| §3а «привязка id объекта к проекту переживает снятие регистрации (Д-A2) — SRI-23 строка a» (строка 265) | PB-02; для заказов, зарегистрированных до выкатки, — PB-08 |
| SRI-23 a — «kaname отверг регистрацию; объекта `registry_registry:e12813c6a/abc123` в kaname нет» (строки 877-880) | PB-02 (отказ, строки зеркала и фактов нет) |
| SRI-23 b — тот же проект: `Registered`, выдач на новый объект 0 (строки 883-886) | PB-03 |
| §4.2 reason `KeyBoundToOtherProject` — «kaname отверг регистрацию: ключ уже привязан к другому проекту» (строка 300) | Р4: машинная причина `OBJECT_BOUND_TO_OTHER_PROJECT` — и когда другой проект назван полем, и когда звеном `project` цепи (PB-24); отличает этот отказ от `FAILED_PRECONDITION` несоответствия проекта и аккаунта цепи (`#982`, SRI-110 e) |
| §4.6 «Освобождение не снимает привязку ключа к проекту в kaname» (строки 542-546) | PB-02, Р3 (освобождения привязки нет, §2 п.5) |
| SRI-110 e — цепь `[project:prjA, account:accB]` → `FAILED_PRECONDITION` | не здесь — `#982` (§2 п.3) |
| §4.1 цепи `registry_registry` и `registry_repository` — обе со звеном `project` (строки 282-283) | Р2 и PB-25 этих цепей не отвергают; поле `parentProjectId` в таблице не названо — §7 строка 2 |

---

## §6. Признак готовности (DoD)

### S1 — `PRO-Robotech/kaname`

1. Новая миграция: хранилище привязок `(модельный тип, id) → проект` с первичным ключом;
   колонка признака у `catalog_resource`; ограничения и триггеры Р9 (заведение привязки и
   сверка проекта строки зеркала и каждого звена `project` цепи с привязкой на вставке и правке
   `resource_mirror` и `resource_parent_edge`, неизменность проекта привязки, запрет удаления и
   `TRUNCATE`).
   Применённые миграции не правятся (ban #5). Основание кодирования — цитата этой приёмки в
   шапке новой миграции: путь `docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md`
   и SHA-256 одобренной редакции. Путь новой миграции не выписывается: его выдаёт дифф
   полосы против её базы, ветки эпика `origin/955`. Предикат гонится в корне kaname на
   закоммиченной голове полосы:

   ```sh
   new=$(git diff --name-only --diff-filter=A origin/955...HEAD -- internal/migrations/ | grep '\.sql$')
   echo "новых миграций: $(printf '%s' "$new" | grep -c .)"
   for m in $new; do
     cites=$(grep -c 'object-keeps-its-project-after-unregistration' "$m")
     ok=0
     for s in $(grep -o '[0-9a-f]\{64\}' "$m" | sort -u); do
       r=docs/specs/reviews/object-keeps-its-project-after-unregistration/$s.yaml
       test -f "$r" && grep -qx 'verdict: APPROVED' "$r" && grep -q "sha256: $s" "$r" && ok=$((ok+1))
     done
     echo "$m · цитат $cites · одобренных отпечатков $ok"
   done
   ```

   Пройдено: «новых миграций» ≥ 1, и в каждой строке вывода «цитат» ≥ 1 и «одобренных
   отпечатков» ≥ 1. Не пройдено: новых миграций 0 (предикату нечего читать, и это отказ, а не
   чистота), либо хотя бы в одной строке «цитат» 0, либо «одобренных отпечатков» 0 — отпечатка
   в шапке нет или он не совпадает ни с одной записью ревью с вердиктом APPROVED.
   Гейта-держателя у этого пункта в kaname пока нет. Гейт
   `PRO-Robotech/kacho:TestNewMigrationCitesAnApprovedAcceptance` читает только дифф дерева
   kacho, и миграцию kaname он не видит никогда. Гейт миграций kaname заводится отдельной
   задачей (задача kaname — гейт миграций). До его посадки пункт проверяется предикатом выше
2. Загрузчик манифеста: ключ `permanentProject` и три отказа Р7; перенос признака в строку
   каталога (`modulecatalog/rows.go`) и в применитель; гейт паритета посева каталога
   (`internal/check/catalog_seed_parity.go`) знает новую колонку; у ключа есть читатель в прод-коде
   (гейт `TestEveryDescriptorFieldHasAReader` либо его аналог для манифеста — зелёный)
3. Применение каталога, впервые выставившее признак, привязывает зарегистрированные объекты типа
   той же транзакцией (Р8)
4. `RegisterResource`: обе проверки формы Р2 (поле, затем звено `project` цепи); сверка Р4 —
   уровнем записи зеркала и цепи (Р9); перевод отказа базы, в том числе пришедшего из коммита, в
   Р4-отказ (не `INTERNAL`); ничего не записывается при отказе
5. `.proto`: комментарии Р10; `buf lint`, `buf breaking`, перегенерация — зелёные
6. Интеграционные пробы PB-01…PB-13, PB-17…PB-25 (22 сценария) зелёные; обе стороны
   каждой пары — в одном наборе, на одной ревизии (ban #12). На `5c6b7c078` до правки:
   сценарии без D-K (PB-06, PB-07, PB-13 a, PB-25 d) — зелёные и остаются зелёными (поведение не
   меняется); каждый сценарий с D-K — красный на загрузке фикстуры (`manifest.Load` с
   `KnownFields(true)`, `internal/manifest/manifest.go:450`: ключ `permanentProject` неизвестен) —
   честное красное отсутствующего предмета; после заведения ключа и до остальной правки красными
   остаются сценарии нового поведения: PB-01, 02, 05, 08, 09 (вторая часть), 10, 12, 17, 18,
   19 a и c, 20, 21 a (вторая часть), 22 a–c, 23 a, 24 a–d, 25 a и b
7. Ни одна прежняя проба домена доступа не ослаблена; набор домена доступа зелёный целиком, в том
   числе URG-01…URG-41 (`#963`) и ND-09 (`parent_edge_move_integration_test.go`)
8. Замер: p50/p95 `Register` на мире ПП, 200 регистраций объявленного типа и 200 необъявленного,
   до правки и после, на одной машине кластера, с единицей (мс) и ревизией; `EXPLAIN` сверки
   привязки — по первичному ключу. Вывод — в комментарии `DoD-proof`
9. Комментарий `DoD-proof @<sha>` в `#983`: команда, сырой итог, код возврата

Сквозного набора (S2) нет: глаголы регистрации — только на внутреннем слушателе (§2 п.10).
Сквозную проверку держит SRI-23 потребителя на `F-SR-KANAME` после §7 строк 1–3.

---

## §7. Внешние зависимости

| что | где | зачем | признак готовности |
|---|---|---|---|
| `permanentProject: true` на ресурсах `registries` и `repositories` манифеста registry svc-registry | svc-registry (единый манифест модуля, Д3 приёмки svc-registry) | без ключа привязка на стенде svc-registry не заводится (Р1), SRI-23 a там — «не выполнилось» | ключ в манифесте svc-registry; SRI-23 a зелёный на `F-SR-KANAME` |
| регистратор svc-registry шлёт `parentProjectId` (= звено `project` цепи) и цепь со звеном `project` для `registries` и `repositories` | svc-registry (таблица §4.1 приёмки svc-registry, строки 282-283: цепь названа, поле — нет) | Р2: с объявленным ключом регистрация без поля или без звена отвергается `INVALID_ARGUMENT`; Р4: поле, расходящееся с цепью, — Р4-отказ. Без строки объявление ключа уронит регистрации svc-registry | поле названо в таблице регистраций приёмки svc-registry; SRI-23 b (`Registered`) зелёный на `F-SR-KANAME` с объявленным ключом |
| регистратор отображает `OBJECT_BOUND_TO_OTHER_PROJECT` в reason `KeyBoundToOtherProject`; двойник kaname `F-SR-IT` отвечает тем же телом Р4 | svc-registry | отличить отказ привязки от отказа цепи (`#982`) | SRI-23 a и b зелёные на `F-SR-IT` (a — reason `KeyBoundToOtherProject`, message — текст §4.2 приёмки svc-registry); держатель — проба `F-SR-IT`, которую строка SRI-23 таблицы проб приёмки svc-registry (строка 1854) называет «заводится» |
| манифесты модулей `PRO-Robotech/kacho` | не меняются | перенос балансировщика и целевой группы — через перерегистрацию (§0.6) | — |
| `PRO-Robotech/kaname#982` | не зависимость посадки (Д-983-1) | Р4 и Р9 сверяют оба носителя проекта сами; `#982` закрывает остатки §2 п.3 | — |

---

## §8. Открытые вопросы

**В1. Для каких типов действует привязка.** Принято Р1 — допущение, сценарии написаны под (а).
- (а) типы, объявившие `permanentProject: true` манифестом. Цена — новый ключ манифеста, три
  отказа загрузчика, зависимость от манифеста svc-registry (§7);
- (б) все типы всех модулей. Цена — ломает `Move` балансировщика и целевой группы платформы
  (§0.6): регистрация назначения отвергается после применённого снятия, ресурс остаётся без
  проекции. Чинится только правкой kacho, которая сейчас запрещена порядком «сначала kaname»;
- (в) все типы, кроме объявивших «переносимый». Цена — та же правка манифеста nlb в kacho до
  выкатки kaname, иначе (б).
**Рекомендация — (а).** Безопасность для registry та же, kacho не трогается.

**В2. Привязывать ли ребёнка к конкретному родителю, а не только к проекту.** Принято: нет (Р6).
- (а) только проект. Цена — перенос репозитория между реестрами одного проекта возможен (ND-09
  одобрен);
- (б) и родитель. Цена — меняет одобренный ND-09, ломает его пробу; repo id у svc-registry и так
  содержит ключ реестра.
**Рекомендация — (а).**

**В3. Освобождение привязки.** Принято: пути нет (§2 п.5). Альтернатива — внутренний глагол
администратора облака с усиленным входом. Цена — новая поверхность и модель угроз.
Рекомендация — не заводить, пока нет случая.

Критичных вопросов без принятого допущения нет. В1 (а), В2 (а), В3 «пути нет» рецензент круга 1
записал дефолтами (запись `1864ef49….yaml`, `defaults_recorded`).

---

## §9. Опора: соседи

| приёмка | отпечаток, состояние | что берётся |
|---|---|---|
| `unregistration-revokes-its-grants.md` (`#963`) | на `5c6b7c078`, в линии | снятие регистрации снимает выдачи; мир У; перерегистрация под тем же проектом (URG-02, URG-03) |
| `nested-rule-reaches-descendants-of-a-named-container.md` (`#874`) | на `5c6b7c078`, в линии | ND-09: перенос ребёнка под контейнер того же проекта сохраняется |
| `non-empty-project-is-not-deleted.md` | на `5c6b7c078`, в линии | охрана непустоты проекта (PB-21 b) |
| `delegated-grants-stay-within-the-delegation.md` (`#986`) | редакция 3, `7512fd96c7aeb85f352fd55954cfb881fa7c8610169574adb2291155bb690fe6`, APPROVED (запись `docs/specs/reviews/delegated-grants-stay-within-the-delegation/7512fd96….yaml`, круг 3, событие опубликовано в `#986` 2026-10-25), коммит `52f5a1e93` ветки `986`; прежняя опора редакции 1 этого документа — `43622b18…` | раскладка документа, решения владельца Р-В1, Р-В3, Р-В5, Р-В7 (§3 соседа, формулировки 2026-10-25 не менялись) |
| приёмка svc-registry, редакция 3 | `2717077568f0057fa3205069807b4cc1b5fa72ec00ecda50eadfad0967b22dc7`, DRAFT | потребитель: Д-A2, §3а, §4.2, §4.6, SRI-23 |

Опора svc-registry — DRAFT. Если её отпечаток сменится до ревью, рецензент сверяет §5.3 с новой
редакцией (fa-b7).

---

## §10. Редакция 2 против редакции 1

По записи круга 1 (`1864ef49….yaml`) и решению диспетчера Д-983-1:

| замечание круга 1 | где закрыто |
|---|---|
| блокирующее COVERAGE: сверка только по `parentProjectId`, решение читает цепь | §0.10 (перепись читателей и писателей цепи), §1, §2 п.3, Р2 (звено `project` обязательно), Р4 (каждое звено `project` цепи против привязки), Р9 (инвариант и на цепи, на обоих путях её записи), §3 «Безопасность», PB-24 (с близнецами), PB-25, PB-19 c/d, §7 строка `#982` |
| важное COVERAGE: регистратор шлёт `parentProjectId` | §7 строка 2, §5.3 последняя строка |
| важное FORMAT: PB-20 c с двумя исходами | PB-20: один исход — триггер `BEFORE TRUNCATE`, класс `23`; §5.1 |
| важное FORMAT: PB-21 b утверждает gRPC-код на уровне писателя | PB-21 b: `errors.Is(err, iamerr.ErrReferenceInUse)` и текст дословно; §5.1 |
| важное CONVENTION: Р-В1 против Р8 | §3 Р-В1 переформулирован |
| важное FORMAT: PB-18 — привязку заводит уровень записи зеркала | Р3, Р9, §5.1 строки PB-01, PB-17, PB-18 |

Попутно: тип ресурса vpc в PB-19 — `vpc.network` (ресурс `network` фикстуры), а не
`vpc.networks`; строка `KnownFields(true)` — `manifest.go:450`; опора `#986` — одобренная
редакция 3 (§9).

## §11. Правка координат после одобрения редакции 2

Одобренная редакция — SHA-256 `1d308bbd5d5bb6cee79994a67f7cf3664e475f504c65f323b983948139b26a72`.
Наблюдаемое поведение и сценарии не меняются. Правка касается двух пунктов признака готовности,
координаты которых мертвы для `TestAcceptanceProbeCoordinateResolves`. Пункт §6 S1 п.1 переписан
повторно по возврату круга 3 (запись `4265bf69…22d8`): прежняя правка называла держателем гейт,
который миграцию kaname не читает.

| где | было | стало |
|---|---|---|
| §6 S1 п.1 | гейт без дома | основание кодирования — цитата этой приёмки и отпечатка одобренной редакции в шапке новой миграции, исход «не пройдено» задан предикатом `git grep -c`. Гейт kacho держателем не назван: он судит дифф своего дерева (`internal/repohygiene/acceptanceledger_test.go`, строки 149–159 на `origin/main` @`41d7edad9b`). Гейта-держателя в kaname нет, он заводится отдельной задачей (задача kaname — гейт миграций) |
| §7 строка 3, признак готовности | имя пробы svc-registry координатой; функции нет ни в одном дереве — проба только заводится | признак — сценарий SRI-23 a и b на `F-SR-IT`, держатель — строка SRI-23 таблицы проб приёмки svc-registry; утверждение то же, адрес не ведёт в несуществующую функцию |

### §11.1. Правка ПОСЛЕ вердикта круга 4

Одобренная редакция — SHA-256 `69280aba687b7b3cb87b71a40c675b6ff8204405fd8550cfe98574d037fdbbd0`
(запись круга 4). Наблюдаемое поведение, сценарии, производители и близнецы не меняются.
Правка касается одного пункта признака готовности: его предикат стоял на пути-заготовке,
которого в дереве нет и не будет, и потому по построению печатал пустоту
(`TestAcceptancePathCoordinateResolves`).

| где | было | стало |
|---|---|---|
| §6 S1 п.1 | `git grep -c` по заготовке пути `<новая>.sql`; отпечаток сверяется словами | путь новой миграции выдаёт дифф полосы против базы `origin/955` с фильтром добавленных файлов; по каждой — счёт цитаты приёмки и счёт отпечатков из шапки, у которых есть запись ревью с вердиктом APPROVED. Пустой дифф — «не пройдено», а не чистота. Утверждение пункта не ослаблено: те же два условия, теперь исполнимые |
