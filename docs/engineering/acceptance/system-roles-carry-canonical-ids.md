<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: системные роли адресуются идентификатором канонической формы

- **Статус:** DRAFT, редакция 3 — правка ПОСЛЕ вердикта круга 2 (APPROVED на редакцию 2,
  `27295473…5877`). Вердикт на редакцию 3 не перенесён: санкции на код и миграцию по ней нет
  (ban #1; миграция — гейт `TestNewMigrationCitesAnApprovedAcceptance`), пока
  `acceptance-reviewer` не вынесет его на её отпечаток
- **Статическая форма:** DRAFT. Слово вписано автором и вердиктом не является. Действующее
  одобрение выводится из записи ревью по отпечатку редакции и из внешнего события, на которое
  запись ссылается (`change-graph.md` §3). После ревью слово DRAFT не правится
- **История ревью:** только дописывается строками вида «дата · круг · вердикт · SHA-256
  редакции · путь записи». Прежние строки не правятся и не удаляются. Записи кладутся в
  `docs/specs/reviews/system-roles-carry-canonical-ids/<sha256>.yaml`
  - 2026-10-29 · круг 1 · CHANGES_REQUESTED · `09399b37d61a2384e469df2e6ff859d25973230cabf839cad5a10449f32f3dcf` ·
    `docs/specs/reviews/system-roles-carry-canonical-ids/09399b37d61a2384e469df2e6ff859d25973230cabf839cad5a10449f32f3dcf.yaml`
  - 2026-10-29 · круг 2 · APPROVED · `27295473fda44228a6fc8426db12bacbbcc6c9a436e151a59e738ecf50375877` ·
    `docs/specs/reviews/system-roles-carry-canonical-ids/27295473fda44228a6fc8426db12bacbbcc6c9a436e151a59e738ecf50375877.yaml`
- **Правка ПОСЛЕ вердикта (2026-10-29, редакция 3).** Основание — возврат посадки: «Дано»
  SRCI-05 редакции 2 объявляло выдачи, которых глагол в заданной форме не принимает (`B2` с
  целью-перечнем), и ожидание, которого продукт не даёт (Ч1 по кластерной выдаче). Что
  правлено: «Дано» SRCI-05 — формы выдач, которые глагол принимает на `092bee4fb`, с таблицей
  ворот и основанием каждого ожидания по коду; `B3` (SRCI-07б) и `B5` (SRCI-12) — та же цель,
  что у новой `B2`; §5, §5а — писатели; §8 — Д6 (находка вне предмета). Прочие сценарии, DoD,
  §0–§3 и §7 не менялись
- **Дата:** 2026-10-29
- **Задача:** `PRO-Robotech/kaname#543`. Потребитель результата — край kacho: правило строгой
  формы id по домену-владельцу (`PRO-Robotech/kacho#2976`, закрыта) пока не может включиться
  для типа `iam_role`, потому что две роли kaname в форму не укладываются
- **Ревизия измерения:** kaname `092bee4fb` (`origin/main`, база ветки `543`); kacho
  `41d7edad9b` (`origin/main`); соседняя ветка `origin/1052` — `1025bbabc`. Каждое число ниже
  снято на этих ревизиях командой рядом. «Дано» показано писателем с координатой (§5).
  Один прогон сюда входит: контроль фикстуры SRCI-05 (проба ветки `543`
  `TestSystemRoleIDs_SRCI05Fixture_SeedIsWhatTheVerbMakes`) на голове `3ca34095c`, внешний
  кластер. Код продукта на ней — `092bee4fb`: ветка правит только пробы
  (`git diff --stat 092bee4fb 3ca34095c -- . ':!*_test.go' ':!docs'` → 4 файла, все в
  `tests/`)
- **Тип изменения:** новая миграция данных (идентификаторы двух строк `kaname.roles` и всех
  ссылок на них); значения двух констант домена; снятие закрытого перечня посеянных
  идентификаторов, принимаемых вопреки длине. Поля, RPC и тексты отказов не добавляются и не
  меняются
- **Сервис:** `kaname`

> **Как в этом документе назван прежний идентификатор.** Литерал прежнего id здесь не
> выписан ни разу: документ сам входит в дерево, по которому считается предикат §6 S1 п.6.
> Прежний id роли называется «прежний id admin» / «прежний id viewer» — это значения, которые
> вставка ролей `kacho-system.admin` и `kacho-system.viewer` пишет в `0001_initial.sql`
> (строки 3785 и 3787 @`092bee4fb`). Шаблон поиска — `rol0\{9\}sys` (BRE), он находит литерал,
> не содержа его.

---

## §0. Перепись производителей — до сценариев

### 0.1. Сколько ролей посеяно не в форме и где

```sh
grep -n "INSERT INTO kaname.roles" internal/migrations/0001_initial.sql | wc -l
# → 48 вставок ролей
grep -n "INSERT INTO kaname.roles" internal/migrations/0001_initial.sql \
  | grep -o "VALUES ('rol[0-9a-z]*'" | awk '{print $2}' | tr -d "('" \
  | grep -vcE '^rol[0-9abcdefghjkmnpqrstvwxyz]{17}$'
# → 2 (admin: 20 знаков, в теле буква вне алфавита; viewer: 21 знак)
grep -ln "INSERT INTO kaname.roles" internal/migrations/2026*.sql | wc -l
# → 0: позже роли миграциями не сеются
```

Форма судится функцией фундамента `ids.HasKnownPrefix` (`corelib@v1.15.0`, `ids/ids.go:489`):
длина 20, префикс из каталога (`rol` в нём есть, `ids.go:245`), тело — 17 знаков алфавита
`0123456789abcdefghjkmnpqrstvwxyz` (`ids.go:22`). Остальные 46 посеянных id ей удовлетворяют
(та же команда без `-v` → 46).

### 0.2. Где сегодня живёт литерал прежних id

```sh
git ls-files | xargs grep -l 'rol0\{9\}sys' | wc -l                       # kaname → 32
git ls-files | xargs grep -l 'rol0\{9\}sys' | awk '{ if ($0~/\.sql$/) c="sql";
  else if ($0~/_test\.go$/) c="go-test"; else if ($0~/\.go$/) c="go-prod"; else c="doc";
  n[c]++ } END {for (k in n) print k, n[k]}'
# → sql 3 · go-prod 1 · go-test 24 · doc 4
git -C ../kacho grep -l 'rol0\{9\}sys' origin/main | wc -l                 # kacho → 0
```

- `sql 3` — применённые миграции `0001_initial.sql`,
  `20260905040500_system_roles_drop_the_read_action.sql`,
  `20260913143007_system_role_names_leave_the_platform_brand.sql`. Править их нельзя (ban #5),
  поэтому литерал в них **остаётся навсегда** — это опровергает посылку «литерал в дереве — 0»
  в её буквальной форме (§8, Д1);
- `go-prod 1` — `internal/domain/constants_extended.go:49,65` (`SystemAdminRoleID`,
  `SystemViewerRoleID`); закрытый перечень `internal/domain/seeded_ids.go:35-39` несёт
  `SystemViewerRoleID` именем константы, не литералом;
- `doc 4` — приёмки `catalog-consequence-reaches-role-readers.md`,
  `roles-come-as-data-not-migrations.md`, `seed-identity-names-its-own-service.md`,
  `system-role-segments-resolve.md` (§7).

Ветка соседней задачи `origin/1052` (`kaname#1052`, ведёт другая сессия) несёт литерал в
**44** файлах (`git grep -l 'rol0\{9\}sys' origin/1052 | wc -l`): сверх ствола — 12, среди
них резерв идентификаторов аккаунта `internal/domain/account_id_form.go:69` (прежний id viewer
как строка, которая id аккаунта стать не может). Это пересечение — §8, Д4.

### 0.3. Кто ссылается на роль по id

```sh
grep -n 'REFERENCES kaname.roles' internal/migrations/*.sql | wc -l       # → 12 внешних ключей
grep -n 'REFERENCES kaname.roles' internal/migrations/*.sql | grep -c 'ON UPDATE'   # → 0
# (ON UPDATE CASCADE в схеме есть — у ключей семейств токенов, — но ни у одного ключа на роль)
cat internal/migrations/*.sql | awk '/^CREATE TABLE/{t=$3}
  /^[[:space:]]+role_ids?[[:space:]]/{print t}' | sort -u
# → access_bindings, access_binding_target_members, grant_delegations, role_grant_orphan,
#   role_rule_ref, role_rule_selectors, role_selector_prune, role_selector_verbs_pending,
#   role_verb  (9 таблиц с колонкой role_id / role_ids)
```

Сверх колонок `role_id` id роли может стоять в тексте: объект отношения (`relation_fact`,
`access_binding_emitted_tuples.object`), полезная нагрузка очередей и журналов
(`fga_outbox`, `subject_change_outbox`, `audit_outbox`, …). Перечень таких колонок здесь
**не выписывается**: он вторая редакция схемы и устарел бы молча. Держатель §4 SRCI-06 обходит
схему целиком и колонок не перечисляет.

### 0.4. Кто в коде судит роль по её id

```sh
git grep -n 'SystemAdminRoleID\|SystemViewerRoleID' -- 'internal/**/*.go' ':!*_test.go'
# → constants_extended.go:49,65 (объявление); role_cluster_admin.go:54 (исключение
#   «область кластера + все объекты» для суперпользователя); seeded_ids.go:38 (перечень)
```

- `internal/domain/role_cluster_admin.go:54` — `IsClusterAdminRole` узнаёт суперпользователя
  по закреплённому id; зовётся из `internal/apps/kaname/api/access_binding/helpers.go:380`
  (отказ `INVALID_ARGUMENT "GLOBAL scope requires names or labels selector for
  non-cluster-admin roles"`);
- `internal/apps/kaname/shared/ids.go:59` — `ValidateResourceID` принимает длину не 20 только для
  литерала закрытого перечня; отказ `INVALID_ARGUMENT "invalid role id '<id>'"`;
- `internal/apps/kaname/api/role/get.go:119` — `NOT_FOUND "Role <id> not found"`;
- `internal/apps/kaname/api/access_binding/structural_gates.go:70` — синхронный отказ
  `FAILED_PRECONDITION "Role <id> not found"` при выдаче на несуществующую роль
  (`create.go:296` зовёт его до чеканки операции);
- посев выдач модуля резолвит роль **по имени**, не по id
  (`internal/repo/kaname/pg/module_seed_writer.go:454-466`, `WHERE name = $1 AND is_system AND
  live`), а повтор держит естественный ключ (там же, шапка `grant`).

### 0.5. Гейты, которые изменение обязано пережить

| гейт | координата | что судит сегодня |
|---|---|---|
| `TestSeededResourceIDsPassTheServiceOwnFormCheck` | `internal/check/seeded_id_form_test.go:263` | литерал `id` в однострочной вставке миграции проходит `ValidateResourceID`; ведомость пуста (`:99`) |
| `TestSeededIDExceptionsHaveASubject` | `internal/check/seeded_id_exception_subject_test.go` | запись закрытого перечня посеяна миграцией И отвергается чеканной формой |
| `TestNoMigrationMovesGrantsBetweenRoles` | `internal/migrations/grant_removal_trace_test.go:95` | ни одна миграция не присваивает `role_id` выдаче |
| `TestMigrationRemovingGrantsLeavesATrace` | там же, `:55` | миграция, удаляющая выдачи, оставляет след; храповик |
| `TestNewMigrationCitesAnApprovedAcceptance` | `internal/check/migration_cites_approved_acceptance_test.go` | новая миграция цитирует приёмку с действующим одобрением |
| гейт монотонности номеров | `internal/check/migration_version_monotonic_test.go` | номер новой миграции выше применённых |

Оба гейта формы читают **текст** миграций. Вставки в `0001_initial.sql` остаются с прежними
id навсегда, поэтому «гейт зелёный без исключений» требует, чтобы гейт судил id, который
корпус миграций оставляет **в силе**, а не текст вставки, позже переименованной (§6 S1 п.3).

### 0.6. Старший номер миграции — на ветках, не только в стволе

```sh
for b in $(git for-each-ref --format='%(refname:short)' refs/remotes/origin refs/heads); do
  git ls-tree --name-only $b internal/migrations/ | grep -E '/[0-9]+.*\.sql$' | sort | tail -1 \
  | sed "s|^|$b |"; done | sort -k2 | tail -3
# → origin/1052 …/20261028180000_account_id_is_a_client_string.sql
#   1065        …/20261028210500_relation_fact_remembers_its_removal.sql
ls internal/migrations/*.sql | tail -1      # ствол → 20261026090000_…
```

### 0.7. Лента изменений ресурсов (подписка) — кто в неё пишет и что из неё отдаётся

```sh
grep -n 'CREATE TRIGGER roles_resource_journal\|CREATE TRIGGER access_bindings_resource_journal' \
  internal/migrations/20260914090000_resource_journal_serves_the_subscription.sql
# → 325, 327, 330 (roles: вставка, правка, снятие); 333, 335, 338 (access_bindings: то же)
grep -n "v_json->>'id'\|jsonb_build_object('id'" \
  internal/migrations/20260914090000_resource_journal_serves_the_subscription.sql
# → строка ленты несёт id СВОЕЙ строки (resource_id) и нагрузку {id}; id роли в строке
#   выдачи лента не несёт
grep -n 'StateNotProduced\|changeDeleted:' internal/subscriptionjournal/journal.go
# → 176 (DELETED → SubscriptionEvent_DELETED), 227 (состояние не производится ни по одному виду)
```

- **Производитель событий** — триггеры ленты `kaname.resource_journal` на `kaname.roles` и
  `kaname.access_bindings` (`…_resource_journal_serves_the_subscription.sql:325-339`): вставка
  строки → `CREATED`, правка, меняющая строку (`WHEN (OLD.* IS DISTINCT FROM NEW.*)`) → `UPDATED`,
  снятие → `DELETED`; `resource_id` — id самой строки. Срабатывают by construction в транзакции
  любого оператора, включая миграцию; подтаблицы роли событий не эмитят (`journal.go`, шапка,
  решение `#73`).
- **Что отдаётся подписчику** — сервер потока фундамента читает ровно эти строки
  (`subscriptionjournal.Journal()`, `journal.go:144-180`: вид, id, изменение, позиция
  `sequence_no`); состояние предмета лента не производит (`StateNotProduced`, `journal.go:223`):
  подписчик по событию **перечитывает** предмет по `resource_id`, а на `DELETED` убирает его у
  себя (`subscription.md` sub-refetch-not-apply, sub-state-unavailable).
- **Следствие для этого изменения.** Подписчик, державший роль или выдачу по событию, узнаёт о
  смене id только событиями ленты: id роли — ключ предмета (`resource_id`), а смена `roleId`
  выдачи видна ему лишь как `UPDATED` этой выдачи. Лента сверх того — запись выданных id: по ней
  уже судится «id выдан однажды» (`20261002120000_account_ids_are_issued_once.sql:145`).
  Решение — Р4 (§3), сценарий — SRCI-12.

---

## §1. Обзор

Две системные роли — суперпользователь `system.admin` и наблюдатель `system.viewer` — посеяны
рукописными идентификаторами, которые не проходят проверку формы фундамента: у одного в теле
буква вне алфавита, у другого лишний знак. Чтобы id наблюдателя вообще был достижим, служба
держит закрытый перечень «посеянного вопреки длине» — единственное место, где проверка формы
id в kaname принимает не каноническую строку. Изменение переводит обе роли на id канонической
формы новой миграцией: строка роли, каждая ссылка на неё и производные проекции переходят на
новый id в одной транзакции, права ни одного субъекта не меняются, перечень исключений
пустеет. После этого строгая проверка формы `iam_role` на крае kacho становится возможной.

## §2. Что НЕ входит

- **Строгая форма id `iam_role` на крае kacho** — следующая задача в kacho (её заведут после
  посадки этой). Здесь — только то, что каждый id роли, который отдаёт kaname, ей уже
  удовлетворяет;
- **имя, правила, права, описание, область и `createdAt` системных ролей** — не меняются
  (их предмет — `system-role-segments-resolve.md`, `seed-identity-names-its-own-service.md`);
- **остальные 46 посеянных ролей** и роли, создаваемые глаголом (`ids.NewID(domain.PrefixRole)`,
  `internal/apps/kaname/api/role/create.go:181`) — уже в форме (§0.1);
- **дефисная форма id** (`rol-…`) — не выбирается: решение диспетчера — форма `ids.NewID`,
  а `ids.HasKnownPrefix` судит именно её;
- **совместимость прежних id** — не сохраняется: прода нет (тело `kaname#543`), в дереве kacho
  ссылок 0 (§0.2). Прежние id после миграции не адресуют ничего (SRCI-04);
- **роли модулей как данные** — предмет `roles-come-as-data-not-migrations.md`; системные роли
  модулю не принадлежат, гейт «миграция не пишет роль модуля» их не касается
  (`internal/check/migration_not_a_writer_of_module_role.go`, шапка, п.3);
- **резерв идентификаторов аккаунта** из `kaname#1052` — его предмет; здесь названо только
  пересечение (§8, Д4).

## §3. Решения, на которые опирается приёмка

- **Р1 (диспетчер, задание этой приёмке):** «системные роли получают id канонической формы
  новой миграцией». Отвергнутые прежде исходы — «перечень исключений» (`seeded_ids.go`, шапка
  «ПОЧЕМУ НЕ ПОЧИНИТЬ ПОСЕВ») — Р1 отменяет: перенос id одной и той же роли — не перенос выдачи
  между ролями (правила, имя и смысл роли те же), и SRCI-05/-07 это утверждают наблюдаемо.
- **Р2 (тело `kaname#543`):** применённые миграции не правятся; старые id для совместимости
  не сохраняются.
- **Р3 (ban #15 в этой задаче):** операции смены id в API нет и не появляется. Смена здесь —
  однократный акт миграции данных над посевом самого продукта, не глагол; ни один RPC не
  получает способности сменить id.
- **Р4 (автор, по заданию круга 2 — «выбери по коду и норме подписки»): миграция ПИШЕТ события
  ленты, лента не глушится и не переписывается.** Довод по коду: триггеры ленты срабатывают
  в транзакции миграции by construction (§0.7), а лента — единственный путь, которым подписчик
  узнаёт о предмете; глушение оставило бы подписчика с id, который больше ничего не адресует
  (SRCI-04), и без события, по которому он бы это узнал. Довод по норме: подписчик перечитывает
  по событию и на `DELETED` убирает предмет (`subscription.md` sub-refetch-not-apply,
  sub-state-unavailable) — значит наблюдаемо достаточно и необходимо: снятие прежнего id роли,
  появление нового и правка каждой выдачи, чья роль сменила id. Отвергнуто: (а) глушение
  триггеров на время миграции — подписчик молча расходится с базой; (б) переписать прошлые
  строки ленты на новый id — подписчик, уже прочитавший их, не узнает ничего, а возобновивший с
  ранней позиции получит `UPDATED` предмета до его `CREATED`; к тому же лента — запись выданных
  id (§0.7). Наблюдаемое — SRCI-12; SRCI-06 и SRCI-10 приведены к этому решению явно.
- **Р5 (диспетчер, исход Д4, дословно):** «вариант (а): резерв прежнего id viewer из #1052
  остаётся, одно исключение в DoD п.6».

Допущения, снятые без ответа и помеченные как допущения, — §8.

---

## §4. Сценарии — стадия S1 (миграция, константы, проверка формы)

Стадия одна: миграция, константы и перечень меняются одним изменением, иначе между ними
служба отвергает собственную роль (SRCI-04 — двусторонний).

### Сценарий 01: посеянные id ролей — канонической формы

**ID:** SRCI-01

**Given** пустая база, к которой применены все миграции дерева
**When** клиент с правом чтения ролей вызывает `GET /iam/v1/roles` и пролистывает все страницы
(`pageSize=1000`, затем `pageToken`, пока `nextPageToken` не пуст)
**Then** у каждой роли ответа `ids.HasKnownPrefix(id)` истинно; ролей с ложным — **0**; число
прочитанных ролей печатается и не меньше 48
**And** у роли `name="system.admin"` `id` равен `domain.SystemAdminRoleID`, у
`name="system.viewer"` — `domain.SystemViewerRoleID`

**Близнец SRCI-01б.** Тот же обход на базе, где применены все миграции **кроме новой** →
ролей с ложным `HasKnownPrefix` ровно **2**, и это роли `system.admin` и `system.viewer`.
Отличие — один факт (новая миграция). Без близнеца «0» неотличимо от непрочитанного.

### Сценарий 02: значения констант

**ID:** SRCI-02

**Given** пакет `internal/domain`
**When** проба зовёт `ids.HasKnownPrefix` на `domain.SystemAdminRoleID` и
`domain.SystemViewerRoleID`
**Then** обе — `true`; значения различны и не совпадают ни с одним из 46 прочих посеянных id
ролей (§0.1)

**Близнец SRCI-02б.** `ids.HasKnownPrefix` на прежних id → `false` для обоих. Прежние id проба
берёт **разбором** вставки `0001_initial.sql` по имени роли, а не литералом в своём тексте
(предикат §6 S1 п.6).

### Сценарий 03: роль читается по новому id

**ID:** SRCI-03

**Given** база SRCI-01
**When** клиент вызывает `GET /iam/v1/roles/{domain.SystemAdminRoleID}`, затем
`GET /iam/v1/roles/{domain.SystemViewerRoleID}`
**Then** HTTP 200; `id` равен запрошенному; `name` — `system.admin` и `system.viewer`;
`isSystem` — `true`
**And** `InternalIAMService.GetRoleCompiled` (`:9091`) с каждым из новых id отвечает без ошибки
и отдаёт те же правила, что `Get`

### Сценарий 04: прежние id не адресуют ничего

**ID:** SRCI-04

**Given** база SRCI-01
**And** вызывающий `K` — кластерный администратор, заведённый объявленным путём
`kaname.restore_cluster_admin('user', K)` (роль `admin` с id `domain.ClusterAdminRoleID`, **не**
одна из двух ролей предмета — право вызывающего от изменения не зависит); адрес `K` подтверждён;
у `K` живая сессия человека уровня «2» — `Create` требует `required_acr_min = "2"`
(`access_binding_service.proto:57`), без неё отказ уровня входа замаскировал бы предмет
**And** посеян пользователь `U3` без выдач (получатель выдач SRCI-04 и SRCI-08)
**When** клиент вызывает `GET /iam/v1/roles/<прежний id admin>`
**Then** HTTP 404, `code` = `NOT_FOUND`, `message` = `Role <прежний id admin> not found`

**When** клиент вызывает `GET /iam/v1/roles/<прежний id viewer>`
**Then** HTTP 400, `code` = `INVALID_ARGUMENT`, `message` = `invalid role id '<прежний id
viewer>'` — длина 21 больше ничем не прощается

**When** `K` вызывает `POST /iam/v1/accessBindings` с телом
`{"subjectType":"user", "subjectId":"<U3>", "roleId":"<прежний id admin>",
"scopeType":"iam.cluster", "scopeId":"cluster_root", "target":{"allInScope":{}}}`
**Then** HTTP 400, `code` = `FAILED_PRECONDITION`, `message` = `Role <прежний id admin> not
found`; операция не чеканится (число строк `kaname.operations` не выросло)

Тело несёт обязательную цель `target` (`access_binding_service.proto:521-526`): без неё
обработчик первым оператором отвечает `INVALID_ARGUMENT "target is required; …"`
(`handler.go:144` → `delta_input.go:27,40`), и до производителя «Тогда» запрос не доходит.
Форма тела — та же, которой строит запрос держатель ствола (`system_class_s2_integration_test.go:382`,
`allInScopeTarget()`). Прежний id admin длины 20 проходит проверку формы обработчика
(`shared/ids.go`, судит префикс и длину) и доходит до структурных ворот `create.go:296`.

**Близнец — SRCI-03** (тот же глагол, новый id → 200) и для выдачи — SRCI-08 (тот же запрос с
новым id → операция без ошибки). Отличие — один факт: id.

### Сценарий 05: выдачи работающей базы переходят без потери

**ID:** SRCI-05

**Given** база, к которой применены все миграции кроме новой, и над ней — пересчёт проекций
системных ролей в порядке старта службы: селекторы правил (`seed.BackfillOwnerBindings` →
`syncAllSystemRoleSelectorsTx`, `cmd/kaname/serve.go:2141`), затем глаголы
(`seed.ReseedSystemRoleVerbs`, `:2162`) и сегменты правил (`seed.ReseedSystemRoleRuleRefs`,
`:2201`). Без этого шага база — та, которую служба ни разу не поднимала: строк селекторов у
системных ролей нет, и правило-подстановка не адресует ни одного объекта
**And** посеяны (писатели — §5): пользователи `U0`–`U4` с подтверждёнными адресами; аккаунт
`A1` — его владелец `U0`, который не субъект ни одной проверки ниже (иначе «разрешено» Ч1 могло
бы прийти от владения, а не от выдачи); проект `P1` в `A1`; объект `O1` вида `vpc.network` (тип
модели прав `vpc_network`, id канонической формы `enp…`) в `P1`/`A1` — строка зеркала объектов,
как в мире П1 ствола; группа `G1` в `A1` с членом `U2`
**And** посеяны выдачи на прежние id. Форма каждой — та, которую глагол `Create` принимает на
`092bee4fb`; прохождение ворот — таблица ниже, а контроль фикстуры (§5) сверяет посев с той же
выдачей глаголом:
  - `B1`: субъект `user:U1`, роль `system.admin` (прежний id admin), `scopeType=iam.account`,
    `scopeId=A1`, `target={"allInScope":{}}`;
  - `B2`: субъект `group:G1#member`, роль `system.viewer` (прежний id viewer),
    `scopeType=iam.account`, `scopeId=A1`, `target={"allInScope":{}}`;
  - `B6`: субъект `user:U4`, роль `system.admin` (прежний id admin), `scopeType=iam.cluster`,
    `scopeId=cluster_root`, `target={"allInScope":{}}` — исключение суперпользователя.

| ворота `Create` (порядок вызова) | координата @`092bee4fb` | `B1` | `B2` | `B6` |
|---|---|---|---|---|
| роль существует | `structural_gates.go:64-70` | посеяна | посеяна | посеяна |
| роль назначаема на область | `structural_gates.go:82` → `role_scope.go:99` (системная — на любой) | да | да | да |
| роль создателя | `structural_gates.go:108` → `creator_gates.go:56-61` | не она | не она | не она¹ |
| цель-перечень: роль без правил (3a), покрытие типа (3) | `structural_gates.go:126`, `:138-146` — судят только `target.resources` | перечня нет | перечня нет | перечня нет |
| ворота системного класса | `create.go:302` → `system_class_gates.go:58-60` | субъект не класс | субъект не класс | субъект не класс |
| кластер + правило-якорь | `create.go:315` → `helpers.go:361`, `:380` | не кластер | не кластер | исключение по закреплённому id (`role_cluster_admin.go:54`), на `092bee4fb` это прежний id admin |

¹ Роль создателя на области не-аккаунта отвергается (`creator_gates.go:59-61`), а глагол
выдачу формы `B6` принял (контроль фикстуры @`3ca34095c`: исход `Create` без ошибки). Значит,
`system.admin` ролью создателя не является, и для `B1`, `B2` эти ворота тоже молчат.

Форма `B2` редакции 2 — цель-перечень `{vpc.network, O1}` — глаголом **недостижима** ни на
какой области. У правила системной роли модуль `*`, а покрытие типа сравнивает модуль точным
равенством (`access_binding_target.go:205`). Отсюда отказ `FAILED_PRECONDITION` «role … does not
grant verbs on vpc.network; …» (`structural_gates.go:141-143`); тот же отказ дал контроль
фикстуры @`3ca34095c`.

**And** снят «срез до»: для `B1`, `B2`, `B6` — `id`, `subjects`, область, цель, `createdAt`; ответы
пяти проверок права — `AuthorizeService.Check` с внутреннего слушателя от имени проверенного
модуля, тем же видом запроса, что у держателя мира П1
(`system_class_world_integration_test.go:260-275`, `check` и ярус глагола `scTierOfVerb`):

| # | `subject` | `resource` | `action` | `requiredRelation` | ожидание | основание по коду @`092bee4fb` |
|---|---|---|---|---|---|---|
| Ч1 | `user:U1` | `{type:"vpc_network", id:"O1"}` | `vpc.networks.update` | `editor` | разрешено | `B1`: роль с правилами материализуется реконсайлером (`create.go:572-576`); на области аккаунта правило-подстановка разворачивается во все материализуемые типы (`rule_fingerprint.go:216-224`, `:269-271`; вызов — `reconcile_adapter.go:405`); глаголы правила — `*` |
| Ч2 | `user:U2` | `{type:"vpc_network", id:"O1"}` | `vpc.networks.get` | `viewer` | разрешено | `B2` через членство `U2` в `G1`; та же развёртка; глаголы правила — `list`, `get` |
| Ч3 | `user:U2` | `{type:"vpc_network", id:"O1"}` | `vpc.networks.update` | `editor` | отказ | глагола `update` в правиле `system.viewer` нет — близнец Ч2, отличие — глагол |
| Ч4 | `user:U3` | `{type:"vpc_network", id:"O1"}` | `vpc.networks.get` | `viewer` | отказ | у `U3` выдач нет — близнец Ч2, отличие — субъект |
| Ч5 | `user:U3` | `{type:"vpc_network", id:"O1"}` | `vpc.networks.update` | `editor` | отказ | то же — близнец Ч1, отличие — субъект |

Срез до обязан дать ровно столбец «ожидание» — это положительный контроль фикстуры: иначе
сценарий судит несозданное условие (выдача не материализована), а не миграцию.

О праве по `B6` срез **не утверждает ничего**. На `092bee4fb` кластерная выдача роли
администратора облака принимается глаголом, но права не даёт (§8, Д6). «Разрешено» поэтому
недостижимо, а «отказ» закрепил бы дефект как контракт. `B6` здесь — строка, которую миграция
обязана перенести: её форму узнаёт по id исключение суперпользователя.

**When** применена новая миграция
**Then** `GET /iam/v1/accessBindings/{B1}`, `{B2}`, `{B6}` → те же `id`, `subjects`, область,
цель, `createdAt`; `roleId` — `domain.SystemAdminRoleID` у `B1` и `B6`,
`domain.SystemViewerRoleID` у `B2`
**And** ответы Ч1–Ч5 совпадают со срезом до побайтно
**And** `GET /iam/v1/accessBindings:listByRole?roleId={domain.SystemAdminRoleID}` возвращает `B1`
и `B6`
**And** число строк `kaname.access_bindings` после миграции равно числу до неё

### Сценарий 06: ни одна строка базы не сохраняет прежний id

**ID:** SRCI-06

**Given** база SRCI-05 после «среза до», в котором сверх того снято: для каждой таблицы схемы
`kaname` — число строк, чей текст (`<таблица>::text`) содержит прежний id admin, прежний id
viewer, новый id admin, новый id viewer
**And** предусловие: новых id до миграции не содержит ни одна строка (счёт 0)
**When** применена новая миграция
**Then** по каждой таблице, **кроме ленты подписки**: строк с прежним id — **0**; строк с новым
id — столько же, сколько до миграции было строк с прежним (по каждой роли отдельно)
**And** лента подписки (`kaname.resource_journal`; имя проба берёт у производителя —
`subscriptionjournal.Table`, а не выписывает): строки, существовавшие до миграции, не изменены
ни на байт (мультимножество `<строка>::text` с `sequence_no` не больше снятого до —
то же); всё, что выросло, — строки, дописанные миграцией, и они ровно те, что утверждает
SRCI-12. Отсюда счёт: строк с прежним id после = до + дописанных о прежнем id; с новым id
после = дописанных о новом id
**And** обход печатает число обойдённых таблиц и падает, если оно 0 или если «до» по прежним
id во всей схеме 0 (иначе равенство выполнялось бы тождественно)

Таблицы обходятся по каталогу схемы, а не по перечню (§0.3): новая таблица со ссылкой на роль
попадает под проверку без правки пробы. Очереди и журналы, кроме ленты подписки, входят в
обход (§8, Д2); лента исключена ОДНА и по свойству, а не по перечню: она — запись того, что
подписчику уже сказано, и переписывать её — Р4 (б), отвергнуто.

### Сценарий 07: миграция не выдаёт и не отзывает

**ID:** SRCI-07

**Given** база SRCI-05; курсор `InternalIAMService.PollSubjectChanges` снят до миграции
**When** применена новая миграция
**Then** опрос с этого курсора не отдаёт ни одного события
**And** число строк `kaname.fga_outbox` и `kaname.subject_change_outbox` после миграции равно
числу до неё: переход id у выдачи — перезапись её строки на месте, а не пара «отзыв + выдача»

**Близнец SRCI-07б.** На той же базе после миграции вызывающий `K` (SRCI-04) создаёт глаголом выдачу
`B3`: `{"subjectType":"user", "subjectId":"<U3>", "roleId":"<domain.SystemViewerRoleID>",
"scopeType":"iam.account", "scopeId":"<A1>", "target":{"allInScope":{}}}`
(форма `B2` и её ворота — SRCI-05; на кластере роль наблюдателя глаголом не выдаётся, SRCI-08б;
цель-перечень системной роли глагол отвергает, SRCI-05)
→ опрос с того же курсора отдаёт событие о `U3`. Отличие — один факт (была ли выдача).
Без близнеца «ни одного события» неотличимо от немого опроса.

### Сценарий 08: исключение суперпользователя следует за новым id

**ID:** SRCI-08

**Given** база SRCI-01; вызывающий `K` и пользователь `U3` — те же, что в SRCI-04 (кластерный
администратор объявленным путём, роль вне предмета; живая сессия уровня «2» под
`required_acr_min = "2"`)
**When** `K` вызывает `POST /iam/v1/accessBindings` с телом `{"subjectType":"user",
"subjectId":"<U3>", "roleId":"<domain.SystemAdminRoleID>", "scopeType":"iam.cluster",
"scopeId":"cluster_root", "target":{"allInScope":{}}}` — цель «все объекты области» явным
выбором `allInScope`, как у держателя ствола (`system_class_s2_integration_test.go:382`)
**Then** ответ — `Operation`; полл `OperationService.Get(id)` до `done=true` — без `error`;
`GET /iam/v1/accessBindings/{id из ответа операции}` отдаёт `roleId` нового id

**Близнец SRCI-08б.** Тот же запрос — с той же целью `{"allInScope":{}}` — с
`roleId = domain.SystemViewerRoleID` (системная роль с
правилом-якорем `*`/`*`, но не суперпользователь) → HTTP 400, `code` = `INVALID_ARGUMENT`,
`message` = `GLOBAL scope requires names or labels selector for non-cluster-admin roles`;
операция не чеканится. Отличие — один факт: роль. Близнец заодно утверждает, что новый id
наблюдателя суперпользователем не признаётся.

### Сценарий 09: снят в редакции 2

**ID:** SRCI-09 — **снят**, номер не переиспользуется.

Редакция 1 утверждала «повторный старт службы не заводит выдач». Утверждение не способно
покраснеть от этого изменения, поэтому держателем не было:

- выдач посева на `system.admin` и `system.viewer` в деревьях нет: `grep -n
  'system\.admin\|system\.viewer' manifest.yaml` → одна строка комментария (`:320`), в kacho
  `git -C project/kacho grep -n 'system\.admin\|system\.viewer' origin/main -- '*manifest*.yaml'`
  → 0 @`41d7edad9b`; выдачи посева в `0001_initial.sql:3190-3196` относительные (`role_id`
  NULL), вставок выдач на прежние id в миграциях нет (`grep -n 'INSERT INTO
  kaname.access_bindings' internal/migrations/*.sql | grep -c 'rol0\{9\}sys'` → 0) —
  применитель ролей этих двух имён не касается вовсе;
- и будь такая выдача, применитель резолвит роль по имени (`module_seed_writer.go:454-466`), а
  id строки выдачи выводит из имени формы, а не из id роли (`module_seed_writer.go:318-329`,
  `formKey = "role:" + <имя>`): после миграции естественный ключ совпадает с перенесённой
  строкой, а промах миграции по этой строке невозможен — внешний ключ без `ON UPDATE` (§0.3)
  не даёт снять прежнюю роль, пока на неё ссылается выдача, и миграция падает целиком (это
  красное SRCI-05/-06, а не SRCI-09).

Свойство «миграция не оставляет выдачу на прежнем id» держат SRCI-05 и SRCI-06.

### Сценарий 10: обратимость

**ID:** SRCI-10

**Given** база SRCI-05 до новой миграции; снят «полный срез»: по каждой таблице схемы `kaname`,
кроме ленты подписки (`subscriptionjournal.Table`), мультимножество `<таблица>::text`; для
ленты — её строки и наибольший `sequence_no`
**When** новая миграция накатывается, затем откатывается
**Then** полный срез (без ленты) совпадает со снятым до наката
**And** после повторного наката полный срез (без ленты) совпадает со срезом после первого наката
**And** лента: строки до наката не изменены; накат, откат и повторный накат каждый дописывают
события по правилу SRCI-12 — откат зеркально (о прежнем id роли последнее событие —
`CREATED`/`UPDATED`, не `DELETED`; о новом id последнее — `DELETED`; о каждой выдаче на роль —
`UPDATED`), повторный накат — то же мультимножество пар «(`resource_kind`, `resource_id`,
`event_type`)», что первый. `sequence_no` растёт и в сравнение не входит: номер выдаёт счётчик
на вставке (`…_resource_journal_serves_the_subscription.sql:48`), и равенство номеров после
повтора было бы требованием тишины, отвергнутой Р4

**SRCI-10б (строки, рождённые между накатом и откатом).** После наката `K` (тот же, что в SRCI-04) создаёт глаголом выдачу `B4` телом SRCI-08
(`U3` → `system.admin`, новый id, кластер, `allInScope`); затем откат → `B4` существует, её `roleId` — прежний id admin;
строк с новым id в схеме, кроме ленты, — 0; в ленте о `B4` после отката есть `UPDATED`. Откат
не теряет выдач, сделанных на новой версии.

### Сценарий 11: выдача, конкурирующая с миграцией

**ID:** SRCI-11

**Given** база SRCI-05 до новой миграции
**When** параллельно: (а) транзакция новой миграции; (б) N ≥ 8 горутин вставляют выдачи на
прежний id admin писателем репозитория
**Then** транзакция миграции зафиксирована (не отвергнута нарушением ключа); каждая вставка (б)
либо зафиксирована и после миграции несёт новый id, либо отвергнута отсутствием роли (`23503` →
`FAILED_PRECONDITION`); строк с прежним id после фиксации обеих сторон, кроме ленты подписки, —
**0**; число зафиксированных (б) равно числу строк `B*` с новым id сверх среза до

Это свойство базы (внешние ключи, `ban #10`), а не проверки в коде. Как миграция держит
первое «Тогда» при ключах без `ON UPDATE` — условие к замыслу У1 (§8а), не к приёмке.

### Сценарий 12: лента подписки сообщает о смене id

**ID:** SRCI-12

**Given** база SRCI-05 до новой миграции, и сверх неё: обычная роль `R0` аккаунта `A1` (не одна
из двух; правило `vpc`/`network`/`get`) и выдача `B5`: субъект `group:G1#member`, роль
`R0`, `scopeType=iam.account`, `scopeId=A1`, `target={"allInScope":{}}`
(субъект, область и цель — те же, что у `B2`; отличие — только роль)
**And** снята позиция ленты `S0` — наибольший `sequence_no` в `subscriptionjournal.Table`; снят
перечень `BR` — id всех строк `kaname.access_bindings`, чей `role_id` — прежний id admin или
прежний id viewer (в базе SRCI-05 — не меньше `B1`, `B2` и `B6`; проба печатает его длину и
падает на нуле)
**When** применена новая миграция
**Then** в ленте с позицией больше `S0` — строки, которые сервер потока читает и отдаёт событиями
подписчику, возобновившему поток с этой позиции (`subscriptionjournal.Journal()`: вид,
`resource_id`, изменение; пообъектное сужение доставки — `subscriptionjournal/narrow.go` — этим
изменением не затрагивается и здесь не утверждается):
  - вида `iam_role` о прежнем id admin и о прежнем id viewer — **последнее** событие о каждом
    `DELETED`;
  - вида `iam_role` о `domain.SystemAdminRoleID` и `domain.SystemViewerRoleID` — **первое**
    событие о каждом `CREATED`, и `DELETED` о них нет;
  - вида `iam_access_binding` — о КАЖДОМ id из `BR` не меньше одного `UPDATED`, и ни одного
    `CREATED` или `DELETED` о них: id выдачи не меняется, это не пара «отзыв + выдача» (SRCI-07);
  - иных пар «вид, `resource_id`» нет: событий о `R0`, `B5` и о прочих 46 ролях — **0**
**And** подписчик, перечитавший по этим событиям предметы (`GET /iam/v1/roles/{id}`,
`GET /iam/v1/accessBindings/{id}`), получает ровно состояние SRCI-03/-04/-05: прежние id — отказ
SRCI-04, новые — роль, выдачи из `BR` — `roleId` нового id

**Близнец SRCI-12б.** `B5` — выдача на роль вне предмета — отличается от `B2` ровно одним фактом
(роль): о `B2` событие `UPDATED` есть, о `B5` — нет. Без близнеца «о `B2` есть событие»
неотличимо от ленты, отмечающей каждую выдачу.

Порядок событий внутри транзакции миграции и их число сверх названного минимума не
утверждаются: номер выдаёт счётчик на вставке, видимыми все становятся одной фиксацией, а
подписчик перечитывает предмет, а не применяет событие (`subscription.md`
sub-refetch-not-apply). Утверждается только то, что подписчику нужно, чтобы сойтись с базой.

---

## §5. Дано → писатель

| Given | писатель / фикстура | координата |
|---|---|---|
| пустая база, все миграции | `pgtest.NewEmptyDB` + `upAllIAMMigrations` | `internal/migrations/system_role_names_leave_the_brand_integration_test.go:59` |
| база «все миграции кроме новой» | `goose.UpTo(db, ".", <предшественник>)` — тот же приём, что у соседней пробы миграции | `internal/migrations/access_binding_pair_in_set_integration_test.go:296-329` (`UpTo`, `DownTo`, повторный `UpTo`) |
| вызывающий `K` (SRCI-04, -07б, -08, -10б) | `kaname.restore_cluster_admin('user', K)`, подтверждение адреса, живая сессия уровня «2» — тот же посев, что у держателя ствола | `system_class_s2_integration_test.go:372-377` (`verifyAddresses`, `restore_cluster_admin`, `seedLiveHumanSession` — `:228`) |
| проекции системных ролей (SRCI-05 и всё, что стоит на его базе) | старт службы, тем же порядком: `seed.SyncAllSystemRoleSelectors` (тело то же, что у `BackfillOwnerBindings`, — `syncAllSystemRoleSelectorsTx`), затем `seed.ReseedSystemRoleVerbs` и `seed.ReseedSystemRoleRuleRefs` | `cmd/kaname/serve.go:2141,2162,2201`; `internal/apps/kaname/seed/migrate_backfill.go:201,246`; мир, зовущий досев селекторов, — `service_account_creator_world_integration_test.go:722` |
| `U0`–`U4`, `A1` (владелец `U0`), `P1`, `G1` | `mustSeedUser`, `seedAccountByOwner(…, U0)`, `seedProjectInAccount`, `seedGroup` + член группы писателем членства | `testhelpers_assignable_test.go:80,113,125`; `system_class_world_integration_test.go:173` (`seedGroup`) |
| объект `O1` (`vpc.network` в `P1`) | `seedMirrorObject(…, "vpc.network", O1, P1, A1)` | `delete_fanout_deadlock_integration_test.go:135`; вызов — `system_class_world_integration_test.go:146` |
| выдачи `B1`, `B2`, `B6` на прежние id (формы — SRCI-05) | `bindingset.Insert` писателя выдач (с `Target`), затем материализация реконсайлером мира П1 (`reconcile.New` над `kanamepg.NewReconcileAdapter`); роль адресуется чтением `SELECT id FROM kaname.roles WHERE name=$1 AND is_system` — **не** литералом. Писатель один на все три выдачи, потому что глагол годится не для всех. С новым кодом на старой базе `B1` глагол принял бы (прежний id admin длины 20 проходит проверку формы, область — не кластер). `B2` он отвергнет проверкой формы (`INVALID_ARGUMENT`: прежний id viewer больше не прощается). `B6` — воротами `helpers.go:380`: `IsClusterAdminRole` ждёт новый id. Что состояние то же, какое глагол принимал на `092bee4fb`, держат таблица ворот SRCI-05 и контроль ниже | `internal/testsupport/bindingset/bindingset.go:95`; `system_class_world_integration_test.go:103` |
| контроль фикстуры SRCI-05 (не сценарий) | на мире со всеми миграциями `K` выдаёт глаголом `Create` близнецов `B1v`, `B2v`, `B6v` — те же формы с другими субъектами, отличие от посева одно: писатель. Исход каждого `Create` — без ошибки; ответы Check близнецов (Ч1, Ч2–Ч3 и ответ по `B6v`) равны ответам посева. Красное — посев строит не то, что глагол | проба ветки `543` `TestSystemRoleIDs_SRCI05Fixture_SeedIsWhatTheVerbMakes` (`system_role_ids_integration_test.go:328`), формы приводятся к SRCI-05 этой редакции |
| проверки Ч1–Ч5 | `AuthorizeService.Check` через обработчик, вызывающий — проверенный модуль (`moduleCtx`) | `system_class_world_integration_test.go:245-275` |
| роль `R0`, выдача `B5` (SRCI-12) | `seedRulesRoleWithSelectors` и `bindingset.Insert` | `delete_fanout_deadlock_integration_test.go:95`; `bindingset.go:95` |
| позиция `S0`, перечень `BR` (SRCI-12) | `SELECT max(sequence_no) FROM kaname.resource_journal`; `SELECT id FROM kaname.access_bindings WHERE role_id IN (SELECT id FROM kaname.roles WHERE name IN ('system.admin','system.viewer') AND is_system)` — до миграции | новая проба (держатель SRCI-12); образец чтения ленты — `internal/migrations/resource_journal_integration_test.go:58` |
| курсор `PollSubjectChanges` | глагол `InternalIAMService.PollSubjectChanges` | `proto/kaname/cloud/iam/v1/internal_iam_service.proto:163` |
| «срез» по таблицам схемы | обход `information_schema.tables WHERE table_schema='kaname'` и счёт `count(*) FILTER (WHERE t::text LIKE …)` | новая проба (держатель SRCI-06/-10) |
| N горутин вставки | писатель выдач + `pgtest` пул | образец гонки — `internal/repo/kaname/pg/group_delete_concurrent_integration_test.go` |

Ни одно Given не требует литерала прежнего id в тексте пробы: прежние id в базе появляются сами,
применением `0001_initial.sql`, и читаются по имени роли.

---

## §5а. Сценарий → производитель

| ID | что производит «Тогда» | координата производителя | чем измерено |
|---|---|---|---|
| SRCI-01 | значения `id` в строках `kaname.roles` после новой миграции; `List` отдаёт их как есть | новая миграция (её нет — производитель **заказан** этой приёмкой); чтение — `internal/apps/kaname/api/role/list.go` | чтение кода @`092bee4fb` |
| SRCI-01б | вставки `0001_initial.sql:3785,3787` | там же | §0.1, команда |
| SRCI-02 | константы `internal/domain/constants_extended.go:49,65`; судья — `ids.HasKnownPrefix` (`corelib@v1.15.0/ids/ids.go:489`) | значения константы **заказаны** | чтение |
| SRCI-03 | `internal/apps/kaname/api/role/get.go` (проверка формы `:76`, чтение) и `get_role_compiled.go:33` | есть | чтение |
| SRCI-04 admin | `internal/apps/kaname/api/role/get.go:119` — `"Role %s not found"`, `NOT_FOUND` | есть | `grep -n 'Role %s not found' internal/apps/kaname/api/role/get.go` |
| SRCI-04 viewer | `internal/apps/kaname/shared/ids.go:59` — `"invalid %s id '%s'"`, ветвь срабатывает, когда перечень `seeded_ids.go` литерала больше не несёт | ветвь есть; снятие записи перечня **заказано** | чтение |
| SRCI-04 выдача | `internal/apps/kaname/api/access_binding/structural_gates.go:70`, зовётся `create.go:296` до чеканки операции; тело с `target` проходит `handler.go:144` (`delta_input.go:27,40` отвергает лишь отсутствие цели) | есть | `sed -n 141,147p handler.go`; `sed -n 36,41p delta_input.go` |
| SRCI-05 | внешние ключи на `kaname.roles(id)` (12, §0.3) и перенос ссылок новой миграцией; ответы Ч1–Ч5 — `AuthorizeService.Check` (`authorize_service.proto:73`) над материализацией выдач: реконсайлер разворачивает правило-подстановку на области аккаунта (`create.go:572-576`, `reconcile_adapter.go:405`, `rule_fingerprint.go:216-224,269-271`) по проекциям, которые пишет старт службы (`serve.go:2141,2162`); формы выдач — ворота `create.go:296,302,315` (таблица SRCI-05) | перенос **заказан**; проверка и материализация есть | §0.3, команда; чтение кода @`092bee4fb`; формы — контроль фикстуры @`3ca34095c` |
| SRCI-06 | та же миграция над всеми таблицами схемы; неизменность прежних строк ленты — отсутствие в миграции правки `kaname.resource_journal` (Р4) | **заказан** | — |
| SRCI-07 | отсутствие новых строк в очередях: миграция перезаписывает, а не эмитирует; событие близнеца — писатель выдачи (`create.go`) | **заказан** / есть | чтение |
| SRCI-08 | `internal/domain/role_cluster_admin.go:54` (`IsClusterAdminRole` по закреплённому id) и отказ `helpers.go:380-382`, зовётся `create.go:315` до чеканки операции; тело с `target.allInScope` — как у держателя ствола `system_class_s2_integration_test.go:382`; держатель текста отказа на стволе — `system_class_s2_integration_test.go:400` (`trunkRule`) | есть; зависит от значения константы | чтение |
| SRCI-09 | — **снят** (§4, Сценарий 09: утверждение без способности покраснеть) | — | `grep -n 'system\.admin\|system\.viewer' manifest.yaml` → 1 (комментарий); kacho манифесты → 0 |
| SRCI-10 | нижняя половина новой миграции; события ленты на откате — те же триггеры §0.7 | **заказан** / есть | чтение |
| SRCI-11 | внешние ключи `access_bindings_role_fk` (`0001_initial.sql:5394`) и транзакция миграции; отображение `23503` — `shared.MapRepoErr`; фиксация миграции под гонкой — У1 (§8а) | есть / **заказан** | чтение |
| SRCI-12 | триггеры ленты `…_resource_journal_serves_the_subscription.sql:325-339` (вставка → `CREATED`, правка строки → `UPDATED`, снятие → `DELETED`, `resource_id` — id строки) в транзакции новой миграции; отображение строки в событие — `subscriptionjournal.Journal()` (`journal.go:144-180`) | триггеры и отображение есть; форма миграции, дающая названные события, **заказана** (Р4, У2) | `grep -n 'CREATE TRIGGER roles_resource_journal\|CREATE TRIGGER access_bindings_resource_journal' …` → 6 (§0.7) |
| SRCI-12б | те же триггеры: срабатывают только на строках, которых коснулся оператор миграции; строка `B5` на роли вне предмета не затрагивается, событий о ней нет | есть | чтение `:333-339` |

«Заказан» — производитель — содержимое этого изменения (миграция, константы, снятие записи
перечня); исполнитель — `go-implementer` по одобрению этой приёмки. Сценариев без производителя
и без заказа — **0**.

---

## §6. DoD — стадия S1

1. **Миграция — новым файлом** `internal/migrations/<номер>_<имя>.sql`; применённые файлы
   не изменены: `git diff --stat origin/main -- internal/migrations/0001_initial.sql
   internal/migrations/20260905040500_*.sql internal/migrations/20260913143007_*.sql` пуст.
   Номер выше **каждого** номера в стволе и на живых ветках на момент посадки — сегодня старший
   `20261028210500` (ветка `1065`, §0.6); предикат: команда §0.6 по голове посадки, номер
   новой миграции — строго больше выведенного; гейт монотонности зелёный. Миграция цитирует
   путь этой приёмки; `TestNewMigrationCitesAnApprovedAcceptance` зелёный на одобренном
   отпечатке.
2. **Форма:** SRCI-01, SRCI-01б, SRCI-02, SRCI-02б зелёные; `ids.HasKnownPrefix` истинно на
   обоих новых id.
3. **Гейт формы посева без исключений:** `TestSeededResourceIDsPassTheServiceOwnFormCheck`
   зелёный, ведомость `seededIDLedger` пуста, закрытый перечень `domain.SeededResourceIDs()`
   пуст либо снят вместе со своей ветвью в `ValidateResourceID` и гейтом предмета (исход
   выбирает замысел — §8, Д3); гейт судит id, который корпус оставляет в силе. Способность
   упасть доказана инъекцией: новая миграция, сеющая роль id вне формы, — красный; та же
   вставка с последующей миграцией, переводящей id в форму, — зелёный.
4. **Переносов выдачи между ролями нет:** `TestNoMigrationMovesGrantsBetweenRoles` и
   `TestMigrationRemovingGrantsLeavesATrace` зелёные **без** новой записи прощения и без
   изменения храповика `GrantRemovalRatchet`.
5. **Поведение:** SRCI-03 … SRCI-08, SRCI-10 … SRCI-12 — интеграционные пробы на Postgres
   (testcontainers) зелёные на внешнем кластере (`heavy-slot.sh`); SRCI-03, SRCI-04, SRCI-08
   сверх того — кейсы края newman (≥1 положительный — SRCI-03; ≥1 отрицательный — SRCI-04;
   классы — `testing-newman.md#qa-classes-per-method`), ID кейсов несут `SRCI-NN`. Трассировка:
   сценарий ↔ одна функция `TestSystemRoleIDs_SRCI<NN>_<Суть>` (близнец — в той же функции
   либо `…_SRCI<NN>b_…`). Покрытие считается **по ID, а не по строкам**:
   `git grep -ho 'SRCI-\?[0-9]\{2\}' -- '*_test.go' tests/newman | tr -d - | sort -u | wc -l` →
   **11** (ID действующих сценариев: 01, 02, 03, 04, 05, 06, 07, 08, 10, 11, 12), и
   `… | sort -u | grep -c 'SRCI09'` → **0** (снятый номер не переиспользован). Отказы
   SRCI-04/-08б утверждаются парой «HTTP-статус + `code`» и текстом `message` дословно;
   `field_violations` эти отказы сегодня не несут, и изменение их не вводит.
6. **Литерал в дереве** (исход Д4 — Р5: резерв `kaname#1052` остаётся, исключение ОДНО):
   - вне миграций в kaname на голове посадки —
     `git ls-files | xargs grep -l 'rol0\{9\}sys' | grep -v '^internal/migrations/.*\.sql$' |
     grep -vxFf <(git diff -G'rol0{9}sys' --name-only <база #1052> <голова #1052>) | wc -l`
     → **0**. Единственное исключение — файлы, в которые литерал внесла сама ветка `#1052`
     (резерв строки, которая не может стать id аккаунта, и его пробы и тексты); перечень
     выводится диффом ветки, а не выписывается (`-G` у git — расширенная форма выражения, отсюда
     `{9}` без обратных косых; на `origin/1052` @`1025bbabc` от `git merge-base origin/1052
     origin/main` — **12** файлов, из них в `internal/migrations/` — 0). Пока `#1052` не влита,
     исключение пусто и тот же конвейер без `grep -vxFf` → **0**;
   - в миграциях — `git ls-files -- 'internal/migrations/*.sql' | xargs grep -l 'rol0\{9\}sys' |
     wc -l` → **4** (три применённые + новая);
   - в kacho — `git grep -l 'rol0\{9\}sys' origin/main | wc -l` → **0**.
7. **Соседние приёмки** (§7): сценарий `KAN-SEED-1-13` объявлен заменённым этим документом в
   самом `seed-identity-names-its-own-service.md` строкой «правка после вердикта»; литерал в
   четырёх приёмках §0.2 заменён именем константы; гейт
   `TestAcceptanceEditedAfterItsVerdictSaysSo` зелёный.
8. **Комментарии, объявляющие прежние id неизменяемыми** (`constants_extended.go:51-64`,
   `seeded_ids.go:19-25`), сняты либо переписаны: после изменения они ложны.

Предикат «готово»: п.1–8 выполнены на одной закоммиченной голове; полный хук отправки — отказов 0.

---

## §7. Отношение к соседним приёмкам

| документ | отпечаток (`sha256sum` @`092bee4fb`) | что здесь учтено | дублирования нет, потому что |
|---|---|---|---|
| `system-role-segments-resolve.md` | `3570293a3600d486dedf8863a867e54092ab5e1bc96c3cac863e6a15526d3a51` | литерал viewer — в его замерах (строки 219, 351, 424, 1672, 1888) как координата роли | его предмет — правила ролей; правила не меняются (§2) |
| `roles-come-as-data-not-migrations.md` | `33c87a6b93b3c00b845cbc2a427390a7f5e4d28e4756275f39cb0cf95e2c07d8` | рукописные id названы вне набора деривации (строки 87, 603-604, 1210) | его предмет — роли модулей; системные роли модулю не принадлежат |
| `seed-identity-names-its-own-service.md` | `7e4523566c2edddeb9b702801f07fa7076567f8dcd7d9badf1f756fb2464ed6d` | `KAN-SEED-1-13` «идентификаторы ролей не сдвинулись ни на символ» утверждает прежние литералы дословно — **противоречит** этой приёмке и заменяется ею | его предмет — имена; сценарий о неизменности id становится ложным и объявляется заменённым (DoD п.7). Файл сейчас правит `kaname#1065` (§0) — правка этой задачи в нём идёт **после** посадки `#1065` |
| `catalog-consequence-reaches-role-readers.md` | `ecbd1d40870bb2ee4941c8d9cbdd70f94e6a7ecdae617796c4b65aec2f6b87ff` | литерал — в выводе замеров (строки 300, 406-409, 2070) | предмет — последствия каталога |

Ни одна из трёх первых не имеет записи ревью в `docs/specs/reviews/` дерева kaname
(`ls docs/specs/reviews | grep -E 'system-role-segments|roles-come-as-data|seed-identity'` → 0
строк): статическое слово APPROVED в их шапке — наследство монорепо, действующим одобрением по
отпечатку оно не является. Опора этой приёмки на них — только на факты дерева, перемеренные выше.

---

## §8. Допущения и открытые вопросы

- **Д1 — посылка «литерал в дереве — 0» в буквальной форме недостижима.** Три применённые
  миграции несут литерал и правиться не могут (ban #5); новая миграция называет прежний id,
  иначе ни накат, ни откат (SRCI-10) не адресуют строку. Принято допущение: предикат DoD п.6 —
  «0 вне `internal/migrations/*.sql`, ровно 4 внутри». Отвергнуто: пересборка базовой миграции
  (нарушает ban #5); склейка литерала выражением (`'rol000000000' || …`) — обход предиката
  написанием, а не предметом. Край kacho судит живые id, а не текст миграций, поэтому для
  `kacho#2976`-продолжения разницы нет.
- **Д2 — очереди и журналы переписываются вместе с живыми таблицами; лента подписки — нет.**
  SRCI-06 требует 0 строк с прежним id во всей схеме, включая `fga_outbox` и `audit_outbox`,
  **кроме** `kaname.resource_journal`. Довод для переписываемых: прямой факт отношения
  складывается из журнала прав триггером, и строка журнала с прежним id при пересборке фактов
  вернула бы факт на объект, которого нет; прода нет, исторической ценности до выпуска нет.
  Цена: эти журналы перестают быть дословной записью прошлого для двух id. Лента подписки —
  иной предмет (Р4): её строки уже прочитаны подписчиками, и правка прошлого им ничего не
  сообщает, поэтому лента не переписывается, а дописывается (SRCI-12). Исключение одно и
  берётся у производителя (`subscriptionjournal.Table`), а не закрытым перечнем таблиц
  (перечень был бы вторым местом о схеме и устарел бы молча).
- **Д3 — судьба механизма «посеянного вопреки длине».** После изменения перечень пуст. Исход
  (снять перечень, его ветвь в `ValidateResourceID` и гейт предмета — либо оставить пустым под
  гейтом) — решение замысла, не приёмки; наблюдаемое одно и то же (SRCI-04 viewer). Рекомендация
  — снять: пустой механизм послабления без предмета — та же слепая зона, от которой его
  самоистечение и стерегло.
- **Д4 — пересечение с `kaname#1052`. Закрыт решением диспетчера (Р5):** вариант (а) — резерв
  прежнего id viewer из `#1052` остаётся (прежний id выдан наружу через `List`, и другому
  ресурсу он выдан быть не должен); одно исключение в DoD п.6, выводимое диффом ветки `#1052`.
  Порядок посадки не важен: `#1052` садится раньше — исключение непусто; позже — пусто.
  Сверх исключения — **допущение**: новые id обеих ролей имеют форму генератора с префиксом
  `rol`; отвергает ли их распознаватель id аккаунта из `#1052` формой, а не резервом, — предмет
  `#1052` (его проба посева против резерва, AID-39). Кто садится вторым, гоняет эту пробу на
  сведённой голове; красная — заказ к этой приёмке, а не молчаливая правка резерва.
- **Д5 — окно выкатки.** Между фиксацией миграции и заменой всех экземпляров службы прежний
  код узнаёт суперпользователя по прежнему id: выдача `system.admin` «на кластер, все объекты»
  через прежний экземпляр отвергается `INVALID_ARGUMENT` тем же текстом, что в SRCI-08б. Направление —
  меньше доступа, не больше; существующий доступ не затронут (SRCI-05). Принято без отдельного
  сценария: прод отсутствует, выкатка — один шаг.
- **Д6 — кластерная выдача роли администратора облака принимается, но прав не даёт.** Это
  находка вне предмета; задачу заводит диспетчер, здесь её не чинят. На `092bee4fb` глагол
  принимает `system.admin` на кластере с целью «все объекты» (исключение `helpers.go:380`),
  операция завершается без ошибки, а прав выдача не даёт:
  - у роли есть правила, а для роли с правилами построитель кортежей выдачи выпускает лишь
    указатель выдачи на родителя (`tuples.go:87-93`);
  - на кластере реконсайлер правило-подстановку не разворачивает намеренно
    (`rule_fingerprint.go:216-224`, `reconcile_adapter.go:405`);
  - отношение администратора облака на кластере пишут другие пути: служба кластера
    (`cluster/helpers.go:77`), посев первого администратора и восстановление объявленным путём.

  Записанное намерение обратное: `docs/engineering/architecture/explicit-rbac-model.md:187-189`
  («этот binding эмитирует то самое cluster-relation») и шапка `role_cluster_admin.go:49`.
  Измерено контролем фикстуры @`3ca34095c`: выдача формы `B6` глаголом — без ошибки, фактов
  отношения о субъекте 0, Check `update` на объекте — отказ.

  Что из этого следует здесь. SRCI-05 о праве по `B6` не утверждает ничего, SRCI-08 утверждает
  только приём выдачи и её `roleId`. Закрытие находки не покраснит ни один сценарий этой
  приёмки, а её перенос id — не помеха закрытию: факт отношения ключуется субъектом, а не id
  роли. Направление дефекта — меньше доступа, не больше.

## §8а. Условия к замыслу (не к приёмке)

Условия реализации, без которых «Тогда» не держится, но которые наблюдаемого поведения не
добавляют (`flow-acceleration.md` fa-b2). Здесь они названы, решаются — в замысле.

- **У1 — замок строки прежней роли до фиксации (SRCI-11).** Ключи на роль без `ON UPDATE`
  (§0.3), значит перенос — «вставить новую строку роли → перевести ссылки → снять прежнюю».
  Вставка выдачи на прежний id, зафиксированная после снимка перевода ссылок, уронила бы саму
  миграцию нарушением ключа на снятии роли. Миграция обязана держать замок строки прежней роли
  с начала переноса до фиксации: тогда конкурирующая вставка либо зафиксирована до замка и
  переводится, либо ждёт и после фиксации получает отказ ключа — страж
  `access_bindings_role_is_live` при отсутствии строки отдаёт решение ключу
  (`0001_initial.sql:281-286` → `23503`).
- **У2 — форма переноса даёт события SRCI-12.** Перенос вставкой новой строки, правкой ссылок и
  снятием прежней строки даёт `CREATED`/`UPDATED`/`DELETED` триггерами ленты by construction.
  Если замысел выберет иную форму (правку `roles.id` при временно изменённых ключах), правка
  `id` даёт `UPDATED` с `resource_id` НОВОГО id, а о прежнем — ничего: такая форма обязана
  дописать `DELETED` о прежнем id сама. Имя роли уникально на кластере для системных ролей
  (`roles_system_unique`, `0001_initial.sql:4905`), поэтому вставка копии под тем же именем до
  снятия прежней невозможна без промежуточного шага; лишние события такого шага SRCI-12
  допускает (утверждает минимум и последние/первые события), но не допускает `DELETED` о новом
  id и `CREATED`/`DELETED` о выдачах.
- **У3 — исход механизма «посеянного вопреки длине»** — Д3.

---

## §9. Признаки маршрута (для диспетчера)

proto — нет · схема БД — да (миграция данных, без DDL предмета; если замысел выберет перенос
ключей через смену поведения внешних ключей — DDL временный, внутри миграции) · публичный RPC
или край — поведение есть (SRCI-04: прежние id), полей нет · UI — нет · новый домен/сервис —
нет · межсервисное ребро — нет · поверхность безопасности — да (исключение суперпользователя
по id, SRCI-08; сужение приёма формы id, SRCI-04) · поток изменений — да: лента подписки
получает события о смене id ролей и выдач (SRCI-12, Р4), очереди прав и смены субъекта —
ни одного (SRCI-07).
