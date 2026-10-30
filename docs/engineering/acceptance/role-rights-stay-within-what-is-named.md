<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: права в ролях не расширяются сверх названного

- **Статус:** DRAFT, редакция 4. Вердикта на эту редакцию нет, санкции на код нет (ban #1).
  Вердикт выносит `acceptance-reviewer`
- **Статическая форма:** DRAFT. Слово вписано автором и вердиктом не является. Действующее
  одобрение выводится из записи ревью по отпечатку редакции и из внешнего события, на которое
  запись ссылается (`change-graph.md` §3). После ревью слово DRAFT не правится
- **История ревью:** только дописывается строками вида «дата · круг · вердикт · SHA-256
  редакции · путь записи». Прежние строки не правятся и не удаляются. Записи кладутся в
  `docs/specs/reviews/role-rights-stay-within-what-is-named/<sha256>.yaml`
  - 2026-10-26 · круг 1 · CHANGES_REQUESTED · `20039abfd0d6e89d3e6aa10f5a48d0f9a9fb5886639e090738ef83c2388883ab`
    (редакция 1) · `docs/specs/reviews/role-rights-stay-within-what-is-named/20039abfd0d6e89d3e6aa10f5a48d0f9a9fb5886639e090738ef83c2388883ab.yaml`
  - 2026-10-26 · круг 2 · CHANGES_REQUESTED · `c6f3981e1ec6b6a9e60b7de030eb31619421bd63bd82375345b1ed31e9aff5fb`
    (редакция 2) · `docs/specs/reviews/role-rights-stay-within-what-is-named/c6f3981e1ec6b6a9e60b7de030eb31619421bd63bd82375345b1ed31e9aff5fb.yaml`
  - 2026-10-26 · сверка дельты после круга 2 · APPROVED · `8f141cbd7fed24693847bc1344bcd77a7f7490431bba7c2edc71378bd2ed7b26`
    (редакция 3; в её шапке стояло «редакция 2») · `docs/specs/reviews/role-rights-stay-within-what-is-named/8f141cbd7fed24693847bc1344bcd77a7f7490431bba7c2edc71378bd2ed7b26.yaml`
  - 2026-10-26 · редакция 4 · вердикта нет · правка одобренной редакции 3 строго по решениям
    диспетчера В-4.1…В-4.3 (§11); прежнее одобрение к этому отпечатку не относится
- **Дата:** 2026-10-26 · **редакция:** 4 (решения диспетчера по исполнению `#1037` — §11)
- **Задачи:** эпик `PRO-Robotech/kaname#1034` (выдача доступа требует владения выдаваемым);
  подзадачи `#1035` (право выдавать не выводится из глагола роли), `#1036` (правка роли и право
  выдавать), `#1037` (состав группы и право выдавать), `#1039` (право удалять не открывает
  изменений). Связь: `#986` (делегирование выдач, посажено на ветку эпика)
- **Ревизия измерения:** kaname `ddd5681af` (голова `origin/955`). Каждое утверждение о дереве
  ниже снято на этой ревизии командой рядом. Посева и прогона сценариев не было: «Дано»
  показано писателем со строкой (§5.2). Исключение редакции 4 — прогон проб ESC-23 и гонок
  поверх продукта этой ревизии (§0.2, §6 S1 п.5; команда и цитата — §11)
- **Тип изменения:** поведение `AccessBindingService.Create` (право выдавать),
  `RoleService.Update`, `GroupService.AddMember`, материализация выдач (ярус, выводимый из
  глаголов правила), ответы `AuthorizeService.Check` и `AuthorizeService.ListSubjects` для
  действия удаления. Сужённый ярус читают и прочие пути службы — перепись в §0.7: право выдавать
  (десять путей, включая отзыв, чтение и перечень выдач и право делегирующего), право
  спрашивать о чужом субъекте, четыре прямых вопроса об отношении `admin` и двери каталога с
  ярусом на области. Полей и сообщений `.proto` не добавляется; меняются комментарии контракта,
  описывающие вывод яруса (§6 S1 п.6). Миграции схемы эта приёмка не требует: решение
  реализации — в замысле; накат, если он появится, держит ESC-32
- **Сервис:** `kaname`

**Как сейчас:** перечисленные ниже свойства сегодня не держатся — `#1035`, `#1036`, `#1037`,
`#1039`; разбор — в задачах, здесь не повторяется.

---

## §0. Перепись производителей — до сценариев

Перепись называет, ЧТО в дереве уже производит каждое «Тогда» этой приёмки, а что заказано.

### 0.1. Форма отказа в праве

```sh
git grep -n 'func PermissionDenied' -- internal/authzguard
# → internal/authzguard/authzguard.go:63
```

Отказ — `PERMISSION_DENIED`, текст `permission denied`, без деталей. Его же отдаёт
`AccessBindingService.Create`, когда у вызывающего нет права выдавать (`requireGrantAuthority`,
`internal/apps/kaname/api/access_binding/helpers.go:155`, вызов — `create.go:278`), и право
спрашивать о чужом субъекте (`internal/apps/kaname/api/authorize/caller_authority.go`, тот же код
и текст). В интеграционном мире эталон Р2 и Р3 — эта форма (код, сообщение, деталей нет). На
слушателе к отказу добавляются сведения о методе (`authzguard/deny_details.go`), поэтому
неотличимость отказа Р2/Р3 от отказа без права на ТОМ ЖЕ методе судят сквозные ESC-E3, ESC-E4.

### 0.2. Форма отказа «участника нет»

```sh
git grep -n -A1 "RAISE EXCEPTION USING ERRCODE = '23503'" -- internal/migrations/0001_initial.sql | head -2
# → :357 (триггер group_members_member_exists, текст '%s %s not found')
git grep -n 'referenced resource does not exist' -- internal/repo/kaname/pg/pgmaperr.go
# → :678 (неразобранная связь 23503 со стороны ссылки — общий текст)
```

Добавление в группу несуществующего участника завершает операцию ошибкой
`FAILED_PRECONDITION`, текст `referenced resource does not exist; create it or correct the
reference before retrying`, деталей в мире проб нет. Текст триггера наружу не идёт:
преобразователь отказа хранилища заменяет его общим (`pgmaperr.go:678`), и в тексте нет ни
вида, ни идентификатора участника. Так измерено прогоном (§11); шапка
`internal/apps/kaname/api/group/add_member.go:7-9`, называющая текст триггера, с измеренным
расходится. Через край — `code` 9, тот же текст, признак `REFERENCE_MISSING` (кейс
`IAM-GRP-AM-NEG-MEMBER-MISSING`, `tests/newman/cases/iam-group.py:1012-1014`). Триггер этой
ревизии проверяет только существование участника (`0001_initial.sql:345-358`). Эта форма —
эталон для участника из чужого аккаунта (Д-3).

### 0.3. Где проверяется право правки роли и группы

```sh
grep -n -E 'rpc (Update|AddMember|RemoveMember) |required_relation' \
  proto/kaname/cloud/iam/v1/role_service.proto proto/kaname/cloud/iam/v1/group_service.proto
# → RoleService.Update :108 — v_update на iam_role (:114)
#   GroupService.AddMember :109, RemoveMember :126 — v_update на iam_group
```

Право ПРАВИТЬ роль и группу судит дверь слушателя до обработчика. Права ВЫДАВАТЬ ни
`RoleService.Update`, ни `GroupService.AddMember` сегодня не спрашивают — его вводят Р2, Р3.

### 0.4. Делегированный путь

Путь делегата (`#986`) держат пробы `TestGrantDelegation_GD10` (выдача по делегированию),
`TestGrantDelegation_GD11`, `TestGrantDelegation_GD16` (субъект из аккаунта делегирования) и
`TestGrantDelegation_GD25` (делегат не трогает проекты, группы, роли). Их утверждения эта
приёмка не меняет (Р4). Меняются две фикстуры, которые кладут в группу acc-A участника не из
acc-A, — Д-3 их исход меняет (В-4.2, §11). Перепись — по дереву полосы `#1037` @`ef558bd04`:

```sh
git grep -n -E 'AddMember(UseCase|Input|Request)?\b|INSERT INTO (kaname\.)?group_members' ef558bd04 \
  -- 'internal/apps/kaname/api/access_binding/grant_delegation_*'
# → 7 строк в 3 файлах из 14 grant_delegation_*: две фикстуры добавления, одна провязка мира
#   (grant_delegation_world_integration_test.go:376), прочее — комментарий и вызовы тех же двух
```

| фикстура | координата @`ef558bd04` | участник → группа | приведение (В-4.2) |
|---|---|---|---|
| GD-25 строка e, `GroupService.AddMember` через дверь | `grant_delegation_cd_bounds_integration_test.go:179-184` | usr-B (`mustSeedUser`: свой аккаунт, членства в acc-A нет) → grp-A | участник — член acc-A: usr-M (членство `ACTIVE`, мир Д) |
| Д4 приёмки делегирования, `TestGrantDelegation_D4_GroupHoldingTheDelegateIsRefused` (состав группы с делегатом) | `grant_delegation_b_grant_integration_test.go:278-286` | sva-iss2 (учётка acc-S) → grp-A | прежнее состояние: строка `kaname.group_members` сеется посевом мира, а не добавлением через API |

Посев строкой Д4 исполним, пока Д-3 держится в операции (Д-4). Если реализация держит Д-3 в
схеме, строка Д4 сеется так же, как в ESC-32, — на схеме, которая её принимает.

### 0.5. Записи каталога прав, спрашивающие ярус на листовом объекте

```sh
jq -r '.[] | select((.required_relation|IN("viewer","editor","admin"))
  and (.scope_extractor.object_type|IN("cluster","account","project","")|not)) | .fqn' \
  internal/apps/kaname/seed/embedded/permission_catalog.json | wc -l
# → 8 (viewer 2, editor 5, admin 1); все восемь — методы модулей платформы, ни одного метода kaname
```

Копия каталога у службы обязана побайтово совпадать с копией края платформы (`Makefile`,
блок `check-permission-catalog`); источник этих восьми строк — аннотации контрактов модулей
в `PRO-Robotech/kacho`. Порядок — решение В2 (§3), внешняя зависимость §7 строка 1.

### 0.6. Посылка задачи

Посылка «свойства на `main` и на `955` одинаковы» — из задач `#1035`, `#1036`, `#1037` (сверка
ревизий там). Для `#1039` сверка не проведена (так сказано в задаче); эта приёмка её не
требует — DoD судит ревизию головы полосы.

### 0.7. Кто читает выведенный ярус — перепись следствий Р1

Р1 меняет вывод яруса, поэтому меняется ответ каждого читателя яруса для держателя, чьё
право держалось только на `delete`. Перепись — двумя предикатами.

**По написанию — право выдавать:**

```sh
git grep -n -E 'requireGrantAuthority\(|grantAuthorityBeyondClusterAdmin\(' -- internal ':!*_test.go' | grep -v 'func '
# → 12 строк: 2 — внутренние обёртки (helpers.go:178, :338), 10 — пути службы
```

| путь | координата | что теряет держатель одного `delete` |
|---|---|---|
| выдача | `create.go:278` | право выдавать (ESC-01, ESC-02) |
| правка выдачи | `update.go:167` | право править выдачу |
| отзыв и удаление выдачи | `removal_authority.go:72` | право снять выдачу |
| чтение выдачи | `get.go:125` | полный вид чужой выдачи |
| перечень по области | `list_by_scope.go:60` | перечень выдач области |
| перечень по аккаунту | `list_by_account.go:77` | перечень выдач аккаунта |
| перечень по роли | `list_by_role.go:180` | перечень выдач роли |
| выдаваемые роли | `list_assignable_roles.go:81` | список ролей к выдаче |
| развёртка доступа | `expand_access.go:204` | ответ «откуда доступ» |
| право делегирующего | `delegated_grant.go:258` | см. ниже, «Делегирование» |

**По предмету — вопросы об отношении `admin`:**

```sh
git grep -n -E 'Relation: *"admin"|, "admin"\)|"admin",' -- internal/apps internal/service ':!*_test.go' | wc -l
# → 12: вопросов к модели 4 — helpers.go:323 (тот же путь права выдавать), subject_read_authority.go:574,
#   account/list_all_operations.go:162, grant_delegation/authority.go:45 (заведение делегирования);
#   не вопросы 8 — invite_authz.go ×4 (перечень ролей приглашения), mirror_tx.go:651 (писатель),
#   tuples.go:301 (отображение на кластер), permission_catalog.json:859 (строка §0.5),
#   authorize_service.go:1380 (дословная передача имени отношения)
git grep -n 'callerAuthorityRelations' -- internal ':!*_test.go'
# → caller_authority.go:55 (= {"admin"}), :122 — право спрашивать о чужом субъекте (ESC-06 б)
git grep -n 'resolveActionToRelation(' -- internal ':!*_test.go'
# → authorize_service.go:1258 — ListSubjects: `delete` → `admin` (:1349) (ESC-06 а)
```

**Двери каталога с ярусом на области:**

```sh
jq -r '.[] | select(.required_relation|IN("viewer","editor","admin"))
  | [(.fqn|startswith("kaname.")), (.scope_extractor.object_type//"")] | @tsv' \
  internal/apps/kaname/seed/embedded/permission_catalog.json | sort | uniq -c
# → методы kaname 13 (account 9, project 3, cluster 1); методы модулей платформы 56
#   (project 40, cluster 8, листовые 8 — §0.5)
```

Каждое следствие — то, что задумано Р1: из одного `delete` не выводится ни право выдавать, ни
ярус (В1), значит, ни один читатель яруса держателю одного удаления больше не отвечает «да».
Два читателя меняются сверх этого. Первый — `ListSubjects` для действия удаления: его ответ
обязан совпадать с ответом `Check(delete)` (ESC-05), иначе держатель одного удаления выпал бы из
ответа «кто может удалить X» — ESC-06 а. Второй — право спрашивать о чужом субъекте: держатель
одного удаления его теряет — ESC-06 б.

**Делегирование.** Делегирование, у которого делегирующий держал право выдавать на аккаунте
только через ярус из одного `delete` (роль аккаунта `{iam, [account], [delete]}`), после Р1
выдавать перестаёт. Правило то же, что для любого делегирующего, утратившего право: Д3 приёмки
делегирования, «делегирующий вправе выдавать в момент выдачи» (`delegated_grant.go:258`). Сам путь
делегата не меняется (Р4, ESC-31). Во встроенном манифесте ролей, называющих `delete`, нет (§3 В1,
счёт 0) — такое делегирование возможно только от роли, заведённой аккаунтом.

---

## §1. Предмет

Каждое право, которое даёт роль, — ровно то, что названо в её правилах. Роль не даёт права
выдавать доступ, если его не назвали явно, и никакая правка роли или состава группы не даёт
правящему больше, чем он сам вправе выдать.

Четыре решения диспетчера (§3) переводятся в наблюдаемое поведение четырёх глаголов и в
ответ модели прав на вопросы «можно ли» и «кто может».

## §2. Что НЕ входит

1. **Модель `bind` и `escalate` целиком** — явное отношение «вправе выдавать эту роль»,
   отдельное от яруса, и проверка escalate на `RoleService.Create` и `Update` по правилам роли
   против прав вызывающего. Это эпик `#1034`, вторая подфаза. Здесь — только сужения Р1–Р3,
   выраженные через существующее право выдавать на области
2. **Отзыв существующего.** Выдачи, роли и составы групп, заведённые до правки, не
   отзываются и не правятся (Р4). Их материализация пересчитывается по новому выводу яруса
   (ESC-30) — это не отзыв выдачи
3. **`RoleService.Create`.** У новой роли нет действующих выдач, проверять по Р2 нечего
4. **`RoleService.Delete`, `GroupService.Delete`, `RemoveMember`.** Сужают доступ, права
   выдавать не требуют; поведение прежнее (ESC-24 — держатель для `RemoveMember`)
5. **Делегированный путь права выдавать (`#986`)** — без изменений (Р4); судьба делегирования,
   чей делегирующий держал право только через `delete`, — §0.7 «Делегирование»
6. **Правка восьми строк каталога у края платформы** — делает владелец контракта в
   `PRO-Robotech/kacho`; здесь — внешняя зависимость §7 и решение В2
7. **Субъекты выдачи из чужого аккаунта на прямом (не делегированном) пути выдачи.** Сверка
   «субъект из аккаунта области» на пути `AccessBindingService.Create` вне делегирования этой
   приёмкой не вводится; для группы — вводится (Р3)
8. **Роли с подстановкой `*` и владелец аккаунта** — их права не меняются (Р1)
9. **Читатели яруса из §0.7 поштучно.** Их новый ответ — прямое следствие вывода яруса (ESC-03,
   ESC-04); отдельного сценария на каждый из десяти путей права выдавать нет. Сценарии есть на
   выдачу (ESC-01, ESC-02), на `ListSubjects` и право спрашивать о чужом субъекте (ESC-06)

---

## §3. Решения

### Решения диспетчера (2026-10-26, не переоткрываются)

**Р1 (`#1035`, `#1039`).** Глагол `delete` в правиле роли даёт только право удалять. Ярус
`admin`, право выдавать доступ и действия уровня `editor` из одного `delete` не выводятся.
Сначала записи каталога, требующие ярус на листовом объекте, переводятся на свои отношения
`v_*`. Затем `delete` снимается из вывода яруса. Роль `[update, delete]` не теряет того, что
даёт `update`. Владелец аккаунта и роли с `*` не меняются.

**Р2 (`#1036`).** Правка правил роли, у которой есть действующие выдачи, допускается, только
если правящий сам вправе выдать эту роль на областях её выдач. Иначе отказ
`PERMISSION_DENIED`, побайтово как отказ без права. Администратор аккаунта — приём.

**Р3 (`#1037`).** Добавить участника в группу, у которой есть выдачи, можно, только если
добавляющий вправе выдавать на областях всех выдач группы. Участник обязан принадлежать
аккаунту группы.

**Р4.** Существующие выдачи, роли и составы групп не отзываются. Путь делегата (`#986`) и
`Check(delete)` других потребителей — без изменений.

**В1 → (а).** Одно `delete` НЕ даёт и яруса `viewer` — только `v_delete`, как в ролевой модели
Kubernetes (глагол удаления не даёт чтения). Правило, все глаголы которого — `delete`, после
правки не даёт объекту ни одного яруса — ни `admin`, ни `editor`, ни `viewer`. Цена:
держатель роли «только удалять» не видит объект в списке. Во встроенном манифесте ролей,
называющих `delete`, нет ни одной (`git grep -n -E 'classes:.*delete' -- manifest.yaml` → 0).
Держатели — строки `viewer` в ESC-03, ESC-04.

**В2 → (а).** kaname снимает `delete` из вывода яруса сейчас. Восемь строк каталога с ярусом на
листовом объекте (§0.5) — методы модулей платформы — правятся в `PRO-Robotech/kacho` до того,
как kacho перезакрепит новую версию kaname. Пока край kacho новую kaname не закрепил, он её
об этих методах не спрашивает. Предикат §7 строка 1 — ворота перезакрепления в kacho, а не
DoD S1: до правки края копия каталога у kaname сохраняет восемь строк, и
`check-permission-catalog` зелёный. В задаче интеграции kacho нужна строка о порядке (§6 S1
п.10).

Номер смежной задачи о праве удалять — `#1039` (`#1038` — шаг установки registry, к предмету не
относится: `gh issue view 1038 -R PRO-Robotech/kaname`).

### Решения и допущения автора

**Д-2. «Вправе выдать на области» — то же право, что спрашивает `AccessBindingService.Create`
на этой области**, после сужения Р1: администратор облака, владелец аккаунта области,
ярус `admin` на объекте области. Делегированный путь (`#986`) в Р2 и Р3 правом не
считается: делегирование ограничено ролями и целями модуля, а роль аккаунта и группа в его
перечень не входят (`TestGrantDelegation_GD25`).

**Д-3. Участник из чужого аккаунта неотличим от несуществующего.** Отказ по Р3 «участник не
из аккаунта группы» — та же форма, что у несуществующего участника (§0.2): операция
завершается ошибкой `FAILED_PRECONDITION` `referenced resource does not exist; create it or
correct the reference before retrying` (В-4.1). Иначе ответ
различал бы «такой учётки нет» и «такая учётка есть в другом аккаунте» — оракул существования
чужих субъектов (`security-hardening.md`, скрытие существования). Принадлежность — по Д6
приёмки делегирования (§3 «Д6» там): учётка — `service_accounts.account_id` равен аккаунту
группы; человек — строка `kaname.memberships` пары «человек, аккаунт группы» в состоянии
`ACTIVE`, читатель — `UserReader.Membership` (`internal/repo/kaname/pg/user_repo.go:158`).
Приглашённый (`PENDING`) участником не считается. Ни выдача на аккаунт (в том числе
администратора аккаунта), ни владение аккаунтом сами по себе членством не являются: судится
только строка членства. Строку заводит приглашение либо колонка аккаунта в строке человека
(`membership_mirror_from_user`, `0001_initial.sql:1197`); человек с выдачей на аккаунт, но без
строки `ACTIVE`, участником не считается — так же, как в Д6.

**Д-4. Порядок проверок.** `RoleService.Update`: форма запроса и маски → существование роли
→ системная роль → проверка правил (форма, каталог) → **право по Р2** → операция. Отказ по Р2
синхронный, операции нет. `GroupService.AddMember`: форма → существование группы → тип
участника → **право по Р3** (синхронно, операции нет) → операция → **принадлежность
участника** (Д-3, в операции, как сегодня несуществующий участник). Отказ в праве поэтому ничего
не говорит об участнике.

**Д-5. «Правка правил»** — запрос, маска которого называет `rules`. Правка только имени или
описания права выдавать не требует (ESC-12).

**Д-6. «Действующая выдача»** — выдача в состоянии `ACTIVE`. Отозванная или истёкшая права
не открывает и в Р2, Р3 не участвует (ESC-11 b).

### Критерии продукта (ban #18)

| критерий | ответ |
|---|---|
| производительность | Р2 и Р3 добавляют чтение выдач роли или группы и вопрос о праве на каждую их ОБЛАСТЬ (не на выдачу): число вопросов ≤ числа различных областей. Замер — `EXPLAIN` чтения выдач по роли и по группе-субъекту в `DoD-proof` (§6 S1 п.8) |
| безопасность | поверхность сужается: три пути получить больше, чем вправе выдать, закрыты; новый текст наружу не появляется (формы §0.1, §0.2); оракул существования чужих субъектов не заводится (Д-3) |
| иновационность | правка роли и состава группы судится тем же правом, что выдача, — одно правило на три глагола вместо трёх |
| узнаваемость | соответствует `bind`/`escalate` ролевой модели Kubernetes (эпик `#1034`): глагол даёт ровно названное, правка роли не шире права выдавать |
| перспективность | контракт не меняется, координаты не трогаются, данные арендатора не мигрируют; вторая подфаза (явное `bind`) расширяет проверку, не ломая этих сценариев |
| благо продукта | выигрыш — закрытие повышения привилегий внутри аккаунта, а не экономия работы |
| производственность | режима «только для стенда» нет; переходного флага нет |

---

## §4. Сценарии

### 4.1. Мир проб

**Мир Э** — `newEscWorld` (заказан, `internal/apps/kaname/api/access_binding/`) поверх мира Д
`newGDWorld` (`grant_delegation_world_integration_test.go:144`). Мир Д уже даёт:

- аккаунт acc-A (владелец usr-A), проект prj-A, учётки sva-A2, sva-A3 в acc-A; аккаунт acc-B
  (владелец usr-C, членства в acc-A нет), учётка sva-B в acc-B;
- реестр X = `reg00000000000000001` в prj-A (`registerRegistry`,
  `public_container_read_world_integration_test.go:179`);
- людей usr-M (членство в acc-A `ACTIVE`) и usr-P (`PENDING`) — `gdSeedMembership`
  (`grant_delegation_world_integration_test.go:266`);
- администратора аккаунта usr-E — каноническая роль `admin` на acc-A, цель — вся область
  (там же, поле `grantE`);
- роли модуля iam из встроенного манифеста — по имени (`roleByName`, `:298`);
- полный проход материализатора — `rec` мира П6 (`public_container_read_world_integration_test.go:306`).

Дополнения мира Э (каждое — посевом мира или существующим глаголом, §5.2). В мире Э, сверх мира
Д, провязаны `RoleService.Update`, `GroupService.AddMember`, `GroupService.RemoveMember` и
обработчик `AuthorizeService` (заказано, §5.2).

**Роли аккаунта acc-A** (`seedRole`, `public_container_read_world_integration_test.go:152` —
тремя сторонами, как `RoleService.Create`):

| роль | правила |
|---|---|
| rol-del | `{module: iam, resources: [project], verbs: [delete]}`, `{module: registry, resources: [registries], verbs: [delete]}` |
| rol-upd-del | те же два правила с `verbs: [update, delete]` |
| rol-star | те же два правила с `verbs: ["*"]` |
| rol-acc-del | `{module: iam, resources: [account], verbs: [delete]}` |
| rol-e1, rol-e0, rol-er, rol-e2 | `{module: registry, resources: [registries], verbs: [get]}` — роли под правку |
| rol-g | `{module: registry, resources: [registries], verbs: [get]}` — роль выдач группам |

**Люди** (`mustSeedUser`, `testhelpers_assignable_test.go:80`) и их выдачи. Каждая выдача —
`AccessBindingService.Create` от usr-A, цель `{"allInScope":{}}`:

| человек | выдачи | что это в мире |
|---|---|---|
| usr-D | rol-del на `iam.project` prj-A | только удаление |
| usr-U | rol-upd-del на prj-A | правка и удаление |
| usr-W | rol-star на prj-A | все глаголы (`*`) |
| usr-Da | rol-acc-del на `iam.account` acc-A | только удаление, на аккаунте |
| usr-R | `iam.role.edit` на acc-A; rol-e1 на prj-A; rol-e2 на prj-A | правка ролей без права выдавать |
| usr-RP | `iam.role.edit` на acc-A; rol-star на prj-A | правка ролей и право выдавать на prj-A |
| usr-G | `iam.group.edit` на acc-A | правка групп без права выдавать |
| usr-GP | `iam.group.edit` на acc-A; rol-star на prj-A | правка групп и право выдавать на prj-A |

**Выдачи ролей под правку** (от usr-A, цель — вся область): rol-e1 → usr-R на prj-A;
rol-e0 — выдач нет; rol-er → sva-A3 на prj-A, затем `AccessBindingService.Revoke` от usr-A
(действующих выдач нет, отозванная есть); rol-e2 → usr-R на prj-A и → sva-A3 на acc-A. Выдачи
rol-e1 и rol-e2 на prj-A одинаковы (субъект, область, цель); rol-e2 отличается от rol-e1 ровно
второй выдачей на acc-A.

**Группы аккаунта acc-A** (`seedGroup`, `system_class_world_integration_test.go:173`) и их
выдачи (rol-g, от usr-A, цель — вся область): grp-e1 — выдача на prj-A; grp-e0 — выдач нет;
grp-e2 — выдачи на prj-A и на acc-A. Участников в начале нет ни у одной.

**Положительные контроли посева** (`pollRelation`, `grant_delegation_world_integration_test.go:439`;
мир, не прошедший контроль, краснеет контролем, а не предметом):

- usr-D — `v_delete` на `registry_registry:X` и на `project:prj-A`; usr-U — `v_update` на X;
- usr-W и usr-RP — `admin` на `project:prj-A`; usr-W — `admin` на `registry_registry:X`;
- usr-R — `v_update` на `iam_role:rol-e1` и `iam_role:rol-e2`; usr-G — `v_update` на `iam_group:grp-e1`;
- rol-er — в `AccessBindingService.ListByRole` одна выдача, `REVOKED`; rol-e2 — две `ACTIVE`.

**Вопрос модели** — двумя формами:

- **с отношением** (`required_relation: <отношение>` в таблицах) — дверь решения мира
  (`relation`, `grant_delegation_world_integration_test.go:426` — та же дверь, что у
  `AuthorizeService.Check`; отношение спрашивается дословно); право спрашивать о чужом субъекте
  в этой форме не участвует;
- **с действием** (`action: <модуль>.<ресурс>.<глагол>`) — обработчик `AuthorizeService` мира Э,
  построенный как `anonSelfCheckHandler` (`anonymous_self_check_module_verb_integration_test.go:46`,
  те же части, что корень службы); вызывающий — модуль (`moduleCtx()`,
  `system_class_world_integration_test.go:245`), как ND-02 (`nested_rule_world_integration_test.go:239`).
  Модульного вызывающего право спрашивать о чужом субъекте пропускает (`caller_authority.go`,
  шапка). Вызывающий-человек назван только в ESC-06 б, где предмет — само это право.

Ответ читается после окна материализации — повтор в ограниченном окне, как `pollRelation`.
Ожидание `false` утверждается после того, как в том же окне парный контроль того же мира стал
`true`.

**Тело выдачи V-E** (вызов от названного в сценарии): область `iam.project` prj-A, роль rol-g,
субъект `{"type":"SUBJECT_TYPE_SERVICE_ACCOUNT","id":"<sva-A2>"}`, цель `{"allInScope":{}}`.

**Тело правки U-R** (`RoleService.Update`): `roleId` — названная роль,
`updateMask: "rules"`, `rules: [{"module":"registry","resources":["registries"],"verbs":["*"]}]`.

**Тело добавления AM** (`GroupService.AddMember`): `groupId` — названная группа,
`memberType: "service_account"`, `memberId: "<sva-A2>"`.

Каждый сценарий — на свежем мире. Строки таблиц отличаются от названного близнеца ровно одним
фактом, он назван в строке.

### Группа A — право удалять даёт только удаление (Р1; `#1035`, `#1039`)

#### ESC-01 · одно право удалять на проекте не даёт права выдавать

**Given** мир Э
**When** вызывающий из таблицы вызывает `AccessBindingService.Create` с телом V-E
| пример | вызывающий | отличие от a | исход |
|---|---|---|---|
| a | usr-D (rol-del) | — | `PERMISSION_DENIED` `permission denied`, синхронно, операции нет |
| b | usr-U (rol-upd-del) | `update` в глаголах | `PERMISSION_DENIED` `permission denied`, синхронно |
| c | usr-W (rol-star) | глаголы `*` | `done`, `error` пуст; выдача `ACTIVE` |
| d | usr-E (`admin` на acc-A) | вызывающий — администратор аккаунта | `done`; выдача `ACTIVE` |
| e | usr-A (владелец acc-A) | вызывающий — владелец | `done`; выдача `ACTIVE` |

**Then** как в таблице; в a, b выдач на prj-A — столько же, сколько до вызова
**And** в c `Check(sva-A2, required_relation: v_get, registry_registry X)` — истина в окне
**And** близнецы: a — c (глаголы роли: `delete` против `*`); b — c (глаголы `[update, delete]`
против `*`): `update` права выдавать не добавляет.

#### ESC-02 · право удалять на аккаунте не даёт ни права выдавать, ни прав в его проектах

**Given** мир Э
**When** usr-Da и usr-E выполняют строки таблицы
| пример | действие | usr-Da (rol-acc-del) | usr-E (`admin`) |
|---|---|---|---|
| a | `AccessBindingService.Create`: тело V-E с областью `iam.account` acc-A | `PERMISSION_DENIED` `permission denied` | `done` |
| b | `AccessBindingService.Create`: тело V-E | `PERMISSION_DENIED` `permission denied` | `done` |
| c | `Check`, `required_relation: editor`, `project:prj-A` | `false` | `true` |
| d | `Check`, `required_relation: v_get`, `registry_registry:X` | `false` | `true` |
| e | `Check`, `action: iam.accounts.delete`, `account:acc-A` | `true` | `true` |

**Then** как в таблице
**And** близнец по одному факту: роль выдачи на той же области с той же целью (rol-acc-del
против канонической `admin`); строка e показывает, что право удалять аккаунт сохранено (Р4).

#### ESC-03 · ярус проекта из одного удаления не выводится

**Given** мир Э
**When** проба задаёт `Check` с `required_relation` из таблицы на `project:prj-A`
| отношение | usr-D (`delete`) | usr-U (`update, delete`) | usr-W (`*`) |
|---|---|---|---|
| `admin` | `false` | `false` | `true` |
| `editor` | `false` | `true` | `true` |
| `viewer` | `false` (В1) | `true` | `true` |
| `v_delete` | `true` | `true` | `true` |

**Then** как в таблице
**And** близнецы: usr-D — usr-U по `editor` (одно `update` в глаголах: роль `[update, delete]`
не теряет того, что даёт `update`); usr-U — usr-W по `admin` (глаголы `*`).

#### ESC-04 · на листовом объекте право удалять не открывает изменений

**Given** мир Э
**When** проба задаёт `Check` на `registry_registry:X`
| пример | вопрос | usr-D | usr-U | usr-W |
|---|---|---|---|---|
| a | `action: registry.registries.update` | `false` | `true` | `true` |
| b | `required_relation: editor` | `false` | `true` | `true` |
| c | `required_relation: admin` | `false` | `false` | `true` |
| d | `required_relation: viewer` | `false` (В1) | `true` | `true` |

**Then** как в таблице
**And** близнецы: usr-D — usr-U в a, b (глагол `update` в правиле); usr-U — usr-W в c (`*`).

#### ESC-05 · удаление остаётся удалением (Р4: `Check(delete)`)

**Given** мир Э
**When** проба задаёт `Check`
| пример | вопрос | usr-D | usr-U | usr-W | usr-E | usr-A | usr-M |
|---|---|---|---|---|---|---|---|
| a | `action: registry.registries.delete`, `registry_registry:X` | `true` | `true` | `true` | `true` | `true` | `false` |
| b | `required_relation: v_delete`, `registry_registry:X` | `true` | `true` | `true` | `true` | `true` | `false` |
| c | `action: iam.projects.delete`, `project:prj-A` | `true` | `true` | `true` | `true` | `true` | `false` |

**Then** как в таблице: ответ на вопрос об удалении тот же, что до правки, у каждого
держателя мира
**And** близнец по одному факту: usr-D — usr-M (выдача rol-del есть / выдач нет).

#### ESC-06 · «кто может удалить» согласен с `Check(delete)`; право спрашивать о чужом не выводится из удаления

**Given** мир Э
**When** строки таблицы — `AuthorizeService.ListSubjects` с ресурсом
`{type: registry_registry, id: X}`, `pageSize: 100`
| пример | вызывающий | действие | исход |
|---|---|---|---|
| а | модуль (`moduleCtx()`) | `registry.registries.delete` | ответ содержит `user:<usr-D>` и не содержит `user:<usr-M>` |
| б1 | usr-D (человек, `asUser`) | `registry.registries.delete` | `PERMISSION_DENIED` `permission denied` |
| б2 | usr-W (человек, `asUser`) | `registry.registries.delete` | ответ получен; содержит `user:<usr-D>` |

**Then** как в таблице
**And** в а держатель одного удаления — в ответе «кто может удалить X», как и `Check(delete)` для
него — истина (ESC-05 a): два ответа на один вопрос не расходятся
**And** близнецы по одному факту: а — usr-D против usr-M (выдача rol-del есть / выдач нет); б1 —
б2: вызывающий с глаголами роли `delete` против `*` (право спрашивать о чужом субъекте на X —
отношение `admin` на X, `caller_authority.go:55`; из одного `delete` оно не выводится, В1).

### Группа B — правка роли не шире права выдавать (Р2; `#1036`)

#### ESC-10 · правка правил роли с действующей выдачей требует права выдавать на её области

**Given** мир Э; у rol-e1 одна действующая выдача — usr-R на prj-A
**When** вызывающий из таблицы вызывает `RoleService.Update` с телом U-R, `roleId` = rol-e1
| пример | вызывающий | отличие от a | исход |
|---|---|---|---|
| a | usr-R | — | `PERMISSION_DENIED` `permission denied`, синхронно, операции нет |
| b | usr-RP | право выдавать на prj-A (выдача rol-star) | `done`, `error` пуст |
| c | usr-E | администратор аккаунта | `done`, `error` пуст |

**Then** в a: `RoleService.Get(rol-e1).rules` равны правилам до вызова;
`Check(usr-R, required_relation: v_delete, registry_registry X)` — `false`; ошибка a равна
`authzguard.PermissionDenied()` по коду, сообщению и деталям (деталей нет) — форма §0.1.
Неотличимость от отказа без права на этом же методе у слушателя держит ESC-E3
**And** в b, c: `Get(rol-e1).rules` равны правилам U-R; `Check(usr-R, required_relation: v_delete,
registry_registry X)` — `true` в окне (действующая выдача следует правилам роли, как сегодня)
**And** близнец: a — b (право выдавать на области выдачи).

#### ESC-11 · без действующих выдач право выдавать не спрашивается

**Given** мир Э
**When** usr-R вызывает `RoleService.Update` с телом U-R
| пример | роль | отличие от ESC-10 a | исход |
|---|---|---|---|
| a | rol-e0 | у роли нет выдач | `done`; `Get(rol-e0).rules` = U-R |
| b | rol-er | единственная выдача отозвана (Д-6) | `done`; `Get(rol-er).rules` = U-R |

**Then** как в таблице.

#### ESC-12 · правка не правил права выдавать не требует

**Given** мир Э
**When** usr-R вызывает `RoleService.Update`: `roleId` = rol-e1, `updateMask: "description"`,
`description: "esc-12"`
**Then** `done`; `Get(rol-e1).description = "esc-12"`, `rules` прежние
**And** близнец ESC-10 a: отличается маской (Д-5).

#### ESC-13 · право нужно на КАЖДОЙ области выдач роли

**Given** мир Э; у rol-e2 действующие выдачи usr-R на prj-A и sva-A3 на acc-A
**When** вызывающий вызывает `RoleService.Update` с телом U-R, `roleId` = rol-e2
| пример | вызывающий | исход |
|---|---|---|
| a | usr-RP (право выдавать на prj-A, не на acc-A) | `PERMISSION_DENIED` `permission denied`, синхронно; `Get(rol-e2).rules` прежние |
| b | usr-E | `done`; `Get(rol-e2).rules` = U-R |

**Then** как в таблице
**And** близнец a — ESC-10 b по одному факту: тот же вызывающий, то же тело, та же выдача
usr-R на prj-A; у rol-e2 сверх неё — выдача sva-A3 на acc-A.

#### ESC-14 · хранилище отношений не отвечает — правка не проходит (fail-closed)

**Given** мир Э; у rol-e1 действующая выдача на prj-A; хранилище отношений отвечает ошибкой
на вопрос о праве выдавать для субъекта `user:<usr-E>` (обёртка двери мира, как `ceFailFor`
в `grant_delegation_ce_integration_test.go:247`)
**When** usr-E вызывает `RoleService.Update` с телом U-R, `roleId` = rol-e1
**Then** `UNAVAILABLE` `authz backend unavailable`, синхронно, операции нет;
`Get(rol-e1).rules` прежние
**And** близнец ESC-10 c: тот же вызов при отвечающем хранилище — `done`.

### Группа C — состав группы не шире права выдавать (Р3; `#1037`)

#### ESC-20 · участник в группу с выдачей — только с правом выдавать на её области

**Given** мир Э; у grp-e1 одна действующая выдача — rol-g на prj-A
**When** вызывающий вызывает `GroupService.AddMember` с телом AM, `groupId` = grp-e1
| пример | вызывающий | отличие от a | исход |
|---|---|---|---|
| a | usr-G | — | `PERMISSION_DENIED` `permission denied`, синхронно, операции нет |
| b | usr-GP | право выдавать на prj-A | `done`, `error` пуст |
| c | usr-E | администратор аккаунта | `done`, `error` пуст |

**Then** в a: `ListMembers(grp-e1)` пуст; `Check(sva-A2, required_relation: v_get,
registry_registry X)` — `false`; ошибка a равна `authzguard.PermissionDenied()` по коду,
сообщению и деталям (форма §0.1); неотличимость от отказа без права на этом же методе у
слушателя держит ESC-E4
**And** в b, c: `ListMembers(grp-e1)` = `[sva-A2]`; `Check(sva-A2, required_relation: v_get,
registry_registry X)` — `true` в окне
**And** близнец: a — b (право выдавать на области выдачи группы).

#### ESC-21 · группа без выдач права выдавать не требует

**Given** мир Э
**When** usr-G вызывает `GroupService.AddMember` с телом AM, `groupId` = grp-e0
**Then** `done`; `ListMembers(grp-e0)` = `[sva-A2]`
**And** близнец ESC-20 a: отличается тем, что у группы нет выдач.

#### ESC-22 · право нужно на КАЖДОЙ области выдач группы

**Given** мир Э; у grp-e2 действующие выдачи на prj-A и на acc-A
**When** вызывающий вызывает `GroupService.AddMember` с телом AM, `groupId` = grp-e2
| пример | вызывающий | исход |
|---|---|---|
| a | usr-GP | `PERMISSION_DENIED` `permission denied`, синхронно; `ListMembers(grp-e2)` пуст |
| b | usr-E | `done`; `ListMembers(grp-e2)` = `[sva-A2]` |

**Then** как в таблице
**And** близнец ESC-20 b: тот же вызывающий, у группы — вторая выдача на acc-A.

#### ESC-23 · участник — только из аккаунта группы (Д-3)

**Given** мир Э; вызывающий usr-E; группа grp-e0 (выдач нет — право выдавать не спрашивается,
судится только принадлежность)
**And** T-нет — текст отказа «участника нет», измеренный на базе (§0.2, §11):
`referenced resource does not exist; create it or correct the reference before retrying`
**When** usr-E вызывает `GroupService.AddMember`, `groupId` = grp-e0; проба поллит операцию
до `done`
| пример | участник | исход |
|---|---|---|
| a | `service_account` sva-A2 (учётка acc-A) | `done`, `error` пуст; участник в `ListMembers` |
| b | `service_account` sva-B (учётка acc-B) | `done`, `error`: `FAILED_PRECONDITION` T-нет |
| c | `user` usr-M (членство в acc-A `ACTIVE`) | `done`, `error` пуст; участник в `ListMembers` |
| d | `user` usr-C (членства в acc-A нет) | `done`, `error`: `FAILED_PRECONDITION` T-нет |
| e | `user` usr-P (членство `PENDING`) | `done`, `error`: `FAILED_PRECONDITION` T-нет |
| f | `service_account` с правильно сформированным id, которого нет нигде | `done`, `error`: `FAILED_PRECONDITION` T-нет |

**Then** как в таблице; в b, d, e, f `ListMembers(grp-e0)` пуст
**And** ошибка b равна ошибке f по коду, тексту и деталям (идентификатора участника в тексте
нет); то же d против f для человека
**And** близнецы по одному факту: a — b (аккаунт учётки); c — d (есть ли членство); c — e
(состояние членства).

#### ESC-24 · убрать участника права выдавать не требует

**Given** мир Э; usr-E добавил sva-A2 в grp-e1 (ESC-20 c)
**When** usr-G вызывает `GroupService.RemoveMember`: `groupId` = grp-e1, `memberType:
"service_account"`, `memberId: "<sva-A2>"`
**Then** `done`; `ListMembers(grp-e1)` пуст; `Check(sva-A2, required_relation: v_get,
registry_registry X)` — `false` в окне
**And** близнец ESC-20 a: тот же вызывающий и та же группа, глагол — снятие, а не добавление.

#### ESC-25 · хранилище отношений не отвечает — участник не добавляется (fail-closed)

**Given** мир Э; у grp-e1 действующая выдача на prj-A; хранилище отношений отвечает ошибкой на
вопрос о праве выдавать для субъекта `user:<usr-E>` (та же обёртка, что в ESC-14)
**When** usr-E вызывает `GroupService.AddMember` с телом AM, `groupId` = grp-e1
**Then** `UNAVAILABLE` `authz backend unavailable`, синхронно, операции нет;
`ListMembers(grp-e1)` пуст
**And** близнец ESC-20 c: тот же вызов при отвечающем хранилище — `done`.

### Группа D — существующее не отзывается (Р4)

#### ESC-30 · материализация, оставленная прежним выводом яруса, сводится к новому без отзыва выдач

Прежняя редакция выводила ярус из глаголов правила (`delete` → `admin`, `internal/domain/rule_verbs.go:158-163`)
и писала ярусный кортеж на каждый объект, где писала `v_*`, под той же координатой члена
(`internal/apps/kaname/api/access_binding/reconcile/tuples.go:68`). Прежнее состояние выдачи
поэтому — новое состояние плюс строка `admin` на каждый объект, где есть `v_delete`.

**Given** мир Э
**And** прежнее состояние, посеянное так, как его оставила прежняя редакция, — одной
транзакцией формы `rewindToPreFix` (`public_container_read_multi_subject_converge_integration_test.go:70`),
одним и тем же оператором для выдачи usr-D и для выдачи usr-W:
- к каждой строке реестра выпущенного этой выдачей (`kaname.access_binding_emitted_tuples`) с
  отношением `v_delete` — строка с отношением `admin` той же выдачи, той же координаты члена,
  того же субъекта и объекта, того же источника (`INSERT … SELECT … ON CONFLICT DO NOTHING`);
- на каждую такую строку — строка журнала записи факта `admin` того же субъекта на том же
  объекте (`kaname.fga_outbox`, форма `gdSeedTuple`, `grant_delegation_world_integration_test.go:278`;
  триггер складывает её в факт тем же коммитом)
**And** контроли посева: `Check(usr-D, required_relation: admin, project:prj-A)` и
`Check(usr-D, required_relation: admin, registry_registry:X)` — истина (прежнее состояние видно);
у выдачи usr-W число строк реестра до посева = после (для `*` оператор ничего не добавил:
ярусные строки там уже есть, форма посева совпадает с формой материализации)
**When** сводящий проход `rec.ConvergeBinding` (`reconcile/reconcile.go:688`) по каждой
действующей выдаче мира — тот самый проход, который `seed.BackfillRunner` исполняет при старте
новой редакции и затем по такту (`internal/apps/kaname/seed/binding_converge.go:84`)
**Then** выдачи usr-D, usr-W, rol-e1 → usr-R, rol-g → grp-e1 — `ACTIVE`, их `id` прежние;
`RoleService.Get(rol-e1).rules` прежние
**And** `Check(usr-D, required_relation: admin, project:prj-A)` и `Check(usr-D, required_relation:
admin, registry_registry:X)` — `false` в окне; `Check(usr-D, required_relation: v_delete, …)` на
обоих — `true`; строк реестра выдачи usr-D с отношением `admin` — 0
**And** `Check(usr-W, required_relation: admin, project:prj-A)` — `true`; строки реестра выдачи
usr-W — те же, что до прохода
**And** повторный проход не пишет ни одной строки журнала (число строк `kaname.fga_outbox` до =
после; форма `TestReconcile_ConvergedModuleRoleBindingIsNotRewritten`,
`reconcile/module_role_implied_delete_test.go:173`)
**And** близнец по одному факту: usr-D — usr-W (глаголы роли: `delete` против `*`; посев и проход
одни).

#### ESC-31 · путь делегата не меняется

**Given** мир Д с делегированием D1 (GD-01 приёмки делегирования)
**When** исполняются сценарии GD-10, GD-11, GD-16, GD-25 приёмки делегирования
**Then** исходы — как в этих сценариях дословно; держатели `TestGrantDelegation_GD10`,
`TestGrantDelegation_GD11`, `TestGrantDelegation_GD16`, `TestGrantDelegation_GD25` зелёные, их
утверждения не ослаблены (§6 S1 п.7)
**And** единственное отличие от текста соседа — участник строки e GD-25: usr-M (член acc-A)
вместо usr-B (В-4.2, §0.4). Свойство строки то же: делегату — `PERMISSION_DENIED`, владельцу
— `done`.

#### ESC-32 · состав группы, принятый прежней редакцией, переживает накат новой

Строку состава с участником из чужого аккаунта новая редакция по построению не заводит (Р3), а
прежняя принимала: триггер этой ревизии проверяет только существование участника (§0.2). Поэтому
строка сеется НА СХЕМЕ прежней редакции — до наката, — и исход не зависит от того, где новая
редакция держит инвариант Р3 (в обработчике, в триггере или в новой миграции).

**Given** база на версии последней миграции ревизии `ddd5681af` — `20261025180000`
(`serOpenAt`, `internal/migrations/human_session_forced_exit_reason_integration_test.go:136`)
**And** на этой схеме посеяны: два аккаунта с владельцами (`serSeedPerson`, `:151`), группа
grp-1 в первом, учётки sva-1 в первом и sva-2 во втором; строки `kaname.group_members`
(grp-1, `service_account`, sva-2) и (grp-1, `service_account`, sva-1) — оператором вставки,
который схема этой версии принимает (помощники посева группы, учётки и строки состава
заказаны, §5.2)
**When** накат до головы (`goose.Up`)
**Then** накат без ошибки; обе строки состава на месте — те, которые читает
`GroupService.ListMembers`
**And** близнец по одному факту: строка sva-2 против строки sva-1 (аккаунт учётки); исход один
— Р4 не различает законное и прежнее.

### S2 — сквозной набор службы (`PRO-Robotech/kaname`, newman, собственный REST-фронт)

**Посев набора** (производитель посева заказан, §5.2): человек H с предъявителями
`jwtHumanEsc` и `jwtHumanEscStepUp`, без выдач в начале кейса (контроль —
`ListBySubject(H)` пуст, иначе «условие не создано»); реестр и его проект в acc-A — переменные
`gdRegistryId`, `gdRegistryProjectId` посева делегирования. Роли, выдачи, группу и учётки
кейс заводит сам от `jwtAccountAdminA` и убирает за собой. Отрицательный кейс утверждает пару
«HTTP-статус, `code` тела» (`api-case-asserts-pair`). Методы с `required_acr_min: "2"` в каталоге
(`AccessBindingService.Create`, `RoleService.Update`, `GroupService.AddMember`) H вызывает
предъявителем `jwtHumanEscStepUp`: иначе отказ пришёл бы от уровня входа, а не от предмета.

#### ESC-E1 · право удалять не даёт права выдавать — через край (держатель ESC-01)

**Given** у H выдача роли `{iam, [project], [delete]}` на проекте `gdRegistryProjectId`
**When** H (`jwtHumanEscStepUp`) `POST /iam/v1/accessBindings` с телом V-E на этом проекте
**Then** `403`, `code` = 7
**And** близнец: выдача H заменена ролью с глаголами `["*"]` на том же проекте — тот же
запрос тем же предъявителем `200`, операция `done`.

#### ESC-E2 · право удалять на объекте — только удаление, через край (держатель ESC-04, ESC-05)

**Given** у H выдача роли `{registry, [registries], [delete]}` на `gdRegistryProjectId`
**When** H (`jwtHumanEsc`; у метода `required_acr_min: "1"`) `POST /iam/v1/authorize:check` о себе
(`subject: user:<H>`), ресурс `{type: registry_registry, id: <gdRegistryId>}`
**Then** `action: registry.registries.update` → `200`, `allowed: false`;
`action: registry.registries.delete` → `200`, `allowed: true`
**And** близнец: выдача H заменена ролью с глаголами `[update, delete]` — `update` →
`allowed: true`.

#### ESC-E3 · правка роли без права выдавать — через край (держатель ESC-10)

**Given** роль R кейса с правилом `{registry, [registries], [get]}`, действующая выдача R → H на
`gdRegistryProjectId`; тело отказа T0 — ответ края на `PATCH /iam/v1/roles/<R>` с телом U-R от
H (`jwtHumanEscStepUp`), снятый ДО выдачи H роли `iam.role.edit` (дверь отказывает: права
правки нет)
**When** H получает `iam.role.edit` на acc-A; контроль — H `PATCH /iam/v1/roles/<R>` с
`updateMask: "description"` получает `200` в ограниченном окне (дверь H уже пропускает:
отказ ниже — не отказ двери); затем H повторяет `PATCH` с телом U-R
**Then** `403`, `code` = 7; тело ответа побайтово равно T0 (Р2: отказ неотличим от отказа без
права на этом же методе)
**And** близнец: тот же `PATCH` от `jwtAccountAdminAStepUp` — `200`, операция `done`.

#### ESC-E4 · состав группы без права выдавать и участник из чужого аккаунта — через край (держатель ESC-20, ESC-23)

**Given** группа Gc кейса в acc-A с выдачей роли кейса `{registry, [registries], [get]}` на
`gdRegistryProjectId`; группа Gc0 кейса в acc-A без выдач; учётка Sa кейса в acc-A; учётка Sb,
заведённая кейсом от `jwtAccountAdminB` в acc-B; тело отказа T1 — ответ на
`POST /iam/v1/groups/<Gc>:addMember` (участник Sa) от H (`jwtHumanEscStepUp`), снятый ДО выдачи
H роли `iam.group.edit`
**When** H получает `iam.group.edit` на acc-A; контроль — H (`jwtHumanEscStepUp`) добавляет Sa в
Gc0 и получает `200`, операция `done`, в ограниченном окне (дверь H уже пропускает); затем H тем
же предъявителем повторяет запрос в Gc
**Then** `403`, `code` = 7; тело побайтово равно T1
**And** близнец: тот же запрос от `jwtAccountAdminAStepUp` — `200`, операция `done` без ошибки
**And** `jwtAccountAdminAStepUp` добавляет в Gc учётку Sb — операция `done`, `error.code` = 9,
`error.message` = `referenced resource does not exist; create it or correct the reference
before retrying` (§0.2, В-4.1); то же для правильно сформированного несуществующего id — та
же форма.

---

## §5. Сценарий → производитель

### 5.1. Таблица

Производитель «заказан» — его заводит реализация; держатель — проба
`TestRoleRightsStayNamed_ESC<NN>_…` в `internal/apps/kaname/api/access_binding/`
(интеграционные, testcontainers), для ESC-32 — в `internal/migrations/`; сквозные —
`tests/newman/cases/iam-role-rights-stay-named.py` (заказан). Отказ в праве —
`authzguard.PermissionDenied` (§0.1); отказ «участника нет» — триггер и преобразователь отказа
хранилища (§0.2).

| ID | что производит «Тогда» | держатель: строка утверждения | чем измерено |
|---|---|---|---|
| ESC-01 | заказан: вывод яруса без `delete` (Р1) и право выдавать по сужённому ярусу; есть: `requireGrantAuthority` (`helpers.go:155`), отказ — `authzguard.PermissionDenied` | код и текст a, b; `done` c–e; число выдач prj-A до = после в a, b; `Check` в c | статус, операция, SQL, `Check` |
| ESC-02 | заказан: тот же вывод на области аккаунта | пять строк × два вызывающих | статус, `Check` |
| ESC-03 | заказан: тот же вывод на объекте области (В1) | двенадцать ответов `Check` | `Check` |
| ESC-04 | заказан: тот же вывод на листовом объекте | двенадцать ответов `Check` | `Check` |
| ESC-05 | есть: ответ `Check` с действием берёт глагол типа из каталога (`moduleVerbRelation`, `authorize_service.go:527`) → `v_delete`; Р1 его не задевает | восемнадцать ответов `Check` | `Check` |
| ESC-06 | заказан: ответ `ListSubjects` для действия удаления — по праву удалять, а не по ярусу (сегодня `delete` → `admin`, `authorize_service.go:1349`); есть: право спрашивать о чужом субъекте — `admin` на ресурсе (`caller_authority.go:55`), отказ `permission denied` | а: членство usr-D, отсутствие usr-M; б1: код и текст; б2: ответ с usr-D | ответ, статус |
| ESC-10 | заказан: проверка Р2 в `RoleService.Update` (Д-2, Д-4); есть: следование выдачи правилам роли | код, текст, детали a и их равенство `authzguard.PermissionDenied()`; `rules` по `Get`; `Check` | статус, тело, `Check` |
| ESC-11 | заказан: Р2 читает только действующие выдачи (Д-6) | `done` a, b; `rules` | операция, тело |
| ESC-12 | заказан: Р2 — только при `rules` в маске (Д-5) | `done`; `description`, `rules` | операция, тело |
| ESC-13 | заказан: Р2 по каждой области | пара a/b | статус, тело |
| ESC-14 | заказан: неполадка хранилища в проверке Р2 → `authzguard.AuthzBackendUnavailable` (`authzguard.go`, тот же ответ, что у `requireGrantAuthority`) | код и текст; `rules` прежние; `done` близнеца | статус, тело |
| ESC-20 | заказан: проверка Р3 в `GroupService.AddMember` | код, текст, детали a и их равенство `authzguard.PermissionDenied()`; `ListMembers`; `Check` | статус, тело, `Check` |
| ESC-21 | заказан: Р3 — только при выдачах группы | `done`; `ListMembers` | операция, тело |
| ESC-22 | заказан: Р3 по каждой области | пара a/b | статус, тело |
| ESC-23 | заказан: принадлежность участника (Д-3) в операции; есть: форма «участника нет» (§0.2), читатель членства `UserReader.Membership` | шесть строк: `error` код и текст T-нет; `ListMembers`; равенство b/f, d/f по коду, тексту и деталям | операция, тело |
| ESC-24 | есть: `RemoveMember` без проверки права выдавать; утверждается, что Р3 его не задел | `done`; `ListMembers`; `Check` | операция, тело, `Check` |
| ESC-25 | заказан: неполадка хранилища в проверке Р3 → `authzguard.AuthzBackendUnavailable` | код и текст; `ListMembers` пуст; `done` близнеца | статус, тело |
| ESC-30 | заказан: новый вывод яруса; есть: сводящий проход `ConvergeBinding` снимает лишнее под координатой члена (`reconcile/emitted_completion.go`, kaname#1006) и его вызов при старте (`seed/binding_converge.go:84`) | контроли посева; статусы и `id` четырёх выдач; восемь ответов `Check`; строки реестра usr-D и usr-W; число строк журнала при повторе; `rules` | тело, `Check`, SQL |
| ESC-31 | есть: `TestGrantDelegation_GD10`, `TestGrantDelegation_GD11`, `TestGrantDelegation_GD16`, `TestGrantDelegation_GD25`; заказано: фикстуры GD-25 e и Д4 под Д-3 (§0.4) | зелёные; пробы GD не ослаблены (§6 S1 п.7) | прогон, сверка утверждений до и после |
| ESC-32 | есть: цепь миграций (`goose.UpTo`, `serOpenAt`); заказано: ни одна новая миграция не снимает и не отвергает прежних строк состава | накат без ошибки; две строки на месте | `goose`, SQL |
| ESC-E1 | заказан: регистрация кейса набора; ESC-01 на реализации | пара «статус, `code`»; `200` близнеца | newman |
| ESC-E2 | заказан: то же | `allowed` трёх вопросов | newman |
| ESC-E3 | заказан: то же; равенство тела отказа двери и отказа Р2 | контроль `200` правки описания; `403`/7; побайтовое равенство с T0; `200` близнеца | newman |
| ESC-E4 | заказан: то же | контроль `200` добавления в Gc0; `403`/7; равенство с T1; `200`; `error` 9 и текст | newman |

Сценариев: **24** (`grep -c '^#### ESC-'` = 24; строк таблицы `grep -c '^| ESC-'` = 24) —
интеграционных 20 (ESC-01…06 — 6, 10…14 — 5, 20…25 — 6, 30…32 — 3), сквозных 4
(ESC-E1…E4). Производитель назван у всех 24.

### 5.2. Дано → писатель

| «Дано» | писатель | координата |
|---|---|---|
| мир Д: аккаунты, проект, учётки, X, usr-M/usr-P с членством, usr-E | посев мира Д | `newGDWorld`, `grant_delegation_world_integration_test.go:144` |
| провязка `RoleService.Update`, `GroupService.AddMember`, `RemoveMember` в мире Э | заказана: `newEscWorld` (в мире Д у ролей и групп провязан только `Create`) | — |
| обработчик `AuthorizeService` мира Э | построение как `anonSelfCheckHandler` | `anonymous_self_check_module_verb_integration_test.go:46` |
| роли rol-* мира Э | `seedRole` тремя сторонами, как `RoleService.Create` | `public_container_read_world_integration_test.go:152` |
| роли `iam.role.edit`, `iam.group.edit` | посев ролей модуля iam при старте; поиск по имени | `manifest.yaml` (роли `iam.role.edit`, `iam.group.edit`), `roleByName` `:298` |
| люди usr-D, usr-U, usr-W, usr-Da, usr-R, usr-RP, usr-G, usr-GP | посев мира `mustSeedUser` | `testhelpers_assignable_test.go:80` |
| группы grp-e0, grp-e1, grp-e2 | посев мира `seedGroup` | `system_class_world_integration_test.go:173` |
| все выдачи мира Э | `AccessBindingService.Create` от владельца usr-A | `createDoneX`, `grant_delegation_world_integration_test.go:470` |
| отозванная выдача rol-er | `AccessBindingService.Revoke` от usr-A | `internal/apps/kaname/api/access_binding/revoke.go` (существующий глагол) |
| обёртка двери, отказывающая на вопросах о субъекте (ESC-14, ESC-25) | `ceFailFor` | `grant_delegation_ce_integration_test.go:247` |
| прежнее состояние ESC-30: строки реестра `admin` и строки журнала факта `admin` | одна транзакция формы `rewindToPreFix`; строки реестра — производные от строк `v_delete` той же выдачи; строки журнала — форма `gdSeedTuple` | `public_container_read_multi_subject_converge_integration_test.go:70`; `grant_delegation_world_integration_test.go:278` |
| сводящий проход ESC-30 | `rec.ConvergeBinding` мира П6 | `public_container_read_world_integration_test.go:306`; `reconcile/reconcile.go:688` |
| база на версии `20261025180000` (ESC-32) | `serOpenAt` | `internal/migrations/human_session_forced_exit_reason_integration_test.go:136` |
| аккаунты с владельцами (ESC-32) | `serSeedPerson` | там же, `:151` |
| группа, учётки, строки состава (ESC-32) | вставка на схеме версии `20261025180000`; помощники в пакете миграций заказаны | — |
| D1 (ESC-31) | `GrantDelegationService.Create` | GD-01 приёмки делегирования |
| участник строки e GD-25 — usr-M, член acc-A (ESC-31, В-4.2) | посев мира Д `gdSeedMembership` (`ACTIVE`) | `grant_delegation_world_integration_test.go:266` |
| прежнее состояние Д4: строка состава sva-iss2 → grp-A (В-4.2) | вставка строки `kaname.group_members` посевом; схема этой ревизии проверяет только существование участника (§0.2) | заказан (§0.4) |
| S2: человек H и его предъявители | полоса посева набора | заказан (§7 строка 2) |
| S2: `gdRegistryId`, `gdRegistryProjectId` | посев набора делегирования | есть (`tests/newman/cases/iam-grant-delegation.py`, `_SEED_VARS`) |

Каждое «Дано», кроме прежнего состояния ESC-30, ESC-32 и Д4, строится существующим глаголом либо
посевом строк, которые мир Д уже кладёт так же. Прежнее состояние сеется намеренно: новый
глагол его не произведёт по построению, а предмет ESC-30 и ESC-32 — именно переход. ESC-30
сеет строку реестра вместе с фактом, привязанной к выдаче-владельцу: снятие идёт только по
реестру выдачи, и факт без строки реестра проход честно не снял бы. ESC-32 сеет строку состава
до наката, на схеме прежней редакции, поэтому посев не зависит от того, где новая редакция
держит инвариант Р3.

---

## §6. Признак готовности (DoD)

### S1 — `PRO-Robotech/kaname`

1. Вывод яруса из правила роли: `delete` не вносит ни одного яруса (Р1, В1); `update` и прочие
   изменяющие глаголы — `editor`, как сегодня; `*` — как сегодня. Правило, все глаголы которого
   — `delete`, даёт только `v_delete`
2. Ответ `AuthorizeService.Check` на действие удаления не меняется ни у одного держателя мира
   (ESC-05); ответ `ListSubjects` на действие удаления с ним согласен (ESC-06 а)
3. Сводящий проход при старте новой редакции приводит материализацию действующих выдач к
   новому выводу без отзыва выдач (ESC-30); повтор прохода не пишет ни одной строки журнала
4. `RoleService.Update` — проверка Р2 (Д-2, Д-4…Д-6); `GroupService.AddMember` — проверка Р3 и
   принадлежность участника (Д-3, Д-4)
5. **Гонка правки и выдачи.** Правка правил роли (добавление участника группы) и заведение
   выдачи этой роли (этой группе) на новой области сериализуются: исход равен одному из двух
   последовательных порядков. Через край порядок не наблюдаем, поэтому держатели — пробы
   уровня хранилища с принудительным чередованием: `TestRoleRightsStayNamed_RulesEditAndNewScopeGrantSerialize`
   и `TestRoleRightsStayNamed_AddMemberAndNewScopeGrantSerialize`. Обе — **охрана** (В-4.3):
   зелёные до и после, как прочие строки охраны п.7 (на базе — прогон §11); в перечень
   «сперва красные» не входят. Для ролей
   сериализацию держит схема этой ревизии: триггер вставки выдачи
   `access_bindings_role_is_live_trg` читает строку роли под `FOR SHARE`
   (`0001_initial.sql:279`), правка роли — `UPDATE roles` (`role_repo.go:792`), который берёт
   строку под `FOR NO KEY UPDATE`; эти замки несовместимы, и из двух транзакций одна ждёт
   другую
6. Комментарии контракта, описывающие вывод отношения из глагола
   (`proto/kaname/cloud/iam/v1/authorize_service.proto`, поле `action`; `ListSubjects`), и
   комментарии `RoleService.Update`, `GroupService.AddMember` говорят то, что делает код;
   `buf lint`, `buf breaking` зелёные
7. Интеграционные пробы — двумя перечнями, обе стороны каждой пары в одном наборе, на одной
   ревизии:
   - **сперва красные на `ddd5681af`, затем зелёные** (ban #12) — строки с новым свойством:
     ESC-01 a, b; ESC-02 a–d (столбец usr-Da); ESC-03 строки `admin`, `editor`, `viewer` у
     usr-D и `admin` у usr-U; ESC-04 b–d у usr-D и c у usr-U; ESC-06 б1; ESC-10 a; ESC-13 a;
     ESC-14; ESC-20 a; ESC-22 a; ESC-23 b, d, e; ESC-25; ESC-30 (утверждения о usr-D после
     прохода). Красное на базе — исходом утверждения предмета, не поломкой мира (контроли
     посева на базе зелёные);
   - **охрана: зелёные до и после** — ESC-01 c–e; ESC-02 столбец usr-E и строка e; прочие
     строки ESC-03, ESC-04 (в том числе ESC-04 a у usr-D); ESC-05; ESC-06 а, б2; ESC-10 b, c;
     ESC-11; ESC-12; ESC-13 b; ESC-20 b, c; ESC-21; ESC-22 b; ESC-23 a, c, f; ESC-24; ESC-30
     (контроли посева, утверждения о usr-W, статусы и `id` выдач, `rules`, повтор прохода);
     ESC-31; ESC-32; пробы гонки п.5.
     Строка этого перечня, красная на базе, — дефект приёмки, а не реализации: возврат автору.

   ESC-31: пробы GD не ослаблены — каждое прежнее утверждение проб `grant_delegation_*`
   сохранено либо переутверждено на том же свойстве (В-4.2); правятся только фикстуры §0.4
   (GD-25 e, Д4). Перечень утверждений до и после — в `DoD-proof`. Ни одна прежняя проба
   домена доступа не ослаблена; набор домена доступа зелёный целиком
8. `EXPLAIN` чтения действующих выдач по роли и по группе-субъекту — по индексу; вывод — в
   `DoD-proof`
9. Комментарий `DoD-proof @<sha>` в `#1035`, `#1036`, `#1037`, `#1039`: команда, сырой итог,
   код возврата; в `#1039` — и сверка свойства на `main` и на ветке эпика (как требует задача)
10. Строка о порядке В2 в задаче интеграции kaname в `PRO-Robotech/kacho`: «восемь строк
    каталога §0.5 переводятся на `v_*` до перезакрепления новой kaname; ворота — предикат §7
    строка 1». Ссылка на неё — в `DoD-proof` `#1035`. Сам предикат §7 строка 1 в DoD S1 не
    входит (В2)

### S2 — `PRO-Robotech/kaname`, сквозной набор

1. `tests/newman/cases/iam-role-rights-stay-named.py` и порождённая коллекция: ESC-E1…ESC-E4;
   строка ведомости производителя для новой коллекции
2. Прогон на внешнем кластере в боевой посадке, своё пространство, снятие в той же задаче,
   перепись остатков после — 0

---

## §7. Внешние зависимости

| что | где | зачем | признак готовности |
|---|---|---|---|
| восемь строк каталога прав, спрашивающих ярус на листовом объекте, — на отношения `v_*` своих типов (первый шаг Р1) | `PRO-Robotech/kacho`: аннотации контрактов модулей и каталог края; копия у kaname — `check-permission-catalog` | край платформы спрашивает по этим строкам ярус; после Р1 держатель одного удаления его не имеет (так и задумано для `editor`-строк), а прочие держатели обязаны сохранить доступ — это и обеспечивает перевод на `v_*` | предикат §0.5 по копии каталога → 0; `check-permission-catalog` зелёный. Это ворота перезакрепления новой kaname в kacho, не DoD S1 (В2). Ограничение для отображения строк на `v_*` (в замысел): держатель `*` и держатель `update` на типе сохраняют каждую `editor`- и `viewer`-строку |
| человек H с предъявителями `jwtHumanEsc`, `jwtHumanEscStepUp` | полоса посева сквозного набора kaname | субъект ESC-E1…E4 | переменные заданы на стенде; `ListBySubject(H)` пуст в начале кейса |

---

## §8. Открытые вопросы

Нет. В1 и В2 редакции 1 решены диспетчером (§3). Вопросы исполнения `#1037` к редакции 3
решены диспетчером (В-4.1…В-4.3, §11).

---

## §9. Опора: соседи

| сосед | редакция | что берётся |
|---|---|---|
| `delegated-grants-stay-within-the-delegation.md` | редакция 3, SHA-256 `7512fd96c7aeb85f352fd55954cfb881fa7c8610169574adb2291155bb690fe6`, APPROVED (запись `docs/specs/reviews/delegated-grants-stay-within-the-delegation/7512fd96c7aeb85f352fd55954cfb881fa7c8610169574adb2291155bb690fe6.yaml`) | мир Д, Д3 (делегирующий вправе выдавать в момент выдачи), Д6 (принадлежность субъекта аккаунту), сценарии GD-10, GD-11, GD-16, GD-25 как держатели Р4 |

---

## §10. Исполнение замечаний круга 1

| замечание | где исполнено |
|---|---|
| B1 CONSTRUCTIBILITY — ESC-30 кортежи без строки реестра | ESC-30: строки реестра `admin` выводятся из строк `v_delete` той же выдачи и координаты, факт — тем же коммитом (форма `rewindToPreFix`); проход — существующий `ConvergeBinding`; контроли посева; §5.2 |
| B1 CONSTRUCTIBILITY — строка sva-B держится на «триггер не проверяет аккаунт» | строка вынесена в ESC-32: посев на схеме версии `20261025180000` до наката (`serOpenAt`), от места инварианта Р3 не зависит; посылка о триггере снята из §5.2 |
| B2 DoD — «сперва красные» невыполнимо для ESC-05, 11, 12, 21, 24 | §6 S1 п.7: два перечня — «сперва красные» по строкам и «охрана: зелёные до и после» |
| B3 COVERAGE — `ListSubjects(delete)` | ESC-06 а (пара usr-D / usr-M) |
| B3 COVERAGE — читатели сужённого яруса | §0.7: перепись двумя предикатами с командами и числами; «Тип изменения»; §2 п.9; право спрашивать о чужом субъекте — ESC-06 б1/б2 |
| B3 COVERAGE — судьба делегирования, чей делегирующий держал право через `delete` | §0.7 «Делегирование»; §2 п.5 |
| B4 TWIN — ESC-13 a отличался от ESC-10 b двумя фактами | §4.1: rol-e2 → usr-R на prj-A и sva-A3 на acc-A; ESC-13 близнец — ровно вторая выдача |
| важное 1 — «побайтово равна ESC-01 a» между разными методами | ESC-10, ESC-20: равенство `authzguard.PermissionDenied()` в мире; неотличимость на том же методе у слушателя — ESC-E3, ESC-E4; §0.1 |
| важное 2 — предъявитель H в ESC-E1, ESC-E4 | посев S2 и ESC-E1, ESC-E4: `jwtHumanEscStepUp` |
| важное 3 — вызывающий `Check` в интеграционных пробах | §4.1 «Вопрос модели»: две формы, модульный вызывающий; человек — только в ESC-06 б |
| важное 4 — владелец и администратор аккаунта без строки членства | Д-3: судится только строка `memberships` `ACTIVE`, как Д6 |
| важное 5 — раскрытие | новых путей текст не собирает; не расширялся |
| дефолты — В1 (а), В2 (а) с воротами перезакрепления | §3 В1, В2; §7 строка 1; §6 S1 п.10 |
| сверх замечаний — опора на соседа | §9: отпечаток и запись редакции 3 соседа (в ред. 1 стояла запись редакции 2) |

---

## §11. Редакция 4: решения диспетчера по исполнению `#1037`

Редакция 4 правит одобренную редакцию 3 (`8f141cbd…2ed7b26`) только по трём решениям
диспетчера от 2026-10-26. В задании полосы они названы В1, В2, В3; здесь — В-4.1…В-4.3, чтобы
не путать с В1, В2 из §3.

| решение | суть решения | где исполнено |
|---|---|---|
| В-4.1 (а) | текст отказа «участника нет» в ESC-23 f и ESC-E4 — измеренный на базе текст `FAILED_PRECONDITION`; код и контракт наружу не меняются; неразличимость Д-3 сохраняется | §0.2 (форма и координата преобразователя); Д-3; ESC-23 (T-нет в b, d, e, f; равенство b/f, d/f — по коду, тексту и деталям); ESC-E4; §5 вступление, §5.1 ESC-23 |
| В-4.2 (а) | Д-3 сохраняется; фикстуры GD приводятся под инвариант: GD-25 e — участник из аккаунта группы; Д4 — прежнее состояние сеется строкой; предикат «нет диффа в `grant_delegation_*`» заменяется на «пробы GD не ослаблены» | §0.4 (перепись и таблица фикстур); ESC-31; §5.1 ESC-31; §5.2 (две строки); §6 S1 п.7 |
| В-4.3 | проба гонки §6 п.5 — охрана (зелёная на обеих ревизиях); для ролей сериализацию держат `FOR SHARE` триггера вставки выдачи против `FOR NO KEY UPDATE` правки роли | §6 S1 п.5; п.7 (перечень охраны) |

**Прогон на базе.** Пробы полос `#1036` и `#1037` (`55cc7abb2`, `8619c19dc`) наложены на
продукт `ddd5681af`. Дифф копии к `ddd5681af` — только файлы `_test.go` и `docs/`
(`git diff --name-only ddd5681af HEAD | grep -v -E '_test\.go$|^docs/'` → пусто). Команда — во
внешнем кластере через слот, из копии:

```sh
KACHO_TASK=1037 scripts/heavy-slot.sh integration -- go test -count=1 -timeout 30m -v \
  ./internal/apps/kaname/api/access_binding/ ./internal/migrations/ \
  -run '^TestRoleRightsStayNamed_(ESC23|ESC32|AddMemberAndNewScope|RulesEditAndNewScope)'
# код 1 (ожидаемо: ESC-23 b, d, e — «сперва красные»)
```

| перечень п.7 · строка | исход на базе | цитата прогона |
|---|---|---|
| охрана · ESC-23 f | код `FailedPrecondition`, деталей 0; текст — T-нет | `actual  : "referenced resource does not exist; create it or correct the reference before retrying"` (проба утверждала прежний текст `service_account <id> not found`) |
| сперва красные · ESC-23 b, d, e | красные предметом: участник принят | `ESC-23 b sva-B (учётка acc-B): участник принят`, то же d, e |
| охрана · гонка правки роли | зелёная | `гонка: правка применена — true` · `--- PASS: TestRoleRightsStayNamed_RulesEditAndNewScopeGrantSerialize` |
| охрана · гонка добавления участника | зелёная | `гонка: добавление применено — true` · `--- PASS: TestRoleRightsStayNamed_AddMemberAndNewScopeGrantSerialize` |
| охрана · ESC-32 | зелёная | `--- PASS: TestRoleRightsStayNamed_ESC32_ForeignAccountGroupMemberSurvivesTheRollForward` |

Тот же текст ESC-23 f снят прогоном `8619c19dc`, где продукт группы тот же, что на базе.
Других строк охраны, для которых эта приёмка задаёт текст отказа, в §6 S1 п.7 нет: прочие
строки охраны утверждают `done`, ответ `Check` или состав; ESC-31 — утверждения проб соседа.
