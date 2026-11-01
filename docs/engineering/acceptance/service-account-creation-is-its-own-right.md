<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: создание служебных учёток — отдельное право

- **Статус:** DRAFT, редакция 3. Вердикта на эту редакцию нет, санкции на код нет (ban #1).
  Вердикт выносит `acceptance-reviewer`
- **Статическая форма:** DRAFT. Слово вписано автором и вердиктом не является. Действующее
  одобрение выводится из записи ревью по отпечатку редакции и из внешнего события, на которое
  запись ссылается (`change-graph.md` §3). После ревью слово DRAFT не правится
- **История ревью:** только дописывается строками вида «дата · круг · вердикт · SHA-256
  редакции · путь записи». Прежние строки не правятся и не удаляются. Записи кладутся в
  `docs/specs/reviews/service-account-creation-is-its-own-right/<sha256>.yaml`
  - 2026-10-25 · круг 1 · CHANGES_REQUESTED (блокирующих 3) ·
    `4dcce34d1cf7a3d2b618bddfe50a47979914726898a250be27db198958ad43ab` ·
    `docs/specs/reviews/service-account-creation-is-its-own-right/4dcce34d1cf7a3d2b618bddfe50a47979914726898a250be27db198958ad43ab.yaml`
  - 2026-10-25 · круг 2 · CHANGES_REQUESTED (блокирующих 1) ·
    `f283293c46bb1d7ce057f0c92331979a060b9c98b161b6c0295db4eb9b7594dc` ·
    `docs/specs/reviews/service-account-creation-is-its-own-right/f283293c46bb1d7ce057f0c92331979a060b9c98b161b6c0295db4eb9b7594dc.yaml`
- **Дата:** 2026-10-25 · **редакция:** 3. Что изменено против редакции 1 — §10, против
  редакции 2 — §11
- **Задача:** `PRO-Robotech/kaname#1003`, эпик `#980`. Связь: `#986` (делегирование выдач,
  приёмка-сосед §9)
- **Потребитель:** приёмка svc-registry «единственный писатель IAM и выдача токенов», редакция 3,
  SHA-256 `2717077568f0057fa3205069807b4cc1b5fa72ec00ecda50eadfad0967b22dc7`, статус DRAFT. Её
  строка §3а «служебная учётка выпускающего `registry-token-issuer` заводит и снимает SA, ключи SA…
  создание SA без права на Project, Group, Role (задача kaname)» опирается на эту приёмку.
  Соответствие строк — §5.3
- **Ревизия измерения:** kaname `5c6b7c078` (голова `origin/955`). Каждое число о дереве ниже
  снято на этой ревизии командой рядом. Посева и прогона не было: «Дано» показано чтением
  писателя со строкой (§4.1, §5.2)
- **Тип изменения:** контракт `.proto` (аннотация права `ServiceAccountService.Create`:
  `required_relation` `editor` → `service_account_creator`; новое поле только вывода
  `Rule.created_by_subject`); модель прав (новое отношение `account#service_account_creator`);
  форма манифеста модуля (контейнерное действие ресурса `containerVerbs` и селектор правила
  `createdBySubject`, Р2а); манифест модуля `iam` (новая системная роль
  `iam.service_account.creator`); поведение `AccessBindingService.Create` (три структурных отказа
  для этой роли), `RoleService.Create`/`Update` (глагол `create` на `serviceAccount` и селектор
  `createdBySubject` — только у системной роли); факт создателя служебной учётки (форма хранения —
  замысел, §3 Р4)
- **Сервис:** `kaname`

---

## §0. Перепись производителей — до сценариев

### 0.1. Что сегодня открывает `editor` на аккаунте

```sh
grep -n 'required_relation) = "editor"' proto/kaname/cloud/iam/v1/*.proto
# → 7: project_service.proto:66, group_service.proto:66, membership_service.proto:124,
#      role_service.proto:83, user_service.proto:94 (Invite), user_service.proto:142
#      (ResendInvite), service_account_service.proto:67
jq -r '.[] | select(.scope_extractor.object_type=="account") | .required_relation' \
  internal/apps/kaname/seed/embedded/permission_catalog.json | sort | uniq -c
# → 16 записей с областью account: editor 7, v_list 3, viewer 2, member_remover 1,
#   v_delete 1, v_get 1, v_update 1
```

Первый предикат — по написанию аннотации, второй — по предмету: каталог прав, выведенный из
аннотаций, который судит дверь слушателя (`authzguard.NewOwnDoor`, `cmd/kaname/serve.go:885`).
Семь записей с `editor` на аккаунте — `Create` проекта, группы, роли, членства, служебной учётки
и `Invite`/`ResendInvite` человека. Восьмая — `UserService.RemoveFromAccount` с
`member_remover`, а `member_remover` в модели и есть `editor` (`fga_model.fga:414`).

В модели `account.editor = [user, service_account, group#member] or admin`
(`fga_model.fga:324`). Ярус неделим: ни одна выдача не даст права создать служебную учётку, не
дав заодно остальных шести созданий и приглашения.

### 0.2. Как сегодня получают право на ключи служебной учётки

- `SAKeyService.Issue` и `Revoke` требуют `v_update` на `iam_service_account`
  (`sa_key_service.proto:60`, `:97`), `ServiceAccountService.Delete` — `v_delete`
  (`service_account_service.proto:105`),
  `Get` — `v_get`, `Update`/`Disable`/`Enable` — `v_update`;
- `iam_service_account.v_* = [user, service_account, group#member] or super_admin`,
  `super_admin = admin from account` (`fga_model.fga:846`, `:895-898`);
- создатель служебной учётки доступа к ней не получает: создание пишет только указатель на
  аккаунт и событие реконсайла (`service_account/create.go:151-162`), доступ материализуется
  по выдачам;
- готовая роль на это — `iam.service_account.admin` (`manifest.yaml:1015-1023`, правило
  `{iam, [serviceAccount], classes: ["*"]}`). Выданная на аккаунт, она даёт глаголы на **все**
  учётки аккаунта, а создать учётку не даёт: `Create` спрашивает `editor` на аккаунте, а не
  глагол учётки.

Следствие на уровне класса: право выпускать ключи всем учёткам аккаунта равносильно праву
действовать от имени любой из них. Учётке модуля сегодня нужно и `editor` на аккаунте, и такой
широкий доступ к чужим учёткам.

### 0.3. Нет ни права «создавать учётки», ни факта создателя

```sh
git grep -c -i -E 'service_account_creator|iam\.service_account\.creator|created_by_principal' \
  -- internal proto manifest.yaml | wc -l
# → 0
sed -n '2563,2573p' internal/migrations/0001_initial.sql | grep -c -E 'created_by|creator'
# → 0; колонки таблицы kaname.service_accounts: id, account_id, name, description,
#   created_at, enabled, labels (0001_initial.sql:2563-2573)
git grep -n -i 'service_accounts' -- 'internal/migrations/2*.sql' | grep -c -i -E 'add column|alter table'
# → 0: поздние миграции колонок таблице не добавляют
```

Первый предикат — по написанию в объявлении таблицы, второй — по предмету: изменения таблицы
после начальной схемы. Совпадения `created_by` в начальной схеме есть, но это ключи учётки
(`service_account_oauth_clients.created_by_user_id`, `0001_initial.sql:5618`), а не учётка.

### 0.4. Глагол `create` в модели

```sh
grep -n 'define v_create' internal/authzmodel/fga_model.fga
# → 1: :1335 (registry_registry)
```

Шапка модели объясняет, почему `v_create` снят с остальных типов: «создать» спрашивают у
родителя, а не у объекта, которого ещё нет (`fga_model.fga`, абзац «`v_create` IS NOT PART OF
THE OBJECT VERB-SET»). Единственный оставленный — у контейнера `registry_registry`, где
«создать репозиторий в этом реестре» и есть действие над реестром. Эта приёмка заводит второе
такое отношение — у контейнера `account` и для одного вида содержимого (Р1). Пообъектного
`v_create` на `iam_service_account` она не заводит (Р2а).

### 0.5. Пересечения в модели нет

```sh
grep -c -E 'define .* and |but not' internal/authzmodel/fga_model.fga
# → 0
```

«Право ведения действует, пока держится выдача» отношением модели вида `creator and …` не
выражается. Поэтому ведение созданных учёток материализуется от выдачи роли и снимается вместе с
ней (Р3), а не выводится каскадом.

### 0.6. Отказы, которые уже есть

| что | производитель | текст |
|---|---|---|
| дверь отвергла вызов (запись каталога без `hide_existence`) | corelib v1.15.0 `authz/interceptor.go:216` | `PERMISSION_DENIED` `permission denied` |
| нет права выдавать | `requireGrantAuthority` (`access_binding/helpers.go:155`) → `authzguard.go:63-64` | `PERMISSION_DENIED` `permission denied` |
| операция чужая или нет такой | corelib `operations/operationspb/handler.go:65-80` (ключ — владелец операции) | `NOT_FOUND` |
| подстановка в правиле арендаторской роли | `domain/rule_policy.go:130`, `:142` | `Illegal argument <поле> (wildcard '*' is system-only)` |
| вложенное правило на входе роли | `role/handler.go:239`, `:250` | `INVALID_ARGUMENT`, поле `rules[<i>].children`, `Illegal argument children (nested rules are declared by a module manifest)` |
| удаление учётки, на которую есть действующая выдача | `pg/service_account_repo.go:286-317` (охрана по `subjects[0]` и `subjects[1..N]`) | `FAILED_PRECONDITION` `ServiceAccount <id> has active access bindings and cannot be deleted` |

```sh
jq -r '.[] | select(.fqn|test("ServiceAccountService/|SAKeyService/")) | .hide_existence // "нет"' \
  internal/apps/kaname/seed/embedded/permission_catalog.json | sort | uniq -c
# → 11 нет
```

### 0.7. Пол уровня входа у машины

`required_acr_min = "2"` у `SAKeyService.Issue`/`Revoke` и `ServiceAccountService.Delete`
машинного принципала не останавливает: служебная учётка освобождена общим правилом
(`internal/authzguard/acr_floor.go:61`; `service_account_service.proto`, абзац «The floor is
INTERACTIVE-ONLY»).

### 0.8. Субъект выдачи из другого аккаунта

Сверки «субъект принадлежит аккаунту области» на прежних путях выдачи нет (§0.5 приёмки-соседа
`#986`, предикат там же). Выдача владельцем acc-A роли учётке из acc-S принимается — как
`admin` учётке sva-iss в GD-62 b соседа.

### 0.9. Список учёток сужается пообъектно

`ServiceAccountService.List` отдаёт только строки, о которых модель ответила «видна»
(`service_account/list.go:261`, `authzfilter.VisibleSet` по `iam_service_account`).

### 0.10. Посылка задачи

| посылка | исход | чем проверено |
|---|---|---|
| `ServiceAccountService.Create` требует того же `editor` на аккаунте, что `Create` проекта, группы и роли (`:67`, `:66`, `:66`, `:83`) | **подтверждена** и шире: тот же `editor` гейтит ещё `MembershipService.Create`, `UserService.Invite`, `ResendInvite`, а через `member_remover` — `RemoveFromAccount` | §0.1, два предиката |
| без нового права учётке модуля нельзя дать создание SA, не дав проекты, группы и роли | **подтверждена** | §0.1 (ярус неделим), §0.2 (`iam.service_account.admin` создания не даёт) |
| приёмка `#986` одобрена | **подтверждена**: редакция 3, запись `docs/specs/reviews/delegated-grants-stay-within-the-delegation/7512fd96…0fe6.yaml` — `verdict: APPROVED`, круг 3, событие опубликовано (`issued: true`) | `sha256sum` редакции соседа и чтение записи ревью на ветке `986` @`4d0a479a3` |

### 0.11. Право создания сегодня в манифесте не объявимо

```sh
yq -o=json -I=0 '.resources[] | select(.name=="serviceAccount") | .verbs' manifest.yaml
# → ["get","list","update","delete"]
yq -o=json -I=0 '[.roles[] | select(.rules[].resources[] == "serviceAccount") | .id]' manifest.yaml
# → ["iam.service_account.admin","iam.service_account.edit","iam.service_account.view"]
git grep -c -i -E 'containerVerbs|createdBySubject|created_by_subject' -- internal proto manifest.yaml | wc -l
# → 0
```

Первый предикат — по написанию объявления ресурса, второй — по предмету: роли, которые сегодня
распоряжаются учётками. Чтением кода на той же ревизии роль C в форме редакции 1
(`{iam, [serviceAccount], verbs: [create]}`) не проходит ни одной из трёх стадий:

1. **загрузчик** отвергает поимённое действие, которого раздел `resources` не объявляет
   (`internal/manifest/rolenamedverbs.go:117-135`, `ErrRoleRuleVerbUnknownToContract` `:65`);
2. **roleexport** счёл бы названный `create` непроизводимым: гейт `ServiceAccountService/Create`
   после Р1 спрашивает отношение на `account`, а правило над `serviceAccount` пишет кортежи только
   на `iam_service_account`. `Produces` отвечает «нет», если объект гейта не тип правила
   (`internal/manifest/roleexport/producibility.go:97-110`), и стадия MOD-RL-19 даёт отказ
   (`roleexport/namedverbs.go:72`, `:131-200`);
3. **объявить `create` в `verbs` ресурса** нельзя: подстановка разворачивается в набор глаголов
   типа (`internal/authzmap/role_verbs.go:51-110`), и `classes: ["*"]` у
   `iam.service_account.admin` (`manifest.yaml:1022`) раскрылась бы в `create`. Генератор модели
   вывел бы `v_create` на `iam_service_account` вопреки §0.4.

У сообщения `Rule` нет селектора «созданные субъектом выдачи»: поля `resources`, `verbs`,
`resource_names`, `match_labels`, `module`, `children` (`role.proto:683-760`). Вторая половина
роли C — ведение созданных учёток — сегодня в каталоге ролей невыразима.

---

## §1. Предмет

Вводится **право создавать служебные учётки** в аккаунте — отдельное от `editor` на аккаунте.
Его даёт системная роль модуля `iam` **`iam.service_account.creator`**, выданная служебной
учётке на аккаунт. Держатель роли:

1. создаёт служебные учётки в этом аккаунте;
2. ведёт **только те учётки, которые создал сам**: читает, правит, выключает и включает,
   выпускает, перечисляет и отзывает ключи, удаляет;
3. ничего больше: ни проектов, групп, ролей, членств и приглашений, ни чужих учёток, ни права
   выдавать.

Конец выдачи любым путём (отзыв, удаление, истечение срока) снимает и создание, и ведение, если у
держателя не осталось другой действующей выдачи этой роли на аккаунт. Учётки и их ключи при этом
остаются. Учётке модуля по умолчанию прав на проекты, группы и роли не даётся.

---

## §2. Что НЕ входит

1. **Делегирование выдач** — `#986`. Здесь утверждается только, что роль создателя права
   выдавать не даёт (SAC-22). Обратное утверждает сосед: делегирование не даёт создания учёток
   (GD-25 g). Эти два права независимы; их состав у одной учётки — §3, «безопасность»
2. **Отдельные права создания проектов, групп и ролей.** `Create` у них остаётся при `editor`.
   Предикат снятия — потребитель с той же нуждой; заводится отдельной задачей
3. **Поле «кто создал» в публичном `ServiceAccount`.** Создателя называет аудит
   `iam.service_account.created` (поле `actor`, есть, `service_account/create.go:131-143`).
   Вопрос В5
4. **Факт создателя у учёток, созданных до изменения.** Обратного заполнения нет: у старых
   учёток создателя нет, и по роли создателя их не ведёт никто (SAC-13 строки a, b)
5. **Пределы числа учёток у создателя** — в kaname их нет (решение владельца Р-В7, §3)
6. **Право модуля писать регистрации на аккаунте** — `#986` предмет 2, там же §2 п.1
7. **Край kacho, консоль, публикация kaname наружу** — не трогаются (Р-В5). Перезакрепление
   версии kaname в kacho — §7
8. **Кто выдаёт роль создателя на аккаунт в боевой посадке** — вопрос В1, общий с В1 соседа
9. **Правка `docs/specs/*`, сайта документации, README**
10. **Контейнерные действия и селектор создателя у других ресурсов.** Форма Р2а общая, но
    загрузчик принимает её только там, где родитель и его отношение объявлены тем же манифестом;
    манифест `iam` объявляет ровно одно контейнерное действие — `create` у `serviceAccount`.
    Предикат снятия — потребитель с той же нуждой у другого ресурса

---

## §3. Решения

### Решения владельца (не переоткрываются)

Переданы заданием диспетчера 2026-10-25; дословные формулировки В1, В3, В5, В7 — §1 приёмки
svc-registry (отпечаток выше), Р-В3 — также §3 соседа `#986` (редакция 3):

- **Р-узко.** «нужно продумать что бы у svc-mng были максимально узкие права»;
- **Р-В1.** «Таплы и токены создает svc-registry-mng». Учётки, ключи и выдачи заводит учётка
  модуля, а не kaname по своей инициативе;
- **Р-В3.** «через канаме только авторизация токенов на пуш пул». Kaname только авторизует.
  Прочтение для этой приёмки — решение диспетчера Д-1003 ниже;
- **Р-В5.** «интернал апи опубликовать не можем». Право работает на арендаторском слушателе kaname
  внутри кластера; новой публикации нет;
- **Р-В7.** «лимиты на кол-во ресурсов только в svc-registry». Kaname не ограничивает число учёток,
  заведённых создателем.

### Решения диспетчера (не переоткрываются)

- **Д-1003** (2026-10-25, ответ на вопрос рецензента круга 1; подтверждено заданием диспетчера
  круга 3 дословно: «кортежи ведения считаются только авторизацией»): кортежи ведения созданных
  учёток (Р3) считаются «только авторизацией» в смысле Р-В3 — kaname авторизует, svc-registry пишет
  учётки, ключи и выдачи. Кортежи — проекция выдачи роли C, которую пишет учётка модуля; своих
  учёток, ключей и выдач kaname не заводит. Предмет этой приёмки;
- **Д11** (приёмка svc-registry): «Права сервиса: отдельные принципалы по функциям; без `admin` на
  аккаунт»;
- **Д-A6** (`#986`): выдачи на объекты registry — делегированием, без `admin` на аккаунт;
- **A4** (допущение приёмки svc-registry, не оспорено): учётка клиента живёт в аккаунте
  регистрации. Поэтому право создавать нужно на **аккаунте арендатора**, а не на своём аккаунте
  модуля.

### Решения автора

**Р1. Новое отношение `account#service_account_creator`.**

```
define service_account_creator: [service_account] or editor
```

`ServiceAccountService.Create` меняет аннотацию права: `required_relation = "editor"` →
`"service_account_creator"`; область (`account` из `account_id`), `permission` и
`required_acr_min = "1"` прежние. Каталог прав выводится из аннотаций заново.

- **`or editor`** — прежние создатели не теряют права: владелец, администратор аккаунта,
  держатели `editor` создают учётки как раньше (держатель — SAC-21, близнец usr-A);
- **прямой субъект — только `service_account`**: людям и группам право выдаётся не этой ролью
  (Р2), а `editor` у них уже есть путём выше;
- **имя без приставки `v_`** — по той же причине, что у `member_remover` (`manifest.yaml`, заметка
  перед `member_remover`, абзац «ПОЧЕМУ НЕ `v_`-приставка»): приставка объявляет глагол объекта,
  глаголы разворачивает подстановка `*`, а реконсайлер эмитит из глаголов только `v_*`. Это право
  на контейнер, и подстановка его не достигает (Р2а);
- **объявление — в манифесте**, разделом `relations` ресурса `account`, как `member_remover`:
  `{name: service_account_creator, definition: '[service_account] or editor', position:
  afterVerbs}`. Модель выводится из манифеста;
- **читатель у отношения есть** — запись каталога `ServiceAccountService/Create`; гейт
  `nonverb_relation_has_reader_test.go` остаётся зелёным;
- **освобождённых двери методов не прибавляется**: решает дверь по модели, а не обработчик.

**Р2. Системная роль `iam.service_account.creator`.** Объявляется манифестом модуля `iam` рядом с
`iam.service_account.admin`:

| поле | значение |
|---|---|
| `id` | `iam.service_account.creator` |
| `description` | `Create service accounts and manage the ones you created` |
| ярус определения | `iam.cluster` / `cluster_root`, как у остальных ролей `iam.*` |
| правило 1 | `{module: iam, resources: [serviceAccount], verbs: [create]}` |
| правило 2 | `{module: iam, resources: [serviceAccount], verbs: [get, list, update, delete], createdBySubject: true}` |

Обе половины права видны в каталоге ролей — `RoleService.Get`/`List` отдают оба правила
(SAC-41). Каталог не показывает меньше, чем роль даёт.

Выдача роли C на аккаунт A субъектам S₁…Sₙ даёт каждому Sᵢ:

1. `account:A#service_account_creator` (правило 1);
2. глаголы `v_get`, `v_list`, `v_update`, `v_delete` на каждой учётке аккаунта A, создатель
   которой — сам Sᵢ (правило 2; Р3, Р4). Учётки, созданные соседним субъектом той же выдачи,
   Sᵢ не ведёт;
3. ничего сверх этого. Ярус (`viewer`/`editor`/`admin`) на аккаунте и на учётках не
   материализуется.

Структурные условия выдачи. Проверяются после права выдавать, на месте структурных ворот
(`structural_gates.go`, шапка ORDERING), и поэтому отказ ничего не раскрывает постороннему:

| условие | отказ `FAILED_PRECONDITION` |
|---|---|
| область — `iam.account` | `role <role_id> grants service account creation on iam.account scope only` |
| цель — `allInScope` | `role <role_id> requires target allInScope` |
| каждый субъект — `SUBJECT_TYPE_SERVICE_ACCOUNT` | `role <role_id> can only be granted to SUBJECT_TYPE_SERVICE_ACCOUNT` |

Условия относятся к любой роли, правило которой называет контейнерное действие или несёт
`createdBySubject` (Р2а). По п.4 такая роль может быть только системной.

4. **Контейнерное действие и селектор создателя — только у системной роли.** В роли аккаунта
   (`RoleService.Create`, `Update`) они отвергаются синхронно, до заведения операции:
   - глагол `create` на `serviceAccount` — `INVALID_ARGUMENT`
     `Illegal argument verbs (create on serviceAccount is system-only)`. Форма — как у соседнего
     отказа подстановки (§0.6);
   - `createdBySubject: true` — `INVALID_ARGUMENT`, поле `rules[<i>].createdBySubject`,
     `Illegal argument createdBySubject (creator-scoped rules are declared by a module manifest)`.
     Форма — как у отказа вложенного правила на входе (§0.6).

   Подстановка `"*"` и классы контейнерного действия не достигают: `iam.service_account.admin` и
   прочие роли с `*` на `serviceAccount` после изменения дают ровно то же, что до него (держатели
   — SAC-11 c, SAC-42 h).

Почему роль, а не новое поле выдачи. Выдача отношением (`AccessBinding.granted_relation`) на входе
`Create` не принимается (поле только вывода, `module-manifest-relation-grant.md` §1.3 п.4).
Открыть её значило бы завести новую поверхность контракта выдач. Роль идёт существующим путём:
право выдавать, отзыв, перечисление выдач, аудит выдачи — всё уже есть.

**Р2а. Форма объявления в манифесте и её следствия.** Закрывает §0.11: третий механизм рядом с
поимённым глаголом объекта и подстановкой.

```yaml
resources:
  - name: account
    relations:
      - name: service_account_creator
        definition: '[service_account] or editor'
        position: afterVerbs
  - name: serviceAccount
    parents: [account]
    verbs: [get, list, update, delete]          # прежние, набор глаголов типа не меняется
    containerVerbs:
      - {name: create, parent: account, relation: service_account_creator}
roles:
  - id: iam.service_account.creator
    rules:
      - {module: iam, resources: [serviceAccount], verbs: [create]}
      - {module: iam, resources: [serviceAccount], verbs: [get, list, update, delete], createdBySubject: true}
```

**Контейнерное действие** — действие над ресурсом, которое авторизуется отношением на его
родителе: «создать учётку в аккаунте». В набор глаголов типа оно не входит.

| кто читает | следствие |
|---|---|
| загрузчик манифеста | правило роли вправе назвать контейнерное действие **только поимённо** (`verbs:`). Через `classes:`, включая `["*"]`, оно не достижимо, а `classes`, названный его именем, — отказ с координатой правила. Объявление `containerVerbs` принимается, только если `parent` есть в `parents` ресурса и объявлен этим же манифестом, `relation` объявлено в `relations` родителя, имеет имя без приставки `v_` и принимает `service_account` прямым субъектом. Вид субъекта спрашивается у модели, как у выдачи отношением (`relationgrant.go`, шапка «Допустимый вид получателя спрашивается У МОДЕЛИ»). `createdBySubject` принимается только в правиле над ресурсом, объявившим контейнерное действие `create`, и только без `resourceNames` и `matchLabels` (селекторы взаимоисключающи, как `resource_names`/`match_labels` у `Rule`) |
| roleexport | MOD-RL-19 считает названный `create` производимым ровно тогда, когда ресурс объявляет его контейнерным действием и гейт спрашивает объявленное `relation` на объявленном `parent`. MOD-RL-18 к контейнерному действию не применяется: класса у него нет, правило экспортируется поимённо. Правило с `createdBySubject` судится как обычное правило с глаголами |
| генератор модели | из `containerVerbs` на типе ресурса не выводится ничего: `define v_create` у `iam_service_account` нет, число `define v_create` в модели остаётся 1. Отношение `service_account_creator` выводится из `relations` аккаунта, как `member_remover` |
| раскрытие `*` и классов | набор глаголов типа берётся из `verbs` (`role_verbs.go:51-110`), контейнерного действия в нём нет. `iam.service_account.admin` (`classes: ["*"]`) разворачивается на `iam_service_account` в `get`, `list`, `update`, `delete` и кортежа на `account` не пишет |
| материализация выдачи | правило 1 пишет `account:<область>#service_account_creator@service_account:<Sᵢ>` на каждого субъекта; правило 2 — `v_get`/`v_list`/`v_update`/`v_delete` на каждой учётке области, у которой факт создателя равен Sᵢ (Р3, Р4) |
| `RoleService` | вход — отказы Р2 п.4. Вывод — `Rule.created_by_subject` (`bool`, только вывода, номер — первый свободный, `7` занят `children`). Без селектора поле не выходит; у роли C оно `true` у правила 2 |

Проекции, перечисляющие глаголы роли по типу, обязаны нести признак селектора. Иначе правило 2
читалось бы как «глаголы на всех учётках». Форма — замысел.

**Р3. Ведение созданных учёток держится, пока держится выдача.** Глаголы Р2 п.2 действуют для Sᵢ,
пока у Sᵢ есть **хотя бы одна** действующая выдача роли C на аккаунт A, в любой позиции субъекта.

1. **Вторая выдача.** Выдача может быть не одна: UNIQUE действующей выдачи стоит по `subjects[0]`
   (`0001_initial.sql:4443`, `access_binding/create.go:213-224`). Например, G с субъектом
   `[sva-iss]` и G' с субъектами `[sva-iss2, sva-iss]`. Конец одной из них не снимает ни
   `service_account_creator`, ни ведения, пока действует другая. Так же сегодня ведёт себя
   общий кортеж двух выдач: свёртка снятия спрашивает о держателях (`access_binding/delete.go`,
   шапка). Держатель — SAC-32.
2. **Пути конца выдачи.** Конец последней такой выдачи снимает и `service_account_creator`, и
   глаголы на созданных учётках, каким бы путём выдача ни кончилась:
   - `AccessBindingService.Revoke` — SAC-30;
   - `AccessBindingService.Delete` — SAC-33 a;
   - истечение `expires_at` проходом срока реконсайлера (`reconcile.go:829`) — SAC-33 b.
3. **Повторная выдача** возвращает ведение ранее созданных учёток (SAC-31; вопрос В4).
4. **Под конкурентной записью.** Инвариант держат три писателя: создание учётки, выдача роли C и
   конец выдачи. Запись и снятие одного кортежа не коммутируют. Поэтому порядок коммитов исход не
   меняет:
   - учётка, созданная одновременно с концом последней выдачи, ведения у создателя не оставляет —
     SAC-34;
   - учётка, созданная одновременно с новой выдачей, получает ведение, если по окончании всех
     операций выдача действует, — SAC-35.

   Механизм синхронизации выбирает замысел.

Учётки, созданные Sᵢ, и их ключи концом выдачи не трогаются: учётные данные клиента не зависят от
того, держит ли выпускающий своё право. Убирает их администратор аккаунта — у него каскад
`super_admin` (SAC-16).

**Исход для самого создателя.**

- **Удаление.** Учётку-создателя с действующей выдачей роли C удалить нельзя — прежний отказ
  `FAILED_PRECONDITION` `ServiceAccount <id> has active access bindings and cannot be deleted`
  (§0.6; охрана и по `subjects[0]`, и по `subjects[1..N]`). Удаляется она только после конца
  всех своих выдач, то есть когда ведения у неё уже нет (п.2). Факт создателя на созданных ею
  учётках остаётся и никого не ведёт: id не переиспользуется (`ids.NewID`), а новая учётка
  факта чужого создателя не наследует.
- **Выключение.** `ServiceAccountService.Disable` создателя выдач и кортежей ведения не трогает,
  как не трогает их у любой учётки. Останавливается выпуск ей новых токенов и ключей, но уже
  выпущенные токены выключение не отзывает: до своего срока они действуют, и по ним учётка
  создаёт и ведёт учётки по роли C (`service_account/set_enabled.go:43-48`). Немедленно право
  создателя снимает конец выдачи роли C (п.2; SAC-30, SAC-33). `Enable` возвращает прежнее без
  перевыдачи.

Нового поведения у удаления и выключения нет. Новых сценариев на них не заводится.

**Р4. Факт создателя.** Создатель — принципал, вызвавший `ServiceAccountService.Create`. Факт
пишется в той же транзакции, что строка учётки (ban #10), на каждом создании, каким бы путём ни
пришло право. Он неизменяем, наружу не выдаётся (§2 п.3) и снимается вместе с учёткой. Ведение по
роли C получает только создатель-учётка (Р2: роль выдаётся только учёткам), поэтому для учёток,
созданных людьми, ничего не меняется. Форму хранения выбирает замысел. Если это новая колонка, то
новой миграцией (ban #5), без обратного заполнения (§2 п.4).

**Р5. Видимость.** `ServiceAccountService.List` создателя по аккаунту A отдаёт только созданные
им учётки — следствие Р2 п.2 и пообъектного сужения списка (§0.9). Новой логики списка нет.

**Р6. Тексты отказов** — часть контракта (`api-error-tone`):

| код | текст | где |
|---|---|---|
| `PERMISSION_DENIED` | `permission denied` | все отказы двери (§0.6) и отказ в праве выдавать |
| `FAILED_PRECONDITION` | три текста Р2 | `AccessBindingService.Create` роли C, синхронно, после права |
| `INVALID_ARGUMENT` | `Illegal argument verbs (create on serviceAccount is system-only)` | `RoleService.Create`, `Update` роли аккаунта |
| `INVALID_ARGUMENT`, поле `rules[<i>].createdBySubject` | `Illegal argument createdBySubject (creator-scoped rules are declared by a module manifest)` | `RoleService.Create`, `Update` |

### Критерии продукта (ban #18)

- **производительность.** Дверь на `Create` задаёт тот же один вопрос модели, что и сегодня; у
  отношения два пути вывода (прямой кортеж или `editor`), без обхода учёток. Материализация
  ведения добавляет к созданию учётки чтение выдач роли C субъекта-создателя на аккаунте — одно
  чтение по индексу «субъект, роль, область» на одну создаваемую учётку. Конец выдачи снимает
  кортежи учёток этого создателя на аккаунте. Число строк пропорционально числу его учёток,
  перебора учёток аккаунта нет. Синхронизация Р3 п.4 не добавляет запросов к модели. Её цена —
  ожидание блокировки только между писателями одного создателя и аккаунта. Замер — `EXPLAIN` обоих
  запросов на базе мира проб, DoD S1 п.8;
- **безопасность.** Поверхность названа:
  1. новое отношение модели на аккаунте и смена отношения в аннотации одного метода;
  2. новая системная роль;
  3. новая материализация — глаголы на учётках по факту создателя;
  4. новая форма манифеста (контейнерное действие, селектор создателя) и поле только вывода
     `Rule.created_by_subject`. Арендаторской роли обе недоступны (Р2 п.4).

  Освобождённых двери методов не прибавляется (Р1). Сужение против сегодняшнего: учётка модуля
  больше не держит `editor` (минус шесть созданий и приглашение) и не держит глаголов на
  чужих учётках аккаунта, то есть не может выпустить ключ учётке, которую не создавала (§0.2,
  класс). Роль выдаётся только учёткам, только на аккаунт, только целиком (Р2) и только
  держателем права выдавать. Делегат `#986` выдать её не может: у делегирования модуль `iam`
  запрещён (Д2 соседа, GD-06 c).

  **Состав с `#986`.** По приёмке svc-registry одна учётка `registry-token-issuer` держит и роль C,
  и делегирование `#986` (её строки 261 и 576). Для такой учётки свойство Д4 соседа («право писать
  выдачи не даёт права на данные») не выполняется. Цепочка: она заводит учётку (роль C), выдаёт ей
  роль registry (делегирование, Д6 соседа допускает субъекта из аккаунта делегирования) и
  выпускает ей ключ (ведение). Это не шире сегодняшнего: сегодня той же учётке нужны `editor` на
  аккаунте, `iam.service_account.admin` и право выдавать, а они дают всё это и больше. Внутри
  kaname эта цепочка не закрывается: заводить учётки и токены — функция модуля (Р-В1). Свойство
  Д4 на уровне одного принципала держится, только если роль C и делегирование выданы разным
  учёткам (Д11). Решает потребитель — вопрос В7;
- **инновационность.** Право создателя, привязанное к действующей выдаче: конец выдачи снимает
  ведение созданного, а сами учётки и ключи клиентов остаются. Контейнерное действие отделено от
  набора глаголов объекта и подстановкой не раздаётся;
- **узнаваемость.** Ближайшие аналоги: право `create` на отдельный тип ресурса в RBAC Kubernetes
  (создавать один вид объектов, не получая остальных) и принцип «создатель-владелец» (CREATOR
  OWNER в списках доступа каталогов LDAP). Имя роли следует ряду `iam.<ресурс>.<ярус>` модуля
  (`admin`, `edit`, `view`) и называет действие. Отличие нашего варианта: ведение созданного
  действует, пока держится выдача, а роль выдаётся только служебной учётке;
- **перспективность.** Шаг обратим: отношение, роль, форма манифеста, поле только вывода и факт
  создателя аддитивны. Отношение в аннотации `Create` шире прежнего (`or editor`), поэтому никто
  права не теряет. Миграции данных арендатора нет, внешне адресуемые координаты не меняются;
- **благо продукта, производственность.** Режима «только для стенда» нет.

---

## §4. Сценарии

### 4.1. Мир проб

**Мир С** — `newSACWorld` (заказан, `internal/apps/kaname/api/access_binding/`) поверх мира П6
`newPCRWorld` (`public_container_read_world_integration_test.go:99`), который поверх
`newSCWorld` (`system_class_world_integration_test.go:88`). Уже даёт:

- аккаунт acc-A (владелец usr-A, живая сессия `seedLiveHumanSession`,
  `system_class_s2_integration_test.go:228`), проект prj-A, человек usr-B без выдач, учётка sva-A и
  группа grp-A в acc-A, аккаунт acc-B (владелец usr-C);
- вопрос о доступе `pollAsk` (`public_container_read_world_integration_test.go:353`): `Check` с
  повтором раз в 200 мс до 30 с.

Дополнения (каждое — существующим глаголом или посевом мира):

- **аккаунт модуля** acc-S (владелец usr-S) и в нём учётки sva-iss, sva-iss2, sva-adm —
  `seedAccountByOwner`, `seedServiceAccount` (`testhelpers_assignable_test.go:113`,
  `system_class_world_integration_test.go:157`). Для гонок (SAC-34, SAC-35) — на каждый раунд k
  свежие sva-iss-k и sva-pad-k тем же посевом;
- **проект** prj-A2 в acc-A — `seedProjectInAccount` (`testhelpers_assignable_test.go:125`);
- **роль аккаунта** rol-own — `RoleService.Create` от usr-A в acc-A с правилом
  `{iam, [project], [get]}`, проба поллит до `done`;
- **учётка, созданная человеком**, sva-A2 — `ServiceAccountService.Create` от usr-A в acc-A, `done`.
  Создатель — usr-A (Р4). sva-A посеяна мимо глагола и факта создателя не несёт — как все учётки
  до изменения;
- **администратор облака** usr-R — `mustSeedUser` (`testhelpers_assignable_test.go:80`),
  `seedClusterAdmin` (`:141`), `seedLiveHumanSession`;
- **роль создателя C** `iam.service_account.creator` — встроенный манифест `iam` (заказан,
  `manifest.yaml`), посев ролей модуля при старте (`internal/apps/kaname/moduleseed`);
  идентификатор проба читает `RoleService.List` по имени. **Роль SAA**
  `iam.service_account.admin` — там же, есть (`manifest.yaml:1015`). **Каноническая роль**
  `view` — `internal/domain/role_catalog.go:24`;
- **дверь мира** — `authzguard.NewOwnDoor` с решателем, собранным как в композиционном корне:
  `authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))`
  (`cmd/kaname/wiring.go:274-275`, `cmd/kaname/serve.go:885`). Каждый вызов метода, который судит
  дверь (§0.1, §0.2), идёт `door.Unary()` → обработчик службы. Окно вердикта двери мира
  (`PositiveTTL`) — 1 с; проба печатает его. Сборка — заказана;
- **реконсайлер мира** работает и дренирует очередь событий; «очередь пуста» —
  `SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE sent_at IS NULL` = 0
  (`pg/reconcile_outbox/outbox.go:83`, `:132`);
- **вызов от учётки** — `operations.WithPrincipal(ctx, Principal{Type: "service_account", ID: …})`
  (образец `system_class_s2_integration_test.go:334`);
- **выпуск ключа** — `IssueSAKeyUseCase` собран как в `sa_keys/audit_outbox_integration_test.go:152`
  (`WithOwnIssuance`), вид ключа по умолчанию;
- **истечение выдачи** — срок ставится строкой `UPDATE kaname.access_bindings SET expires_at =
  now() + interval '2 seconds'` после приёма выдачи: вход `Create` требует не меньше 5 минут
  (`access_binding_service.proto:470-476`). Затем — проход срока `Reconciler.ExpireBinding`
  (`reconcile/reconcile.go:829`). Образец — URG-34
  (`unregister_revokes_grants_world_integration_test.go:784-796`).

**Выдача G** (вызов от usr-A): роль C, область `iam.account` acc-A, субъект
`{SUBJECT_TYPE_SERVICE_ACCOUNT, sva-iss}`, цель `{"allInScope":{}}`. **G2** — то же с субъектом
sva-iss2. **G'** — то же с субъектами `[{SUBJECT_TYPE_SERVICE_ACCOUNT, sva-iss2},
{SUBJECT_TYPE_SERVICE_ACCOUNT, sva-iss}]`; вторая действующая выдача для sva-iss (Р3 п.1). G2 и G'
в одном мире не встречаются: у обеих `subjects[0]` — sva-iss2. После `done` каждой проба ждёт
`pollAsk(service_account:<субъект>, service_account_creator, account, acc-A, true)` по каждому
субъекту.

**Тело учётки U** (вызов от sva-iss): `{"accountId":"<acc-A>","name":"cr-1"}`. Учётку, созданную
по U, ниже зовём sva-cr1.

Строки отказов ниже отличаются от своего близнеца ровно одним полем или одним вызывающим.

### Группа A — выдача права

#### SAC-01 · владелец выдаёт роль создателя учётке модуля

**Given** мир С; выдач роли C в acc-A нет
**When** usr-A вызывает `AccessBindingService.Create` с телом G; проба поллит операцию
**Then** `done`, `error` пуст; `AccessBindingService.Get` выдачи от usr-A: роль C, субъект
sva-iss, область `iam.account` acc-A, `status = ACTIVE`
**And** `pollAsk(service_account:<sva-iss>, service_account_creator, account, acc-A, true)` в окне
**And** сразу после — `Check(sva-iss, r, account:acc-A)` для r ∈ {`editor`, `admin`, `viewer`,
`v_get`, `v_update`} — все false
**And** близнец — каждая строка SAC-02 (одно поле).

#### SAC-02 · роль создателя — только учётке, только на аккаунт, только целиком

**Given** мир С
| пример | отличие от G | вызывающий | исход |
|---|---|---|---|
| a | область `iam.project` prj-A | usr-A | `FAILED_PRECONDITION` `role <C> grants service account creation on iam.account scope only` |
| b | область `iam.cluster` `cluster_root` | usr-R | тот же текст |
| c | цель `{"resources":{"resources":[{"type":"iam.serviceAccount","id":"<sva-A>"}]}}` | usr-A | `FAILED_PRECONDITION` `role <C> requires target allInScope` |
| d | субъект `{SUBJECT_TYPE_USER, usr-B}` | usr-A | `FAILED_PRECONDITION` `role <C> can only be granted to SUBJECT_TYPE_SERVICE_ACCOUNT` |
| e | субъект `{SUBJECT_TYPE_GROUP, grp-A}` | usr-A | тот же текст, что d |
| f | субъект `{SUBJECT_TYPE_SYSTEM_CLASS, authenticated}` | usr-A | тот же текст, что d |
**When** `AccessBindingService.Create`
**Then** как в таблице, синхронно, операции нет; выдач роли C — столько же, сколько до вызова
**And** близнец каждой строки — SAC-01 (b — та же выдача G от usr-R на acc-A: `done`).

#### SAC-03 · без права выдавать роль не выдаётся

**Given** мир С
**When** a) usr-B вызывает `AccessBindingService.Create` с телом G; b) sva-iss — тот же запрос
(выдача себе)
**Then** a, b) `PERMISSION_DENIED` `permission denied`, синхронно, операции нет; выдач роли C в
acc-A — 0
**And** близнец — SAC-01 (отличается вызывающим).

### Группа B — создатель заводит и ведёт свои учётки

#### SAC-10 · создатель заводит учётку в аккаунте выдачи

**Given** мир С; G выполнена
**When** sva-iss вызывает `ServiceAccountService.Create` с телом U через дверь мира; проба поллит
`OperationService.Get` от sva-iss
**Then** `done`, `error` пуст; учётка sva-cr1: `accountId = acc-A`, `name = "cr-1"`,
`enabled = true`
**And** в `kaname.audit_outbox` строка `iam.service_account.created` с `resource_id = sva-cr1` и
`actor = sva-iss`
**And** близнец — SAC-11 a (отличается аккаунтом).

#### SAC-11 · создаёт только там, где держит роль создателя

**Given** мир С; G выполнена; sva-adm держит выдачу SAA (от usr-A, область `iam.account` acc-A,
цель `allInScope`, `done`); контроль — `pollAsk(service_account:<sva-adm>, v_update,
iam_service_account, sva-A, true)`
| пример | вызов `ServiceAccountService.Create` | исход |
|---|---|---|
| a | sva-iss, `accountId = acc-B` | `PERMISSION_DENIED` `permission denied` |
| b | sva-iss2 (выдачи нет), тело U | `PERMISSION_DENIED` `permission denied` |
| c | sva-adm, тело U | `PERMISSION_DENIED` `permission denied` |
**When** вызов через дверь мира
**Then** как в таблице, синхронно; перепись учёток acc-A и acc-B до и после равна
**And** близнец каждой строки — SAC-10: a отличается аккаунтом, b и c — вызывающим. Строка c
держит Р2 п.4: роль с `*` на учётках ведёт все учётки аккаунта, а права создавать не получает.

#### SAC-12 · создатель ведёт созданную учётку весь цикл

**Given** мир С; G выполнена; SAC-10 выполнен (sva-cr1)
**When** sva-iss по порядку, каждый шаг до `done`:
1. `ServiceAccountService.Get` sva-cr1;
2. `SAKeyService.Issue` sva-cr1 — ключ K1, затем ещё раз — ключ K2;
3. `SAKeyService.List` sva-cr1;
4. `SAKeyService.Revoke` K1, затем `SAKeyService.List` sva-cr1;
5. `ServiceAccountService.Update` sva-cr1, `updateMask: ["labels"]`, `labels: {"k":"v"}`;
6. `ServiceAccountService.Disable`, затем `Enable` sva-cr1;
7. `SAKeyService.Revoke` K2; `ServiceAccountService.Delete` sva-cr1.
**Then** первый шаг проходит в окне материализации: проба повторяет его, пока не прошла дверь,
не дольше окна `pollAsk`. Каждый шаг — без ошибки:
1) тело sva-cr1;
2) два ключа с разными `keyId`;
3) ключей два — K1 и K2;
4) после отзыва ключ один — K2;
5) метки `{"k":"v"}`;
6) `enabled` — false, затем true;
7) `ServiceAccountService.List` от usr-A по acc-A sva-cr1 не содержит.
**And** близнец шагов 1, 2, 7 — SAC-13 c, a, b (тот же глагол на учётке, которую sva-iss не
создавала).

#### SAC-13 · чужие учётки аккаунта создателю недоступны

**Given** мир С; G выполнена; SAC-10 выполнен
| пример | вызов от sva-iss | учётка |
|---|---|---|
| a | `SAKeyService.Issue` | sva-A (факта создателя нет) |
| b | `ServiceAccountService.Delete` | sva-A |
| c | `ServiceAccountService.Get` | sva-A2 (создатель usr-A) |
| d | `SAKeyService.Issue` | sva-A2 |
| e | `ServiceAccountService.Update` `labels` | sva-A2 |
**When** вызов через дверь мира
**Then** каждая строка — `PERMISSION_DENIED` `permission denied`, синхронно, операции нет; учётки
на месте; ключей у sva-A и sva-A2 — столько же, сколько до вызова
**And** близнец: a, d — SAC-12 шаг 2; b — SAC-12 шаг 7; c — SAC-12 шаг 1; e — SAC-12 шаг 5
(отличается учёткой: создана sva-iss или нет).

#### SAC-14 · два создателя одного аккаунта не ведут учёток друг друга

**Given** мир С; G и G2 выполнены; sva-iss создал sva-cr1 (U), sva-iss2 создал sva-cr2
(`{"accountId":"<acc-A>","name":"cr-2"}`)
**When** a) sva-iss2 вызывает `SAKeyService.Issue` sva-cr1; b) sva-iss2 — `ServiceAccountService.Delete`
sva-cr1; c) sva-iss2 — `SAKeyService.Issue` sva-cr2
**Then** a, b) `PERMISSION_DENIED` `permission denied`; sva-cr1 на месте, ключей 0; c) `done`
**And** c — близнец a: отличается учёткой (своя или соседа-создателя).

#### SAC-15 · список создателя — только его учётки

**Given** мир SAC-14 до шага When
**When** a) sva-iss вызывает `ServiceAccountService.List` `accountId=acc-A`; b) usr-A — тот же
вызов
**Then** a) ровно одна строка — sva-cr1; b) среди строк есть sva-A, sva-A2, sva-cr1, sva-cr2
**And** b — близнец a: отличается вызывающим.

#### SAC-16 · администратор аккаунта распоряжается учётками создателя

**Given** мир С; G выполнена; SAC-10 выполнен
**When** usr-A вызывает a) `ServiceAccountService.Disable` sva-cr1; b) `ServiceAccountService.Delete`
sva-cr1
**Then** a, b) `done`; после b `ServiceAccountService.List` от usr-A sva-cr1 не содержит
**And** близнец — SAC-13 b (отличается вызывающим: администратор аккаунта или создатель чужой
учётки).

### Группа C — без прав сверх учёток (#1003)

#### SAC-20 · создатель не трогает проекты, группы и роли

**Given** мир С; G выполнена; контроль — `pollAsk(service_account:<sva-iss>,
service_account_creator, account, acc-A, true)`
| пример | вызов и тело | от sva-iss | близнец: от usr-A |
|---|---|---|---|
| a | `ProjectService.Create` `{"accountId":"<acc-A>","name":"p-20a"}` | `PERMISSION_DENIED` | `done` |
| b | `ProjectService.Update` prj-A2, `updateMask: ["labels"]`, `labels: {"k":"v"}` | `PERMISSION_DENIED` | `done` |
| c | `ProjectService.Delete` prj-A2 | `PERMISSION_DENIED` | `done` |
| d | `GroupService.Create` `{"accountId":"<acc-A>","name":"g-20d"}` | `PERMISSION_DENIED` | `done` |
| e | `GroupService.Update` grp-A, `updateMask: ["description"]`, `description: "d"` | `PERMISSION_DENIED` | `done` |
| f | `GroupService.AddMember` grp-A, участник `{SUBJECT_TYPE_SERVICE_ACCOUNT, sva-A}` | `PERMISSION_DENIED` | `done` |
| g | `GroupService.Delete` grp-A | `PERMISSION_DENIED` | `done` |
| h | `RoleService.Create` `{"accountId":"<acc-A>","name":"r_20h","rules":[{"module":"iam","resources":["project"],"verbs":["get"]}]}` | `PERMISSION_DENIED` | `done` |
| i | `RoleService.Update` rol-own, `updateMask: ["description"]`, `description: "d"` | `PERMISSION_DENIED` | `done` |
| j | `RoleService.Delete` rol-own | `PERMISSION_DENIED` | `done` |
**When** вызов через дверь мира
**Then** как в таблице; текст отказа `permission denied`; при отказе объект не появился и не
изменился (перепись проектов, групп, ролей acc-A до и после равна)
**And** правый столбец — близнец левого (отличается вызывающим). Строки c, g, j справа — каждая
на свежем мире.

#### SAC-21 · перепись: у создателя на аккаунте ровно одно право

**Given** мир С; G выполнена (контроль — как в SAC-20)
**When** проба читает из каталога прав, который судит дверь мира, все записи с областью
`account`. Для каждой задаёт решателю двери вопрос `(service_account:<sva-iss>,
required_relation, account:acc-A)`. Затем для объектов o ∈ {`project:prj-A`, `iam_group:grp-A`,
`iam_role:rol-own`, `iam_service_account:sva-A`} и каждого отношения r, которое тип o объявляет из
{`viewer`, `editor`, `admin`, `v_get`, `v_list`, `v_update`, `v_delete`}, задаёт вопрос
`(sva-iss, r, o)`
**Then** записей с областью `account` прочитано ≥ 1 (проба печатает число; на `5c6b7c078` — 16).
Истина — ровно у одной: `ServiceAccountService/Create`; у остальных — false
**And** все вопросы об объектах — false
**And** проба печатает число заданных вопросов; 0 — «не выполнилось»
**And** близнец: та же перепись для `user:<usr-A>` — истина у каждой записи и каждого вопроса
(отличается субъектом).

#### SAC-22 · право создавать не даёт права выдавать

**Given** мир С; G выполнена; SAC-10 выполнен
**When** a) sva-iss вызывает `AccessBindingService.Create`: каноническая `view`, область
`iam.account` acc-A, субъект sva-cr1, цель `allInScope`; b) тот же запрос от usr-A
**Then** a) `PERMISSION_DENIED` `permission denied`, синхронно, операции нет; выдач с субъектом
sva-cr1 — 0; b) `done`
**And** b — близнец a: отличается вызывающим.

### Группа D — конец выдачи, повторная выдача, гонки

#### SAC-30 · отзыв выдачи снимает и создание, и ведение; учётка и ключ остаются

**Given** мир С; G выполнена — выдача Bc; SAC-10 выполнен; sva-iss выпустил K1 на sva-cr1
**When** usr-A вызывает `AccessBindingService.Revoke` Bc, `done`; проба ждёт
`pollAsk(service_account:<sva-iss>, service_account_creator, account, acc-A, false)` и
`pollAsk(service_account:<sva-iss>, v_update, iam_service_account, sva-cr1, false)`, затем окно
вердикта двери мира; после этого a) sva-iss — `ServiceAccountService.Create` с телом
`{"accountId":"<acc-A>","name":"cr-9"}`; b) sva-iss — `SAKeyService.Issue` sva-cr1
**Then** a, b) `PERMISSION_DENIED` `permission denied`
**And** `ServiceAccountService.Get` sva-cr1 от usr-A — учётка на месте, `enabled = true`;
`SAKeyService.List` sva-cr1 от usr-A — K1 есть
**And** близнец — SAC-12 шаг 2 (тот же выпуск ключа до отзыва) и SAC-32 a (тот же отзыв при второй
действующей выдаче).

#### SAC-31 · повторная выдача возвращает ведение созданных раньше

**Given** мир SAC-30 после шага When
**When** usr-A снова выдаёт G, `done`; проба ждёт
`pollAsk(service_account:<sva-iss>, v_update, iam_service_account, sva-cr1, true)`; sva-iss
вызывает `SAKeyService.Issue` sva-cr1
**Then** `done`; ключей у sva-cr1 два
**And** близнец — SAC-30 b (отличается тем, действует ли выдача).

#### SAC-32 · вторая действующая выдача держит создание и ведение

**Given** мир С; G выполнена — выдача Bc; SAC-10 выполнен (sva-cr1); G' выполнена — выдача Bc'
(субъекты `[sva-iss2, sva-iss]`); контроль — `pollAsk(service_account:<sva-iss>,
service_account_creator, account, acc-A, true)`
**When** a) usr-A вызывает `AccessBindingService.Revoke` Bc, `done`; проба выжидает окно вердикта
двери мира; sva-iss вызывает `ServiceAccountService.Create`
`{"accountId":"<acc-A>","name":"cr-32"}` и `SAKeyService.Issue` sva-cr1;
b) затем usr-A вызывает `AccessBindingService.Revoke` Bc', `done`; проба ждёт
`pollAsk(service_account:<sva-iss>, service_account_creator, account, acc-A, false)` и
`pollAsk(service_account:<sva-iss>, v_update, iam_service_account, sva-cr1, false)`, затем окно
двери; sva-iss вызывает `SAKeyService.Issue` sva-cr1
**Then** a) обе операции `done`; `Check(sva-iss, v_update, iam_service_account:sva-cr1)` и
`Check(sva-iss, service_account_creator, account:acc-A)` — true; `AccessBindingService.Get` Bc —
`status = REVOKED`
**And** b) `PERMISSION_DENIED` `permission denied`; sva-cr1 и её ключ на месте
**And** близнец a — SAC-30 (тот же отзыв, второй выдачи нет); близнец b — a (отличается тем,
осталась ли действующая выдача).

#### SAC-33 · удаление выдачи и истечение срока снимают создание и ведение

**Given** мир С; G выполнена — выдача Bc; SAC-10 выполнен; sva-iss выпустил K1 на sva-cr1
| пример | как кончается Bc |
|---|---|
| a | usr-A вызывает `AccessBindingService.Delete` Bc, `done` |
| b | срок Bc ставится на «сейчас + 2 с» (§4.1, «истечение выдачи»); проба ждёт, пока `expires_at < now()`, и вызывает `Reconciler.ExpireBinding` Bc |
**When** после конца Bc проба ждёт `pollAsk(service_account:<sva-iss>, service_account_creator,
account, acc-A, false)` и `pollAsk(service_account:<sva-iss>, v_update, iam_service_account,
sva-cr1, false)`, затем окно вердикта двери мира; sva-iss вызывает
`ServiceAccountService.Create` `{"accountId":"<acc-A>","name":"cr-33"}` и `SAKeyService.Issue`
sva-cr1
**Then** оба вызова — `PERMISSION_DENIED` `permission denied`
**And** sva-cr1 на месте, `enabled = true`; K1 есть (`Get`, `SAKeyService.List` от usr-A)
**And** b) `AccessBindingService.Get` Bc от usr-A — `status = REVOKED`,
`revocationReason = REVOCATION_REASON_EXPIRED`
**And** близнец — SAC-12 шаг 2 (тот же выпуск ключа при действующей выдаче); строки a, b
отличаются от SAC-30 только путём конца выдачи.

#### SAC-34 · гонка: создание учётки против отзыва выдачи

**Given** мир С; раундов 10; в раунде k — свежая учётка-создатель sva-iss-k (acc-S), выдача Gk
(как G, субъект sva-iss-k), `done`, контроль `pollAsk(service_account:<sva-iss-k>,
service_account_creator, account, acc-A, true)`
**When** в каждом раунде 16 горутин sva-iss-k вызывают `ServiceAccountService.Create` через дверь
мира с телами `{"accountId":"<acc-A>","name":"r34-<k>-<i>"}`, i = 1…16. Одновременно (один общий
барьер старта) usr-A вызывает `AccessBindingService.Revoke` Gk. Проба поллит все операции до
`done`
**Then** Ck — учётки раунда, чьё создание кончилось `done` без ошибки. Каждый вызов кончается
либо `done`, либо `PERMISSION_DENIED` `permission denied`. Перепись учёток `r34-<k>-*` от usr-A
равна |Ck|
**And** по каждой учётке из Ck `pollAsk(service_account:<sva-iss-k>, v_update,
iam_service_account, <учётка>, false)` в окне, и `pollAsk(…, service_account_creator, account,
acc-A, false)`
**And** затем очередь событий реконсайла мира пуста (§4.1) и прошло окно вердикта двери. Повторный
`Check(sva-iss-k, v_update, iam_service_account:<учётка>)` по каждой учётке из Ck — снова false
**And** проба печатает по раунду |Ck| и число отказов. Раунд с |Ck| = 0 — «не выполнилось» для
раунда; если не выполнились все 10, сценарий — «не выполнилось»
**And** близнец — тот же прогон без отзыва Gk: по каждой учётке из Ck `pollAsk(…, v_update, …, true)`
(отличается одним фактом — был ли отзыв).

#### SAC-35 · гонка: создание учётки против новой выдачи

**Given** мир С; раундов 10; в раунде k — свежие sva-iss-k и sva-pad-k (acc-S), выдача Gk (как G,
субъект sva-iss-k), `done`, контроль как в SAC-34
**When** в каждом раунде 16 горутин sva-iss-k вызывают `ServiceAccountService.Create` с телами
`{"accountId":"<acc-A>","name":"r35-<k>-<i>"}`. Одновременно (общий барьер) usr-A вызывает
`AccessBindingService.Create` G'k — роль C, `iam.account` acc-A, субъекты `[sva-pad-k,
sva-iss-k]`, `allInScope`. Проба поллит все операции до `done`. Затем, последовательно, usr-A
отзывает Gk, `done`
**Then** G'k `done`; `pollAsk(service_account:<sva-iss-k>, service_account_creator, account, acc-A,
true)` после отзыва Gk
**And** Ck — учётки раунда, созданные `done` без ошибки (все 16: Gk действовала на всём окне
создания). По каждой учётке из Ck `pollAsk(service_account:<sva-iss-k>, v_update,
iam_service_account, <учётка>, true)` в окне
**And** затем очередь событий реконсайла пуста и прошло окно двери. Повторный `Check` по каждой
учётке из Ck — снова true
**And** проба печатает |Ck| по раунду; |Ck| = 0 — «не выполнилось»
**And** близнец — тот же прогон, где G'k выдана и `done` до барьера создания (отличается одним
фактом — порядком выдачи G'k и создания).

### Группа E — форма права и роль создателя только системная

#### SAC-40 · роль аккаунта не называет `create` на учётках и не несёт селектора создателя

**Given** для каждого варианта a–e — свежий мир С с теми же исходными объектами и связями;
создание роли в c не меняет мир остальных вариантов
**When** usr-A вызывает a) `RoleService.Create` `{"accountId":"<acc-A>","name":"r_40a","rules":
[{"module":"iam","resources":["serviceAccount"],"verbs":["create"]}]}`; b) `RoleService.Update`
rol-own, `updateMask: ["rules"]`, то же правило; c) `RoleService.Create` с телом a, но
`"verbs":["get"]`; d) `RoleService.Create` с телом c и `"createdBySubject":true` в правиле;
e) `RoleService.Update` rol-own, `updateMask: ["rules"]`, правило d
**Then** a, b) `INVALID_ARGUMENT`, `message` `Illegal argument verbs (create on serviceAccount is
system-only)`, синхронно, операции нет; правила rol-own прежние; c) `done`;
d, e) `INVALID_ARGUMENT`, поле `rules[0].createdBySubject`, `message` `Illegal argument
createdBySubject (creator-scoped rules are declared by a module manifest)`, синхронно, операции
нет; у e правила rol-own прежние
**And** c — близнец a (отличается глаголом) и d (отличается селектором); b и e — те же отказы, что
a и d, на методе `Update` (Р2 п.4 отвергает в `Create` и в `Update`).

Техническая правка, 2026-11-01, после независимого BLOCKED на отпечаток
`bda4d4fcc1bb29203a4677f4855a8116294518cc540aa2243b0d1f26c985da4c`: в SAC-20 h и
SAC-40 a (и наследующих тело вариантах c, d) исправлены только имена пользовательских ролей;
для SAC-40 явно указана изоляция вариантов. Проверяемые права, исходы и состав сценариев
сохранены. Эта редакция требует независимого ревью по новому отпечатку; одобрение ей здесь
не присваивается. Прежние записи ревью и пометка правки SAC-E3 сохранены как история.

#### SAC-41 · роль создателя видна в каталоге ролей целиком

**Given** мир С
**When** usr-A вызывает `RoleService.List` и находит роли по имени `iam.service_account.creator` и
`iam.service_account.admin`
**Then** у роли C `isSystem = true`, `definitionTier = {iam.cluster, cluster_root}`,
`health = ROLE_HEALTH_HEALTHY`, правил ровно два:
`{module: "iam", resources: ["serviceAccount"], verbs: ["create"]}` без ключа `createdBySubject`
и `{module: "iam", resources: ["serviceAccount"], verbs: ["get", "list", "update", "delete"],
createdBySubject: true}`
**And** у роли SAA ключа `createdBySubject` нет ни в одном правиле
**And** близнец — SAC-40 a и d: то же правило в роли аккаунта отвергается.

#### SAC-42 · форма манифеста: загрузчик, roleexport, генератор модели, подстановка

Модульная проба пакета `internal/manifest` (с `roleexport` и генератором модели), без базы.

**Given** встроенный манифест `iam` после изменения (вариант a) и варианты, отличающиеся от него
ровно одной правкой
| пример | вариант | исход |
|---|---|---|
| a | как есть | загрузчик — 0 отказов; roleexport — 0 находок MOD-RL-18/19; в выведенной модели у `account` есть `define service_account_creator: [service_account] or editor`, у `iam_service_account` нет `define v_create`, всего `define v_create` — 1 |
| b | у `serviceAccount` снята запись `containerVerbs` | загрузчик отвергает роль C: отказ называет `create` и координату `verbs` правила 1 (как сегодня, §0.11 п.1) |
| c | правило 1 роли C — `classes: [create]` вместо `verbs: [create]` | манифест не принимается; отказ называет роль C и координату правила 1 |
| d | `relation: v_service_account_creator` (с приставкой; отношение объявлено под этим именем) | отказ загрузчика: имя контейнерного отношения с приставкой `v_` |
| e | `parent: project` | отказ загрузчика: `project` не родитель `serviceAccount` |
| f | `createdBySubject: true` в правиле над `group` | отказ загрузчика: у ресурса нет контейнерного действия `create` |
| g | правило 2 с `createdBySubject: true` и `resourceNames: [x]` | отказ загрузчика: селекторы взаимоисключающи |
| h | как есть; вопрос — набор, в который разворачивается правило `iam.service_account.admin` (`classes: ["*"]`) на `iam_service_account` | ровно `get`, `list`, `update`, `delete`; `create` нет; отношения на `account` правило не даёт |
**When** загрузка, roleexport и вывод модели по каждому варианту
**Then** как в таблице; проба печатает число вариантов и число отказов по каждому; 0 прочитанных
вариантов — «не выполнилось»
**And** близнец каждой строки b–g — строка a (одна правка).

### S2 — сквозной набор службы (`PRO-Robotech/kaname`, newman, собственный REST-фронт)

Мир — посев набора (`tests/authz-fixtures`, образец переменных — `tests/newman/cases/iam-service-account.py`,
шапка): `accountAId` и `jwtAccountAdminA` (учётка, `admin` на `accountAId`), `accountBId`,
`svaAId`. Заказано: учётка-создатель `saCreatorId` в отдельном аккаунте с ключом и предъявителем
`jwtSaCreator` (`client_credentials`). Утверждается пара: HTTP-статус и `code` из тела.

#### SAC-E1 · роль создателя выдаётся через край

**Given** посев набора
**When** `jwtAccountAdminA`: `POST /iam/v1/accessBindings` — роль C, область `iam.account`
`accountAId`, субъект `saCreatorId`, цель `allInScope`; полл `GET /iam/v1/operations/{id}`
**Then** 200; операция `done` без ошибки.

#### SAC-E2 · создатель ведёт свою учётку через край

**Given** E1 выполнен; набор ждёт видимости права ограниченным повтором первого шага
**When** `jwtSaCreator`: `POST /iam/v1/serviceAccounts` `{"accountId":"{{accountAId}}","name":"cr-{{runId}}"}`;
полл; `POST /iam/v1/serviceAccounts/{id}/keys` `{"credentialKind":"CREDENTIAL_KIND_SECRET","ttlSeconds":3600}`;
полл; `DELETE /iam/v1/serviceAccounts/{id}/keys/{keyId}`; полл; `DELETE /iam/v1/serviceAccounts/{id}`; полл
**Then** 200 на каждом шаге; каждая операция `done` без ошибки.

#### SAC-E3 · близнец E2: проекты, группы и роли — нет

**Given** как E2
| пример | вызов | `jwtSaCreator` | близнец: `jwtAccountAdminA` |
|---|---|---|---|
| a | `POST /iam/v1/projects` `{"accountId":"{{accountAId}}","name":"p-{{runId}}"}` | 403, `code: 7` | 200 |
| b | `POST /iam/v1/groups` `{"accountId":"{{accountAId}}","name":"g-{{runId}}"}` | 403, `code: 7` | 200 |
| c | `POST /iam/v1/roles` `{"accountId":"{{accountAId}}","name":"r{{runId}}","rules":[{"module":"iam","resources":["project"],"verbs":["get"]}]}` | 403, `code: 7` | 200 |
**When** вызов
**Then** как в таблице; у отказа `message: "permission denied"`.

Правка после вердикта, 2026-11-01: в строке c исправлена конструируемость положительного
контроля — имя `r{{runId}}` одинаково у creator и admin; семантика прав и утверждения
не меняются. Отдельный круг приёмки этой буквальной правки снят диспетчером по явному
разрешению пользователя на процессное сокращение. Прежние отпечатки ревью не являются
одобрением изменённой редакции.

#### SAC-E4 · близнец E2: ключ чужой учётке — нет

**Given** как E2
**When** `jwtSaCreator`: `POST /iam/v1/serviceAccounts/{{svaAId}}/keys` — тело шага ключа E2
**Then** 403, `code: 7`, `message: "permission denied"`
**And** близнец — шаг ключа E2 (отличается учёткой: своя или нет).

#### SAC-E5 · близнец E2: чужой аккаунт — нет

**Given** как E2
**When** `jwtSaCreator`: `POST /iam/v1/serviceAccounts` `{"accountId":"{{accountBId}}","name":"cr-b-{{runId}}"}`
**Then** 403, `code: 7`, `message: "permission denied"`
**And** близнец — первый шаг E2 (отличается аккаунтом).

---

## §5. Сценарий → производитель

### 5.1. Таблица

Производитель «заказан» — его заводит реализация. Держатель — проба с именем
`Test<Предмет>_SAC<NN>_…`: интеграционные (testcontainers) — в
`internal/apps/kaname/api/access_binding/`; SAC-42 — модульная, в `internal/manifest/`; сквозные —
`tests/newman/cases/iam-service-account-creator.py`.

| ID | что производит «Тогда» | держатель: строка утверждения | чем измерено |
|---|---|---|---|
| SAC-01 | заказан: роль C в манифесте `iam`; проекция правила 1 в `account#service_account_creator` (Р2 п.1, Р2а). Есть: путь выдачи `AccessBindingService.Create` | тело `Get` выдачи; `pollAsk(…service_account_creator…)` истина; пять вопросов о ярусах и глаголах аккаунта — false | тело, Check |
| SAC-02 | заказан: три структурных условия роли C (Р2) после права выдавать; тексты Р6 | код и `message` каждой строки дословно; число выдач роли C до = после | статус, SQL |
| SAC-03 | есть: `requireGrantAuthority` (`helpers.go:155`), текст `authzguard.go:63-64` | код, текст; выдач роли C — 0 | статус, SQL |
| SAC-10 | заказан: аннотация `Create` → `service_account_creator`, отношение в модели (Р1); факт создателя (Р4). Есть: use-case создания, аудит `iam.service_account.created` с `actor` (`create.go:131-143`) | `done`; поля учётки; строка аудита с `actor = sva-iss` | операция, тело, SQL |
| SAC-11 | заказан: Р1 (`[service_account] or editor`) и Р2а (`*` не достигает контейнерного действия). Есть: отказ двери (corelib `interceptor.go:216`) | три кода и текста; перепись учёток до = после; контроль `pollAsk(sva-adm, v_update, sva-A)` истина | статус, SQL, Check |
| SAC-12 | заказан: правило 2 — глаголы `v_get/v_list/v_update/v_delete` на учётках создателя по факту создателя (Р2 п.2, Р2а, Р4). Есть: use-case учётки и ключей, пол уровня входа для машины (`acr_floor.go:61`) | семь шагов без ошибки; поля, `keyId`, число ключей, метки, `enabled`, отсутствие в списке | тело, операция |
| SAC-13 | заказан: материализация только по факту создателя, без обратного заполнения (Р4). Есть: отказ двери | пять кодов и текстов; ключей до = после | статус, SQL |
| SAC-14 | заказан: тот же производитель, что SAC-12, — по создателю, а не по роли | пара a/b против c | статус, операция |
| SAC-15 | есть: пообъектное сужение списка (`list.go:261`); заказан: глаголы по факту создателя | множество строк a; включение в b | тело |
| SAC-16 | есть: каскад `super_admin` учётки (`fga_model.fga:846`) | два `done`; отсутствие в списке | операция, тело |
| SAC-20 | есть: аннотации `editor`/`v_update`/`v_delete` (§0.1) и дверь; заказано — роль C их не даёт (Р2 п.3) | десять пар; перепись до = после | статус, SQL |
| SAC-21 | есть: каталог прав двери (`permission_catalog.json`, выведен из аннотаций), решатель двери (`wiring.go:274-275`); заказано — Р1, Р2 п.3 | одна истина среди записей с областью `account`; все вопросы об объектах false; число вопросов; близнец usr-A — все истина | Check |
| SAC-22 | есть: право выдавать — три пути (`helpers.go:155`); заказано — роль C пути не добавляет | пара a/b; выдач с субъектом sva-cr1 — 0 | статус, SQL |
| SAC-30 | заказан: снятие `service_account_creator` и глаголов на учётках создателя отзывом выдачи (Р3 п.2). Есть: отзыв выдачи (`revoke.go:80`), учётка и ключи не трогаются | два отказа; учётка и K1 на месте | статус, тело, Check |
| SAC-31 | заказан: Р3 п.3 — повторная выдача возвращает глаголы по факту создателя | `done`; два ключа | операция, тело |
| SAC-32 | заказан: Р3 п.1 — снятие только при конце последней выдачи субъекта, в любой позиции субъекта. Есть: свёртка общего кортежа по держателям (`access_binding/delete.go`, шапка) | a — два `done` и два Check истина после отзыва Bc; b — отказ после отзыва Bc' | операция, Check, статус |
| SAC-33 | заказан: Р3 п.2 на путях `Delete` и истечения. Есть: `DeleteAccessBindingUseCase` (`delete.go:84`), проход срока `ExpireBinding` (`reconcile.go:829`), причина `REVOCATION_REASON_EXPIRED` | по строке два отказа; учётка и K1 на месте; b — `status`, `revocationReason` | статус, тело, Check |
| SAC-34 | заказан: Р3 п.4 — конец последней выдачи против конкурентного создания | по раунду: каждая учётка Ck — Check false после окна и после дренажа; |Ck| и отказы напечатаны | Check, SQL |
| SAC-35 | заказан: Р3 п.4 — новая выдача против конкурентного создания | по раунду: каждая учётка Ck — Check истина после отзыва Gk, окна и дренажа | Check, операция |
| SAC-40 | заказан: отказы Р2 п.4 — путь проверки правил `RoleService` (`rule_policy.go`), селектор на входе — рядом с отказом `children` (`role/handler.go:250`) | код и `message` a, b, d, e; поле `rules[0].createdBySubject` у d, e; правила rol-own прежние; c `done` | статус, тело |
| SAC-41 | заказан: роль C в манифесте `iam` (Р2), поле `Rule.created_by_subject` в выводе (Р2а) | поля роли C, два правила, `health`; у SAA ключа нет | тело |
| SAC-42 | заказан: форма `containerVerbs`/`createdBySubject` в загрузчике, roleexport и генераторе (Р2а). Есть: отказ необъявленного действия (`rolenamedverbs.go:117-135`), `Produces` (`producibility.go:97`), раскрытие подстановки (`role_verbs.go:51-110`) | восемь строк; число вариантов и отказов напечатано | исход загрузки, текст модели |
| SAC-E1 | заказан: роль C на стенде (встроенный манифест) | 200, `done` | newman |
| SAC-E2 | заказан: Р1, Р2, Р4 на собранной службе | 200 на каждом шаге | newman |
| SAC-E3 | есть: дверь слушателя; заказано — Р2 п.3 | три пары «статус, `code`» и три 200 | newman |
| SAC-E4 | заказано — Р4 (чужая учётка) | 403 + `code` 7 | newman |
| SAC-E5 | заказано — Р1 (право на одном аккаунте) | 403 + `code` 7 | newman |

Сценариев: **27** (`grep -c '^#### SAC-'` = 27; строк таблицы `grep -c '^| SAC-'` = 27) — пробы
службы 22 (SAC-01…03 — 3, 10…16 — 7, 20…22 — 3, 30…35 — 6, 40…42 — 3; из них SAC-42 модульная),
сквозных 5 (SAC-E1…E5). Производитель назван у всех 27.

### 5.2. Дано → писатель

| «Дано» | писатель | координата |
|---|---|---|
| acc-A, usr-A, prj-A, usr-B, sva-A, grp-A, acc-B, usr-C | посев мира | `system_class_world_integration_test.go:88-142` |
| живая сессия usr-A, usr-R | `seedLiveHumanSession` | `system_class_s2_integration_test.go:228` |
| acc-S, sva-iss, sva-iss2, sva-adm, sva-iss-k, sva-pad-k | `seedAccountByOwner`, `seedServiceAccount` | `testhelpers_assignable_test.go:113`, `system_class_world_integration_test.go:157` |
| prj-A2 | `seedProjectInAccount` | `testhelpers_assignable_test.go:125` |
| rol-own | `RoleService.Create` от usr-A | есть (use-case роли) |
| sva-A2 (создатель usr-A) | `ServiceAccountService.Create` от usr-A | есть (`service_account/create.go`) |
| usr-R — администратор облака | `mustSeedUser`, `seedClusterAdmin` | `testhelpers_assignable_test.go:80`, `:141` |
| роль C | посев ролей модуля при старте из встроенного манифеста | заказан (`manifest.yaml`), `internal/apps/kaname/moduleseed` |
| роль SAA, выдача SAA учётке sva-adm | тот же посев; `AccessBindingService.Create` от usr-A | `manifest.yaml:1015`; есть |
| выдачи G, G2, G', Gk, G'k (Bc, Bc') | `AccessBindingService.Create` от usr-A (SAC-01); многосубъектная — `subjects[]` (`access_binding/create.go:213-224`) | путь есть, роль заказана |
| срок выдачи «сейчас + 2 с» и его проход | строка `UPDATE kaname.access_bindings SET expires_at` после приёма; `Reconciler.ExpireBinding` | образец URG-34 `unregister_revokes_grants_world_integration_test.go:784-796`; `reconcile.go:829` |
| sva-cr1, sva-cr2, учётки раундов Ck | `ServiceAccountService.Create` от создателя (SAC-10) | заказан (Р1) |
| K1, K2 | `SAKeyService.Issue` от создателя (SAC-12) | use-case есть, право заказано |
| дверь мира | `authzguard.NewOwnDoor` + решатель композиционного корня | `serve.go:885`, `wiring.go:274-275`; сборка мира заказана |
| дренаж реконсайла | реконсайлер мира; признак — `resource_reconcile_outbox.sent_at IS NULL` = 0 | `pg/reconcile_outbox/outbox.go:83`, `:132` |
| вызов от учётки | `operations.WithPrincipal` | `system_class_s2_integration_test.go:334` |
| варианты манифеста SAC-42 | манифест, собранный текстом в пробе, с одной правкой против варианта a | заказан; образец сборки — `namedVerbManifest` (`internal/manifest/rolenamedverbs_test.go:49`) |
| посев S2: `saCreatorId`, `jwtSaCreator` | посев набора | заказан; образец — `iam-service-account.py`, шапка |

Каждое «Дано» строится либо существующим писателем, либо глаголом, чей положительный путь —
отдельный сценарий этой приёмки (SAC-01, SAC-10, SAC-12). Посева мимо глагола для выдач роли C,
учёток создателя и ключей нет. Мимо глагола ставится только срок выдачи: вход `Create` короче
5 минут не принимает, и проба повторяет приём URG-34. Единственная учётка без факта создателя —
sva-A, посеянная мимо глагола намеренно: она представляет учётки до изменения (Р4, §2 п.4).

### 5.3. Строки потребителя → сценарии

| строка приёмки svc-registry | сценарий здесь |
|---|---|
| §3а «служебная учётка выпускающего заводит и снимает SA, ключи SA… создание SA без права на Project, Group, Role» | SAC-10, SAC-12, SAC-20, SAC-21 |
| SRI-60 — новая SA в аккаунте `accA`, ключ со сроком | SAC-10, SAC-12 шаг 2; выдача роли registry на неё — `#986` (GD-10, Д6 соседа) |
| SRI-65 — отзыв одного ключа | SAC-12 шаг 4 |
| SRI-66 — ротация (второй ключ, затем отзыв первого) | SAC-12 шаги 2–4 |
| SRI-67 — удаление учётных данных | SAC-12 шаг 7; снятие выдач до удаления — `#986` (GD-30) |
| SRI-111 f — `ProjectService/Create` | SAC-20 a |
| SRI-111 g — группа, `RoleService/Create` | SAC-20 d, f, h |
| SRI-111 «привязок `admin`/`owner` на аккаунт у учёток svc-registry — 0» | SAC-21 (свойство kaname); перепись привязок стенда — держатель svc-registry |
| SRI-90 — SA и ключи пишет только `registry-token-issuer` | SAC-10 (аудит с `actor`) |
| В-SA — отдельный аккаунт для SA токенов с `editor` там | не нужен: умолчание A4 исполнимо без `editor` (Р1, Р2) |

---

## §6. Признак готовности (DoD)

### S1 — `PRO-Robotech/kaname`

1. `service_account_service.proto`: `Create` — `required_relation = "service_account_creator"`,
   прочие опции прежние (Р1). `role.proto`: поле только вывода `Rule.created_by_subject` (Р2а).
   Встроенный каталог прав (`internal/apps/kaname/seed/embedded/permission_catalog.json`)
   перевыведен из аннотаций. `buf lint`, `buf breaking`, перегенерация — зелёные
2. Форма манифеста (Р2а): `containerVerbs` у ресурса и `createdBySubject` у правила — в схеме
   манифеста, загрузчике, roleexport и генераторе модели со следствиями таблицы Р2а
3. Манифест `iam` (`manifest.yaml` и встроенная копия): отношение `service_account_creator` у
   ресурса `account` с текстом Р1; контейнерное действие `create` у `serviceAccount`; роль
   `iam.service_account.creator` с двумя правилами Р2. Модель прав перевыведена из манифеста;
   канон и встроенная копия побайтово равны (`TestEmbeddedModelIsByteIdenticalToCanonical`);
   гейт неглагольных отношений с читателем зелёный
4. Факт создателя — в транзакции создания учётки (Р4); если колонка — новой миграцией, без
   обратного заполнения. Применённые миграции не правятся (ban #5)
5. Проекция выдачи роли C: отношение на аккаунте и глаголы на учётках создателя (Р2 пп.1–3);
   снятие при конце последней выдачи субъекта на всех трёх путях и под конкурентной записью (Р3);
   структурные условия и тексты (Р2, Р6); отказы Р2 п.4 и неразворачивание `*`
6. Пробы службы SAC-01…SAC-42 (22) — сперва красные на `5c6b7c078` (ban #12), затем зелёные; обе
   стороны каждой пары — в одном наборе, на одной ревизии. Проба, чьё «Дано» требует роли C или её
   выдачи, на `5c6b7c078` не строится (роли C до изменения нет) и кончается «не выполнилось», а не
   красным (так — SAC-13, SAC-20 слева, SAC-22 a); в `DoD-proof` исход каждой пробы до и после
   изменения назван одной из трёх категорий: зелёный · красный · не выполнилось. Мир С вызывает
   методы, которые судит дверь, только через дверь мира. Гонки SAC-34, SAC-35 печатают |Ck| по
   раунду
7. Ни одна прежняя проба домена доступа не ослаблена; набор домена доступа зелёный целиком
8. `EXPLAIN` запроса материализации ведения (выдачи роли C по субъекту и аккаунту) и запроса
   снятия при конце выдачи — по индексу, без перебора учёток аккаунта; вывод — в комментарии
   `DoD-proof`
9. Врезки модели и манифеста о `v_create` (шапка модели, абзац «`v_create` IS NOT PART…») и о
   том, что `editor@account` гейтит создание каждого ресурса, правятся тем же изменением: после Р1
   они неполны (второе отношение-контейнер — `account#service_account_creator`, объявленное
   контейнерным действием, а не глаголом)
10. Комментарий `DoD-proof @<sha>` в `#1003`: команда, сырой итог, код возврата

### S2 — `PRO-Robotech/kaname`, сквозной набор

1. `tests/newman/cases/iam-service-account-creator.py` и порождённая коллекция: SAC-E1…SAC-E5, пара
   «статус, `code`» в каждом отрицательном; посев `saCreatorId`/`jwtSaCreator`; строка ведомости
   производителя для новой коллекции
2. Прогон на внешнем кластере в боевой посадке, своё пространство, снятие в той же задаче,
   перепись остатков после — 0

---

## §7. Внешние зависимости

| что | где | зачем | признак готовности |
|---|---|---|---|
| каталог прав у края kacho | `PRO-Robotech/kacho`, закрепление версии kaname | край kacho судит по каталогу, выведенному из аннотаций закреплённой у него версии kaname. До перезакрепления он требует `editor` у `ServiceAccountService.Create`: отказ создателю через край kacho уже, а не шире (fail-closed). svc-registry ходит к kaname напрямую, на арендаторский слушатель (Р-В5) | перезакрепление — после kaname (порядок «сначала kaname»), отдельной задачей kacho; этой приёмкой не требуется |
| кто выдаёт роль C на аккаунт арендатора | вопрос В1 | без выдачи учётка выпускающего на настоящем kaname учёток не заводит | В1 решён; шаг выдачи назван в приёмке потребителя |
| роль C в манифесте и учётка выпускающего | svc-registry: посев учётки `registry-token-issuer` без вступления в группы | субъект выдачи | учётка заведена посевом манифеста svc-registry |
| разведение роли C и делегирования по учёткам | приёмка svc-registry, вопрос В7 | свойство Д4 `#986` на уровне принципала (§3, «безопасность») | В7 решён в приёмке потребителя |

---

## §8. Открытые вопросы

**В1. Кто выдаёт роль C на аккаунт арендатора в боевой посадке.** Тот же вопрос, что В1 соседа
`#986` (делегирование): kaname наружу не публикуется (Р-В5).
- (а) платформа при включении registry для аккаунта: тем же шагом от администратора облака, что
  заводит делегирование. Цена — один шаг платформы на аккаунт, две записи вместо одной;
- (б) роль C на кластере. Цена — нарушает Р-узко: создатель заводил бы учётки в любом аккаунте.
  Отвергнуто в Р2 (SAC-02 b).
**Рекомендация — (а)**, одним шагом с В1 соседа.

**В2. Переживает ли ведение конец выдачи.** Принято: нет (Р3). Альтернатива — факт создателя даёт
ведение навсегда, как владелец файла. Цена альтернативы — у отозванного выпускающего остаётся
право выпускать ключи учёткам клиентов. Рекомендация — как принято.

**В3. Кому выдаётся роль.** Принято: только служебной учётке (Р2). Альтернатива — человеку и
группе. Цена альтернативы — для группы «кто создатель» становится неоднозначным (член в момент
создания или нынешний), а у людей уже есть `editor`. Рекомендация — как принято.

**В4. Повторная выдача возвращает ведение ранее созданных учёток.** Принято: да (Р3, SAC-31).
Альтернатива — ведение только учёток, созданных под действующей выдачей. Цена альтернативы —
после перевыдачи выпускающий не может отозвать ключи и удалить учётки, созданные раньше, и их
убирает только администратор аккаунта. Рекомендация — как принято.

**В5. Создатель в публичном `ServiceAccount`.** Принято: не выдаётся (§2 п.3), его называет аудит.
Альтернатива — поле вывода `createdBy`. Цена — поле контракта, его проекция в `Get` и `List`
(`api-projection-says`). Рекомендация — завести отдельной задачей, если консоли понадобится
показывать создателя.

**В6. Роль аккаунта с глаголом `create` на учётках.** Принято: отвергается (Р2 п.4). Альтернатива —
разрешить, с теми же структурными условиями. Цена альтернативы — смысл «ведение созданного»
задаёт роль, которую автор аккаунта мог не понять, а проверок становится больше. Рекомендация —
как принято.

**В7. Роль C и делегирование `#986` у одной учётки.** Вопрос к приёмке svc-registry, не к kaname.
- (а) разные учётки: создатель (роль C) и делегат (`#986`). Цена — вторая учётка модуля и два
  ключа в его конфигурации. Свойство Д4 соседа держится для каждой из учёток;
- (б) одна учётка, как в редакции 3 потребителя. Цена — Д4 для неё не держится (§3,
  «безопасность»); это не шире сегодняшнего положения.
**Рекомендация — (а)**, по Д11 «отдельные принципалы по функциям».

---

## §9. Опора: соседи

| приёмка | отпечаток, состояние | что берётся |
|---|---|---|
| `delegated-grants-stay-within-the-delegation.md` (`#986`) | `7512fd96c7aeb85f352fd55954cfb881fa7c8610169574adb2291155bb690fe6`, редакция 3, вердикт APPROVED (круг 3), событие опубликовано | мир П6 и его помощники; Р-В3 (§3 соседа); GD-25 g (делегат не создаёт учёток) не противоречит этой приёмке: роль C делегированием не даётся (модуль `iam` делегировать нельзя, Д2 соседа); Д4, Д6 — состав (§3); В1 |
| `module-manifest-relation-grant.md` | на `5c6b7c078` | выдача отношением на входе `Create` не принимается — довод против второго пути (Р2); вид получателя спрашивается у модели (Р2а) |
| `module-manifest-roles-and-seed-grants.md` | на `5c6b7c078` | роли модуля объявляет манифест; поимённая форма права и MOD-RL-18/19 (Р2а) |
| `nested-rule-reaches-descendants-of-a-named-container.md` | на `5c6b7c078` | образец поля правила только вывода, объявляемого манифестом (`children`), и его отказа на входе (Р2 п.4, Р2а) |
| приёмка svc-registry, редакция 3 | `2717077568f0057fa3205069807b4cc1b5fa72ec00ecda50eadfad0967b22dc7`, DRAFT | потребитель: §3а, SRI-60…67, SRI-90, SRI-111, A4, Д11, В-SA; строки 261 и 576 (состав, §3) |

Редакция 1 опиралась на редакцию 2 соседа (`43622b18…37c1`). Между ними правка узкая (§11
соседа: Р5, GD-30, GD-70, §7), опору этой приёмки она не трогает: `diff` двух редакций соседа по
GD-25, GD-06, GD-10, GD-62, Д2, Д4, Д6, Р-В3, В1 пуст. Если отпечаток соседа сменится до ревью,
рецензент сверяет строку §9 и §5.3 с новой редакцией (fa-b7).

---

## §10. Что изменено против редакции 1 (`4dcce34d…`)

| основание (запись круга 1) | где закрыто |
|---|---|
| B1 CONSTRUCTIBILITY — роль C загрузчик не примет; нужен механизм проекции на родительский `account`, не раскрываемый `*`; каталог показывает меньше, чем роль даёт | §0.11 (предикаты «сегодня не объявимо»: загрузчик, roleexport, подстановка, нет селектора у `Rule`); Р2а (форма `containerVerbs` и `createdBySubject`, следствия для загрузчика, roleexport, генератора, раскрытия `*`, материализации, `RoleService`); Р2 — два правила роли; Р2 п.4 — отказ селектора на входе; SAC-41 — оба правила и `health`; SAC-42 — держатель формы; SAC-40 d |
| B2 NEGATIVE — нет гонки «создание против отзыва/выдачи» | Р3 п.4; SAC-34 (против отзыва, близнец без отзыва); SAC-35 (против новой выдачи, близнец с выдачей до создания) |
| B3 COVERAGE — вторая действующая выдача; концы через `Delete` и истечение | Р3 пп.1–2; SAC-32 (G' с субъектами `[sva-iss2, sva-iss]`); SAC-33 a (`Delete`), b (истечение, `REVOCATION_REASON_EXPIRED`); мир — выдача G', приём истечения; §5.2 |
| важное 1 SCOPE — Р-В3 и прочтение кортежей ведения | §3: Р-В3 в решениях владельца; Д-1003 — решение диспетчера 2026-10-25 |
| важное 2 COVERAGE — состав с `#986` | §3, «безопасность», абзац «Состав с `#986`»; §7 строка; В7 |
| важное 3 FORMAT — тела SAC-20 a, d, h и SAC-E3 c | SAC-20 — тела всех строк; SAC-E3 a–c — полные тела |
| важное 4 COVERAGE — исход при удалении и выключении создателя | Р3, «Исход для самого создателя»; §0.6 — строка отказа удаления |
| опора сменилась: `#986` — редакция 3, круг 3, событие опубликовано | шапка §0.10, §9 |

---

## §11. Что изменено против редакции 2 (`f283293c…`)

| основание (запись круга 2) | где закрыто |
|---|---|
| B4 COVERAGE — пункт «Выключение» называл неверный исход: выключение не отзывает выпущенные токены | Р3, «Исход для самого создателя», «Выключение»: выпущенные токены действуют до срока; немедленно право снимает конец выдачи роли C (SAC-30, SAC-33). Нового поведения и сценариев нет |
| важное 1 COVERAGE — `Update` с `createdBySubject` не держится | SAC-40 e (`RoleService.Update`, правило d); §5.1 строка SAC-40 |
| важное 3 SCOPE — подлинность Д-1003 | §3, Д-1003: подтверждено заданием диспетчера круга 3, цитата |
| важное 4 DoD — «сперва красные» у проб с непостроимым «Дано» | DoD S1 п.6: «не выполнилось» у проб, требующих роли C; три категории исхода в `DoD-proof` |
