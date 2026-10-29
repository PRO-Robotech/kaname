# Размер страницы ListSubjects — платформенный — Acceptance

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** — (только дописывается)
> **Дата:** 2026-10-29
> **Эпик/issue:** kaname#615 (поглотил закрытый kaname#845)

## Обзор

`AuthorizeService.ListSubjects` («кто держит право на ресурсе») — единственный публичный
список службы, у которого размер страницы живёт по своим правилам: `pageSize = 0` даёт
страницу из 500 держателей, отрицательный `pageSize` молча превращается в то же умолчание, а
значение больше 1000 отвергается собственным текстом без указания поля. Каждый прочий `List`
службы применяет правило платформы: `0` — 50, допустимо `[0..1000]`, вне диапазона —
`INVALID_ARGUMENT` с именем поля. Приёмка приводит `ListSubjects` к тому же правилу и
закрепляет контрактом, что комментарий поля называет именно его.

## Решение: умолчание — 50, диапазон — `[0..1000]`, отказ — платформенный

Задача называла 50, контракт после kaname#755 (коммит `6a01bbbea`) называет 500 «как есть».
Выбрано **50** — по конвенции API, а не по нынешнему коду:

- **Канон.** Конвенция пагинации `.claude/rules/api-conventions.md` §«Pagination / filter»
  (запись `api-pagesize`): `corevalidate.PageSize` — `0 → 50`, максимум 1000, вне `[0..1000]` —
  `INVALID_ARGUMENT`, не подрезка. Её же применяют все прочие списки службы: шесть вызовов
  `corevalidate.PageSize("page_size", …)` в непроверочном коде `internal/`
  (`git grep -c 'corevalidate.PageSize("page_size"' HEAD -- internal ':!*_test.go' | wc -l` → 6
  @a3a53471e) и общий помощник `shared.DefaultListPageSize = 50`; 28 публичных `List`-глаголов
  отдают 50 на `0` — соседняя приёмка `list-page-size-default-named-once.md` (DRAFT, SHA-256
  `7d7314a4899c78b368a3b2c8a3688d8958580e4846ccd516be40cdeb0cd5e34f`), раздел «Обзор».
- **Единица страницы не особая.** Держатель права — элемент ответа, как проект или выдача;
  «страница держателей» не даёт основания для своего числа. Стоимость страницы принадлежит
  запросу: каждая строка страницы проходит проверку допуска держателя (одним вопросом на
  страницу), и умолчание в десять раз меньше — в десять раз меньше работы на вызов, о размере
  которого клиент не просил.
- **Ничего не становится недостижимым.** Продолжение у списка работает (`nextPageToken`),
  клиенту, которому нужна крупная страница, доступно явное `pageSize` до 1000 — это закреплено
  сценариями LSP-02 и LSP-03.
- **Кого задевает смена умолчания.** Перепись потребителей публичного глагола @a3a53471e:
  в непроверочном коде kaname вызов `ListSubjectsRequest{` один — сам обработчик
  (`git grep -ln 'ListSubjectsRequest{' HEAD -- '*.go' ':!*_test.go' ':!pkg/api'` →
  `internal/apps/kaname/api/authorize/handler.go`); в kacho @`41d7edad9b` (`origin/main`)
  глагол назван только маршрутом края и его пробами, вызывающего прод-кода нет
  (`git grep -n 'ListSubjectsRequest\|authorize:listSubjects' origin/main -- ':!*.pb.go'
  ':!*.pb.gw.go'` → пять строк, все в `gateway/internal/middleware/*` и
  `internal/repohygiene/*`). Полагающегося на 500 потребителя нет.
- **Критерии продукта** (`00-kacho-core.md` §«Non-negotiables», ban #18): производительность —
  умолчание 50 вместо 500, работа одного вызова без явного размера меньше в 10 раз по числу
  строк страницы; безопасность — поверхность не расширяется (отказ формата раньше отказа в
  правах сообщает только о форме запроса, LSP-08); перспективность — изменение обратимо, адресация
  и форма ответа не меняются; производственность — режима «только для стенда» нет.

## Что НЕ входит

- **Курсор `pageToken` у `ListSubjects`.** Сейчас это сырой идентификатор держателя, а не
  непрозрачный токен; мусорный токен не отвергается. Это другое отклонение от той же конвенции
  (`api-pagination-cursor`), со своим производителем; заводится отдельной задачей и сюда не
  входит.
- **Укорачивание страницы после среза** — фильтром `subjectTypeFilter` и снятием недопущенных
  держателей (человек без подтверждённого адреса не называется). Страница может быть короче
  `pageSize` при непустом продолжении; это свойство пообъектного сужения, и сценарии ниже
  строятся так, чтобы его не задевать (см. «Дано → писатель»).
- **Внутренние читатели держателей** (`AccessBindingService.ExpandAccess` и прочие, кто
  перечисляет держателей внутри службы, а не через глагол) — их наблюдаемое поведение не
  меняется.
- **Прочие `List`-глаголы и их комментарии** — предмет соседней приёмки
  `list-page-size-default-named-once.md`.
- **Край kacho** (`/iam/v1/authorize:listSubjects` маршрутом шлюза) — проводит запрос насквозь
  и не правится; поведение следует службе.

## Полоса и фикстуры

Три уровня держателей, у каждого свои фикстуры.

**Интеграционный мир (LSP-01…03)** — настоящая база (testcontainers), мир
`newAdmWorld` (`internal/service/address_admission_integration_test.go:47`): дверь решения
`authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))` и служба
`AuthorizeService` поверх неё. Глагол зовётся **через обработчик** — уровень, на котором
стоит проверка формата: `authorize.NewHandler(svc, authorize.NewWhoAmIUseCase(nil, nil))`
поверх той же службы (как `newHandlerWithAuthorizer`,
`internal/apps/kaname/api/authorize/handler_test.go:229`) с проверкой полномочий вызывающего,
подключённой к той же двери (`WithCallerAuthority`, `handler.go:123`). Вызывающий — человек
`usr-lsp-01` (контекст `operations.WithPrincipal(…, Principal{ID: "usr-lsp-01", Type: "user"})`,
как `userCtx` в `caller_authority_test.go:78-79`): он сам держит `admin` на `account:acc-lsp` и
потому проходит проверку полномочий (`caller_authority.go:118-131`; в корне службы та же проверка подключена к двери —
`cmd/kaname/wiring.go:1311`).

**Модульная проба обработчика (LSP-04…09)** — `authorize.Handler` с дублёрами источника
вердикта и проверки полномочий вызывающего; дублёр считает обращения.

**Край — собственный публичный фронт kaname (LSP-04…09)**, `{{ownRestBaseUrl}}`, полоса
предъявленного. Фикстуры — машинный посев `tests/authz-fixtures/seed_own_stand.py`:
`jwtAccountAdminA` — сервисная учётка с встроенной ролью `admin` на `iam.account`
`{{accountAId}}` (посев, стр. 1210–1218); `{{accountBId}}` — второй аккаунт, на котором
`jwtAccountAdminA` ролей не имеет. Тело запроса во всех сценариях края:

```json
{"resource": {"type": "account", "id": "<аккаунт>"}, "action": "iam.account.get", "pageSize": <N>}
```

`POST {{ownRestBaseUrl}}/iam/v1/authorize:listSubjects`; ответ отказа — `{code, message, details}`,
статус HTTP — таблица края по умолчанию (`runtime.DefaultHTTPErrorHandler`,
`internal/restfront/stepup.go:53-54`; указание повышения уровня сюда не относится): `INVALID_ARGUMENT` → 400, `PERMISSION_DENIED` → 403.

> Допущение (снимается первым прогоном положительного близнеца LSP-05): встроенная роль
> `admin` на `iam.account` даёт вызывающему отношение `admin` на `account:{{accountAId}}`, которого
> требует проверка полномочий вызывающего (`caller_authority.go:53`, `callerAuthorityRelations`).
> Не даёт — близнец LSP-05 красный с 403, и это поломка фикстуры, а не продукта.

### Дано → писатель

| Дано | сценарии | писатель | контроль конструкции |
|---|---|---|---|
| аккаунт `acc-lsp` с владельцем, адрес владельца подтверждён | LSP-01…03 | `ciWorld.seedAccountWithOwner` (`internal/service/cascade_from_committed_rows_integration_test.go:134`; владелец вставляется с `email_verified_at`, стр. 145-146) | строка аккаунта читается |
| 61 человек `usr-lsp-01…61` в `acc-lsp` с подтверждённым адресом, у каждого — факт `admin` на `account:acc-lsp` | LSP-01…03 | `ciWorld.seedUser` (стр. 155: вставка с `email_verified_at`) и `ciWorld.factThroughJournal(t, "user:"+id, "admin", "account", "acc-lsp")` (стр. 202) — тот же писатель факта, что в EV-55 (`address_admission_integration_test.go:215`) | `SELECT count(*) FROM kaname.users WHERE account_id = 'acc-lsp' AND email_verified_at IS NULL` → `0` |
| вызывающий `usr-lsp-01` проходит проверку полномочий | LSP-01…03 | его же факт `admin` на `account:acc-lsp` (строка выше) | контрольный шаг ниже отвечает без ошибки |
| число держателей `T` известно и `T ≥ 61` | LSP-01…03 | контрольный шаг: `ListSubjects` `pageSize = 1000` → `T` субъектов, `nextPageToken` пуст; `T` запоминается | `T < 61` — фикстура сломана, сценарий не исполнен (не красный) |
| `jwtAccountAdminA` администрирует `{{accountAId}}` | LSP-04…07 | `seed_own_stand.py` (стр. 1213–1218, `grant_role(… role_admin, "iam.account", account_id)`) | положительные близнецы LSP-05, LSP-07 |
| `jwtAccountAdminA` не администрирует `{{accountBId}}` | LSP-08, LSP-09 | тот же посев: роль на B выдаётся другой учётке (стр. 1410–1425), не `jwtAccountAdminA` | близнец LSP-09 (403) |
| вызывающий проходит внешний перехватчик глагола | LSP-04…09 | каталог требует для глагола `viewer` на кластере, выданный классу `authenticated` (`caller_authority.go:7-17`); уровень сессии — машинная учётка от порога освобождена (`seed_own_stand.py:31`) | положительные близнецы |

Почему 61 и почему **люди с подтверждённым адресом**: страница режется до проверки допуска, а
недопущенный держатель снимается со страницы после среза — один такой среди первых 50 дал бы
49 и неотличимость от «умолчание 49». Подтверждённый адрес у каждого человека-держателя, включая владельца, убирает
этот факт из сценария. 61 — наименьшее число, при котором и `0` (50), и `60` (60) дают полную страницу
с продолжением.

## Сценарий 01: `pageSize = 0` — страница из 50 с продолжением

**ID:** LSP-01

**Given** аккаунт `acc-lsp`, у которого держателей `admin` ровно `T ≥ 61`, и каждый допущен
**When** клиент вызывает `AuthorizeService.ListSubjects` с payload:
  - `resource` = `{type: "account", id: "acc-lsp"}`
  - `action` = `iam.account.admin`
  - `page_size` = `0` (не задан)

**Then** ответ без ошибки, в `subjects` ровно `50` элементов
**And** `next_page_token` непуст.

## Сценарий 02: явный `pageSize = 60` — 60 (близнец LSP-01)

**ID:** LSP-02 — отличается от LSP-01 ровно `page_size = 60`.

**Then** ответ без ошибки, в `subjects` ровно `60` элементов
**And** `next_page_token` непуст — 50 в LSP-01 есть умолчание, а не потолок данных или
перечисления.

## Сценарий 03: продолжение страницы умолчания доводит обход до конца

**ID:** LSP-03 — продолжает LSP-01 тем же вызовом с `page_token` = `next_page_token` ответа LSP-01,
`page_size = 0`.

**Then** ответ без ошибки, в `subjects` ровно `T − 50` элементов
**And** `next_page_token` пуст
**And** ни один элемент не повторяет элемент страницы LSP-01, а объединение двух страниц равно
множеству `T` держателей контрольного шага — умолчание 50 не оставляет держателей недостижимыми.

## Сценарий 04: отрицательный `pageSize` — `INVALID_ARGUMENT` с именем поля

**ID:** LSP-04

**Given** вызывающий `jwtAccountAdminA` администрирует `{{accountAId}}`
**When** клиент вызывает `POST /iam/v1/authorize:listSubjects` с телом
`{"resource": {"type": "account", "id": "{{accountAId}}"}, "action": "iam.account.get", "pageSize": -1}`

**Then** HTTP `400`, `code` = `3` (`INVALID_ARGUMENT`), `message` = `invalid argument`
**And** в `details` — `google.rpc.BadRequest`, у которого `fieldViolations` содержит ровно одно
нарушение: `field` = `page_size`, `description` = `page_size must be in [0..1000] (0 means default)`
**And** источник держателей не опрошен (модульная проба: счётчик обращений дублёра — `0`).

## Сценарий 05: `pageSize = 0` принят (близнец LSP-04)

**ID:** LSP-05 — отличается от LSP-04 ровно `"pageSize": 0`.

**Then** HTTP `200`, `subjects` — массив (держателей `viewer` на аккаунте, не меньше одного)
**And** модульная проба: источник держателей опрошен с размером `50`.

## Сценарий 06: `pageSize = 1001` — `INVALID_ARGUMENT` с именем поля

**ID:** LSP-06 — отличается от LSP-04 ровно `"pageSize": 1001`.

**Then** HTTP `400`, `code` = `3`, `message` = `invalid argument`
**And** `fieldViolations` — ровно одно: `field` = `page_size`,
`description` = `page_size must be in [0..1000] (0 means default)`
**And** прежний текст `Illegal argument page_size 1001 > 1000` не производится
**And** источник держателей не опрошен.

## Сценарий 07: `pageSize = 1000` принят (близнец LSP-06)

**ID:** LSP-07 — отличается от LSP-06 ровно `"pageSize": 1000`.

**Then** HTTP `200`, `subjects` — массив
**And** модульная проба: источник держателей опрошен с размером `1000`.

## Сценарий 08: формат страницы судится раньше полномочий вызывающего

**ID:** LSP-08

**Given** вызывающий `jwtAccountAdminA` **не** администрирует `{{accountBId}}`
**When** клиент вызывает `POST /iam/v1/authorize:listSubjects` с телом
`{"resource": {"type": "account", "id": "{{accountBId}}"}, "action": "iam.account.get", "pageSize": -1}`

**Then** HTTP `400`, `code` = `3`, `fieldViolations` — `field` = `page_size` (как в LSP-04)
**And** модульная проба: проверка полномочий вызывающего не опрошена (счётчик дублёра — `0`) —
вопрос «правильно ли составлен запрос» имеет один ответ для всех вызывающих
(`internal/apps/kaname/shared/pagination.go:78-80`, порядок «формат → права → хранилище»).

## Сценарий 09: тот же вызывающий с допустимым `pageSize` — отказ в правах (близнец LSP-08)

**ID:** LSP-09 — отличается от LSP-08 ровно `"pageSize": 0`.

**Then** HTTP `403`, `code` = `7` (`PERMISSION_DENIED`), `message` = `permission denied`
**And** источник держателей не опрошен — без полномочий перечисления нет.

## Сценарий 10: комментарий поля в контракте называет действующее правило

**ID:** LSP-10

**Then** комментарий поля `ListSubjectsRequest.page_size`
(`proto/kaname/cloud/iam/v1/authorize_service.proto`) называет умолчание `50`, допустимый
диапазон `[0..1000]` и отказ `INVALID_ARGUMENT` вне него; не называет иного умолчания
**And** проба контракта `TestPageSizeContractNamesTheDefaultTheServiceApplies`
(`internal/contracttext/page_size_default_test.go`) судит `ListSubjectsRequest.PageSize` по
умолчанию службы — записи исключения для него нет
**And** комментарий глагола (`Hard cap: page size ≤ 1000`) не расходится с полем: называет
диапазон `[0..1000]`.

## Сценарий → производитель

| ID | что производит «Тогда» | координата и строка утверждения держателя | чем измерено |
|---|---|---|---|
| LSP-01, LSP-05 (размер 50) | `corevalidate.PageSize`: `0 → DefaultPageSize` | corelib v1.15.0 (пин `go.mod:8`) `validate/validate.go:255-256` `if value == 0 { return DefaultPageSize, nil }`, `DefaultPageSize int64 = 50` — стр. 63. **Заказан** вызов в обработчике `ListSubjects` до проверки полномочий вызывающего и передача результата вниз (kaname#615, go-implementer); сегодня `0` уходит вниз как есть и превращается в 500 (`relverdict/subjects.go:201-203`, `list.go:87`) | прочитано в модуле @v1.15.0; `git grep -n 'DefaultPageSize = 500' HEAD -- internal` @a3a53471e |
| LSP-01, LSP-02 (непустое продолжение) | полная страница отдаёт курсор | `internal/repo/kaname/pg/relverdict/subjects.go:244-246` `if len(subjects) == limit { nextAfter = subjects[len(subjects)-1] }`; курсор проходит сквозь сужение допуска — `internal/authzcascade/own_gates.go:255-266` | прочитано @a3a53471e |
| LSP-02 (60) | `corevalidate.PageSize`: `1..1000 → value` | `validate.go:258` `return value, nil`; предел `LIMIT $4::int` — `subjects.go:180` | прочитано |
| LSP-03 (продолжение без повторов и пропусков) | порядок и отсечка по держателю | `subjects.go:178-180` `WHERE g.subject > $3::text ORDER BY g.subject LIMIT $4::int`; `AfterID` = `page_token` — `relverdict/asker_gate.go:38-55` | прочитано |
| LSP-04, LSP-06, LSP-08 (отказ с именем поля) | `corevalidate.PageSize`: вне `[0..1000]` | `validate.go:250-253` `AddFieldViolation(field, field+" must be in [0..1000] (0 means default)")`; `message` = `invalid argument` — corelib `errors/errors.go:80`; деталь `BadRequest` — `errors.go:47-49`. **Заказан** вызов с `field = "page_size"` (тот же, что `shared/pagination.go:87`) | прочитано |
| LSP-06 (прежний текст не производится) | снятие собственной проверки | сегодня — `internal/service/authorize_service.go:1255-1257` `Illegal argument page_size %d > 1000` и проброс по префиксу `handler.go:303-305`; **заказано** снятие | `git grep -n 'page_size %d > 1000' HEAD -- internal` @a3a53471e → 1 строка |
| LSP-04…LSP-07 (HTTP 400/200) | таблица края | `internal/restfront/stepup.go:53-54` → `runtime.DefaultHTTPErrorHandler` (не указание повышения уровня) | прочитано |
| LSP-08 (формат раньше полномочий) | порядок в обработчике | сегодня проверка полномочий — `handler.go:291` до вызова службы, формат — внутри службы; **заказана** проверка формата первым стейтментом после обязательных полей (`handler.go:282-287`) | прочитано |
| LSP-09 (403) | проверка полномочий вызывающего | `internal/apps/kaname/api/authorize/caller_authority.go:139` `status.Error(codes.PermissionDenied, "permission denied")` | прочитано |
| LSP-10 (текст контракта) | правка комментария и снятие записи исключения | сегодня — `authorize_service.proto:313-314` («default 500 …»), исключение — `page_size_default_test.go:53`; **заказаны** оба (kaname#615) | `git grep -n 'default 500' HEAD -- proto`; `git grep -n '"ListSubjectsRequest.PageSize"' HEAD -- internal` @a3a53471e |

## DoD

- **LSP-01…03** — интеграционная проба (testcontainers) в пакете `service_test`
  (`internal/service`, рядом с миром `newAdmWorld` и помощниками `ciWorld`) по посеву таблицы
  «Дано → писатель», вызов через обработчик с вызывающим `usr-lsp-01`; имена `TestLSP01_…`…`TestLSP03_…`. Красная на
  @a3a53471e (LSP-01 даёт `T`, а не 50, и пустой курсор при `T ≤ 500`), зелёная после правки.
- **LSP-04…09** — модульная проба обработчика с дублёрами, считающими обращения к источнику
  держателей и к проверке полномочий; утверждает пару «код + `fieldViolations[].field`» и счётчики.
  Красная на @a3a53471e (LSP-04: ответ без ошибки; LSP-06: текст без поля; LSP-08: отказ в
  правах раньше формата).
- **LSP-04…09 на краю** — newman-кейсы в существующем наборе собственного фронта
  `tests/newman/cases/kaname-own-rest-front.py` (уже адресуется к `{{ownRestBaseUrl}}` и читает
  `jwtAccountAdminA`, `accountAId`, `accountBId`; новой коллекции не заводится), ID —
  `IAM-OWNREST-LSP-04-…` … `IAM-OWNREST-LSP-09-…`; утверждается пара «HTTP-статус + `code`», у
  отказов формата — `fieldViolations[].field == "page_size"` и `description` дословно. Заводит
  производитель проб (`qa-test-engineer`).
- **LSP-10** — `TestPageSizeContractNamesTheDefaultTheServiceApplies` зелёная без записи
  `ListSubjectsRequest.PageSize` в `pageSizeOwnDefault`:
  `git grep -c '"ListSubjectsRequest.PageSize"' HEAD -- internal/contracttext/page_size_default_test.go` → `0`,
  и `git grep -n 'default 500' HEAD -- proto` → пусто. Правка `.proto` (только комментарии) —
  регенерацией заглушек, `buf lint` и `buf breaking` зелёные.
- Страница сайта документации службы `docs/content/api/authorize.mdx` (раздел `ListSubjects`,
  сегодня «Page size ≤ 1000», стр. 151) называет умолчание 50 и диапазон `[0..1000]`.
- `relverdict.DefaultPageSize` и прочие внутренние читатели держателей наблюдаемо не меняются:
  существующие пробы `ExpandAccess` и `relverdict` зелёные без правки.
