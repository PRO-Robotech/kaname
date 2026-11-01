# Идентификатор объекта в цели выдачи подчиняется грамматике объекта — Acceptance

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** (только дописывается)
> - 2026-10-26 · круг 1 · CHANGES_REQUESTED (B1 TWIN, B2 FORMAT) · редакция 1 `1d7635a30cc4a8efa1a73d61a99d02171d2f2183a7a0101401f1f145c1a9d01b` ·
>   `docs/specs/reviews/access-target-object-id-follows-the-object-grammar/1d7635a30cc4a8efa1a73d61a99d02171d2f2183a7a0101401f1f145c1a9d01b.yaml`
> **Дата:** 2026-10-26
> **Эпик/issue:** kaname#1004 · эпик kaname#980

## Обзор

Выдача роли с целью «названные объекты» (`AccessBindingService.Create`, поле
`target.resources[].id`) принимает идентификатор объекта без проверки формы: отвергается только
пустой. Регистрация объекта (`InternalIAMService.RegisterResource`, поле `object`) ту же форму
судит строже: идентификатор не несёт пробела, табуляции, перевода строки, `#` и `:`. Поэтому
цель выдачи может назвать объект, которого не бывает, и при этом два разных состава цели
сверяются как один: выдача на цель из одного такого объекта отвергается как повтор действующей
выдачи на цель из двух объектов, которой у вызывающего не было. Две разные цели неразличимы.

Приёмка закрепляет решение диспетчера (2026-10-26): идентификатор объекта цели, который
грамматика объекта не допускает, отвергается синхронно кодом `INVALID_ARGUMENT` с именем поля.
Проверка формы стоит там же, где сегодня отказ на пустой идентификатор: раньше проверки права
выдавать (`create.go:254` против `create.go:278`). Отказ синтаксический и о чужих объектах ничего
не сообщает, поэтому ниже ворот права его не переносят.
Способ, которым служба сверяет состав цели, не меняется: прежние выдачи остаются теми же целями,
что и были. Идентификатор с `/` (объекты модуля registry: репозиторий под реестром) остаётся
законным и разбирается дословно.

**Допущение (Д1).** «Грамматика объекта» здесь — та, по которой регистрация судит часть
идентификатора после двоеточия: непуст, без пробела, табуляции, перевода строки, `#` и `:`.
Объект с идентификатором, который регистрация отвергает, зарегистрирован быть не может, поэтому
отказ не отнимает ни одной законной выдачи. Расширять набор запретов сверх регистрации
(возврат каретки, прочие пробельные знаки Юникода) приёмка не берётся — см. «Что НЕ входит».

## Что НЕ входит

- Способ сверки состава цели и его хранимая форма — решение диспетчера «кодировку не менять».
  Миграции нет, хранимые выдачи не пересчитываются.
- Выдачи, уже лежащие в хранилище: приёмка судит вход `Create`, хранимые строки заново не
  проверяются. Изменить цель хранимой выдачи клиент не может: `Update` принимает только
  `deletion_protection` и `labels`.
- Грамматика регистрации объекта (`RegisterResource`): не меняется. Возврат каретки и прочие
  пробельные знаки Юникода она сегодня пропускает; их запрет, общий для регистрации и цели, —
  отдельный предмет, а не эта приёмка.
- Отказ на границах `/` (пустой сегмент, лишний сегмент, экранированный разделитель): служба
  такой идентификатор не режет и не нормализует, отказ на нём — дело грамматики владельца объекта
  (служба registry). Здесь эти границы — только положительные близнецы.
- Форма `ResourceRef.id` в вопросах о доступе (`AuthorizeService.Check` и соседи) — другое поле,
  другой предмет.
- Тип объекта цели (`target.resources[].type`): его по-прежнему судит живой каталог, раньше
  идентификатора (`access-target-names-live-catalog-types.md`).

Других писателей цели из клиентского входа нет. Измерено @ddd5681af двумя предикатами:
по написанию — `git grep -n 'targetFromProto(' -- internal ':!*_test.go'` → одно определение и
один вызов (`handler.go:144`); по предмету — `git grep -n 'AccessTarget{Resources:' -- internal ':!*_test.go'`
→ три строки: разбор входа (`delta_input.go:65`), сужение хранимой цели подмножеством
(`unregistered_key.go:169`), чтение хранимой цели (`relverdict/target.go:127`). Остальные
присваивания `Target:` в не-тестовом дереве — `AllInScope`.

## Полоса и фикстуры

**Полоса A (Go integration, мир П6).** Условие — зарегистрированный объект — создаёт только
модуль на внутреннем слушателе, а предмет включает хранимое число выдач, которого край не
показывает. Мир — `newPCRWorld` (`internal/apps/kaname/api/access_binding/public_container_read_world_integration_test.go:99`),
те же части, что корень службы.

**Полоса B (край, newman).** Собственный публичный фронт, набор
`tests/newman/cases/iam-access-binding-redesign.py`, вызывающий `jwtAccountAdminA` на аккаунте
`accountAId`, субъект `userNOBId`.

### Дано → писатель

| Given | писатель | где |
|---|---|---|
| объекты `registry.repositories` с идентификаторами `<base>/one`, `<base>/one/two`, `<base>/o-ne` зарегистрированы с цепью `[project, account]` | посев выводом: `RegisterResource` модулем, хелпер `registerSlashRepo` (заведён на ветке `1004`, коммит `534eed4e4`) | полоса A |
| роль с правилом `registry / repositories / get`, выдаваемая `usr-A` в проекте мира | фикстура мира: `w.seedRole` | полоса A |
| действующая выдача `usr-D` на цель `{<base>/one, <base>/one/two}` | посев выводом: `w.createDone` + `w.grantRequest` | полоса A |
| тип `registry.repositories` жив в каталоге мира | фикстура мира (`kanamepg.NewCatalogTypeReader` в `newPCRWorld`) | полоса A |
| роль аккаунта, покрывающая `compute.instance` | посев выводом: `_seed_role` того же набора (как в `IAM-ACB-RD-CR-TARGET-RESOURCES-OK`) | полоса B |
| `compute.instance` жив в каталоге стенда | условие стенда, уже несущее `IAM-ACB-RD-CR-TARGET-RESOURCES-OK` | полоса B |

`<base>` — `reg0000000000000s1a9` (константа `slashBase` ветки `1004`).

## Сценарий 01: идентификатор с `/` — законная цель

**ID:** ATI-01 — положительный сценарий: `/` законен. Близнецы отрицаний названы у каждого
отдельно: ATI-02 — ATI-02b, ATI-03 — столбец таблицы, ATI-04 — выдача `usr-D` из «Дано»,
ATI-05 — ATI-02b.

**Given** объект `registry.repositories:<base>/one` зарегистрирован
**When** `usr-A` вызывает `AccessBindingService.Create` (REST `POST /iam/v1/accessBindings`) с
`subjects=[usr-B]`, ролью из «Дано», `scopeType=iam.project`, `scopeId=<проект мира>`,
`target.resources=[{type: "registry.repositories", id: "<base>/one"}]`
**Then** ответ — `Operation`; поллинг `OperationService.Get` даёт `done=true` без `error`
**And** вопрос о доступе `usr-B` · `v_get` · `registry_repository:<base>/one` в окне
материализации отвечает «разрешено» (`AuthorizeService.Check` и `InternalIAMService.Check`)
**And** каждая граница `/` — `<base>/one/two`, `<base>/one/`, `<base>//one`, `/<base>/one`,
`<base>%2Fone`, `<base>\/one` — так же принимается целью выдачи: `Create` отвечает `Operation`,
поллинг даёт `done=true` без `error`.

## Сценарий 02: один объект не выдаёт себя за два

**ID:** ATI-02 — отрицание; его близнец — ATI-02b ниже: то же «Дано», тот же вызывающий, тот же
субъект `usr-D`, та же роль и область, отличие ровно одно — у идентификатора цели нет хвоста
«перевод строки и `registry.repositories:<base>/one/two`».

**Given** действующая выдача `usr-D` на цель `{<base>/one, <base>/one/two}`
**When** `usr-A` вызывает `Create` с `subjects=[usr-D]`, той же ролью и областью и
`target.resources=[{type: "registry.repositories", id: "<base>/one\nregistry.repositories:<base>/one/two"}]`
**Then** синхронный отказ `INVALID_ARGUMENT` (край: `400`, `code=3`), `Operation` не создаётся
**And** текст отказа дословно:
`Illegal argument target.resources[0].id (not a valid object id: space, tab, newline, '#' and ':' are not allowed)`
**And** число выдач `usr-D` по этой роли и области не изменилось — одна, действующая, на цель из
двух объектов
**And** отказ `ALREADY_EXISTS` («these permissions are already granted…») на этот вход не
производится.

Текст отказа дословен для цели с одним негодным элементом. Проверка цели копит отказы по всем
элементам, и при двух негодных текст — их склейка; такой вход приёмка не утверждает.

### Близнец ATI-02: законный идентификатор той же выдачи

**ID:** ATI-02b — положительный близнец ATI-02.

**Given** то же, что в ATI-02: действующая выдача `usr-D` на цель `{<base>/one, <base>/one/two}`
**When** `usr-A` вызывает `Create` с `subjects=[usr-D]`, той же ролью и областью и
`target.resources=[{type: "registry.repositories", id: "<base>/one"}]`
**Then** синхронной ошибки нет, ответ — `Operation`; поллинг `OperationService.Get` даёт
`done=true` без `error`
**And** выдач `usr-D` по этой роли и области становится две: прежняя на `{<base>/one, <base>/one/two}`
и новая на `{<base>/one}`.

## Сценарий 03: каждый запрещённый знак — отказ

**ID:** ATI-03 — пять отрицаний; каждое отличается от своего близнеца ровно одним знаком в
середине идентификатора.

**When** `Create`, как в ATI-01, с `target.resources=[{type: "registry.repositories", id: "<base>/o" + X + "ne"}]`

| X | исход | близнец (X = `-`) |
|---|---|---|
| пробел | `INVALID_ARGUMENT`, текст ATI-02 | `<base>/o-ne` принят, `done=true` без `error` |
| табуляция | то же | то же |
| перевод строки | то же | то же |
| `#` | то же | то же |
| `:` | то же | то же |

**Then** по каждой строке — исход из таблицы; `Operation` у отказа не создаётся.

## Сценарий 04: отказ называет позицию в перечне

**ID:** ATI-04 — отличается от выдачи `usr-D` из «Дано» ровно вторым элементом цели: вместо
`<base>/one/two` стоит `<base>/one two`.

**When** `Create` с `target.resources=[{…, id: "<base>/one"}, {…, id: "<base>/one two"}]`
**Then** `INVALID_ARGUMENT`, текст
`Illegal argument target.resources[1].id (not a valid object id: space, tab, newline, '#' and ':' are not allowed)`
(позиция `1`, а не `0`).

## Сценарий 05: сверка состава цели прежняя

**ID:** ATI-05 — отрицание; его положительный близнец — ATI-02b (то же «Дано», тот же субъект,
роль и область; отличие одно — состав цели `{<base>/one}` вместо того же состава в обратном
порядке).

**Given** действующая выдача `usr-D` на цель `{<base>/one, <base>/one/two}`
**When** `usr-A` вызывает `Create` с `subjects=[usr-D]`, той же ролью и областью и целью в
обратном порядке
`target.resources=[{type: "registry.repositories", id: "<base>/one/two"}, {type: "registry.repositories", id: "<base>/one"}]`
**Then** синхронной ошибки нет, ответ — `Operation` (как до этой правки)
**And** поллинг `OperationService.Get` даёт `done=true` и `error` с `code=6` (`ALREADY_EXISTS`),
текст дословно: `these permissions are already granted to <usr-D> on project:<проект мира>` —
где `<usr-D>` и `<проект мира>` — идентификаторы субъекта и проекта из «Дано»
**And** число выдач `usr-D` по этой роли и области не изменилось — одна
**And** цель другого состава из законных идентификаторов — `{<base>/one}` при том же «Дано» —
сосуществует с действующей (исход ATI-02b): сверка состава различает состав, а не порядок.

## Сценарий → производитель

| ID | что производит «Тогда» | координата и строка утверждения держателя | чем измерено |
|---|---|---|---|
| ATI-01 | принятие идентификатора с `/` дословно | производитель — `targetFromProto` (`internal/apps/kaname/api/access_binding/delta_input.go:62-65`) переносит `id` без разбора. Держатель — проба ветки `1004` @`43750c544`, строка `w.pollAsk(usrB, "v_get", pcrRepoType, legit, true, …)` и `assert.True(t, w.askInternal(usrB, "v_get", pcrRepoType, legit), …)`; прогон — блок ниже. Границы `/` целью выдачи сегодня не выдаются ни одной пробой — **заказан** держатель (полоса реализации): выдача на каждую из шести границ даёт `done=true` без `error` | прочитано @ddd5681af; исход пробы — комментарий `DoD-proof @43750c544` в kaname#1004 (PASS) |
| ATI-02…04 | синхронный отказ `INVALID_ARGUMENT` с текстом и позицией | **заказан** производитель: проверка формы идентификатора в той же проверке цели, что сегодня отвергает пустой (`internal/domain/access_binding_target.go:72-91`, `Illegal argument target.resources[%d].id (empty)`), до выпуска `Operation` (`create.go:254`, раньше проверки полномочий `create.go:278`). Держатель ATI-02 — проба ветки `1004` после ужесточения: ветка «принято как отдельная цель» снимается, остаётся `require.Equal(codes.InvalidArgument, …)` плюс дословный текст и число выдач. ATI-03/04 — **заказана** табличная проба на обе стороны каждой строки | красная проба: `DoD-proof @43750c544`, `--- FAIL` с `code:6` (сегодня `ALREADY_EXISTS`) |
| ATI-02b | цель `{<base>/one}` при действующей выдаче на `{<base>/one, <base>/one/two}` принята, выдач `usr-D` две | производитель — сверка состава цели по записи состава (`internal/domain/access_binding_target.go:140-151`) и частичная уникальность действующей выдачи (`create.go:331-333`): разный состав — разная запись, вставка проходит. Держатель на уровне `Create` сегодня отсутствует — **заказан** (DoD п.1): тот же мир и «Дано», что у ATI-02, `require.NoError` на `Create`, `assert.Nil(done.Error)`, число выдач `usr-D` по роли и области — две. На уровне хранилища то же свойство держит `TestAB_IAM_1_29_DistinctTargets_Coexist` (`require.NoError(t, e2, "a DISTINCT per-object target must NOT collide with ins-1")`) | прочитано @ddd5681af |
| ATI-02 (край), ATI-03 (край, строка «перевод строки») | пара `400` + `code=3` и текст | **заказан** newman-кейс (DoD п.3) | — |
| ATI-05 | повтор той же цели в обратном порядке: синхронной ошибки нет, `Operation.error` `code=6` с дословным текстом; другой состав сосуществует | производитель отказа — частичная уникальность действующей выдачи в воркере `Create` (`create.go:331-333`), текст — `internal/repo/kaname/pg/pgmaperr.go:470-478` (`"these permissions are already granted to %s on %s"`). Порядок не различается — `TestAB_IAM_1_29_TargetDigestOrderIndependent` (`f8_target_test.go`, `assert.Equal(t, a.Digest(), b.Digest(), …)`); разный состав сосуществует — `TestAB_IAM_1_29_DistinctTargets_Coexist` (`internal/repo/kaname/pg/access_binding_target_integration_test.go:140`). Дословная пара «код и текст» в `Operation.error` на повтор уже утверждается `TestURG10_DuplicateOfUnnarrowedGrantRefused` (`assert.Equal(t, int32(codes.AlreadyExists), done.Error.Code, …)` и `assert.Equal(t, fmt.Sprintf("these permissions are already granted to %s on project:%s", …), done.Error.Message, …)`) — тот же повтор, без перестановки. На уровне `Create` с перестановкой — контроль пробы ветки `1004`, **заказано** ужесточение (DoD п.1): сегодняшний `if err == nil { require.NotNil(t, done.Error, …) }` пропускает любой синхронный отказ и любой код | прочитано @ddd5681af; исход отказа воспроизведён прогоном рецензента круга 1 @43750c544 (`Code:6`, текст той же формы) |

Пробы ветки `1004`, которые держат ATI-01/02 (в стволе `955` их ещё нет; отбор по имени):

```
go test -count=1 -run '^TestSlashObjectID_RegistrationGrantAndCheckAreVerbatim$' ./internal/apps/kaname/api/access_binding/
go test -count=1 -run '^TestAccessTarget_DistinctObjectSetsAreDistinctTargets$' ./internal/apps/kaname/api/access_binding/
go test -short -count=1 -run '^TestObjectIDWithSlash' ./internal/apps/kaname/api/internal_iam/
```

## DoD

1. **ATI-02, ATI-02b, ATI-05** — проба ATI-02 ветки `1004` (вторая команда блока выше) в одном
   мире и при одном «Дано» несёт три шага, и каждый утверждает исход целиком, без ветвления по
   виду ошибки:
   - ATI-02: синхронный `INVALID_ARGUMENT` (`status.Code(err)`), дословный текст ATI-02, число
     выдач `usr-D` по роли и области — одна. Красная на `43750c544`, зелёная на голове полосы;
   - ATI-02b (близнец): `require.NoError` на `Create`, `done=true` и `done.Error == nil`, выдач
     `usr-D` по роли и области — две;
   - ATI-05 (контроль сверки состава): `require.NoError` на `Create`, `done.Error.Code == 6` и
     `done.Error.Message` дословно `these permissions are already granted to <usr-D> on project:<проект мира>`;
     форма `if err == nil { require.NotNil(done.Error) }` не держатель и снимается.
   Шаг ATI-05 идёт до ATI-02b: после ATI-02b у `usr-D` две выдачи, и счёт ATI-02 и ATI-05
   («одна») меряется до него.
2. **ATI-01, ATI-03, ATI-04** — проба полосы A на обе стороны: каждая из пяти строк ATI-03
   отвергнута с дословным текстом, её близнец `<base>/o-ne` принят; каждая из шести границ `/`
   принята целью выдачи; позиция `[1]` в ATI-04. Проба способна упасть: мутация «проверка формы
   снята» краснит отрицания, мутация «`/` запрещён» краснит близнецов — исход мутаций в
   `DoD-proof`.
3. **Край** — кейс в существующем наборе `tests/newman/cases/iam-access-binding-redesign.py`
   (новой коллекции нет), классы `NEG`: роль — `_seed_role`, как в
   `IAM-ACB-RD-CR-TARGET-RESOURCES-OK`; шаг-отрицание с `id = "ins-rdacb{{runId}}\ncompute.instance:ins-rdacb{{runId}}-2"`
   → пара `400` + `code=3` и дословный текст ATI-02; шаг-близнец с `id = "ins-rdacb{{runId}}"`
   → `done=true` без `error`; уборка выдачи и роли в том же кейсе. Коллекция пересобрана из
   кейсов тем же коммитом.
4. **ATI-05** — `TestAB_IAM_1_29_TargetDigestOrderIndependent` и
   `TestAB_IAM_1_29_DistinctTargets_Coexist` зелёные на голове полосы; способ сверки состава не
   тронут и миграции нет:
   `git diff --name-only origin/955...HEAD -- internal/migrations` → пусто;
   `git diff origin/955...HEAD -- internal/domain/access_binding_target.go | grep -c '^[-+].*Digest'` → `0`.
5. **Регрессия `/`** — первая и третья команды блока выше (пробы ветки `1004`: регистрация,
   цепь, выдача и вопрос о доступе по идентификатору с `/`; разбор объекта на входе регистрации)
   зелёные на голове полосы.
6. Комментарий поля `ResourceRef`-перечня цели в `proto/kaname/cloud/iam/v1/access_binding.proto`
   (`AccessTargetResources`) называет запрещённые знаки и отказ; регенерация, `buf lint` и
   `buf breaking` зелёные.
7. Хук отправки полный, отказов 0; комментарий `DoD-proof @<sha>` в kaname#1004 с ревизией,
   на которой мерено.
