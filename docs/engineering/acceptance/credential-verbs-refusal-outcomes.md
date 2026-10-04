<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: исходы отказов глаголов удостоверений — отзыв несуществующего и выдача ключевой пары без токен-эндпоинта

- **Статус:** DRAFT — вердикта нет. Действующий вердикт выводится из записи ревью
  `acceptance-reviewer` о SHA-256 этой редакции, а не из этой строки
- **История ревью:** — (строки только дописываются: дата · круг · вердикт · SHA-256 редакции)
- **Дата:** 2026-10-03
- **Задачи:** `PRO-Robotech/kaname#522` (исход отзыва несуществующего у трёх видов удостоверений),
  `PRO-Robotech/kaname#547` (выдача ключевой пары человека на посадке без токен-эндпоинта);
  родитель обеих — `PRO-Robotech/kaname#536` (волна-2 эпика `#296`, полоса NA24)
- **Ревизия измерения:** `8a84dcff6eb1` — ствол службы. Дерево ветки волны `536`
  (`9bac42bdc`, база этого изменения) с ним совпадает целиком: `git diff --stat 8a84dcff6eb1 9bac42bdc`
  пуст. Все строки и числа ниже сняты на этой ревизии
- **Сервис:** `kaname`; затрагивает `internal/apps/kaname/api/user_tokens/`,
  `internal/apps/kaname/api/sa_keys/`, `internal/apps/kaname/api/access_keys/` (только новый файл
  пробы), `cmd/kaname/`, комментарии `proto/kaname/cloud/iam/v1/user_token_service.proto` и
  `proto/kaname/cloud/iam/v1/sa_key_service.proto`, `docs/content/api/tokens.mdx`,
  `docs/content/architecture/overview.mdx`, `docs/engineering/components/05-sa-keys.md`,
  `tests/newman/cases/`
- **Тип изменения:** меняет наблюдаемый исход двух глаголов: `UserTokenService.Revoke` и
  `SAKeyService.Revoke` на удостоверении, которого у названного субъекта нет (было: операция
  с успехом и `revokedAt`; станет: синхронный `NOT_FOUND`); `UserTokenService.Issue` вида
  `KEYPAIR` на посадке без токен-эндпоинта (было: ключ выдан; станет: синхронный
  `FAILED_PRECONDITION`). Схема, миграции, поля контракта не меняются

---

## Обзор

Два глагола службы отвечают на один и тот же вопрос по-разному в зависимости от вида
удостоверения. Отзыв удостоверения, которого у названного субъекта нет, у ключа доступа отвергается
`NOT_FOUND`, а у токена человека и ключа служебной учётки отвечает успехом с отметкой отзыва —
опечатка в идентификаторе при реакции на утечку выглядит для вызывающего как состоявшийся отзыв.
Выдача ключевой пары на посадке без токен-эндпоинта у служебной учётки отказывает с именем
настройки, а у человека выдаёт ключ, который обменять негде. Документ приводит оба глагола к
одному исходу на всех видах и называет этот исход контрактом.

## Что НЕ входит

- **Сторона ключа доступа не меняется.** Её исход (`NOT_FOUND`, чужой и несуществующий
  неразличимы) записан приёмкой `access-keys-are-ours.md`, сценарии Ф7-25, Ф7-27, Ф7-47; здесь он
  только назван образцом и подтверждается новой пробой, зелёной до и после правки (CVR-09).
  Комментарий `access_key_service.proto` и страница `auth-lane.mdx` не правятся.
- **Форма идентификатора удостоверения на отзыве.** Токен человека и ключ служебной учётки
  сегодня не судят форму `token_id` / `key_id` (обработчики `internal/apps/kaname/api/user_tokens/handler.go:138`,
  `internal/apps/kaname/api/sa_keys/handler.go:128` передают строку дальше без проверки формы).
  Это отдельный дефект конвенции `api-conventions.md` §«Gotcha'и» и отдельная задача; в
  сценариях ниже всякий идентификатор — **годной формы**.
- **Отзыв на несуществующем или чужом субъекте** (`user_id`, `service_account_id`): исход
  `NOT_FOUND` о субъекте и `PERMISSION_DENIED` по отношению на крае — без изменений.
- **Выдача на боевой посадке.** В боевых режимах посадка без токен-эндпоинта не поднимается
  (строка контура выдачи в `internal/apps/kaname/config/lane_requirements.go:167-182`); здесь
  меняется только ответ глагола на посадке режима разработчика и в пробах уровня глагола.
- **Вид FEDERATED у человека** — его нет в контракте by construction
  (`internal/apps/kaname/api/user_tokens/usecases.go:201`, `ResolveIssuedKind(…, false, false)`).
- **Консоль и прочие клиенты в `PRO-Robotech/kacho`.** Консоль вызывает отзыв
  (`ui-future/shared/src/api/tokens.ts:193`, `:207` на `PRO-Robotech/kacho@origin/main`) и
  показывает отказ общим путём; её поведение на новом `404` — предмет её владельца.
- **Церемония входа приложения** (`kaname#525`, та же полоса NA24) — своя приёмка.

---

## §0. Перепись производителей — до сценариев

**Замер на ревизии `8a84dcff6eb1`.** Каждая строка ниже получена командой из этого раздела;
команды воспроизводятся из корня клона службы.

### 0.1. Кто сегодня печатает исход отзыва

```sh
git grep -n 'if !found {' -- internal/apps/kaname/api/user_tokens/usecases.go internal/apps/kaname/api/sa_keys/usecases.go internal/apps/kaname/api/access_keys/revoke.go
# → user_tokens/usecases.go:684 · sa_keys/usecases.go:1018 · access_keys/revoke.go:169
git grep -n 'return revokeUserTokenResponse\|return revokeSAKeyResponse' -- internal/apps/kaname/api/user_tokens/usecases.go internal/apps/kaname/api/sa_keys/usecases.go
# → user_tokens :688 и :719 · sa_keys :1022 и :1040 — один производитель тела успеха на вид,
#   и ветка «не найдено» возвращает ТО ЖЕ тело
git grep -n 'notFound(' -- internal/apps/kaname/api/access_keys/revoke.go
# → :97 (синхронно, до операции) и :171 (внутри операции, гонка)
```

| вид | исход отзыва несуществующего / повторного / чужого | производитель | где |
|---|---|---|---|
| UserToken | операция, `done`, ответ `tokenId` + `revokedAt`, ничего не снято | `revokeUserTokenResponse` | `internal/apps/kaname/api/user_tokens/usecases.go:684-688`, `:730` |
| SAKey | операция, `done`, ответ `keyId` + `revokedAt`, ничего не снято | `revokeSAKeyResponse` | `internal/apps/kaname/api/sa_keys/usecases.go:1018-1022` |
| AccessKey | синхронный `NOT_FOUND` `AccessKey <id> not found`, операции нет | `notFound` | `internal/apps/kaname/api/access_keys/revoke.go:95-97`, текст — `refusals.go:45`, `:103` |

Производителей отзыва в прод-дереве — по одному на вид, сборка каждого — одна:

```sh
git grep -n 'NewRevokeUserTokenUseCase(\|NewRevokeSAKeyUseCase(' -- '*.go' ':!*_test.go'
# → cmd/kaname/wiring.go:1120 (SAKey) · cmd/kaname/wiring.go:1158 (UserToken) + два объявления конструктора
```

Текст «не найдено» обоих видов уже существует у хранилища и сегодня до клиента не доходит:
`UserToken %s not found` (`internal/repo/kaname/pg/user_oauth_clients_repos.go:53`) и
`SAOAuthClient %s not found` (`internal/repo/kaname/pg/iam_extension_repos.go:52`). Второй несёт
внутреннее имя типа строки, а не имя ресурса контракта, поэтому текст отказа назначается здесь
(Р2), а не наследуется.

### 0.2. Кто сегодня утверждает исход отзыва — и чей вердикт этот документ меняет

```sh
git grep -n -E 'UserTokenService|SAKeyService' -- docs/engineering/acceptance ':!docs/engineering/acceptance/credential-verbs-refusal-outcomes.md' | grep -i revoke
# → 3 строки, все в access-keys-are-ours.md (1574, 1690, 3976) — о поле уровня и области
#   каталога, не об исходе отзыва несуществующего
git grep -l 'BAT-1-44' -- '*.go' docs ':!docs/engineering/acceptance/credential-verbs-refusal-outcomes.md'
# → 7 файлов: docs/engineering/components/05-sa-keys.md · обе пробы
#   usecase_revoke_idempotent_test.go · оба usecases.go · две интеграционные пробы хранилища
```

**Посылка задачи `#522` опровергнута наполовину.** В доме приёмок службы исхода отзыва
несуществующего UserToken/SAKey нет (3 строки выше — о другом). Но **он есть** в одобренной
приёмке воркспейса `PRO-Robotech/kacho-workspace:docs/specs/sub-phase-BAT-1-basic-access-token-acceptance.md`,
сценарий BAT-1-44: повторный отзыв — **успех**, отзыв никогда не существовавшего — **тот же**
исход. Сегодняшние пробы уровня глагола держат именно его
(`TestRevoke_RepeatAbsentAndForeignShareOneOutcome`, `TestRevokeSAKey_RepeatAbsentAndForeignShareOneOutcome`).
Этот документ **замещает** в BAT-1-44 одно утверждение — какой именно исход — и сохраняет второе
— что исход один (Р1, Р3).

### 0.3. Кто сегодня решает выдачу ключевой пары без токен-эндпоинта

```sh
git grep -n 'kind != domain.CredentialKindSecret && !u.ownIssuance' -- internal/apps/kaname/api/sa_keys/usecases.go
# → :349 — отказ FAILED_PRECONDITION с именем ручки, до чтения и записи
git grep -n 'ownIssuance' -- internal/apps/kaname/api/user_tokens
# → 0 строк: у выдачи человека условия нет вовсе
git grep -n 'NewIssueUserTokenUseCase(' -- '*.go' ':!*_test.go'
# → cmd/kaname/wiring.go:1148 (сборка) + объявление конструктора; путь выдачи ключевой пары
#   человека в прод-дереве один
git grep -n 'func (c Config) SAKeyIssuanceIsOurs' -- internal/apps/kaname/config
# → sakey_binding.go:27 — `return c.AuthN.ClientToken.Enabled`, единственное условие
git grep -n 'client-token.enabled' -- docs/engineering/acceptance ':!docs/engineering/acceptance/credential-verbs-refusal-outcomes.md'
# → 1 строка (ceremony-lifespans-are-declared-within-their-ceilings.md:458 — страж старта
#   под own); выдачу без эндпоинта не держит ни одна приёмка
```

Неназванный вид у человека разрешается в KEYPAIR
(`internal/domain/credential_kind.go:77-82`); сборка выдачи человека ручку не читает
(`cmd/kaname/wiring.go:1139-1157`); предупреждение старта режима разработчика называет только
служебные учётки (`cmd/kaname/wiring.go:1076-1084`). **Посылка задачи `#547` подтверждена.**

### 0.4. Посев: чем строится каждое «Дано»

| «Дано» | чем строится | проверено |
|---|---|---|
| живое своё удостоверение человека / учётки | заглушка хранилища пакета глагола: `stubUserClientRepo.getRow` (`internal/apps/kaname/api/user_tokens/usecase_test.go:31-54`), `stubSAClientRepo.getRow`; на стенде — шаг `issue-basic-secret` (`tests/newman/cases/basic-access-token.py:112`) и выдача ключа в `tests/newman/cases/iam-service-account.py` | поля читаются сегодняшними пробами отзыва |
| удостоверение, которого нет / уже снято | `getErr` заглушки — `ErrNotFound`; на стенде — тот же идентификатор после шага `revoke-basic-secret` (`basic-access-token.py:278`) и после `_revoke_key_steps` (`iam-service-account.py:81`, вызовы `:1178`, `:1179`) | шаги существуют, идентификаторы сохраняются в переменные окружения прогона |
| чужое удостоверение | `getRow` со вторым владельцем (образец — `usecase_revoke_idempotent_test.go` в обоих пакетах); в хранилище — `TestUserOAuthClient_13_DeleteOwnedByID_IdempotentAndOwnerScoped` | заглушка и интеграционная проба есть |
| посадка без токен-эндпоинта | глагол выдачи собран без объявления эндпоинта — образец `newEndpointlessIssueUC` (`internal/apps/kaname/api/sa_keys/issuance_needs_the_token_endpoint_test.go:44-47`); процесс — режим разработчика с `authn.client-token.enabled=false` | образец есть; в боевом режиме такая посадка не строится (вне объёма) |
| посадка с токен-эндпоинтом | объявление эндпоинта глаголу; на стенде — боевая посадка, где эндпоинт собран всегда; шаг `issue-user-token` без вида (`tests/newman/cases/iam-token-facade-conformance.py:620`) | шаг существует и ждёт `done` |
| хранилище не отвечает | `accountErr` заглушки (`usecase_test.go:50-53`); для нового чтения отзыва — тот же приём | поле есть |

---

## §1. Решения

**Р1 — исход отзыва того, чего у названного субъекта нет, — `NOT_FOUND` у трёх видов.**
Закреплён решением диспетчера до старта волны-2 (R37, `kaname#536`, предикат полосы NA24) и
здесь записан контрактом. «Нет» объединяет три случая: идентификатор никогда не существовал;
удостоверение уже отозвано; удостоверение принадлежит другому субъекту. Три случая
**неразличимы** между собой — кодом, текстом (кроме эха названного идентификатора) и
деталями; это то же требование скрытия существования, что держал прежний единый успех, только
исход назван иначе. Причина смены — цена для клиента (`#522`): успех на опечатке означает
неснятое утёкшее удостоверение, а сценарий, общий для трёх видов, падает на одном из них.

**Р2 — отказ синхронный, тот же по форме, что у ключа доступа.** Без операции; код `NOT_FOUND`;
текст `<Resource> <id> not found`, где `<Resource>` — `UserToken` либо `SAKey` (имена ресурсов
сервисов `UserTokenService` и `SAKeyService`), `<id>` — названный вызывающим идентификатор;
деталей глагол не приклеивает — как у ключа доступа сегодня (`notFound` собирается
`status.Errorf` без деталей, `internal/apps/kaname/api/access_keys/refusals.go:103-105`), поэтому
набор деталей на проводе у трёх видов один и тот же. Край отдаёт пару
HTTP `404` и `code: 5` (`api-conventions.md` §«gRPC-код → HTTP-статус»). Если удостоверение
исчезло между синхронной сверкой и снятием (гонка двух отзывов), проигравший получает операцию,
завершённую ошибкой с **тем же** кодом и текстом — как `access_keys/revoke.go:169-171`; успеха на
строке, которую снял другой, не бывает.

**Р3 — замещение в BAT-1-44.** Утверждение «повторный отзыв даёт **успех**» замещается
утверждением «повторный отзыв даёт `NOT_FOUND` по Р2». Утверждение «отзыв никогда не
существовавшего даёт **тот же** исход, что повторный» сохраняется и усиливается: тот же исход
даёт и чужое удостоверение. Утверждение BAT-1-44 о снятии строки и положительном контроле
(второе удостоверение проходит) не затрагивается. Одобренный документ воркспейса этой правкой не
редактируется; запись о замещении в нём — пункт DoD п.9.

**Р4 — выдача ключевой пары человека без токен-эндпоинта отказывает так же, как у служебной
учётки.** Синхронно; после разбора запроса (сформированный неверно запрос получает свой отказ с
именем поля на любой посадке); до всякого чтения хранилища и записи; код
`FAILED_PRECONDITION`; текст называет `authn.client-token.enabled`. Касается вида KEYPAIR и
неназванного вида (он разрешается в KEYPAIR). SECRET обмена не требует и выдаётся. Условие одно —
`Config.SAKeyIssuanceIsOurs`, его уже читают сборка ключей учёток и страж старта; копию условия
не заводить. Предупреждение старта режима разработчика называет и путь человека.

---

## §2. Сценарии — отзыв (`#522`)

### UserToken

**ID: CVR-01** — положительный близнец §2 для токена человека
**Given** человек `A`; у него живое удостоверение `T` (любого вида), строка `T` принадлежит `A`
**When** клиент вызывает `UserTokenService.Revoke` (`DELETE /iam/v1/users/{userId}/tokens/{tokenId}`):
  - `userId` = `A`
  - `tokenId` = `T`
**Then** ответ — `Operation`; полл `OperationService.Get` до `done=true` даёт `response`
`RevokeUserTokenResponse` с `tokenId` = `T` и заполненным `revokedAt`
**And** строка `T` снята; событие аудита отзыва записано ровно одно
**And** перечень удостоверений `A` (`UserTokenService.List`) `T` не содержит

**ID: CVR-02** · отрицание; близнец — CVR-01, отличается **одним** фактом: строки с
идентификатором `T` нет и не было
**Given** человек `A`; идентификатор `T` годной формы, которому не отвечает ни одна строка
**When** тот же вызов, что в CVR-01
**Then** синхронный отказ: gRPC `NOT_FOUND`, текст `UserToken T not found`; на крае — HTTP `404`,
`code: 5`
**And** операции не заведено; ничего не снято; события аудита нет

**ID: CVR-03** · отрицание; близнец — CVR-01, отличается **одним** фактом: `T` уже снят этим же
глаголом
**Given** состояние после CVR-01
**When** тот же вызов повторно
**Then** исход **побайтово равен** CVR-02 после замены идентификатора: код, текст, детали
**And** операции не заведено; события аудита второго нет; второе удостоверение `A`, если оно есть,
по-прежнему перечисляется и предъявляется

**ID: CVR-04** · отрицание, закрывающее оракул; близнец — CVR-01, отличается **одним** фактом:
строка `T` принадлежит другому человеку `B`
**Given** люди `A` и `B`; живое удостоверение `T` принадлежит `B`
**When** вызов с `userId` = `A`, `tokenId` = `T`
**Then** исход **побайтово равен** CVR-02 после замены идентификатора
**And** строка `T` на месте: перечень удостоверений `B` её содержит, событие аудита не записано

### SAKey

**ID: CVR-05** — положительный близнец §2 для ключа служебной учётки
**Given** служебная учётка `S`; у неё живой ключ `K`
**When** клиент вызывает `SAKeyService.Revoke` (`DELETE /iam/v1/serviceAccounts/{serviceAccountId}/keys/{keyId}`):
  - `serviceAccountId` = `S`
  - `keyId` = `K`
**Then** ответ — `Operation`; полл до `done=true` даёт `RevokeSAKeyResponse` с `keyId` = `K` и
заполненным `revokedAt`
**And** строка `K` снята; событие аудита отзыва ровно одно

**ID: CVR-06** · отрицание; близнец — CVR-05, отличается **одним** фактом: строки `K` нет и не
было
**Given** учётка `S`; идентификатор `K` годной формы без строки
**When** тот же вызов
**Then** синхронный `NOT_FOUND`, текст `SAKey K not found`; на крае HTTP `404`, `code: 5`
**And** операции нет; ничего не снято; события аудита нет

**ID: CVR-07** · отрицание; близнец — CVR-05, отличается **одним** фактом: `K` уже снят
**Given** состояние после CVR-05
**When** тот же вызов повторно
**Then** исход побайтово равен CVR-06 после замены идентификатора; операции и события нет

**ID: CVR-08** · отрицание, закрывающее оракул; близнец — CVR-05, отличается **одним** фактом:
ключ `K` принадлежит другой учётке `S2`
**Given** учётки `S` и `S2`; живой ключ `K` принадлежит `S2`
**When** вызов с `serviceAccountId` = `S`, `keyId` = `K`
**Then** исход побайтово равен CVR-06 после замены идентификатора
**And** ключ `K` на месте: перечень ключей `S2` его содержит

### AccessKey — образец, не меняется

**ID: CVR-09** · отрицание; близнец — Ф7-25 (`TestAccessKey_F7_25_RevokeRemovesOneKey`),
отличается **одним** фактом: снимаемый ключ уже снят
**Given** человек с двумя принятыми ключами, вошедший, момент предъявления в окне свежести; первый
ключ `K1` снят (состояние после Ф7-25)
**When** `AccessKeyService.Revoke` с `accessKeyId` = `K1` повторно
**Then** синхронный `NOT_FOUND`, текст `AccessKey K1 not found` — **побайтово равный** отказу по
никогда не существовавшему идентификатору годной формы (Ф7-27,
`TestAccessKey_F7_27_ForeignAndAbsentAreOneRefusal`) после замены идентификатора
**And** второй ключ на месте и предъявляется
**And** проба этого сценария зелена **до и после** правки — сторона ключа доступа не меняется

### Три вида вместе

**ID: CVR-10** · сличение видов; близнецы — CVR-02, CVR-06, CVR-09
**Given** по одному идентификатору годной формы без строки для каждого вида; субъект каждого
существует и вызывающий вправе им распоряжаться
**When** отзыв каждым из трёх глаголов
**Then** у трёх исходов совпадают: синхронность (операции нет ни у одного), gRPC-код `NOT_FOUND`,
набор деталей, форма текста `<Resource> <id> not found`; различаются только
`<Resource>` (`UserToken` · `SAKey` · `AccessKey`) и эхо идентификатора
**And** на крае у трёх — пара HTTP `404`, `code: 5`

### Гонка и недоступность

**ID: CVR-11** · конкуренция; близнец — CVR-01 (и CVR-05), отличается **одним** фактом: два
отзыва одного удостоверения идут одновременно
**Given** живое удостоверение `T` человека `A` (и, отдельным прогоном, живой ключ `K` учётки `S`)
в настоящей базе
**When** N ≥ 2 параллельных вызовов отзыва `T` (соответственно `K`)
**Then** ровно один вызов завершается успехом CVR-01 (CVR-05); каждый прочий получает либо
синхронный отказ CVR-02 (CVR-06), либо операцию, завершённую ошибкой с тем же кодом и текстом
**And** строка снята один раз; событие аудита отзыва ровно одно; ни один проигравший не получил
`revokedAt`

**ID: CVR-12** · отрицание; близнец — CVR-02, отличается **одним** фактом: хранилище не ответило
на синхронной сверке существования
**Given** человек `A`; хранилище службы недоступно на чтении, которым глагол отзыва судит
существование удостоверения (тот же приём для учётки `S`)
**When** вызов CVR-02
**Then** `UNAVAILABLE` (fail-closed мутации), а **не** `NOT_FOUND`: неполученный ответ не есть
«нет»; операции нет
**And** то же для `SAKeyService.Revoke`

---

## §3. Сценарии — выдача ключевой пары человека (`#547`)

**ID: CVR-21** · отрицание; близнец — CVR-23, отличается **одним** фактом: эндпоинт не объявлен
**Given** посадка без токен-эндпоинта (`authn.client-token.enabled=false`, режим разработчика);
активный человек `A`
**When** клиент вызывает `UserTokenService.Issue` (`POST /iam/v1/users/{userId}/tokens`):
  - `userId` = `A`, `createdByUserId` = `A`
  - `credentialKind` = `CREDENTIAL_KIND_KEYPAIR`
**Then** синхронный `FAILED_PRECONDITION`; текст содержит `authn.client-token.enabled`
**And** операции не заведено; строки удостоверения нет; события аудита нет
**And** хранилище не читалось: отказ стоит до разрешения аккаунта владельца

**ID: CVR-22** · вторая ветвь CVR-21; отличается от неё **одним** фактом: вид не назван
**Given** то же, что в CVR-21
**When** тот же вызов без `credentialKind`
**Then** исход **побайтово равен** CVR-21: неназванный вид разрешается в KEYPAIR до отказа

**ID: CVR-23** — положительный близнец §3
**Given** посадка с объявленным токен-эндпоинтом; активный человек `A`
**When** вызов CVR-21 (и, ветвью, CVR-22)
**Then** ответ — `Operation`; полл до `done=true` без ошибки; строка удостоверения вида KEYPAIR
записана; ответ несёт приватный ключ однократно (поведение без изменений)

**ID: CVR-24** · положительный близнец; от CVR-21 отличается **одним** фактом: вид SECRET
**Given** посадка без токен-эндпоинта; активный человек `A`
**When** вызов CVR-21 с `credentialKind` = `CREDENTIAL_KIND_SECRET`
**Then** выдача состоялась: операция завершена на пути запроса, строка вида SECRET записана —
поведение без изменений

**ID: CVR-25** · порядок отказов; близнец — CVR-21, отличается **одним** фактом: запрос
сформирован неверно (`ttlSeconds` = `-1`)
**Given** посадка без токен-эндпоинта; активный человек `A`
**When** вызов CVR-21 с `ttlSeconds` = `-1`
**Then** `INVALID_ARGUMENT` с именем поля `ttl_seconds`, а **не** отказ CVR-21: разбор запроса идёт
раньше вопроса о посадке

**ID: CVR-26** · одно условие на два пути выдачи
**Given** конфигурация процесса, где `authn.client-token.enabled` принимает значение `true`
(ветвь а) и `false` (ветвь б)
**When** собираются оба обработчика выдачи — ключей учёток и токенов человека
**Then** в ветви а оба выдают KEYPAIR, в ветви б оба отказывают по Р4: решение обоим даёт один и тот
же предикат `Config.SAKeyIssuanceIsOurs`, второго чтения ручки в сборке нет
**And** в ветви б предупреждение старта режима разработчика называет **оба** пути выдачи и ручку,
которой отказ снимается

---

## §4. Сценарий → производитель

| ID | что производит «Тогда» | координата в дереве (ревизия измерения) | чем измерено |
|---|---|---|---|
| CVR-01 | снятие строки владельцем и тело успеха | `DeleteOwnedByID` + `revokeUserTokenResponse`, `internal/apps/kaname/api/user_tokens/usecases.go:669-735` — **есть** | §0.1 |
| CVR-02, 03, 04 | синхронный `NOT_FOUND` до операции | **заказан**: сегодня ветка `!found` (`usecases.go:684-688`) отдаёт тело успеха; производителя отказа нет — пишет полоса NA24 (`#522`) | §0.1, `git grep -n 'if !found {'` |
| CVR-05 | снятие и тело успеха учётки | `internal/apps/kaname/api/sa_keys/usecases.go:1003-1040` — **есть** | §0.1 |
| CVR-06, 07, 08 | синхронный `NOT_FOUND` учётки | **заказан**: сегодня `sa_keys/usecases.go:1018-1022` отдаёт успех — полоса NA24 (`#522`) | §0.1 |
| CVR-09 | синхронный `NOT_FOUND` ключа доступа | `internal/apps/kaname/api/access_keys/revoke.go:95-97`, текст `refusals.go:45` — **есть** | §0.1 |
| CVR-10 | три производителя одной формы | два заказанных (CVR-02, CVR-06) + `notFound` ключа доступа | §0.1 |
| CVR-11 | проигравший гонку получает отказ, а не успех | **заказан**: внутриоперационная ветка «не найдено» у обоих видов (образец — `access_keys/revoke.go:169-171`); атомарность снятия — существующий оператор `DeleteOwnedByID` (`TestUserOAuthClient_13_DeleteOwnedByID_IdempotentAndOwnerScoped`) | §0.1 |
| CVR-12 | `UNAVAILABLE` на недоступном хранилище | **заказан** вместе с синхронной сверкой; отображение ошибки хранилища — `mapPGErrLogged`, `internal/apps/kaname/api/user_tokens/usecases.go:873` (есть) | чтение кода |
| CVR-21, 22 | отказ с именем ручки до чтения | **заказан** (`#547`): `git grep -n 'ownIssuance' -- internal/apps/kaname/api/user_tokens` → 0; образец — `internal/apps/kaname/api/sa_keys/usecases.go:349` | §0.3 |
| CVR-23 | выдача KEYPAIR при эндпоинте | `IssueUserTokenUseCase.Execute`, `user_tokens/usecases.go:173-313` — **есть**; на стенде — шаг `issue-user-token` | §0.3, §0.4 |
| CVR-24 | выдача SECRET без эндпоинта | `issueSecretSync`, `user_tokens/usecases.go:295` — **есть** | чтение кода |
| CVR-25 | отказ формы раньше отказа посадки | проверка `ttl_seconds` до разрешения вида, `user_tokens/usecases.go:196-198` — **есть**; порядок относительно нового отказа — **заказан** (`#547`) | чтение кода |
| CVR-26 | одно условие и предупреждение | `saKeyIssuanceIsOurs`, `cmd/kaname/wiring.go:1040-1047` и предупреждение `:1076-1084` — **есть** для учёток; чтение в `buildUserTokensHandler` (`:1139`) и строка предупреждения о человеке — **заказаны** (`#547`) | §0.3 |

Сценариев без производителя после правки — ноль: каждый «заказан» строкой выше закрывается
полосой NA24 и проверяется пробой DoD.

---

## §5. DoD

Каждый пункт — с командой; «пройдено» значит вывод команды равен названному.

1. **Пробы отзыва уровня глагола, красные до правки.** Сегодняшние пробы
   `TestRevoke_RepeatAbsentAndForeignShareOneOutcome` и
   `TestRevokeSAKey_RepeatAbsentAndForeignShareOneOutcome` переводятся на исход Р1/Р2
   (CVR-01…08): положительный контроль остаётся, три безрезультатных случая сверяются отпечатком
   и равны синхронному `NOT_FOUND` с операцией не заведённой. Имя функции сохраняется — оно
   координата этого документа; переименование допустимо только той же правкой с правкой здесь.
   ```sh
   go test -count=1 -run 'RepeatAbsentAndForeignShareOneOutcome' ./internal/apps/kaname/api/user_tokens/ ./internal/apps/kaname/api/sa_keys/
   ```
   красна на базе `9bac42bdc`, зелена после.
2. **Проба ключа доступа — новым файлом** в `internal/apps/kaname/api/access_keys/` (CVR-09 и
   ключевая строка CVR-10): зелена **до и после** правки.
   ```sh
   go test -count=1 -run 'TestAccessKey_CVR09' ./internal/apps/kaname/api/access_keys/
   ```
3. **Сличение трёх видов (CVR-10)** — одна проба, собирающая три исхода и сверяющая код, детали,
   синхронность и форму текста; красна до правки.
4. **Гонка (CVR-11)** — интеграционная проба на настоящей базе, N ≥ 2 параллельных отзыва: ровно
   один успех, одно событие аудита, прочие — `NOT_FOUND`. Для `sa_keys` харнесс базы уже есть
   (`internal/apps/kaname/api/sa_keys/testmain_pgtest_test.go`); для `user_tokens` заводится
   такой же.
5. **Недоступность (CVR-12)** — проба уровня глагола на обоих видах: ошибка чтения хранилища →
   `UNAVAILABLE`, не `NOT_FOUND`; рядом законный близнец CVR-02.
6. **Пробы выдачи (CVR-21…25)** — в `internal/apps/kaname/api/user_tokens/`, близнецы по образцу
   `TestIssue_WithoutTheTokenEndpoint_ExchangedKindsAreRefusedNamingTheKnob`,
   `TestIssue_WithTheTokenEndpoint_ExchangedKindsAreIssued`,
   `TestIssue_WithoutTheTokenEndpoint_SecretIsIssued` пакета `sa_keys`:
   ```sh
   go test -count=1 -run 'TokenEndpoint' ./internal/apps/kaname/api/user_tokens/
   ```
   красна до правки (отказа нет), зелена после. Пробы пакета, ждущие выдачи KEYPAIR от глагола,
   собранного без эндпоинта (в том числе `TestBAT1_11_UnnamedKindKeepsTheKeypairBehaviourVerbatim`),
   объявляют эндпоинт — их утверждения не меняются.
7. **Сборка (CVR-26)** — проба рядом с `TestSAKeyIssuanceIsOurs_FollowsTheExchangeEndpoint`
   (`cmd/kaname/sa_key_own_issuance_wiring_test.go`): `buildUserTokensHandler` при обоих
   значениях ручки даёт исход Р4; строка предупреждения называет путь человека — близнец
   `TestSAKeyIssuanceWarning_ReachedOnlyOutsideProductionModes` и законный близнец молчания
   `TestSAKeyIssuanceWarning_SilentWhereIssuanceHasAnExecutor` (`cmd/kaname/sa_key_issuance_warning_reach_test.go`)
   утверждают текст, называющий оба пути.
   ```sh
   git grep -n 'saKeyIssuanceIsOurs(cfg)\|SAKeyIssuanceIsOurs()' -- cmd/kaname
   # сегодня прод-строк 2 (wiring.go:1046, :1076); после правки — та же функция читается и в
   # buildUserTokensHandler, а прямых чтений cfg.AuthN.ClientToken.Enabled в cmd/kaname не прибавилось
   ```
8. **Сквозные пробы (newman), коллекций новых — ноль.** В существующие кейсы добавляются шаги
   повторного отзыва после успешного: `tests/newman/cases/basic-access-token.py` — после
   `revoke-basic-secret` и его полла (CVR-03 на стенде); `tests/newman/cases/iam-service-account.py`
   — после `_revoke_key_steps` (CVR-07 на стенде). Каждый шаг утверждает **пару**: HTTP `404` и
   `code: 5`, плюс текст отказа. Коллекции `tests/newman/collections/basic-access-token.postman_collection.json`
   и `iam-service-account.postman_collection.json` перегенерируются из кейсов тем же изменением.
9. **Документы называют исход.** `docs/content/api/tokens.mdx` — строка таблицы отказов и раздел
   «Отзыв идемпотентен успехом» переписаны на Р1/Р2; там же выдача ключевой пары без эндпоинта
   называет и `UserTokenService.Issue` (обе врезки — около строк 84 и 485);
   `docs/content/architecture/overview.mdx:86-87` говорит одно с кодом на обоих путях;
   `docs/engineering/components/05-sa-keys.md` — раздел об исходе отзыва; комментарии
   `rpc Revoke` в `user_token_service.proto` и `sa_key_service.proto` называют исход Р1/Р2.
   Запись о замещении BAT-1-44 (Р3) — выноской «правлено после вердикта» в
   `PRO-Robotech/kacho-workspace:docs/specs/sub-phase-BAT-1-basic-access-token-acceptance.md`,
   отдельным изменением воркспейса.
   ```sh
   git grep -n -i -E 'идемпотентен (\*\*)?успехом' -- docs/content docs/engineering/components internal/apps/kaname/api/user_tokens internal/apps/kaname/api/sa_keys
   # → 0
   git grep -n 'BAT-1-44 требует' -- internal/apps/kaname/api
   # → 0
   ```
10. **Гейты службы зелёные.** `make lint`; `go test -count=1 ./internal/check/` — в том числе
    `TestAcceptanceProbeCoordinateResolves` и `TestAcceptancePathCoordinateResolves` на этом
    документе.
11. **Ведомость сценариев закрыта:** каждый ID CVR-01…12 и CVR-21…26 назван в имени или
    комментарии хотя бы одной пробы.
    ```sh
    for id in 01 02 03 04 05 06 07 08 09 10 11 12 21 22 23 24 25 26; do printf '%s ' "CVR-$id"; git grep -l "CVR-$id" -- '*_test.go' tests/newman/cases | wc -l; done
    # → у каждого ID число ≥ 1
    ```

## Вопросы владельцу

Открытых — ноль. Исход отзыва закреплён решением R37 до старта волны-2; исход выдачи задан телом
`#547` и совпадает с уже действующим исходом ключа служебной учётки.
