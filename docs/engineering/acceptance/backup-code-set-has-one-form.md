<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: набор запасных кодов — одна форма во всех ответах раздела второго фактора (iam Ф12, дополнение)

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** строки только дописываются; прежние не правятся и не удаляются
> - редакция 1 — 2026-10-19 — кругов ноль; отпечаток считает `sha256sum` этого файла
> - 2026-10-19 · круг 1 · CHANGES_REQUESTED · редакция 1 `7f950ca3f0709ac5b05558ae8deb441d7c9bd36df91fbe24253b7aa43347c81f` ·
>   `docs/specs/reviews/backup-code-set-has-one-form/7f950ca3f0709ac5b05558ae8deb441d7c9bd36df91fbe24253b7aa43347c81f.yaml`
> - редакция 2 — 2026-10-19 — по замечаниям круга 1 (B1, B2, B3, N1, N2) и только по ним; отпечаток — `sha256sum` этого файла
> - 2026-10-19 · круг 2 · APPROVED · редакция 2 `c6e042f38106b49bedddc3abeef2af6dd0a647d8e555c1848d22e7a6774e21c6` ·
>   `docs/specs/reviews/backup-code-set-has-one-form/c6e042f38106b49bedddc3abeef2af6dd0a647d8e555c1848d22e7a6774e21c6.yaml`
> - редакция 3 — 2026-10-19 — две правки и только они: (1) решение В-1 сменено на «один шаг»
>   (владелец 2026-10-19, §«Решения»): этапы S1 → S2 → S3 и сценарии сосуществования BCS-20…22
>   сняты; (2) предикаты по дереву консоли записаны древовидным аргументом клона
>   `PRO-Robotech/kacho` (гейт `TestAcceptancePathCoordinateResolves` отверг путь `ui-future`
>   после `--` как мёртвый в дереве службы). Одобрение редакции 2 на эту редакцию не переносится
> **Дата:** 2026-10-19
> **Эпик/issue:** PRO-Robotech/kaname#297 (Refs #296)
> **Дом:** `docs/engineering/acceptance/` службы — предмет внутри одного сервиса (полоса входа
> kaname); потребитель за границей репозитория — консоль kacho, правится той же волной (§«Совместимость»)
> **Опоры (одобренные редакции, отпечатки @`db8bcb7e` origin/main):**
> - `second-factor-totp-and-recovery-codes.md` (Ф12), APPROVED,
>   `c6ea48973b048e0430bf3712e317aca39ac7df2e77dcb5e8d71e65c59aa33e2f`
>   (запись `docs/specs/reviews/second-factor-totp-and-recovery-codes/c6ea4897….yaml`);
> - `step-up-with-any-enrolled-method.md` (SUA), APPROVED,
>   `35224856e3e2aec098ac0398deaeceb22dbb8cd4702232d921af62ea8168d683`
>   (запись `docs/specs/reviews/step-up-with-any-enrolled-method/35224856….yaml`).
>
> Этот документ меняет у опор **только форму** представления набора и остатка (ось «какой ключ,
> какого типа, каким путём»). Семантику набора — десять кодов, однократность, замена целиком,
> показ один раз, исчерпание, снятие — он не трогает и не переутверждает (Ф12 Р6, Р4; SUA Р6).

## Обзор

Раздел второго фактора полосы входа отдаёт один предмет — набор запасных кодов и его остаток —
пятью ответами, и в них у предмета две формы ключа и два имени остатка: `backupCodes` — объект
в чтении состояния и массив в подтверждении и перечеканке; остаток — вложенный
`backupCodes.remaining` в чтении и плоский `backupCodesRemaining` в снятии и повышении, причём у
снятия это постоянный ноль со смыслом «фактора нет», а у повышения — настоящий остаток. Документ
утверждает целевую форму: **у каждого ключа один тип и один смысл во всех ответах**, остаток
читается **одним путём**, а «сводки набора нет» (набора нет либо он не читается) выражается
отсутствием ключа, а не нулём. Разрыв
совместимости назван явно, переход — один шаг, служба и консоль одной волной (§«Совместимость»,
§«Решения»).

## Посылка задачи — перемерена

Ревизия измерения — `origin/main` kaname @ `db8bcb7e87f11b267bb1470894bf033b3c033e78`; консоль —
`origin/main` kacho @ `a952484649` и линия `origin/3172-identity-own-2` @ `5e4facc5ff`.

**Производители ключей в ответах (по предмету — писатели тела в обработчике полосы):**

| глагол | ключ в ответе 200 | тип | писатель |
|---|---|---|---|
| `GET /iam/v1/auth/second-factor` (фактор заведён) | `backupCodes` | объект `{remaining, total, issuedAt, lastUsedAt?}` | `internal/handler/loginlanehttp/handler.go:970-979` |
| `POST …/second-factor/confirm` | `backupCodes` | массив из 10 строк (коды, показ один раз) | `handler.go:932` |
| `POST …/second-factor/backup-codes` | `backupCodes` | массив из 10 строк | `handler.go:1043` |
| `POST …/second-factor/remove` | `backupCodesRemaining` | число, всегда `0` | `handler.go:1010-1011`; значение — `humansession/sf_remove.go:166-167` |
| `POST /iam/v1/auth/step-up` (`lookup_secret`) | `backupCodesRemaining` | число — остаток после траты | `handler.go:1088-1089`; значение — `humansession/step_up.go:233-235` |

Команды: `git grep -n -E '"backupCodes"|"backupCodesRemaining"|"remaining"' -- internal/handler/loginlanehttp/handler.go`
(по написанию: 3 + 2 + 1 = 6 строк) и чтение пяти функций обработчика `confirmSecondFactor`,
`secondFactorStatus`, `removeSecondFactor`, `regenerateBackupCodes`, `stepUp` (по предмету: 5
глаголов). Вход `POST /iam/v1/auth/login` с запасным кодом ключей набора не несёт
(`handler.go:620-677`, тело — `user`, `session`).

**Расхождения — восемь** (Р-8 найден ревью круга 1):

| № | ось | что расходится | координата |
|---|---|---|---|
| Р-1 | тип ключа | `backupCodes` — объект в `GET` и массив строк в `confirm` и перечеканке | `handler.go:978` против `:932`, `:1043` |
| Р-2 | имя и путь остатка | вложенный `backupCodes.remaining` в `GET` против плоского `backupCodesRemaining` в `remove` и `step-up` | `handler.go:972` против `:1011`, `:1089` |
| Р-3 | смысл одного имени | `backupCodesRemaining` у снятия — постоянный `0` «фактора нет», у повышения — остаток живого набора; ноль под одним именем значит два разных факта | `sf_remove.go:166-167` против `step_up.go:233-235` |
| Р-4 | документация | `backupCodesRemaining` ответа повышения не описан: раздел церемонии повышения называет тело `{ "session", "assurance" }`; задача-источник перечисляет четыре ответа, производителей пять | `docs/content/api/auth-lane.mdx` раздел «Церемония повышения» (пример тела `session`/`assurance`) |
| Р-5 | класс секретности под одним именем | под `backupCodes` лежат то одноразовые коды (секрет), то сводка числами; срез отчёта проб вынужден различать их по форме значения, а не по имени | `.github/scripts/redact-newman-report.py:2418-2421` (близнец «сводка под `backupCodes` выжила») |
| Р-6 | домен | остаток назван `BackupCodesView.Remaining` в чтении и `BackupCodesRemaining *int` в выходах снятия и повышения — домен повторяет раздвоение края | `humansession/sf_status.go:28-29`; `sf_remove.go:40`; `step_up.go:78` |
| Р-7 | текст отказа | отказ формы запасного кода `Illegal argument code: must be 10 characters of the backup-code alphabet` в документации не назван (назван только `must be 6 digits`) и ни одной пробой не утверждается | производитель `humansession/second_factor.go:285`; `git grep -c 'backup-code alphabet'` → 1 файл, только производитель |
| Р-8 | третий смысл нуля | фактор заведён, а строки набора нет либо её материал не читается: чтение состояния всё равно отдаёт сводку — `remaining: 0` (как у исчерпания) и `issuedAt: "0001-01-01T00:00:00Z"` (нулевой момент); схема такое состояние допускает (Ф12 §13: связывающего ограничения строк `totp` и набора нет) | `humansession/sf_status.go:106` (сводка создаётся с `Remaining` 0 **до** чтения набора), `:114-120` (нечитаемый и отсутствующий набор — только журнал); момент — `handler.go:1548` (`moment`) |

**Слои без расхождения (названы, чтобы «все слои» было перечнем, а не словом):**

- **proto** — предмета нет: ни одного поля о наборе в `proto/` (`git grep -n -i -E 'backup|remaining' -- proto`:
  два комментария `user_service.proto:461,479` у `ResetSecondFactor` и два поля ключей доступа
  `access_key_service.proto:394-395` — другой предмет). Полоса входа — JSON края, а не gRPC;
  `reserved` номеров здесь нет и не нужно.
- **хранение** — одна форма: набор — строка способа входа `lookup_secret` с проверочным материалом,
  остаток вычисляется из материала (`sf_status.go:107-113`, `Sets.SetSize`); колонки остатка нет.

**Посылка задачи:** подтверждена по Р-1 и Р-2 с уточнениями — номера строк задачи (219/222/233/243)
устарели, на ревизии измерения это строки 404, 436, 446, 450 `auth-lane.mdx`; ответов с предметом
пять, а не четыре (повышение); найдены ещё Р-3…Р-8 (Р-8 — ревью круга 1).

**Потребители текущих форм (перепись, будут затронуты переходом):**

| где | что читает | координата |
|---|---|---|
| консоль kacho, клиент полосы | `SecondFactorState.backupCodes?: {remaining,total,…}`, `Confirmed.backupCodes: string[]`, `Ceremony.backupCodesRemaining?` | `ui-future/shared/src/api/login-lane.ts:156,166,174` @main; `:167,185,193`, разбор `:833-838` @3172 |
| консоль kacho, экраны | остаток из `GET`; остаток из повышения | `pages/auth/AccountSettingsPage.tsx:311-313` @main; `pages/auth/security/SecondFactorSections.tsx:62,456,566-567` и `components/molecules/auth/StepUpModal/StepUpModal.tsx:270-273` @3172 |
| консоль kacho, сквозные пробы | массив `backupCodes` подтверждения и перечеканки | `ui-future/e2e/specs/{ceremony-seed,access-key-seed,account-settings,account-access-keys}.ts`, `e2e/measurements/second-factor-classes.spec.ts` |
| консоль kacho, сквозная проба полосы администратора | `backupCodesRemaining` = `0` у снятия (ломаемая форма №3) | `ui-future/e2e/specs/cloud-admin-lane.spec.ts:278-280` @main |
| консоль kacho, модульная проба поля кода | объект `backupCodes` в теле `GET` (ломаемая форма №1) | `shared/src/components/molecules/auth/SecondFactorCodeField/SecondFactorCodeField.four-forms.test.tsx:29` @main |
| kaname, фикстуры прав | массив `backupCodes` подтверждения | `tests/authz-fixtures/seed_ceremony.py`, `seed_key_person.py` |
| kaname, пробы края | все пять форм | `tests/newman/cases/kaname-second-factor.py` (19 строк `backupCodes`, 3 — `backupCodesRemaining`), `kaname-access-keys.py:3541` |
| kaname, срез отчёта | имя кода и близнецы сводки | `.github/scripts/redact-newman-report.py` (5 + 5 строк) |

## Что НЕ входит

- **слово способа** `lookup_secret` (поле `method`, `stepUpMethods`, `missingForLevel2`, метрики) —
  это словарь способов предъявления, общий для входа, повышения и уровня, а не ключ набора;
  его смена — отдельный, более широкий разрыв, предметом `kaname#297` не названный;
- **путь** `POST /iam/v1/auth/second-factor/backup-codes` и вид признака `second-factor` — не
  меняются;
- **ответ входа** с запасным кодом: сводки набора не несёт и после этого документа (он един с
  ответом регистрации и завершения восстановления — Ф12 Р4 «тот же ответ»); остаток после входа
  читается `GET`;
- **семантика набора** (десять кодов, однократность, замена целиком, исчерпание, уровень) — Ф12 Р6,
  SUA Р6, без изменений;
- **сброс администратором** `UserService.ResetSecondFactor` — в его сообщениях предмета нет;
- **багфикс `kaname#275`** не пересматривается: его инвариант «остаток **снятого** набора наружу не
  выходит» сохраняется (BCS-10, BCS-11); меняется только форма, которой ответ снятия это выражает
  (решение В-2, §«Решения»).

## Решение (наблюдаемое)

**Р1. У ключа `backupCodes` один тип и один смысл:** массив ровно из десяти строк — коды
только что выпущенного набора, показанные один раз. Он есть **только** в ответах подтверждения
заведения и перечеканки. Ни в каком другом ответе раздела ключа `backupCodes` нет.

**Р2. Состояние набора — ключ `backupCodeSet`, у него один тип:** объект с закрытым набором ключей
`remaining` (число, остаток неиспользованных кодов), `total` (число, `10`), `issuedAt` (момент
выпуска набора, UTC до секунды) и `lastUsedAt` (момент последней траты кода этого набора; **ключа
нет**, если из набора не тратили). Кодов и их материала в `backupCodeSet` нет никогда.
`backupCodeSet` отдаётся **только о прочитанном наборе**: строка набора есть и её материал
открылся. Значений-заглушек нет — ни нулевого `remaining` вместо неизвестного остатка, ни
нулевого момента вместо неизвестного `issuedAt`.

**Р3. Остаток читается одним путём — `backupCodeSet.remaining` — во всех ответах.** Плоского
`backupCodesRemaining` нет ни в одном ответе раздела.

**Р4. `backupCodeSet` в ответе — состояние набора ПОСЛЕ глагола:**

| ответ 200 | `backupCodeSet` | значение |
|---|---|---|
| `GET …/second-factor`, фактор заведён | есть | текущее состояние |
| `GET …/second-factor`, фактора нет либо заведение не подтверждено | **нет ключа** | набора нет |
| `GET …/second-factor`, фактор заведён, а строки набора нет либо её материал не читается | **нет ключа** | сводки нет; `totp.enrolled` = `true`; `stepUpMethods` без `lookup_secret`; дефект хранения — наша сторона, журнал службы (Ф12 §13), решение Д-4 (а), §«Решения» |
| `confirm` | есть | `{remaining: 10, total: 10, issuedAt}`, без `lastUsedAt` |
| перечеканка (любым годным способом) | есть | новый набор: `{remaining: 10, total: 10, issuedAt}`, без `lastUsedAt` |
| `step-up` способом `lookup_secret` | есть | остаток после траты, `lastUsedAt` — момент этой траты |
| `step-up` способами `password`, `totp`, `webauthn` | **нет ключа** | набор глаголом не менялся; состояние — `GET` |
| `remove` (любым годным кодом) | **нет ключа** | набора после снятия нет |
| любой отказ | **нет ключа** | — |

Значения `backupCodeSet` в ответе глагола совпадают со значениями `backupCodeSet` следующего
`GET` той же сессии (те же ключи, те же значения). Ноль `remaining` означает ровно одно —
«фактор заведён, набор прочитан, коды исчерпаны»; «сводки набора нет» выражается **отсутствием
ключа**, а не нулём. Что именно отсутствует, клиент различает по `totp.enrolled`: `false` —
фактора нет; `true` — набора нет либо он не читается (оба — дефект хранения, наружу не
различаются).

**Р5. Отказ формы запасного кода — один текст, названный в документации дословно:**
`400`, `code` `3`, `Illegal argument <поле>: must be 10 characters of the backup-code alphabet`,
где `<поле>` — `code` у снятия, перечеканки и повышения и `secondFactor.code` у входа. Отказ формы
попыткой не считается (Ф12 Р4 — как у `must be 6 digits`; держатель — опора Ф12, сценария этого
документа нет). Производителей отказа два: разбор поля второго фактора (снятие, перечеканка,
вход) и суд формы повышения (повышение) — у каждого свой сценарий (BCS-12, BCS-18, BCS-14,
BCS-17).

**Р6. Документация раздела** (`docs/content/api/auth-lane.mdx`, разделы «Второй фактор» и
«Церемония повышения») показывает ровно форму Р1…Р5; абзац о «двух разных нулях» снимается
вместе с предметом.

## Совместимость

**Это публичный контракт.** Полоса входа описана на сайте документации службы
(`docs/content/api/auth-lane.mdx`), её ретранслирует край kacho (`gateway/internal/middleware/login_lane_paths.go`,
цель `RelayTargetForm`), её читает консоль. Proto здесь нет — разрыв в именах полей JSON, а не в
номерах; аналог `reserved` для JSON — **запрет повторного использования снятых имён с другим
смыслом**: после этого изменения имя `backupCodesRemaining` в разделе не появляется вовсе, а
`backupCodes` никогда не означает объект (держатель — BCS-32).

**Что ломается (разрыв назван явно):**

1. `GET …/second-factor`: ключ `backupCodes` (объект) **снимается**, его место — `backupCodeSet`;
2. `POST /iam/v1/auth/step-up`: `backupCodesRemaining` **снимается**, остаток — `backupCodeSet.remaining`;
3. `POST …/second-factor/remove`: `backupCodesRemaining: 0` **снимается**, «набора нет» — отсутствие ключа.

Ответы `confirm` и перечеканки **не ломаются**: массив `backupCodes` остаётся, `backupCodeSet`
добавляется. Ни один ключ не меняет тип на месте.

**Почему новое имя у сводки, а не у массива** (вариант «`backupCodes` — объект везде, коды под
новым именем» отвергнут): там тип ключа `backupCodes` в `confirm` менялся бы с массива на объект
**на месте** — разрыв ещё и для трёх потребителей массива (консоль, фикстуры прав, пробы края),
которых выбранная форма не трогает; и под одним именем остались бы секрет и сводка (Р-5).
Выбранная форма даёт имени `backupCodes` один класс секретности — «коды, показ один раз», а
`backupCodeSet` кодов не несёт (последнее слово имени — не «код», срез отчёта проб его не режет).
Имя повторяет словарь, уже принятый в дереве: «backup code set» — комментарии proto
(`user_service.proto:479`), журналы и порты домена (`Sets.SetSize`, `sf_status.go:115,119`).

**Путь перехода — один шаг** (решение В-1, §«Решения»): прежних форм служба не отдаёт ни на одной
ревизии, сосуществования двух форм нет.

| часть | репозиторий | что | ломает? |
|---|---|---|---|
| служба | kaname | `backupCodeSet` во всех ответах Р4; три прежние формы сняты тем же изменением; разрыв объявлен в `CHANGELOG.md` разделом ломающих изменений и в сообщении коммита | **да** — для клиента, читающего прежние формы |
| консоль | kacho, **та же волна** | перепин службы, консоль и её пробы читают только `backupCodeSet` (сводка) и `backupCodes` (массив) — одним изменением | нет — консоль и пин службы не расходятся ни на одной ревизии |

Порядок посадки: изменение службы вливается в kaname; в kacho перепин на ревизию с ним и правка
консоли — одним изменением той же волны. До перепина kacho отдаёт прежнюю службу с прежней
консолью (обе в прежней форме), после — обе в новой; ревизии, где консоль читает форму, которой её
служба не отдаёт, нет. Сторонний клиент полосы окна не получает — цена принята решением В-1.

Предикат готовности консоли — по написанию, в клоне `PRO-Robotech/kacho` на голове изменения
консоли (каталог консоли назван древовидным аргументом `HEAD:ui-future`, команда исполняется
дословно): `git grep -c -E 'backupCodesRemaining|backupCodes\??: \{' HEAD:ui-future` → пусто
(ни одного файла); контроль, что предикат читает: на `origin/main` @ `a98dc1ebba` тот же образец
по `a98dc1ebba:ui-future` → 4 файла, 6 строк. По предмету — сквозные пробы консоли BCS-40…42
зелёные на стенде с kaname этого изменения.

## Общее Given

**G0.** Установка в боевой посадке; личность P с паролем и подтверждённым адресом, без ключа
доступа; вход паролем дал сессию S уровня `1`; P завёл и подтвердил код по времени
(`enroll` → `confirm` первым кодом с секрета ответа `enroll`) — сессия S уровня `2`, свежая;
коды набора из ответа `confirm` сохранены (C1…C10). Признак формы каждого `POST` получен
`GET /iam/v1/auth/csrf?form=<вид>` с тем же печеньем `kaname_form`.
Посев: шаги `enroll`, `confirm` и захват `sfBackupCodes` набора newman `kaname-second-factor`
(`tests/newman/cases/kaname-second-factor.py:832…881`); в Go — обвязка
`internal/handler/loginlanehttp/step_up_any_method_harness_integration_test.go`. Код по времени
вычисляется из секрета (`_present_totp`, `kaname-second-factor.py:276`).

## Служба — целевая форма (kaname)

### Сценарий BCS-01: чтение заведённого фактора

**ID:** BCS-01

**Given** G0; из набора не тратили
**When** клиент вызывает `GET /iam/v1/auth/second-factor` с печеньем S
**Then** `200`; `backupCodeSet` — объект с ключами ровно `remaining`, `total`, `issuedAt`;
`remaining` = `10` (число), `total` = `10`, `issuedAt` — момент UTC до секунды
**And** ключа `backupCodeSet.lastUsedAt` нет
**And** ни одно значение `backupCodeSet` не равно ни одному из C1…C10

### Сценарий BCS-02: чтение без фактора — близнец BCS-01

**ID:** BCS-02

**Given** личность Q как в G0, но **без** заведённого второго фактора (вход паролем, уровень `1`)
**When** клиент вызывает `GET /iam/v1/auth/second-factor` с сессией Q
**Then** `200`; `totp.enrolled` = `false`; ключа `backupCodeSet` **нет**; ключа `backupCodes` **нет**

### Сценарий BCS-03: подтверждение заведения

**ID:** BCS-03

**Given** личность R как в G0 до шага `confirm`: `enroll` выполнен, секрет получен
**When** клиент вызывает `POST /iam/v1/auth/second-factor/confirm` с payload:
  - `code` = текущий код по времени из секрета
  - `csrfToken` = признак вида `second-factor`
**Then** `200`; `backupCodes` — массив ровно из 10 строк, каждая `^[0-9A-HJKMNP-TV-Z]{10}$`, все различны
**And** `backupCodeSet` = `{remaining: 10, total: 10, issuedAt}`, ключа `lastUsedAt` нет
**And** ни одно значение `backupCodeSet` не равно ни одному элементу `backupCodes`
**And** следующий `GET …/second-factor` той же сессии: `backupCodeSet` равен `backupCodeSet` ответа
(те же ключи, те же значения)

### Сценарий BCS-04: перечеканка кодом по времени

**ID:** BCS-04

**Given** G0; из набора потрачен один код (C1, повышением `lookup_secret`); `GET` даёт `remaining` = 9
**When** клиент вызывает `POST /iam/v1/auth/second-factor/backup-codes` с payload:
  - `method` = `totp`, `code` = текущий код по времени, `csrfToken` = признак вида `second-factor`
**Then** `200`; `backupCodes` — 10 новых строк, ни одна не входит в C1…C10
**And** `backupCodeSet` = `{remaining: 10, total: 10, issuedAt}`, `issuedAt` не раньше прежнего, ключа `lastUsedAt` нет
**And** следующий `GET`: `backupCodeSet` равен `backupCodeSet` ответа

### Сценарий BCS-05: перечеканка запасным кодом — близнец BCS-04 (иной способ)

**ID:** BCS-05

**Given** как BCS-04
**When** то же, но `method` = `lookup_secret`, `code` = C2
**Then** `200`; `backupCodeSet.remaining` = `10` — остаток **нового** набора, а не `8` прежнего; ключа `lastUsedAt` нет
**And** следующий `GET`: `backupCodeSet` равен `backupCodeSet` ответа

### Сценарий BCS-06: повышение запасным кодом

**ID:** BCS-06

**Given** G0; из набора не тратили; запомнен `issuedAt` из `GET`
**When** клиент вызывает `POST /iam/v1/auth/step-up` с payload:
  - `method` = `lookup_secret`, `code` = C1, `csrfToken` = признак вида `step-up`
**Then** `200`; `backupCodeSet` = `{remaining: 9, total: 10, issuedAt: <запомненный>, lastUsedAt}`
**And** ключа `backupCodesRemaining` нет
**And** следующий `GET`: `backupCodeSet` равен `backupCodeSet` ответа

### Сценарий BCS-07: повышение кодом по времени — близнец BCS-06 (иной способ)

**ID:** BCS-07

**Given** как BCS-06
**When** `POST /iam/v1/auth/step-up` с `method` = `totp`, `code` = текущий код по времени
**Then** `200`; ключа `backupCodeSet` **нет**; ключа `backupCodesRemaining` нет
**And** следующий `GET`: `backupCodeSet.remaining` = `10` — не изменился

### Сценарий BCS-08: исчерпание — ноль числом, ключ на месте

**ID:** BCS-08

**Given** G0; C1…C9 потрачены повышениями `lookup_secret` (после девятого `remaining` = 1)
**When** `POST /iam/v1/auth/step-up` с `method` = `lookup_secret`, `code` = C10
**Then** `200`; `backupCodeSet.remaining` = `0` — число, ключ присутствует; `total` = `10`
**And** следующий `GET`: `totp.enrolled` = `true`, `backupCodeSet.remaining` = `0`,
`stepUpMethods` не содержит `lookup_secret`

### Сценарий BCS-09: потраченный код — отказ без сводки; близнец BCS-06

**ID:** BCS-09

**Given** G0; C1 потрачен (BCS-06), `GET` даёт `remaining` = 9
**When** `POST /iam/v1/auth/step-up` с `method` = `lookup_secret`, `code` = C1
**Then** `401`, `code` `16`, `authentication failed`; ключей `backupCodeSet` и `backupCodesRemaining` в теле нет
**And** следующий `GET`: `backupCodeSet.remaining` = `9` — не изменился

### Сценарий BCS-10: снятие кодом по времени — набора нет, ключа нет

**ID:** BCS-10

**Given** G0
**When** `POST /iam/v1/auth/second-factor/remove` с payload:
  - `method` = `totp`, `code` = текущий код по времени, `csrfToken` = признак вида `second-factor`
**Then** `200`; ключи тела ровно `session`, `assurance`
**And** следующий `GET`: `totp.enrolled` = `false`, ключа `backupCodeSet` нет

### Сценарий BCS-11: снятие запасным кодом — близнец BCS-10 (иной способ)

**ID:** BCS-11

**Given** G0; из набора не тратили
**When** то же, что BCS-10, но `method` = `lookup_secret`, `code` = C1
**Then** `200`; ключи тела ровно `session`, `assurance`; остатка снятого набора (`9`) нет ни под
каким ключом (инвариант `kaname#275` сохранён)
**And** следующий `GET`: `totp.enrolled` = `false`, ключа `backupCodeSet` нет

### Сценарий BCS-12: отказ формы запасного кода назван дословно — близнец BCS-11

**ID:** BCS-12

**Given** G0
**When** `POST /iam/v1/auth/second-factor/remove` с payload:
  - `method` = `lookup_secret`, `code` = `ABC`, `csrfToken` = признак вида `second-factor`
**Then** `400`, `code` `3`, `message` = `Illegal argument code: must be 10 characters of the backup-code alphabet`
**And** фактор не снят: следующий `GET` — `totp.enrolled` = `true`, `backupCodeSet.remaining` = `10`
**And** положительный близнец — BCS-11: различие одно — `code` годной формы и живой (C1) → `200`

### Сценарий BCS-13: годный по форме неверный код — соседний отказ (сверки), не близнец

**ID:** BCS-13

**Given** G0
**When** то же, что BCS-12, но `code` = десять знаков алфавита, не входящие в C1…C10
**Then** `401`, `code` `16`, `authentication failed` — отказ сверки, а не формы
**And** отличает отказ сверки от отказа формы BCS-12; положительный близнец обоих — BCS-11

### Сценарий BCS-14: тот же текст у входа — поле с префиксом

**ID:** BCS-14

**Given** G0; новая форма входа
**When** `POST /iam/v1/auth/login` с payload:
  - `email`, `password` личности P, `csrfToken` вида `login`
  - `secondFactor` = `{ "method": "lookup_secret", "code": "ABC" }`
**Then** `400`, `code` `3`, `message` = `Illegal argument secondFactor.code: must be 10 characters of the backup-code alphabet`
**And** положительный близнец — BCS-16 (то же, но живой код)

### Сценарий BCS-16: вход живым запасным кодом — близнец BCS-14

**ID:** BCS-16

**Given** G0; из набора не тратили; новая форма входа
**When** `POST /iam/v1/auth/login` с payload как BCS-14, но `secondFactor.code` = C1
**Then** `200`; `session.assuranceLevel` = `"2"`; ключи тела ровно `user`, `session` — ключей
`backupCodeSet`, `backupCodes`, `backupCodesRemaining` нет (§«Что НЕ входит»: ответ входа сводки не несёт)
**And** следующий `GET …/second-factor` новой сессии: `backupCodeSet.remaining` = `9`
**And** опора того же пути — Ф12-12 (`second-factor-totp-and-recovery-codes.md`, отпечаток `c6ea4897…`)

### Сценарий BCS-17: отказ формы запасного кода у повышения — близнец BCS-06

**ID:** BCS-17

**Given** G0; из набора не тратили
**When** `POST /iam/v1/auth/step-up` с payload:
  - `method` = `lookup_secret`, `code` = `ABC`, `csrfToken` = признак вида `step-up`
**Then** `400`, `code` `3`, `message` = `Illegal argument code: must be 10 characters of the backup-code alphabet`
**And** ключей `backupCodeSet` и `backupCodesRemaining` в теле нет
**And** следующий `GET`: `backupCodeSet.remaining` = `10` — не изменился
**And** положительный близнец — BCS-06: различие одно — `code` = C1 → `200`

### Сценарий BCS-18: отказ формы запасного кода у перечеканки — близнец BCS-05

**ID:** BCS-18

**Given** G0; из набора не тратили
**When** `POST /iam/v1/auth/second-factor/backup-codes` с payload:
  - `method` = `lookup_secret`, `code` = `ABC`, `csrfToken` = признак вида `second-factor`
**Then** `400`, `code` `3`, `message` = `Illegal argument code: must be 10 characters of the backup-code alphabet`
**And** ключей `backupCodes` и `backupCodeSet` в теле нет
**And** следующий `GET`: `backupCodeSet` не изменился (`remaining` = `10`, прежний `issuedAt`)
**And** положительный близнец — BCS-05: различие одно — `code` годной формы и живой → `200`

### Сценарий BCS-15: документация показывает одну форму

**ID:** BCS-15

**Given** редакция `docs/content/api/auth-lane.mdx` изменения `kaname#297`
**When** читатель открывает разделы «Второй фактор» и «Церемония повышения»
**Then** `backupCodes` описан только как массив ответа `confirm` и перечеканки; `backupCodeSet` —
с ключами Р2 и таблицей Р4 (в каких ответах есть, в каких нет); ответ повышения способом
`lookup_secret` показан с `backupCodeSet`; текст отказа Р5 приведён дословно
**And** `backupCodesRemaining` в документации не встречается; абзаца о «двух разных нулях» нет

## Служба — набор без годного состояния (Go integration)

Состояние — дефект хранения (Ф12 §13): через край его не построить, поэтому держатель — Go
integration в `internal/handler/loginlanehttp` на настоящей базе. Посев — обвязка G0
(`step_up_any_method_harness_integration_test.go`) и правка строки набора в
`kaname.user_login_methods` (вид `lookup_secret`) в самом тесте; образец записи строки набора —
`address_claim_integration_test.go:554` (`ReplaceLookupSet`), образец хранимого значения вне
перечня форматов — `humansession/verifier_our_side_callers_test.go:33` (`unreadableStored`).

### Сценарий BCS-50: строки набора нет — ключа нет; близнец BCS-01

**ID:** BCS-50

**Given** G0; затем строка вида `lookup_secret` личности P удалена из `kaname.user_login_methods`,
строка `totp` цела
**When** `GET /iam/v1/auth/second-factor` с печеньем S
**Then** `200`; `totp.enrolled` = `true`; ключа `backupCodeSet` **нет**; ключа `backupCodes` **нет**;
`stepUpMethods` не содержит `lookup_secret`
**And** ни одно значение тела не равно `0001-01-01T00:00:00Z`
**And** положительный близнец — BCS-01: различие одно — строка набора на месте

### Сценарий BCS-51: материал набора не читается — ключа нет; близнец BCS-01

**ID:** BCS-51

**Given** G0; затем материал строки `lookup_secret` личности P заменён хранимым значением формата вне
перечня (строка есть, `Sets.SetSize` её не открывает)
**When** `GET /iam/v1/auth/second-factor` с печеньем S
**Then** `200`; `totp.enrolled` = `true`; ключа `backupCodeSet` **нет**; `stepUpMethods` не
содержит `lookup_secret`
**And** тело равно телу BCS-50 по всем ключам, кроме моментов фактора `totp` — отсутствие и
нечитаемость наружу не различаются
**And** положительный близнец — BCS-01: различие одно — материал открывается

## Консоль — та же волна (kacho)

### Сценарий BCS-40: экран безопасности показывает остаток из `backupCodeSet`

**ID:** BCS-40

**Given** G0 в браузере консоли; служба изменения `kaname#297`
**When** P открывает раздел безопасности своей учётной записи
**Then** блок запасных кодов показывает «Осталось 10 из 10», значения — из `backupCodeSet` ответа `GET`

### Сценарий BCS-41: окно повышения показывает остаток после траты

**ID:** BCS-41

**Given** как BCS-40; действие, требующее повышения
**When** P подтверждает действие запасным кодом C1
**Then** окно показывает «Осталось запасных кодов: 9» — значение `backupCodeSet.remaining` ответа повышения
**And** близнец: подтверждение кодом по времени — строки об остатке нет

### Сценарий BCS-42: показ кодов один раз — массив `backupCodes`

**ID:** BCS-42

**Given** личность R как в BCS-03, в браузере консоли
**When** R подтверждает заведение первым кодом
**Then** экран показывает десять кодов — элементы `backupCodes` ответа `confirm`; перечеканка показывает десять новых из `backupCodes` своего ответа

## Служба — прежних форм нет (kaname)

### Сценарий BCS-30: чтение без прежнего объекта

**ID:** BCS-30

**Given** G0; служба изменения `kaname#297`
**When** `GET /iam/v1/auth/second-factor`
**Then** `200`; ключа `backupCodes` нет; `backupCodeSet` как в BCS-01
**And** близнец — BCS-03: ответ `confirm` той же службы несёт `backupCodes` массивом

### Сценарий BCS-31: ни один ответ не несёт плоского остатка

**ID:** BCS-31

**Given** G0; служба изменения `kaname#297`
**When** повышение `lookup_secret` (BCS-06) и снятие кодом по времени (BCS-10)
**Then** в обоих телах ключа `backupCodesRemaining` нет; остаток повышения — `backupCodeSet.remaining`

### Сценарий BCS-32: один тип ключа во всех ответах раздела

**ID:** BCS-32

**Given** G0; служба изменения `kaname#297`
**When** клиент проходит последовательность: `GET` · повышение `password` · повышение `totp` ·
повышение `lookup_secret` · перечеканка `totp` · `GET` · снятие `totp` · `GET` · `enroll` ·
`confirm` · `GET`, сохраняя тело каждого ответа `200`
**Then** в каждом теле, где есть `backupCodes`, это массив ровно из 10 строк, и такие тела —
только ответы `confirm` и перечеканки
**And** в каждом теле, где есть `backupCodeSet`, это объект с ключами из {`remaining`, `total`,
`issuedAt`, `lastUsedAt`} и обязательными первыми тремя; присутствие — ровно по таблице Р4
**And** ни в одном теле нет ключа `backupCodesRemaining`

## Сценарий → производитель

Производитель целевой формы — изменение `kaname#297` (служба) и задача консоли той же волны (заводится);
сегодняшний писатель — координата, которую изменение правит.

| ID | что производит «Тогда» | координата в дереве (@`db8bcb7e`) | чем измерено |
|---|---|---|---|
| BCS-01, 30 | тело `GET`: сводка набора | `handler.go:970-979` (`secondFactorStatus`), значения `humansession/sf_status.go:106-113` | newman `kaname-second-factor` (`_backup_summary`, `:325`); Go `loginlanehttp/second_factor_test.go` |
| BCS-02 | отсутствие ключа без фактора | `sf_status.go:96-101` (ранний возврат без `BackupCodes`) | те же |
| BCS-50, 51 | отсутствие ключа при заведённом факторе без прочитанного набора | `sf_status.go:106-122` (сегодня сводка создаётся до чтения набора — правка **заказана**, #297); `stepUpMethods` — `sf_status.go:131`, `setHasCodes` `:158-170` (уже без `lookup_secret`) | **заказана** Go integration `loginlanehttp` (сегодня ни одной) |
| BCS-03 | тело `confirm`: массив и сводка | `handler.go:931-935`; коды `humansession/sf_enroll.go:248,335`; сводка — **заказана** (#297) | newman шаг `confirm` (`:871-881`); Go `level_two_enrollment_integration_test.go` |
| BCS-04, 05 | тело перечеканки | `handler.go:1042-1046`; `humansession/sf_backup_codes.go:83,154-157`; сводка — **заказана** (#297) | newman шаги перечеканки (`:1093-1106`) |
| BCS-06, 08, 31 | тело повышения `lookup_secret` | `handler.go:1087-1090`; остаток `step_up.go:233-235` ← `sf_present.go:192,206`; момент траты — запись набора (`sf_status.go:111`) | newman `_backup_step_up_ok` (`:609-626`); Go `step_up_any_method_ceremony_integration_test.go`, `humansession/second_factor_usecase_test.go:585-696` |
| BCS-07 | отсутствие ключа у иных способов | `step_up.go:233` (ветвь `st.consumed`) | newman повышение `totp`; Go `second_factor_usecase_test.go:572` |
| BCS-09 | отказ без сводки | `handler.go:1081-1085` (`writeError`) | newman `_backup_step_up_refused` (`:628`) |
| BCS-10, 11 | тело снятия | `handler.go:1008-1013`; `sf_remove.go:159-168` | Go `second_factor_remove_integration_test.go`; newman шаги `remove` |
| BCS-12, 13 | отказ формы / отказ сверки у снятия | `parseSecondFactorField("", …)` — `handler.go:996` → `:862-876` → `JudgeCodeForm` `humansession/second_factor.go:283-286`, текст `refusals.go:93` | **заказана** проба: newman и Go — сегодня ни одной (Р-7) |
| BCS-18 | отказ формы у перечеканки | **тот же производитель, что снятие**: `parseSecondFactorField("", …)` — `handler.go:1029` → `:862-876` | **заказана** проба (newman `kaname-second-factor`) |
| BCS-17 | отказ формы у повышения | **свой производитель**, мимо `parseSecondFactorField`: `handler.go:1077` → `humansession.JudgeStepUpForm` (`second_factor.go:227-235`) → `JudgeCodeForm("code", …)` | **заказана** проба (newman `kaname-second-factor`) |
| BCS-14 | тот же текст у входа с префиксом поля | `parseSecondFactorField("secondFactor", …)` — `handler.go:642` → `:862-876` | **заказана** проба (newman `kaname-login-lane`) |
| BCS-16 | вход живым запасным кодом: тело без сводки | `handler.go:670-673` (тело `user`, `session`; вход с `secondFactor` — `:636-647`) | newman `kaname-login-lane`; опора Ф12-12 |
| Р5 «отказ формы попыткой не считается» | — | опора Ф12 Р4; сценария этого документа нет — держатель у опоры | — |
| BCS-15 | текст документации | `docs/content/api/auth-lane.mdx`, разделы `#second-factor` и «Церемония повышения» | предикаты DoD п. 5 |
| BCS-32 | инвариант типа по всем ответам | все пять писателей выше | **заказана** проба-обход: newman `kaname-second-factor`, новая последовательность |
| BCS-40 | экран безопасности | kacho `ui-future/shared/src/pages/auth/security/SecondFactorSections.tsx:456,566` (@3172), разбор `api/login-lane.ts:833-838` | playwright `ui-future/e2e/specs/account-settings.spec.ts` |
| BCS-41 | окно повышения | kacho `components/molecules/auth/StepUpModal/StepUpModal.tsx:270-273` (@3172) | `StepUpModal.test.tsx:199` + playwright `account-access-keys.spec.ts` |
| BCS-42 | показ кодов | kacho `pages/auth/AccountSettingsPage.tsx:377,389` (@main) | playwright `account-settings.spec.ts:569-570,691-692` |

## DoD

Каждый пункт — «пройдено / не пройдено» по названной команде либо прогону.

**Служба (kaname), одно изменение:**
1. Сценарии BCS-01…18 и BCS-30…32 — newman-кейсы края в `kaname-second-factor` (BCS-14, BCS-16 —
   в `kaname-login-lane`), у отказов утверждается пара «HTTP-статус и `code`»; для BCS-03…11 —
   Go integration в `internal/handler/loginlanehttp`; BCS-50, BCS-51 — только Go integration там же
   (дефект хранения через край не строится); падающие пробы — до кода (TDD).
2. Новая коллекция не заводится; если всё же заводится — строка ведомости производителя тем же
   изменением.
3. Срез отчёта проб: самопроверка `.github/scripts/redact-newman-report.py` утверждает — элементы
   `backupCodes` срезаны, `backupCodeSet` (числа и моменты) выжил; близнец «сводка под
   `backupCodes`» заменён близнецом «сводка под `backupCodeSet`».
4. Фикстуры прав `tests/authz-fixtures/seed_ceremony.py`, `seed_key_person.py` зелёные без правки
   (массив `backupCodes` не менялся).
5. Документация: `auth-lane.mdx` описывает только форму Р1…Р5, прежних форм не называет; ответ
   повышения `lookup_secret` описан (закрывает Р-4); `git grep -c 'backupCodesRemaining' -- docs/content`
   → 0; абзаца о «двух нулях» нет; BCS-15 сверен чтением раздела.
6. По написанию: `git grep -n 'backupCodesRemaining' -- internal cmd docs/content tests .github` → 0
   строк; по предмету: BCS-32 зелёный (пять писателей, обход всех ответов раздела).
7. `CHANGELOG.md` — запись в разделе ломающих изменений с перечнем трёх снятых форм (§«Совместимость»);
   сообщение коммита изменения службы объявляет разрыв.
8. Опоры Ф12 и SUA: их сценарии, утверждающие прежнюю форму (Ф12-02, Ф12-18, Ф12-25, Ф12-26,
   Ф12-28, Ф12-45; SUA-02, SUA-12, SUA-31, SUA-40, SUA-60, SUA-61), получают отсылку к этому
   документу по оси формы — новой редакцией опоры с ревью по дельте; до этого два места об одном
   предмете не сходятся, и изменение службы не вливается.

**Консоль (kacho), та же волна:**
9. Перепин службы на ревизию с изменением `kaname#297` и правка консоли с её пробами — одним
   изменением в kacho той же волны (§«Совместимость», порядок посадки).
10. BCS-40…42 зелёные на стенде с kaname этого изменения; по написанию — в клоне `PRO-Robotech/kacho`
    на голове изменения консоли `git grep -c -E 'backupCodesRemaining|backupCodes\??: \{' HEAD:ui-future`
    → пусто (контроль, что предикат читает, — §«Совместимость»).

## Решения

Решения диспетчера по вопросам ВОЗВРАТа; допущений, открытых в этом документе, нет.

- **В-1 — один шаг** (сменено в редакции 3). Решение владельца 2026-10-19: «прода нет». Установок,
  где консоль прежней версии работает с новой службой, нет — окно сосуществования двух форм ничего
  не защищает, а стоит этап и три сценария. Поэтому `backupCodeSet` вводится сразу, прежние формы
  снимаются тем же изменением службы, консоль kacho правится в той же волне (§«Совместимость»).
  Снято вместе с прежним выбором В-1 (а) «три этапа S1 → S2 → S3» круга 2: этапы, сценарии
  сосуществования BCS-20…22, «устаревающие» формы в документации.
- **В-2 — принято, без изменений** (прежнее Д-2). Ответ снятия выражает «набора нет» отсутствием
  `backupCodeSet`, а не `0`: это меняет форму, выбранную по `kaname#275`, но сохраняет его инвариант
  (остаток снятого набора не выходит, BCS-11). Основание — предикат снятия `kaname#297` прямо
  включает `remove`.
- **В-3 — имя `backupCodeSet`, без изменений** (прежнее Д-3). Альтернатива — `backupCodes` объектом и
  коды под новым именем — отвергнута в §«Совместимость» (смена типа на месте у потребителей массива;
  секрет и сводка под одним именем).
- **Д-4 — вариант (а), без изменений.** Фактор заведён, а набора нет либо он не читается: чтение
  состояния отвечает `200` **без** ключа `backupCodeSet` (BCS-50, BCS-51), а не отказом. Основание —
  `stepUpMethods` в этом состоянии уже не называет `lookup_secret` (`sf_status.go:158-170`), так что
  ответ согласован сам с собой; остальное состояние (код по времени, способы повышения, ключи
  доступа) остаётся читаемым, а человеку остаётся путь починки — перечеканка кодом по времени.
  Отвергнутая альтернатива — `503` на всё чтение состояния (как у повышения запасным кодом в этом же
  состоянии, Ф12-35 «г»): цена — консоль теряет экран безопасности целиком из-за одного дефектного
  набора.
