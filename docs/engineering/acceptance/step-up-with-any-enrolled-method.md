<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Приёмка: повышение внутри живой сессии — любым заведённым способом: код по времени, запасной код, ключ доступа (kaname#827)

- **Статус:** DRAFT — редакция 1; кругов ревью не было
- **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
  на отпечаток редакции (`change-graph.md` §3 «Вердикт относится к ОТПЕЧАТКУ, а не к документу»)
- **История review:** (только дописывается) — записей нет
- **Дата:** 2026-10-14
- **Задача:** `PRO-Robotech/kaname#827` (P1), эпик `PRO-Robotech/kaname#746`, линия
  `release:identity-own-2`; зеркало у платформы — `PRO-Robotech/kacho#3230` (эпик
  `PRO-Robotech/kacho#3172`). Связаны: `kaname#729` (человек только с ключом не освежает сессию
  повышением), `PRO-Robotech/kacho#3196` (окно повышения не ведёт человека без кода к ключу),
  `PRO-Robotech/kacho#3229` п. 4 (ключи, выключенные на установке)
- **Основание:** решение владельца 2026-10-14, дословно: «2-й фактор должен подтверждать по
  OTP/коды/passwordLess. Саму страницу оформи с учетом лучших практик UX/UI по работе с личными
  настройками в личном кабинете.» Ранее, 2026-10-07: «все что разработали как замена ory все
  должно быть включено и смогли этим воспользоваться».
- **Дорожная карта:** `kacho-workspace:docs/specs/04-roadmap-and-phasing.md` строки этой линии не несёт
  (`git show origin/main:docs/specs/04-roadmap-and-phasing.md | grep -ciE 'втор(ой|ого) фактор|ключ доступа|F8'` → 0);
  объём задают решение владельца и эпик — как у соседей линии identity-own.
- **Экран** — отдельный документ дома приёмок консоли:
  `PRO-Robotech/kacho-workspace:docs/specs/sub-phase-F8-S7-console-security-settings-and-step-up-methods-acceptance.md`
  (далее — **F8-S7**). Он потребитель этого контракта и ни одного решения отсюда не переоткрывает.
- **Ревизии измерения:** служба — `PRO-Robotech/kaname@bbbe33524` (`origin/main`); ветка этого
  изменения `827` — от ветки эпика `origin/746@bee57fd5c`; платформа —
  `PRO-Robotech/kacho@8514270c4` (`origin/main`).
- **Тип изменения:** новый способ у существующей церемонии повышения, один новый глагол (выдача
  испытания повышения ключом), новые поля ответа чтения состояния второго фактора, новый отказ
  «ключи доступа на установке выключены» у трёх выдач испытания. Правило вывода уровня (Ф11 Р2)
  **не меняется**; полы каталога прав **не меняются**.
- **Формат:** Given-When-Then, только markdown. Оба ствола публичны: сборки «координата + условие
  + следствие» здесь нет, ссылок на рабочие каталоги задач — тоже.

## §0 Обзор

Человек подтверждает действие с полом «2» (или освежает сессию для правки своих данных) тем
способом, который у него заведён: кодом из приложения, одним из запасных кодов или ключом
доступа. Сегодня третьего способа у церемонии нет: человек с паролем и ключом, вошедший паролем,
поднять сессию ключом не может, а человек только с ключом не может освежить сессию иначе, чем
выйти и войти снова. Этот документ вводит ключ в церемонию повышения тем же глаголом, объявляет
человеку, какие способы ему доступны сейчас и когда каждым пользовались, и даёт службе сказать
«ключи доступа на этой установке выключены» вместо отказа о происхождении в конце церемонии.

### §0.1 Соседи — одобренные редакции, названы отпечатком

| сосед | отпечаток (`git show bbbe33524:<путь> \| sha256sum`) | что взято | что меняется этим документом |
|---|---|---|---|
| Ф7 `access-keys-are-ours.md` | `5ea26ad012add99800a8c185e98b9e2f38910c1c54daec5bdd8a5c4f3ea3efbe` | проверяющий утверждения `webauthnverify.VerifyAssertion` (Р13 Ф13 — второго нет); три ручки привязки (Р2); `lastUsedAt` ключа (Р1); страж последнего способа входа (Р12, Ф7-26) | новый отказ `ACCESS_KEYS_DISABLED` у `BeginRegistration` при пустом перечне происхождений (Р7) |
| Ф11 `assurance-level-is-declared-by-our-session.md` | `b39219bcd07e241fe2a1c52a4081ea1def2fe538812bbd611bfa8092712e73c8` | правило уровня Р2; предъявление внутри сессии Р5 (носитель перевыпущен, момент последнего предъявления сдвинут); монотонность; форма указания на повышение Р11 | — (словарь Ф11 Р8 имя `webauthn` уже несёт) |
| Ф12 `second-factor-totp-and-recovery-codes.md` | `c6ea48973b048e0430bf3712e317aca39ac7df2e77dcb5e8d71e65c59aa33e2f` | глагол `POST /iam/v1/auth/step-up` и его ответ (Р4); код по времени (Р5); набор из 10 запасных кодов (Р6); счёт попыток (Р7); снятие только кодом (Р9) | Р4: перечень способов церемонии — `password · totp · lookup_secret · webauthn`; §4.2 строка «ключ доступа как второй фактор» — возвращена в объём (§4 здесь) |
| Ф13 `passwordless-login-with-access-key.md` | `5fe6cca1aea606f96b2f24174a8f45411291f69250e6fb268b3274fd17a58af4` | форма `credential` (Ф13-05, Ф13-07); единый отказ входа; сгорание испытания до приговора (Ф13-08) | Р5 абзац «обратное направление — не предмет этой фазы» — предмет этого документа (§4) |
| `level-two-is-enrolled-at-level-two.md` | `41723d6b6369c8987a12477db36b24012a85c5f680d4ae7d40333625072dee65` | Р1: способ, дающий «2» одним предъявлением, заводится сессией «2»; Р4: у личности с ключом код заводится сессией «2»; Р5: снятие ключа — сессией «2» | — (путь Р4 для человека без кода становится исполнимым: повышение ключом, SUA-50) |

### §0.2 Посылка задания — проверена

Посылка: «подтверждение кодом и запасным кодом есть, ключом — нет». **Подтверждена** (§1.1):
разбор способа церемонии знает три имени, `webauthn` среди них нет; проверка утверждения Ф7
сессии не касается; множество предъявленного, из которого пересчитывается уровень записи
сессии, ключа не знает.

## §1 Перепись производителей — измерено

### §1.1 Церемония и уровень

```sh
# ДОМ: PRO-Robotech/kaname @ bbbe33524
git grep -c 'must be one of password|totp|lookup_secret"' bbbe33524 -- internal ':!*_test.go'
#   → internal/apps/kaname/api/humansession/second_factor.go:2  (ParseStepUpMethod, JudgeStepUpForm)
git show bbbe33524:internal/apps/kaname/api/access_keys/finish_assertion.go | grep -ciE 'session|bearer'
#   → 0  (проверка утверждения Ф7 сессию не пишет)
git show bbbe33524:internal/apps/kaname/api/humansession/session_level.go | sed -n 60,90p | grep -cE 'Method(Password|TOTP|LookupSecret|RecoveryCode|WebAuthn)\.String'
#   → 4  (пароль, код, запасной код, код восстановления; ключа нет)
git grep -c 'step-up/access-key' bbbe33524 -- .
#   → 0  (выдачи испытания повышения нет)
```

Производители, которые этот документ переиспользует, а не заводит:

| что производит | координата @bbbe33524 |
|---|---|
| церемония повышения, порядок «форма → сессия → частота → сверка → предъявление» | `internal/apps/kaname/api/humansession/step_up.go` |
| единственный писатель уровня внутри сессии | `humansession/session_level.go` (`presentInSession`) |
| отказ `authentication failed` (401, `code` 16) | `humansession/refusals.go` (`TextAuthenticationFailed`), `internal/handler/loginlanehttp/handler.go` (`writeError`) |
| отказ частоты 429, `code` 8, `TOO_MANY_ATTEMPTS`, `Retry-After` | `humansession/rate.go`, `handler.go` (`writeError`) |
| повтор кода по времени и потраченный запасной код — тот же вердикт «не сошёлся», он же попытка | `humansession/sf_present.go` (`countsAsAttempt`) |
| проверка утверждения ключа | `internal/webauthnverify/verify.go` (`VerifyAssertion`) |
| запись `lastUsedAt` ключа | `internal/repo/kaname/pg/access_key_repo.go` (`UPDATE user_access_keys SET … last_used_at`) |
| отказ `LAST_SIGN_IN_METHOD` | `internal/apps/kaname/api/access_keys/refusals.go` |

### §1.2 Чтение состояния и величины частоты

```sh
git show bbbe33524:internal/handler/loginlanehttp/handler.go | grep -c 'lastUsedAt\|issuedAt'
#   → 0  (у кода и набора моментов использования нет; у ключа — есть, AccessKey.last_used_at)
git grep -n 'ACCESS_KEYS_DISABLED' bbbe33524 | wc -l
#   → 0
git show bbbe33524:deploy/values.prod.yaml | sed -n 256,259p
#   → addressAttempts: 5 · addressWindow: 15m · sourceAttempts: 50 · sourceWindow: 15m
git show bbbe33524:.github/scripts/stand-own.sh | sed -n 295p
#   → export KANAME_AUTHN__LOGIN__ADDRESS_ATTEMPTS=5   (стенд проб — та же величина)
```

## §2 Решения (ратифицировать явно)

### Р1. Глагол повышения один, способов четыре; способ называет клиент

`POST /iam/v1/auth/step-up` принимает `method` из словаря Ф11 Р8:
`password · totp · lookup_secret · webauthn`. Второго адреса на способ не заводится (довод
`step_up.go`: два адреса об одном предмете). Умолчания нет: без `method` — отказ формы.

Форма по способу — каждое поле читается, лишнее отвергается с именем поля
(`api-conventions.md` §«Принято-и-проигнорировано — ЗАПРЕЩЕНО»):

| `method` | обязательное | отвергается, если прислано |
|---|---|---|
| `password` | `password` | `code`, `credential` |
| `totp`, `lookup_secret` | `code` (форма Ф12 Н12) | `password`, `credential` |
| `webauthn` | `credential` — объект той же формы, что у входа ключом (Ф13-05: `id`, `rawId`, `type`, `response.{clientDataJSON, authenticatorData, signature, userHandle}`) | `password`, `code` |

Тексты отказов формы (400, `code` 3) — формой `FieldError`:
`Illegal argument method: required` ·
`Illegal argument method: must be one of password|totp|lookup_secret|webauthn` ·
`Illegal argument credential: required` ·
`Illegal argument <поле>: not accepted with method <способ>`.
Разбор `credential` и его тексты — те же, что у входа ключом (Ф13-07), одним разборщиком.

### Р2. Испытание повышения ключом — свой глагол под живой сессией

`POST /iam/v1/auth/step-up/access-key/begin`, тело `{csrfToken}` (свой вид признака формы —
`step-up-access-key-begin`), пол — живая сессия любого уровня. Ответ 200:

```json
{"publicKey": {"challenge": "<b64url>", "rpId": "<имя доверяющей стороны>", "timeout": <мс>,
  "userVerification": "<литерал Ф7 Р9>",
  "allowCredentials": [{"type": "public-key", "id": "<credentialId b64url>"}]}}
```

- `allowCredentials` — **все** годные к предъявлению ключи этого человека, упорядочены по
  `(createdAt, id)` (`api-conventions.md` §«Пустое значение обязано означать «пусто»»); пустым
  не бывает — при нуле ключей отказ (Р5).
- Испытание **привязано к записи сессии**: у одной сессии одно живое испытание повышения, новая
  выдача сменяет прежнее. Срок — величина Ф7 (`ChallengeTTL`), своей ручки нет.
- Выдача попыткой не считается: испытание принадлежит сессии, и подбора им нет.

**Почему не пара Ф7 `BeginAssertion`/`FinishAssertion`:** они проверяют утверждение и отдают флаги,
не трогая сессию (§1.1, `→ 0`), и живут на gRPC без признака формы. Церемония повышения живёт
на полосе формы (сессия печеньем + признак формы), там же, где её три прежние ветви. Пара Ф7
остаётся как есть.

### Р3. Предъявление ключа: порядок несущий, приговор один

Порядок внутри `method: webauthn`: форма → сессия → частота (обе оси Ф3 Р10) → **сгорание
испытания** (до приговора и независимо от него, как Ф13-08) → строка удостоверения среди
годных ключей **этого** человека → сверка проверяющим Ф7 той же привязкой → предъявление одним
исходом (строка личности первой, `presentInSession`, `lastUsedAt` и счётчик подписи ключа) →
запись журнала `iam.session.step_up` с `method: webauthn`, `outcome: accepted`.

| исход | ответ | попытка? | журнал |
|---|---|---|---|
| испытания для этой сессии нет | 400, `code` 9, `CHALLENGE_NOT_ISSUED`, `step-up challenge was not issued: begin step-up again` | нет | нет |
| испытание уже предъявлено | 400, `code` 9, `CHALLENGE_ALREADY_PRESENTED`, `step-up challenge was already presented: begin step-up again` | нет | нет |
| испытание истекло | 400, `code` 9, `CHALLENGE_EXPIRED`, `step-up challenge expired: begin step-up again` | нет | нет |
| подпись не сошлась · происхождение вне перечня · хэш имени доверяющей стороны не тот · нет присутствия пользователя · удостоверение не этого человека · ключ снят · алгоритм вне перечня | **401, `code` 16, `authentication failed`** — побайтово тот же, что у неверного кода | **да**, обе оси | `outcome: refused` |
| сверка прошла | 200, тело Р4 | — (успех) | `outcome: accepted` |

Один текст на все суждённые отказы — потому что так уже устроены код и запасной код: различимый
текст «ключ не этого человека» был бы оракулом принадлежности удостоверения. Машинное различие
причины — внутрь, клеткой наблюдаемости (Р10), не наружу.

### Р4. Уровень — правилом Ф11 Р2 над накопленным множеством; ответ — прежней формы

Успешное предъявление ключа — предъявление Ф11 Р5: способ ложится в множество записи сессии,
уровень пересчитывается правилом Ф11 Р2 (монотонно), носитель перевыпускается
(`Set-Cookie`), момент последнего предъявления сдвигается — окно свежести 15 мин открыто;
момент аутентификации не двигается. Ключ с проверкой пользователя, не допускающий резервного
копирования, даёт «3»; любое иное утверждение ключа — «2».

Ответ — прежний объект церемонии Ф12 Р4: `session.{expiresAt, assuranceLevel, emailVerified}` и
`assurance.{level, level2Reachable, missingForLevel2}`. У личности с хотя бы одним годным ключом
при включённых ключах (Р7) `webauthn` входит в заведённые способы: `level2Reachable` истинно, и
`missingForLevel2` в сессии «1» называет `webauthn`.

### Р5. Способ не заведён — отказ состояния, не попытка

| способ | у человека не заведён | ответ |
|---|---|---|
| `totp`, `lookup_secret` | строки кода нет либо `pending` | 400, `code` 9, `SECOND_FACTOR_NOT_ENROLLED`, `second factor is not enrolled` (Ф12 Р4, без изменения) |
| `webauthn` (выдача испытания) | годных ключей ноль | 400, `code` 9, `ACCESS_KEY_NOT_REGISTERED`, `no access key is registered: register an access key first` |

Ни тот ни другой попыткой не считаются и записи журнала не оставляют.

### Р6. Чтение состояния способов несёт моменты и перечень доступных способов

`GET /iam/v1/auth/second-factor` дописывает ключи (прежние — без изменения):

| ключ | значение | когда ключа нет |
|---|---|---|
| `totp.lastUsedAt` | момент последнего **принятого** предъявления кода по времени после подтверждения (вход с `secondFactor`, повышение, перевыпуск набора) | предъявлений после подтверждения не было |
| `backupCodes.issuedAt` | момент выпуска действующего набора (подтверждение заведения либо перевыпуск) | набора нет (фактор не заведён) |
| `backupCodes.lastUsedAt` | момент последнего потраченного кода **этого** набора | из этого набора не тратили |
| `accessKeys.available` | `true` либо `false` — включены ли ключи доступа на установке (Р7) | ключ есть всегда |
| `stepUpMethods` | **набор** способов второго фактора, которые человек может предъявить в церемонии сейчас: `totp` — при `active`; `lookup_secret` — при `active` и остатке > 0; `webauthn` — при ≥ 1 годном ключе и `accessKeys.available`. Порядок — лексикографический, смысла не несёт | ключ есть всегда; пусто — `[]` |

Моменты — RFC 3339, усечены до секунды. Отсутствие — **отсутствие ключа**, а не `null` и не
пустая строка. Пароль в `stepUpMethods` не входит: он даёт свежесть, а не «2» (довод
`step-up-methods.ts` консоли, тот же). Моменты ключа доступа — уже в `AccessKey`
(`createdAt`, `lastUsedAt`); повышение ключом двигает `lastUsedAt` тем же писателем, что вход
ключом. Второго чтения о ключах не заводится.

### Р7. «Ключи доступа на установке выключены» — объявление службы

Ключи выключены ровно тогда, когда объявленный перечень происхождений пуст («никого»; ручка
`authn.access-keys.origins`, Ф7 Р2). Тогда:

- `accessKeys.available` — `false`, `webauthn` нет в `stepUpMethods` и в заведённых для `assurance`;
- три выдачи испытания — `BeginRegistration` (Ф7), `POST /iam/v1/auth/access-key/begin` (Ф13),
  `POST /iam/v1/auth/step-up/access-key/begin` (Р2) — отвечают **до выдачи испытания**:
  `code` 9 `FAILED_PRECONDITION` (REST — 400), `ACCESS_KEYS_DISABLED`,
  `access keys are turned off on this installation`; попыткой не считается;
- перечень ключей (`List`) и снятие (`Revoke`) работают: человек видит и убирает свои ключи.

Перечень непуст — поведение Ф7 прежнее: происхождение вне перечня на приёме результата
регистрации — `ORIGIN_NOT_ALLOWED` (Ф7, без изменения). Это пункт 4 `kacho#3229` на стороне
службы: консоль получает **факт**, а не выводит его из отказа.

### Р8. Лимит попыток — тот же счёт, числом

Все способы церемонии кладут суждённый отказ в **один** счёт Ф3 Р10 по двум осям. Величины —
профилем поставки (`deploy/values.prod.yaml`) и стенда проб (тот же `5`):
**5 неверных предъявлений на адрес почты за 15 мин; 50 — на источник за 15 мин.** Проверка
частоты идёт **до** сверки: шестое предъявление в окне отвергается и верным материалом —
429, `code` 8, `TOO_MANY_ATTEMPTS`, `too many attempts; try again later`, `Retry-After` в
секундах (1…900). Попытки — по Р3 и Ф12 Р7: неверный код, повторённый код, потраченный
запасной, суждённый отказ ключа. Не попытки: отказ формы, отказ состояния (Р5, Р7), отказ
испытания (Р3, первые три строки), отказ частоты.

### Р9. Заведение и снятие способов — контракты соседей, без изменения

| способ | заведение | снятие | защита последнего |
|---|---|---|---|
| код по времени + набор | `enroll` → `confirm` (Ф12 Р4, Р8; у личности с ключом — сессией «2», level-two Р4) | `remove` только кодом (Ф12 Р9) | снятие требует предъявить сам фактор; без годного ключа после снятия `level2Reachable` — `false` (виден в ответе состояния) |
| ключ доступа | `BeginRegistration` → `FinishRegistration`, сессией «2» и в окне свежести (level-two Р3, Ф7 Р5) | `Revoke`, сессией «2» и в окне свежести (level-two Р5) | последний способ входа не снимается: `LAST_SIGN_IN_METHOD` (Ф7-26) |
| запасные коды | выпуск при подтверждении; показ **один раз** в ответе `confirm` и перевыпуска (Ф12 Р6) | перевыпуск `POST …/backup-codes` кодом гасит прежний набор целиком | остаток числом в чтении состояния; ноль — число, не молчание |

Новое здесь одно: повышение ключом делает исполнимым путь level-two Р4 для человека с паролем и
ключом без кода — «2» ключом, затем заведение кода (SUA-50).

### Р10. Наблюдаемость и журнал

Запись журнала `iam.session.step_up` — у ключа тем же видом, с `method: webauthn`. Клетки
счётчика предъявлений — способ × исход дописываются парами `webauthn × matched` и
`webauthn × mismatched`; отказы состояния — клетками `access-key-not-registered` и
`access-keys-disabled`; причины суждённого отказа ключа — клетками полосы Ф13 (происхождение,
хэш имени доверяющей стороны, присутствие, подпись). Ни кода, ни материала, ни носителя в
записях нет.

### Р11. Поверхность безопасности — названа

Расширение одно: путь `POST /iam/v1/auth/step-up/access-key/begin` на слушателе формы (за
краем — ретрансляция, F8-S7), под живой сессией и признаком формы своего вида. Он раскрывает
предъявителю идентификаторы **его же** удостоверений — ровно то, что раскрывает перечень ключей
на полу «1». Каталог прав не меняется; полы глаголов — прежние. Уровень «3» этим документом
впервые достижим внутри сессии, выданной паролем; глаголов с полом «3» — 0 (§6).

## §3 Сценарии (Given-When-Then)

**Посевы** (каждое «Дано» строится глаголами продукта; адрес почты — свой у каждого сценария):

| посев | что лежит | чем строится |
|---|---|---|
| **П-п** | человек с паролем, адрес подтверждён | `tests/authz-fixtures/seed_login_lane.py` (`seed`) |
| **П-к** | П-п + код по времени `active` + набор 10 кодов; секрет и коды — в окружении пробы | П-п, затем `enroll` → `confirm` полосой Ф12 (код — RFC 6238 от секрета ответа `enroll`) |
| **П-кл** | пароль + один ключ, кода нет | `tests/authz-fixtures/seed_key_person.py` шаги 1–4 (без снятия пароля); материал ключа — `_KEYS` подставного аутентификатора `tests/newman/cases/kaname-access-keys.py` |
| **П-ккл** | пароль + код + ключ | П-к, затем регистрация ключа из сессии «2», выданной подтверждением (Ф12-02) |
| **П-л** | только ключ | `seed_key_person.py` целиком (шаги 1–5) |
| **Б** | второй человек со своим ключом | П-кл со своим адресом |
| **выкл** | установка с пустым перечнем происхождений | integration-проба: лента собирается с `Binding.Origins = []` над той же базой, где ключ П-кл заведён лентой с непустым перечнем; на стенде — своё пространство имён проб с этой величиной профиля |

Флаги утверждения подставной аутентификатор задаёт значением (`_UP`, `_UV`, `_BE`), происхождение
— параметром `origin` (`_finish_assertion`). Ось времени — управляемые часы пробы (`Now` ленты),
ожидания нет.

### §3.1 Каждый способ проходит подтверждение

**ID: SUA-01** — код по времени
**Given** П-к; сессия «1» — вход паролем без `secondFactor`
**When** `POST /iam/v1/auth/step-up` `{method: "totp", code: <текущий код>, csrfToken}`
**Then** 200; `session.assuranceLevel` = `"2"`; `assurance` = `{level: "2", level2Reachable: true, missingForLevel2: []}`
**And** новый носитель в `Set-Cookie`; прежний носитель следующим запросом — отказ «сессии нет» (Ф11 Р5)
**And** `GET /iam/v1/auth/second-factor` несёт `totp.lastUsedAt` = момент предъявления (до секунды)

**ID: SUA-02** — запасной код
**Given** П-к; сессия «1»; код `B1` из ответа `confirm`, ещё не тративший
**When** `POST /iam/v1/auth/step-up` `{method: "lookup_secret", code: B1, csrfToken}`
**Then** 200; `assurance.level` = `"2"`; `backupCodesRemaining` = 9
**And** `GET /iam/v1/auth/second-factor`: `backupCodes.remaining` = 9, `backupCodes.total` = 10, `backupCodes.lastUsedAt` присутствует

**ID: SUA-03** — ключ, уровень «2»
**Given** П-кл; сессия «1»; аутентификатор с ключом П-кл, флаги `UP|UV|BE`
**When** `POST /iam/v1/auth/step-up/access-key/begin` `{csrfToken}`
**Then** 200; `publicKey.allowCredentials` — ровно `[{type: "public-key", id: <удостоверение П-кл>}]`
**When** `POST /iam/v1/auth/step-up` `{method: "webauthn", credential: <утверждение над выданным испытанием>, csrfToken}`
**Then** 200; `session.assuranceLevel` = `"2"`; `assurance.missingForLevel2` = `[]`
**And** `AccessKey.lastUsedAt` ключа (перечень Ф7) = момент предъявления; журнал — `iam.session.step_up`, `method: webauthn`, `outcome: accepted`

**ID: SUA-04** — ключ, уровень «3»; отличие от SUA-03 одно: флаги `UP|UV` (без `BE`)
**Given / When** как SUA-03
**Then** 200; `session.assuranceLevel` = `"3"`; `assurance.level` = `"3"`

**ID: SUA-05** — ключ освежает сессию человека только с ключом (`kaname#729`)
**Given** П-л; сессия, выданная входом ключом, последнее предъявление старше 15 мин (часы пробы)
**When** `POST /iam/v1/auth/sessions/end-others` (глагол своих сессий с требованием свежести)
**Then** 403, `SESSION_NOT_FRESH`, `re-authentication required: present a credential again`
**When** испытание повышения ключом, затем `POST /iam/v1/auth/step-up` `{method: "webauthn", …}`
**Then** 200; уровень прежний (`"2"` либо `"3"` по флагам — монотонность)
**When** тот же `POST /iam/v1/auth/sessions/end-others`
**Then** 200; тело `{ended: <число>}` (приёмка `own-sessions-are-listed-and-ended-by-their-owner.md`)

### §3.2 Отказы — каждый с конкретным текстом и близнецом

**ID: SUA-10** — неверный код; близнец SUA-01, отличие — код
**Given** П-к; сессия «1»
**When** `step-up` `{method: "totp", code: <код, не совпадающий ни с одним шагом окна>}`
**Then** 401; `code` 16; `message` = `authentication failed`
**And** уровень сессии «1»; носитель не перевыпущен; `totp.lastUsedAt` не изменился; журнал — `outcome: refused`

**ID: SUA-11** — повтор кода; близнец SUA-01 (первое предъявление того же кода)
**Given** П-к; сессия S1 подняла уровень кодом `C` (SUA-01); сессия S2 того же человека — «1»
**When** в S2 `step-up` `{method: "totp", code: C}` в том же шаге времени
**Then** 401; `code` 16; `authentication failed`; S2 остаётся «1»
**And** код следующего шага в S2 — 200 (положительный контроль той же сессии)

**ID: SUA-12** — потраченный запасной код; близнец SUA-02
**Given** П-к; `B1` потрачен в SUA-02; новая сессия «1»
**When** `step-up` `{method: "lookup_secret", code: B1}`
**Then** 401; `code` 16; `authentication failed`; `backupCodes.remaining` = 9 (не изменился)

**ID: SUA-13** — ключ с чужого происхождения; близнец SUA-03, отличие — `origin` в данных клиента
**Given** П-кл; сессия «1»; выданное испытание; утверждение подписано ключом П-кл, но `clientDataJSON.origin` вне перечня установки
**When** `step-up` `{method: "webauthn", credential}`
**Then** 401; `code` 16; `authentication failed`; уровень «1»; `AccessKey.lastUsedAt` не изменился
**And** то же испытание повторно — 400, `code` 9, `CHALLENGE_ALREADY_PRESENTED` (сгорело до приговора)

**ID: SUA-14** — ключ другого человека; близнец SUA-03, отличие — чьё удостоверение
**Given** П-кл и Б; сессия П-кл «1»; испытание выдано сессии П-кл
**When** `step-up` с утверждением ключом Б над этим испытанием
**Then** 401; `code` 16; `authentication failed`; `lastUsedAt` ключа Б не изменился

**ID: SUA-15** — снятый ключ; близнец SUA-03
**Given** П-ккл; ключ снят глаголом `Revoke` (операция `done` без ошибки); сессия «1»
**When** испытание повышения, затем утверждение снятым ключом
**Then** `allowCredentials` снятого удостоверения не содержит; `step-up` — 401, `code` 16, `authentication failed`

**ID: SUA-16** — испытание другой сессии; близнец SUA-03
**Given** П-кл; сессии S1 и S2 «1»; испытание выдано S1
**When** в S2 `step-up` с утверждением над испытанием S1
**Then** 400; `code` 9; `CHALLENGE_NOT_ISSUED`; `step-up challenge was not issued: begin step-up again`; попытки нет

**ID: SUA-17** — испытание сменено новой выдачей; положительный близнец внутри
**Given** П-кл; сессия «1»; испытание E1, затем испытание E2 той же сессии
**When** утверждение над E1 → **Then** 400, `CHALLENGE_NOT_ISSUED`
**When** утверждение над E2 → **Then** 200, уровень «2»

**ID: SUA-18** — истёкшее испытание; близнец SUA-03, отличие — момент
**Given** П-кл; испытание выдано; часы пробы сдвинуты за срок испытания Ф7
**When** `step-up` с утверждением над ним
**Then** 400; `code` 9; `CHALLENGE_EXPIRED`; `step-up challenge expired: begin step-up again`

**ID: SUA-19** — форма; близнецы SUA-01 и SUA-03
**Given** П-ккл; сессия «1»
**When / Then** (каждая строка — свой запрос, 400, `code` 3):
  - без `method` → `Illegal argument method: required`
  - `method: "passkey"` → `Illegal argument method: must be one of password|totp|lookup_secret|webauthn`
  - `method: "webauthn"` без `credential` → `Illegal argument credential: required`
  - `method: "totp"` с `code` и `credential` → `Illegal argument credential: not accepted with method totp`
  - `method: "webauthn"` с `credential` и `code` → `Illegal argument code: not accepted with method webauthn`
**And** попыток ноль: счёт по адресу после пяти строк — тот же

### §3.3 Способ не заведён, ключи выключены

**ID: SUA-20** — кода нет; близнец SUA-01
**Given** П-кл (кода нет); сессия «1»
**When** `step-up` `{method: "totp", code: "123456"}`
**Then** 400; `code` 9; `SECOND_FACTOR_NOT_ENROLLED`; `second factor is not enrolled`; попытки нет

**ID: SUA-21** — ключа нет; близнец SUA-03 (выдача)
**Given** П-к (ключей ноль); сессия «1»
**When** `POST /iam/v1/auth/step-up/access-key/begin`
**Then** 400; `code` 9; `ACCESS_KEY_NOT_REGISTERED`; `no access key is registered: register an access key first`

**ID: SUA-22** — ключи выключены на установке; близнец — тот же человек на установке с непустым перечнем (SUA-03)
**Given** выкл; П-кл; сессия «1»
**When** `GET /iam/v1/auth/second-factor`
**Then** `accessKeys.available` = `false`; `stepUpMethods` = `[]`
**When** `POST /iam/v1/auth/step-up/access-key/begin`
**Then** 400; `code` 9; `ACCESS_KEYS_DISABLED`; `access keys are turned off on this installation`
**And** перечень ключей Ф7 по-прежнему несёт ключ П-кл; `Revoke` его — операция `done` без ошибки

**ID: SUA-23** — регистрация при выключенных; близнец Ф7-01 (перечень непуст — испытание выдано)
**Given** выкл; П-к; сессия «2», свежая
**When** `BeginRegistration`
**Then** 400 / `code` 9; `ACCESS_KEYS_DISABLED`; `access keys are turned off on this installation`; испытание не выдано

**ID: SUA-24** — вход ключом при выключенных; близнец Ф13-01
**Given** выкл; без сессии
**When** `POST /iam/v1/auth/access-key/begin`
**Then** 400; `code` 9; `ACCESS_KEYS_DISABLED`; тот же текст; попытка по источнику не записана

### §3.4 Выбор способа, когда их несколько

**ID: SUA-30** — перечень доступных способов
**Given** четыре человека: П-ккл, П-к, П-кл, П-п
**When** `GET /iam/v1/auth/second-factor` каждым
**Then** `stepUpMethods`: П-ккл — `["lookup_secret","totp","webauthn"]`; П-к — `["lookup_secret","totp"]`; П-кл — `["webauthn"]`; П-п — `[]`

**ID: SUA-31** — набор исчерпан; близнец SUA-30 (П-к)
**Given** П-к; все 10 запасных кодов потрачены повышениями
**When** `GET /iam/v1/auth/second-factor`
**Then** `backupCodes.remaining` = 0 (число); `stepUpMethods` = `["totp"]`

**ID: SUA-32** — любой из нескольких проходит; умолчания нет
**Given** П-ккл; три сессии «1»
**When** в первой — `totp`, во второй — `lookup_secret`, в третьей — `webauthn` (флаги `UP|UV|BE`)
**Then** все три — 200, уровень «2»

**ID: SUA-33** — что недостаёт; близнец П-п
**Given** П-кл; сессия «1»
**When** `step-up` `{method: "password", password: <верный>}`
**Then** 200; `assurance` = `{level: "1", level2Reachable: true, missingForLevel2: ["webauthn"]}`
**And** у П-п тот же запрос — `{level: "1", level2Reachable: false, missingForLevel2: []}`

### §3.5 Моменты способов

**ID: SUA-40** — сразу после подтверждения
**Given** П-к сразу после `confirm`
**When** `GET /iam/v1/auth/second-factor`
**Then** `totp.enrolled` = `true`; `totp.confirmedAt` присутствует; ключа `totp.lastUsedAt` **нет**
**And** `backupCodes` = `{remaining: 10, total: 10, issuedAt: <= confirmedAt до секунды>}`; ключа `backupCodes.lastUsedAt` **нет**
**And** положительный близнец — SUA-01 и SUA-02: после предъявления оба ключа появляются

**ID: SUA-41** — вход с вторым фактором двигает момент
**Given** П-к
**When** вход паролем с `secondFactor {method: "totp", code}` (Ф12)
**Then** `totp.lastUsedAt` = момент входа

### §3.6 Заведение и снятие

**ID: SUA-50** — путь level-two Р4 стал исполним (`kacho#3196` на стороне службы)
**Given** П-кл; сессия «1»
**When** `POST /iam/v1/auth/second-factor/enroll`
**Then** 401; `code` 16; `authentication level is insufficient: step up with a second factor, or present a credential of another kind`; `WWW-Authenticate` с `acr_values` (level-two Р4, Ф11 Р11 — без изменения)
**When** повышение ключом (SUA-03), затем `enroll` → `confirm` первым кодом
**Then** 200 на обоих; `totp.enrolled` = `true`; `stepUpMethods` = `["lookup_secret","totp","webauthn"]`

**ID: SUA-51** — последний способ входа не снимается; близнец — снятие у П-кл
**Given** П-л; сессия ключом «2», свежая
**When** `Revoke` единственного ключа
**Then** 400 / `code` 9; `LAST_SIGN_IN_METHOD`; `last sign-in method cannot be revoked: enrol another sign-in method first`; ключ в перечне
**And** у П-кл (есть пароль) тот же запрос из свежей сессии «2» — операция `done` без ошибки; затем `stepUpMethods` = `[]`, `assurance.level2Reachable` в следующем повышении — `false`

**ID: SUA-52** — снятие кода по-прежнему только кодом; повышение ключом его не заменяет
**Given** П-ккл; сессия поднята ключом до «2», свежая
**When** `POST /iam/v1/auth/second-factor/remove` с неверным кодом
**Then** 401; `code` 16; `authentication failed`; фактор на месте
**And** тот же запрос с верным кодом — 200; `stepUpMethods` = `["webauthn"]`

### §3.7 Запасные коды: показ один раз и перевыпуск

**ID: SUA-60** — показ один раз
**Given** П-п; сессия «1», свежая; `enroll` выполнен
**When** `confirm` первым кодом
**Then** тело несёт 10 кодов
**And** `GET /iam/v1/auth/second-factor` кодов не несёт: объект `backupCodes` — ровно ключи `remaining`, `total`, `issuedAt` (и `lastUsedAt` после траты)

**ID: SUA-61** — перевыпуск гасит прежний набор; близнец — новый код проходит
**Given** П-к; `B1` из прежнего набора не тратил; сессия «2», свежая
**When** `POST /iam/v1/auth/second-factor/backup-codes` с верным кодом по времени
**Then** 200, 10 новых кодов; `backupCodes.issuedAt` сдвинут; ключа `backupCodes.lastUsedAt` нет
**And** `step-up` `lookup_secret` кодом `B1` — 401, `authentication failed`; новым кодом — 200

### §3.8 Лимит попыток — числом

**ID: SUA-70** — шестое предъявление отвергается и верным кодом
**Given** П-к; профиль `addressAttempts: 5`, `addressWindow: 15m`; сессия «1»
**When** 5 повышений неверным кодом (каждое — 401 `authentication failed`), затем шестое верным кодом
**Then** шестое — 429; `code` 8; `TOO_MANY_ATTEMPTS`; `too many attempts; try again later`; `Retry-After` — целое 1…900; уровень «1»

**ID: SUA-71** — близнец SUA-70: неверных четыре
**Given** как SUA-70
**When** 4 неверных, затем верный код
**Then** пятое — 200, уровень «2»

**ID: SUA-72** — суждённые отказы ключа — тот же счёт
**Given** П-кл; сессия «1»
**When** 5 повышений ключом с происхождением вне перечня (SUA-13, каждый раз новое испытание), затем шестое верным утверждением
**Then** шестое — 429, `TOO_MANY_ATTEMPTS`
**And** близнец: 4 таких, затем верное — 200

**ID: SUA-73** — отказы испытания счёта не тратят
**Given** П-кл; сессия «1»
**When** 5 предъявлений над невыданным испытанием (SUA-16, каждое — 400 `CHALLENGE_NOT_ISSUED`), затем новое испытание и верное утверждение
**Then** 200

## §4 Что этот документ заменяет в одобренных соседях — поимённо

| сосед | место | было | становится |
|---|---|---|---|
| Ф12 | Р4, перечень способов церемонии; текст отказа формы | `password · totp · lookup_secret`; `must be one of password\|totp\|lookup_secret` | Р1 здесь: четыре способа, текст с `webauthn` |
| Ф12 | Р4, форма церемонии: поле другого способа в теле | не судилось | отказ формы с именем поля `Illegal argument <поле>: not accepted with method <способ>` (Р1) |
| Ф12 | §4.2 строка «ключ доступа как второй фактор (`webauthn` в церемонии)» — 0 сценариев | за границей | в объёме: §3.1, §3.2 здесь |
| Ф12 | Р4, ответ чтения состояния | `totp.{enrolled, confirmedAt\|pendingUntil}`, `backupCodes.{remaining, total}` | плюс ключи Р6 здесь; прежние ключи без изменения |
| Ф13 | Р5, абзац «Обратное направление — ключ как второй фактор при входе паролем — не предмет этой фазы» | вынесено | предмет этого документа; остальная Р5 без изменения |
| Ф7 | отказ `BeginRegistration` при пустом перечне происхождений | испытание выдаётся, отказ `ORIGIN_NOT_ALLOWED` на приёме результата | отказ `ACCESS_KEYS_DISABLED` до выдачи (Р7) |
| Ф13 | `POST /iam/v1/auth/access-key/begin` при пустом перечне | испытание выдаётся | отказ `ACCESS_KEYS_DISABLED` (Р7) |

Каждая строка меняет отпечаток **этого** документа, а не соседа: соседи не правятся, их вердикты
остаются вердиктами их редакций (`change-graph.md` §3).

## §5 Сценарий → производитель

| ID | что производит «Тогда» | координата | чем измерено |
|---|---|---|---|
| SUA-01, 02, 10, 11, 12, 20 | ветви кода церемонии | `humansession/step_up.go`, `sf_present.go` @bbbe33524 | существует (§1.1); `totp.lastUsedAt`, `backupCodes.lastUsedAt` — **заказ** этой задачи |
| SUA-03, 04, 13…18 | ветвь `webauthn` церемонии и выдача испытания повышения | — | `git grep -c 'step-up/access-key'` → 0: **заказ** этой задачи (`kaname#827`) |
| SUA-05 | предъявление внутри сессии сдвигает момент последнего предъявления | `session_level.go` (`presentInSession`) | существует; ветвь ключа — заказ |
| SUA-19 | разбор формы церемонии | `second_factor.go` (`ParseStepUpMethod`, `JudgeStepUpForm`) | существует; тексты с `webauthn` и «not accepted with method» — заказ |
| SUA-21…24 | отказы `ACCESS_KEY_NOT_REGISTERED`, `ACCESS_KEYS_DISABLED` | — | `git grep -n 'ACCESS_KEYS_DISABLED'` → 0: заказ |
| SUA-30…33 | `stepUpMethods`, `assurance` с `webauthn` | `sf_status.go`, `second_factor.go` (`assuranceViewOf`, `enrolledMethods`) | существует без `webauthn`; дописывается — заказ |
| SUA-40, 41, 60, 61 | моменты набора и кода | `sf_status.go`, `sf_backup_codes.go`, `handler.go` (`secondFactorStatus`) | `grep -c 'lastUsedAt\|issuedAt'` → 0: заказ |
| SUA-50 | условие level-two Р4 | `humansession/sf_enroll_level.go` | существует; путь исполним с SUA-03 |
| SUA-51 | страж последнего способа входа | `access_keys/refusals.go` (`LAST_SIGN_IN_METHOD`) | существует |
| SUA-52 | снятие кодом | `humansession/sf_remove.go` | существует |
| SUA-70…73 | счёт попыток, отказ 429 | `humansession/rate.go`, `handler.go` (`writeError`) | существует; клетки ключа — заказ |

Сценариев без производителя после этой задачи — 0: каждый «заказ» — `kaname#827`.

## §6 Что НЕ входит

| вынесено | почему | носитель |
|---|---|---|
| экран «Безопасность», окно повышения консоли, QR-код, ретрансляция нового пути краем | дом приёмок консоли | F8-S7 (`PRO-Robotech/kacho#3230`) |
| полы «3» у глаголов, условие `mfa_fresh` | смена полов — своя приёмка (Ф12 §4.2) | `kaname#133`, `kaname#754` |
| момент последнего использования **пароля**, ответ «заведён ли пароль» | пароль не второй фактор; решение F8 Р13 (консоль не знает, есть ли пароль) остаётся | держателя нет — условие возврата: решение, заводящее чтение способов входа своей приёмкой |
| переименование ключа | у контракта Ф7 правки ключа нет | — |
| политика обязательности второго фактора по личности либо аккаунту | Ф12 Р3: ресурс аккаунта со своим владельцем | — |
| способы вне словаря Ф11 Р8 (письмо с кодом, сообщение на телефон, подтверждение в приложении) | словарь закрыт | — |
| письмо «добавлен новый способ входа» | дом — служба уведомлений (решение владельца 2026-09-17, P3) | — |
| экран входа консоли при выключенных ключах | экран F8-S4; служба даёт отказ с признаком (SUA-24) | F8-S7 §6 |

## §7 Инварианты

1. Уровень внутри сессии пишет один писатель (`presentInSession`); у ключа второго нет.
2. Суждённый отказ церемонии — один текст на все способы и причины: `authentication failed`.
3. Испытание повышения сгорает до приговора; принадлежит одной записи сессии; живое — одно.
4. Отсутствие момента — отсутствие ключа ответа; `null` и пустой строки нет.
5. `accessKeys.available` выводится из объявленного перечня происхождений и только из него.
6. Счёт попыток — один на все способы, величины — профилем, умолчания в коде нет (Ф3 Р10).

## §8 DoD

1. Падающие пробы до кода: Go integration (`internal/apps/kaname/api/humansession`) на SUA-01…05,
   10…24, 30…33, 40, 41, 50…52, 60, 61, 70…73 — имя пробы начинается с ID сценария.
2. Сквозные пробы края newman (`tests/newman/cases/kaname-login-lane.py`,
   `kaname-access-keys.py`): ≥ 1 положительный и ≥ 1 отрицательный на каждый новый путь и способ —
   минимум SUA-03, SUA-04, SUA-13, SUA-16, SUA-21, SUA-22, SUA-70; пара «HTTP-статус + `code`»
   в каждом утверждении (`api-conventions.md` §«gRPC-код → HTTP-статус»).
3. Страницы `docs/content/api/auth-lane.mdx` (церемония повышения, состояние второго фактора) и
   страница ключей доступа называют четыре способа, новый путь, новые ключи и отказы; путь
   освежения для человека только с ключом назван (`kaname#729`).
4. Ведомость ответов (`ResponseObjectKeys`) и клиентская страница сверены пробой
   `internal/check/client_page_auth_lane_test.go`.
5. Комментарий `DoD-proof @<sha>` в `kaname#827`.
