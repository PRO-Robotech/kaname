<!--
Copyright (c) PRO-Robotech
SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Замысел: повышение внутри живой сессии любым заведённым способом — ключ доступа третьим способом церемонии (kaname#827)

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующего одобрения замысла нет — оно выводится из внешнего
> события и записи пересверки на ОТПЕЧАТОК ЭТОГО документа (`change-graph.md` §3), а не из слова
> в шапке. До чистой пересверки `class-exposure-analyst` замысел не одобрен.
> **Владелец истины:** технические решения, инварианты, отображение классов риска и порядок
> работ (`change-graph.md` §1). Наблюдаемое поведение и перечень сценариев — у приёмки, здесь
> **не переоткрываются**.
> **Предмет приёмки (редакция 3):** `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`
> (далее — **SUA**)
> **Отпечаток приёмки:** `35224856e3e2aec098ac0398deaeceb22dbb8cd4702232d921af62ea8168d683`
> (`sha256sum <путь>` на ветке `827`; содержимое — коммит `a897548d8`); вердикт `APPROVED` круга 3 —
> запись `docs/specs/reviews/step-up-with-any-enrolled-method/35224856….yaml`, событие опубликовано
> в `kaname#827`.
> **Разбор классов:** `docs/specs/reviews/step-up-with-any-enrolled-method-class-exposure/initial/c9224c8b….md`
> (первичный, на редакцию 2 `c9224c8b…`; его «вернуть в приёмку» M1 закрыто редакцией 3 — запись
> круга 3, блок `m1_closure`). Пересверка на редакцию 3 — по дельте (`flow-acceleration.md` fa-b1).
> **Дом:** `PRO-Robotech/kaname` — `docs/engineering/acceptance/` (предмет внутри одной службы);
> экран — `kacho-workspace:docs/specs/sub-phase-F8-S7-console-security-settings-and-step-up-methods-acceptance.md` (F8-S7).
> **Issue:** `PRO-Robotech/kaname#827` · эпик `kaname#746` · зеркало `PRO-Robotech/kacho#3230`
> **Ревизии измерения:** служба — ветка `827`, ревизия `6a82d3198` (код совпадает с головой ветки
> эпика `746`, ревизия `bee57fd5c`: `git diff --stat bee57fd5c 6a82d3198 -- internal cmd` → пусто); платформа — `kacho@8514270c4`
> (`origin/main`). Координаты ниже — на этих ревизиях; на голове ветки после слияния с полосой
> проб (`1ee5848a3`) названные файлы не правлены: `git diff --stat 6a82d3198 1ee5848a3 -- internal cmd
> ':!*_test.go'` — 7 файлов, ни одного из названных здесь. Сдвинется голова — перемерь.
> **История редакций замысла (только дописывается):**
> - редакция 1 — опора на SUA редакции 3; решения диспетчера по честному красному
>   2026-10-14 (шесть пунктов) учтены в §1б.
> - редакция 2 — правка ПОСЛЕ объявления состояния (строка «Статус» не менялась, вердикта у
>   замысла нет), до первой пересверки: заказанные пробы названы прозой, а не координатой (их в
>   дереве ещё нет), пробы платформы — с домом и ревизией, ревизии измерения — хешем. Решения не
>   менялись.
> - редакция 3 (эта) — правка ПОСЛЕ объявления состояния, до первой пересверки: пробы, которые
>   соседняя полоса уже завела красными (`ef2fa20be`), названы своими именами; заказанной остаётся
>   одна детерминированная проба шва «сдвиг проигран» (§2.3) и пробы уборки (решение диспетчера 4).
>   Решения не менялись.

---

## §0 Что это, и чего оно НЕ делает

Замысел отображает каждое решение SUA (`Р1…Р11`) в техническое решение и каждую строку разбора
классов — в механизм дерева и пробу, его держащую. Он **не** правит приёмку, **не** пишет код,
схему, `.proto` и пробы — называет решения и символы, которые их исполнят, и **не** ставит себе
вердикта.

Существо изменения: **третий вызывающий** проверяющего утверждений Ф7 — ветвь `webauthn`
церемонии повышения (`internal/apps/kaname/api/humansession/step_up.go`), **свой глагол выдачи**
испытания под живой сессией, **своё хранилище** испытаний повышения, **столбец момента
последнего использования** у строк второго фактора и **один предикат** «ключи выключены» у шести
читателей. Новый `.proto` не заводится; каталог прав и полы глаголов не меняются.

---

## §1 Решение приёмки → решение замысла

| Р | решение SUA | техническое решение замысла | где в дереве (`6a82d3198`) |
|---|---|---|---|
| **Р1** | один глагол, четыре способа; форма по способу, лишнее поле отвергается | `ParseStepUpMethod` узнаёт `webauthn`; текст словаря `must be one of password\|totp\|lookup_secret\|webauthn` производит **одна** константа (сегодня литерал стоит дважды — `second_factor.go:160` и `:175`); `stepUpForm` получает поле `credential` (`json.RawMessage`), `JudgeStepUpForm` судит «поле не того способа» текстом `Illegal argument <поле>: not accepted with method <способ>` по таблице Р1; разбор `credential` — **один** разборщик на вход ключом и повышение: нынешний `accessKeyLoginInput` (`internal/handler/loginlanehttp/access_key_login.go:160`) выносится в разбор утверждения, который зовут оба обработчика, обязательность полей — одна функция домена полосы, а не `switch` внутри `AccessKeyLoginUseCase.Execute` (`access_key_login.go:276–291`) | `humansession/second_factor.go:149`, `:165`; `loginlanehttp/handler.go:1016` (`stepUp`) |
| **Р2** | глагол выдачи под живой сессией; испытание у записи сессии, одно живое, сменяется новой выдачей; срок Ф7; частоты нет; положение подтверждения — отказ | путь `PathStepUpAccessKeyBegin = "/iam/v1/auth/step-up/access-key/begin"`, вид признака `FormStepUpAccessKeyBegin = "step-up-access-key-begin"` (17-е значение `formKinds`); use-case `StepUpAccessKeyBeginUseCase`: признак формы → положение → `resolveLiveSession` → предикат «выключено» (§2.6) → удостоверения человека `CredentialIDsOf` (`ORDER BY created_at, id`, `access_key_repo.go:167`) → ноль — отказ Р5 → 32 случайных байта → выдача одним оператором (§2.1); срок — `access_keys.ChallengeTTL` (`deps.go:43`), `rpId` — `Binding.RPID`, `userVerification` — литерал Ф7 Р9; счёт частоты не спрашивается и не пишется | §2.1; §2.4 |
| **Р3** | порядок «форма → сессия → частота → сгорание → строка ключа → сверка → предъявление»; один 401 на все суждённые | §2.2 (порядок), §2.3 (шов счётчика); отказ — тот же путь `recordRefusal` → `ErrAuthenticationFailed`, что у кода (`step_up.go:239`, `:267`) | `step_up.go:81` (`Execute`) |
| **Р4** | уровень — правило Ф11 Р2 над накопленным множеством; ответ прежней формы | `presentInSession` принимает **предъявление этого акта** (`assurance.Presentation`), а не имя способа: множество пополняется именем `act.Method()`, кандидат — `LevelOf(presentationsOf(записанное) ∪ {act})`; у ключа акт — `assurance.KeyAssertion(flags.UserVerified, flags.BackupEligible)` из ответа `VerifyAssertion`; слово `webauthn` в записи по-прежнему не переводится (`session_level.go:28`); писатель уровня остаётся один (`session_level.go:54`), четыре вызывающих (`step_up.go:166`, `sf_enroll.go:304`, `sf_remove.go:128`, `sf_backup_codes.go:126`) передают акт своего способа | `humansession/session_level.go:50`, `:59` |
| **Р5** | ключей ноль — `ACCESS_KEY_NOT_REGISTERED`, не попытка | отказ состояния тем же видом, что `ErrSecondFactorNotEnrolled` (`second_factor.go:229`): сентинел + `Reason` + текст в доме отказов второго фактора; на выдаче, до чеканки испытания; ни следа попытки, ни журнала | `humansession/second_factor.go:200–230` |
| **Р6** | чтение состояния несёт моменты и `stepUpMethods`, `accessKeys.available` | §2.5 (столбец), §2.6 (предикат); `StatusOutput` получает `TOTPLastUsedAt`, `BackupCodesIssuedAt`, `BackupCodesLastUsedAt` (каждый — значение **с отдельным признаком присутствия**, не нулевое время), `AccessKeysAvailable`, `StepUpMethods`; транспорт пишет ключ JSON только при присутствии, моменты — `.UTC().Truncate(time.Second).Format(time.RFC3339)`, как `confirmedAt` сегодня (`handler.go:937`); `stepUpMethods` — отсортированный набор, пусто — `[]` | `humansession/sf_status.go:58`; `loginlanehttp/handler.go:925` |
| **Р7** | «выключено» ⟺ перечень происхождений пуст; три выдачи отвечают `ACCESS_KEYS_DISABLED` до выдачи | §2.6 | `webauthnverify/verify.go:116` |
| **Р8** | один счёт попыток, величины профилем | ветвь ключа не заводит своего счёта: `uc.gate.check` до сгорания, суждённый отказ — `recordRefusal` (след по обеим осям и журнал `refused` одной транзакцией, `step_up.go:267`) | `step_up.go:93`, `:267` |
| **Р9** | заведение и снятие — контракты соседей | без правок; путь level-two Р4 исполняется повышением ключом (SUA-50) | `humansession/sf_enroll_level.go` |
| **Р10** | журнал и клетки; сигнал клонирования только при невыросшем счётчике | §2.7 | `humansession/observer.go:266`, `:271`; `observability/metrics/access_key_recorder.go:75` |
| **Р11** | расширение поверхности одно — новый путь | §2.4; каталог прав и полы — без изменений; «3» внутри сессии пароля впервые достижим, глаголов с полом «3» — 0 (§1а строка SUAX-04) | — |

**Решений без технического решения нет.**

---

## §1а Отображение строк разбора классов (19 из 19)

Нумерация `SUAX-NN` — порядок строк таблицы «Экспозиция и условия на код» разбора; в скобках —
решение разбора, к которому строка относится. Форма строки — fa-b3: «пункт → решение замысла →
место в коде → проба-держатель». Имена проб — с ID сценария первым (SUA §8 п.1); заказанные (их в дереве ещё нет) написаны прозой, без кода-координаты, существующие — координатой; **размещение**
— `internal/handler/loginlanehttp` (решение диспетчера 1, §1б).

| пункт | решение замысла | место в коде | проба-держатель |
|---|---|---|---|
| SUAX-01 (SUAD3, хвост суждения третьим вызывающим) | §2.2: перепись ветвей Ф13 и Ф7 против ветви повышения — таблица §2.2, ни одна ветвь не выпала | `step_up.go` (ветвь `webauthn`) | по пробе на ветвь: `TestSUA13_…`, `TestSUA14_…`, `TestSUA15_…`, `TestSUA80_SignCountThatDidNotGrowIsRefusedAndSignalled`, TestSUA80_LostAdvanceIsRefusedWithoutTheCloneSignal (заказ); статический гейт полноты хвоста — **заказ** `tooling-maintainer` (§7) |
| SUAX-02 (SUAD3, сдвиг в транзакции предъявления) | §2.3: `AdvanceSignCount` — оператором транзакции `PersonWriter`, после строки личности, до `presentInSession`; ноль строк — откат всей транзакции | `humansession.Writer` + общий оператор `advanceSignCountTx` (`pg/access_key_repo.go:512`) | TestSUA80_LostAdvanceIsRefusedWithoutTheCloneSignal (заказ); гонка двух повышений — `TestSUA80_LostCounterRaceIsRefused` |
| SUAX-03 (SUAD4, предъявление акта, а не имя) | Р4 строка §1 | `session_level.go:50` | `TestSessionLevelHasOneWriterCallSite` (есть); `TestSUA03_…` и `TestSUA04_…` — пара по `BE` |
| SUAX-04 (SUAD4, «3» впервые внутри сессии пароля) | признак `BE` — из каждого утверждения; у строки ключа не хранится; условие возврата — первый глагол с полом «3» (`kaname#133`, `kaname#754`) | — | держится вниманием до `kaname#754`; гейта нет, предмета (глагола «3») нет |
| SUAX-05 (SUAD2, своё хранилище) | §2.1: **новая таблица**, а не расширение `access_key_challenges` | новая миграция | `TestIntegration_CheckLedgerCoversTheLiveSchema`, `TestIntegration_EveryLiveCheckAnswersInItsLane` (есть; краснеют без строк перечня); перекрёстное непринятие — `TestSUA16_…`, `TestSUAX_CROSS_ChallengesOfThreeKindsAreNotInterchangeable` |
| SUAX-06 (SUAD2, «сменено» ≠ «предъявлено») | §2.1 п. 3–4: смена — переписью значения строки арбитром частичного ключа (прежнего значения в таблице нет — «не выдавалось»), предъявление — отметкой `consumed_at` | адаптер испытаний повышения | `TestSUA17_…`, `TestSUA13_…` (повтор → `CHALLENGE_ALREADY_PRESENTED`) |
| SUAX-07 (SUAD2, привязка к записи сессии) | §2.1 п. 2: `session_id` → `human_sessions(id)`, не дайджест носителя (носитель перевыпускается каждым повышением) | новая таблица | `TestSUA16_…` (испытание S1 не сгорает в S2) |
| SUAX-08 (SUAD2, рост без потолка) | §2.1 п. 6: одно живое на сессию + уборка в реестре | `retention/registry.go:120`, `:232` | TestWithHumanSessionsCarriesTheStepUpChallengeSweeper (реестр), TestAccessKeyStepUpRepo_SweepRemovesOnlyUnservable (integration) — после замысла, решение диспетчера 4 |
| SUAX-09 (SUAD10, путь в положениях) | §2.4 | `loginlanehttp/handler.go:125`, `:149` | `TestEveryLanePathIsDeclaredInTheR2List`, `TestLaneServesExactlyItsDeclaredPaths` (есть); вызов `admitted` — `TestSUAX_POSITION_BeginIsRefusedInVerificationPosition` |
| SUAX-10 (SUAD7, одно написание «выключено») | §2.6: метод `Binding.Disabled()`, шесть читателей зовут только его | `webauthnverify/verify.go:116` | SUA-22/23/24; гейт «один читатель» — **заказ** `tooling-maintainer` (§7) |
| SUAX-11 (SUAD7, отказ до выдачи и до попытки) | §2.6 п. 3 | `access_keys/begin_registration.go`, `humansession/access_key_login.go` (выдача Ф13), новый use-case | `TestSUA23_…`, `TestSUA24_…` (счёт по источнику не вырос) |
| SUAX-12 (SUAD6, `totp.lastUsedAt` — свой столбец) | §2.5 | `pg/login_method_repo.go:511` (`recordAcceptedStepTx`), `:437` (`activateTOTPTx` — не пишет) | `TestSUA40_…` + `TestSUA01_…`, `TestSUA41_…` |
| SUAX-13 (SUAD6, `backupCodes.lastUsedAt` и `issuedAt`) | §2.5 | `:493` (`consumeLookupElementTx`), `:453` (`replaceLookupSetTx`) | `TestSUA02_…`, `TestSUA61_…` |
| SUAX-14 (SUAD6, усечение и отсутствие) | Р6 строка §1: формат транспорта; отсутствие — отсутствие ключа | `loginlanehttp/handler.go:925` | `TestSUA40_…` (ключа нет; момент до секунды); гейт усечения моментов живёт в доме платформы (`PRO-Robotech/kacho@8514270c4:TestOperationTimestampsAreTruncatedEverywhere`, `internal/repohygiene/operationtimestamptruncation_test.go`) и дерева службы не читает — держит проба |
| SUAX-15 (SUAD6, миграция) | §2.1, §2.5: две новые миграции, шапка «Санкция» с отпечатком `35224856…` и записью круга 3; откат не уничтожает материала | `internal/migrations/` | `TestNewMigrationOutranksEveryAppliedOne`; цитату санкции держит `db-architect-reviewer` (гейта цитаты в службе нет — разбор) |
| SUAX-16 (SUAD1, один разборщик, отказ формы до сессии) | Р1 строка §1 | `loginlanehttp/access_key_login.go:160`, `handler.go:1016` | `TestSUA19_…` (пять строк, счёт по адресу не вырос) |
| SUAX-17 (SUAD2, порядок `allowCredentials`) | `CredentialIDsOf` без изменения (`ORDER BY created_at, id`) | `pg/access_key_repo.go:167` | `TestSUAX_ORDER_AllowCredentialsAreOrderedByCreationThenID` (≥ 3 ключа, заведённых не в порядке `id`) |
| SUAX-18 (SUAD8, отказ ключа в том же счёте) | Р8 строка §1 | `step_up.go:267` | `TestSUA72_…`, `TestSUA73_…` |
| SUAX-19 (SUAD9, клетки) | §2.7 | `humansession/observer.go` | клетки утверждаются в `TestSUA03_…`, `TestSUA13_…`, `TestSUA21_…`, `TestSUA22_…`, `TestSUA80_…` |

Сверх таблицы: «вопрос к замыслу» разбора (ось частоты `begin`) решён приёмкой — Р2 вариант «б»,
здесь исполняется §2.1 п. 6; заказ «M1» — закрыт редакцией 3 (запись круга 3).

---

## §1б Решения диспетчера по честному красному — где исполнены

| № | решение | где в замысле |
|---|---|---|
| 1 | пробы службы — в `internal/handler/loginlanehttp`: статус, тело и `Set-Cookie` наблюдаемы только на проводе полосы | имена проб §1а; полоса L7 (§5) |
| 2 | посев С-л F8-S7 — записью в хранилище, как `seed_key_person.py` | вне предмета службы; L7 newman переиспользует тот же посев П-л |
| 3 | SUA-80, гонка: шов называет замысел | §2.3 |
| 4 | проба уборки — после замысла | имя таблицы и предмета реестра — §2.1; проба — SUAX-08 |
| 5 | newman SUA-22 — на своём стенде в пространстве имён внешнего кластера | полоса L7, исполнитель `deploy-engineer`; величина профиля «перечень происхождений пуст» — профилем того пространства |
| 6 | F8-S7-24 и -27: окно открывает «Выйти на всех, кроме этой» | вне предмета службы; служба отвечает `SESSION_NOT_FRESH` (SUA-05) без изменения |

---

## §2 Технические решения

### §2.1 Хранилище испытаний повышения — своя таблица

**Решение.** Новая таблица `kaname.access_key_step_up_challenges`:

| столбец | тип | смысл |
|---|---|---|
| `challenge` | `bytea NOT NULL`, PK, `CHECK (octet_length(challenge) = 32)` | значение испытания; `SET STATISTICS 0` |
| `session_id` | `text NOT NULL`, `REFERENCES kaname.human_sessions(id) ON DELETE CASCADE` | запись сессии, которой выдано |
| `issued_at` | `timestamptz NOT NULL` | момент выдачи |
| `expires_at` | `timestamptz NOT NULL`, `CHECK (expires_at > issued_at)` | предел; умолчания нет — срок приносит вызывающий |
| `consumed_at` | `timestamptz NULL`, `CHECK (consumed_at IS NULL OR consumed_at >= issued_at)` | отметка предъявления |

Индексы: частичный уникальный `(session_id) WHERE consumed_at IS NULL` — одно живое на сессию;
`(expires_at)` — для уборки. Столбца `purpose` нет: таблица и есть назначение.

1. **Почему не расширение `access_key_challenges`** (`20260917221000_access_keys_are_our_record.sql:121`,
   CHECK `access_key_challenges_purpose_check` ∈ {`registration`, `assertion`}, `:131`). Расширение
   потребовало бы нового значения `purpose` **и** столбца сессии, осмысленного у одного значения
   из трёх: пара «`purpose = 'step-up'` ⟺ `session_id IS NOT NULL`» — второй CHECK о двух
   столбцах, частичный ключ «одно живое» — под условием по `purpose`, а раздельность испытаний
   повышения, регистрации и проверки утверждения держалась бы совпадением значения фильтра в
   каждом читателе (`Challenge(…, purpose)`, `:186`; снятие при сбросе ключей,
   `retireRegistrationChallengesTx`, `:295`), а не таблицей. Тот же довод уже записан у Ф13
   (`20261005032942_login_challenge_is_bound_to_the_form_context.sql`, «Почему своя таблица»).
   Ключ привязки у повышения — **запись сессии**, у Ф7 — человек, у Ф13 — контекст формы: три
   ключа — три таблицы; испытание одного вида в чужой церемонии не находится by construction.
2. **Привязка — `human_sessions.id`, не дайджест носителя.** Носитель перевыпускается каждым
   предъявлением (Ф11 Р5); привязка к дайджесту делала бы испытание непредъявимым после
   соседней ветви. Человек выводится через сессию — столбца `user_id` нет, второй источник
   принадлежности не заводится. Снятие записи сессии уборкой каскадом снимает её испытания.
3. **Выдача и смена — один оператор:** `INSERT … ON CONFLICT (session_id) WHERE consumed_at IS NULL
   DO UPDATE SET challenge = EXCLUDED.challenge, issued_at = …, expires_at = …` — тот же приём
   арбитра, что у Ф13 (`pg/access_key_login_repo.go:60`, kaname#769), не «снять, затем вставить».
   Прежнее значение после смены в таблице не лежит ни в каком виде — его предъявление читается
   «не выдавалось» (SUA-17), а не «уже предъявлено».
4. **Сгорание — один условный оператор** по паре (сессия, испытание): `UPDATE … SET consumed_at = $now
   WHERE session_id = $s AND challenge = $c AND consumed_at IS NULL AND expires_at > $now`,
   исход — число строк. Ноль строк — **одно** классифицирующее чтение той же пары: строки нет →
   `CHALLENGE_NOT_ISSUED` (в том числе испытание другой сессии и сменённое); `consumed_at` есть →
   `CHALLENGE_ALREADY_PRESENTED`; предел вышел → `CHALLENGE_EXPIRED`. Чтение лишь называет
   причину: решение о годности принял оператор, и проигравший гонку сгорания читает
   «уже предъявлено».
5. **Часы — часы службы (`deps.Now`), моментом-параметром**, как у испытаний Ф7
   (`access_key_repo.go:443`), а не `now()` базы, как у Ф13. Довод: SUA §3 строит ось времени
   управляемыми часами пробы (SUA-18 — без ожидания), а срок — величина Ф7 (`ChallengeTTL`,
   5 мин), с которой расхождение часов реплик соизмеримо не бывает.
6. **Рост ограничен:** у сессии живое испытание одно (п. 3), погашенные и истёкшие убирает реестр
   хранения: предмет `SubjectAccessKeyStepUpChallenges = "access_key_step_up_challenges"` в
   `retention/registry.go` (рядом с `:120`, `:123`), уборщик — поле `StepUpChallenges` в
   `HumanSessionReapers` (`:146`), порог — `ChallengeTTL`, **не ноль**: три состояния испытания
   повышения наружу различимы (SUA Р3), и различимость держит только хранение строки — тот же
   довод, что у `SubjectAccessKeyChallenges` (`:267–279`). `nil` — ветвь ключа не провязана, и
   предмета у реестра нет (как `LoginChallenges`, `:310`).
7. **Перечень проверок** `pg/check_value_lanes.go` получает строку таблицы: все три CHECK —
   полоса **дефекта службы** (испытание чеканит служба, сессию — `resolveLiveSession`, моменты —
   часы службы).
8. **Миграция** — новая, сверх последней применённой (`20261012120000_*` на `6a82d3198`); откат
   снимает таблицу без потерь: строка одноразова и ничьим материалом не является.

Порт: `humansession.StepUpChallengeStore` — `IssueStepUpChallenge`, `ConsumeStepUpChallenge`,
`StepUpChallengeState`, плюс чтения `KeyByCredentialID`, `CredentialIDsOf` — **те же** операторы
хранилища ключей (как `AccessKeyLoginRepo`, `pg/access_key_login_repo.go:96–104`). Адаптер —
`internal/repo/kaname/pg/access_key_step_up_repo.go`; доменный тип испытания с самопроверкой
(32 байта, непустая сессия) — `internal/domain`.

### §2.2 Порядок ветви `webauthn` и перепись хвоста суждения

**Порядок** (SUA Р3; пп. 1–3 — общие с кодом):

1. обработчик: тело → признак формы `step-up` → положение `PathStepUp` → `ParseStepUpMethod` →
   разбор `credential` общим разборщиком → `JudgeStepUpForm` (поля не того способа);
2. `resolveLiveSession` → `uc.gate.check` по обеим осям (`step_up.go:93`);
3. `ParseClientData`; не разбирается — суждённый отказ (клетка «подпись»), сгорать нечему;
4. **сгорание** по паре (сессия, испытание из данных клиента) своей фиксацией — до приговора и
   независимо от него (§2.1 п. 4); не сгорело — отказ испытания (не попытка, без журнала);
5. строка ключа `KeyByCredentialID`; нет — сверка над ключом-приманкой (`webauthnverify.NewDecoyKey`,
   как `finish_assertion.go:73`, `access_key_login.go:327`): работа отказа равна работе сверки;
6. `VerifyAssertion` с `Binding` установки (`verify.go:409`) — третий вызывающий;
7. приговор (таблица ниже); затем `JudgeCounter(key.SignCount, res.SignCount)`;
8. транзакция предъявления (§2.3): `PersonWriter` → `AdvanceSignCount` → `presentInSession` →
   `resetFailuresOnCompletedLogin` → журнал `accepted` → фиксация.

**Перепись хвоста** — ветви отказа у двух существующих вызывающих против ветви повышения:

| ветвь суждения | Ф7 `finish_assertion.go` | Ф13 `access_key_login.go` | повышение |
|---|---|---|---|
| испытание не годно | `:134` (три причины) | `:346` (одна) | три причины — 400 `code` 9, не попытка (Р3) |
| удостоверение неизвестно | `:136` | `:348`, `:367`, `:396` | 401, попытка |
| ключ другого человека | `:138` | — (человека называет ключ) | 401, попытка (`key.UserID ≠` человек сессии) |
| рукоятка | `:140` (при присутствии) | `:351` (безусловно) | 401, попытка — **безусловно**, `handleMatches` (`:432`): форма та же, что у входа (Р1, Ф13-07), поле обязательно |
| отказ проверяющего: происхождение · хэш имени · присутствие · подпись/алгоритм/данные | `:142` | `:356` | 401, попытка, клетка причины |
| счётчик не вырос | `:147` + сигнал | `:359` (без сигнала) | 401, попытка, **сигнал** (Р10) |
| сдвиг проигран | `:167` без сигнала | `:382` | 401, попытка, **без** сигнала |
| личность не `ACTIVE` | — | `:371` | — (сессия уже разрешена `resolveLiveSession`) |

Выпавших ветвей нет. Общая функция хвоста **не** заводится этим изменением: два прежних вызывающих
не правятся, а полноту третьего держат пробы по ветви и заказанный статический гейт (§7).

### §2.3 Шов счётчика: «не вырос» против «сдвиг проигран» (SUA-80; решение диспетчера 3)

**Где решается.** Чтение строки ключа (шаг 5) идёт **до** транзакции предъявления, сдвиг — **в**
ней. Это два разных места, и у каждого свой исход:

- **«не вырос»** решает **чтение**: `JudgeCounter` над записанным значением, прочитанным на шаге 5,
  дал `CounterRegressed` → сигнал `SignCountRegressionObserved` (+1), отказ; транзакция предъявления
  не открывается;
- **«сдвиг проигран»** решает **оператор**: чтение показало «растёт», а условный `UPDATE
  user_access_keys SET sign_count = $reported, last_used_at = $now WHERE id = $id AND sign_count =
  $expected AND $reported > sign_count` внутри транзакции дал ноль строк — другое утверждение того
  же ключа зафиксировало сдвиг между чтением и оператором (либо строку ключа сняли — тот же ноль,
  та же клетка) → откат всей транзакции (уровня нет, носитель не перевыпущен), отказ **без** сигнала.

**Транзакция.** Сдвиг — оператор транзакции `PersonWriter` (строка личности — первым оператором,
`step_up.go:147`), до `presentInSession`. Порядок замков «личность → строка ключа → запись сессии»
тот же, что у снятия ключа (личность первой, затем ключи) — встречного нет. Сдвиг своей
транзакцией до предъявления (как у Ф13, `access_key_login_repo.go:109`) здесь не годится: сдвинутый
счётчик пережил бы откат предъявления. `humansession.Writer` получает метод `AdvanceSignCount`;
его адаптер (`humanSessionWriter`) и `accessKeyWriter` (`access_key_repo.go:512`) зовут **один**
оператор, вынесенный функцией над `pgx.Tx`. Предикат единственности (перемерь):
`git grep -c 'UPDATE user_access_keys SET' -- internal/repo ':!*_test.go'` → `access_key_repo.go:2`
(@`6a82d3198`, обе строки в `AdvanceSignCount`); после изменения — то же число в одной функции.

**Шов пробы.** Граница порта между шагом 5 и шагом 8. Проба «сдвиг проигран» оборачивает порт
`StepUpChallengeStore` декоратором над **настоящим** адаптером: `KeyByCredentialID` отдаёт
прочитанную строку, а перед возвратом фиксирует настоящим оператором сдвиг того же ключа на
присланное значение (так, как это сделало бы утверждение соседней сессии). Ветвь повышения видит
«растёт» по прочитанному и проигрывает оператору. Декоратор подаётся сборке стенда пробы тем же
путём, что наблюдатель (`suaOptions` в `internal/handler/loginlanehttp/step_up_any_method_harness_integration_test.go`);
прод-кода шов не требует — это граница порта, а не ручка. Утверждения пары:

| проба | вход | исход | сигнал клонирования |
|---|---|---|---|
| `TestSUA80_SignCountThatDidNotGrowIsRefusedAndSignalled` | П-кл после SUA-03, `count="same"` | 401 `code` 16 `authentication failed`; уровень «1»; `Set-Cookie` нет; `lastUsedAt` прежний; журнал `refused`; след попытки +1 | +1 |
| TestSUA80_LostAdvanceIsRefusedWithoutTheCloneSignal (заказ) | тот же человек, `count="next"`, декоратор фиксирует сдвиг между чтением и оператором | тот же 401 и те же следствия | 0 |
| близнец (SUA-03) | `count="next"`, декоратор не вмешивается | 200, уровень «2» | 0 |

Общая проба гонки (без декоратора): две сессии одного человека, у каждой своё испытание, два
утверждения одного ключа с одним присланным значением, запуск под барьером —
`TestSUA80_LostCounterRaceIsRefused`: ровно одно 200 и **не больше одного**
сигнала (0 — оба прочитали до фиксации, 1 — второй прочитал после неё).

Сигнал — счётчик `kaname_access_key_sign_count_regressions_total`
(`observability/metrics/access_key_recorder.go:21`), тот же, что у Ф7: порт наблюдателя полосы
сессии получает `SignCountRegressionObserved()`, провязанный к тому же регистратору.

### §2.4 Новый путь полосы

1. `PathStepUpAccessKeyBegin` — в `Paths()` (`handler.go:125`; перепись 23 → 24), в регистрациях
   `New` (рядом с `:317`) и в `pathPositions` как **`PathRefusedInVerification`** (рядом с `:168`),
   в один голос с `PathStepUp`. Обработчик зовёт `h.admitted(w, r, PathStepUpAccessKeyBegin, …)`
   после признака формы — как `stepUp` (`:1025`). Необъявленный путь `admitted` отвергает (503,
   `:565`) — пройти мимо объявления нечем.
2. Перепись в `path_positions_test.go:162` — 23 → 24 той же правкой (число записано в пробе).
3. Константа ставится сразу после `PathStepUp` в том же блоке: самое длинное имя блока —
   `PathSecondFactorBackupCodes`, выравнивание `gofmt` не сдвигается, и строка, которую подменяет
   инъекция `TestR2ListInjection` (`path_positions_test.go:174`, литерал строки `PathStepUp`),
   остаётся дословной. Сдвиг выравнивания сделал бы подмену холостой — проба инъекции это
   покажет, но цена круга — лишний прогон.
4. Вид признака формы `step-up-access-key-begin` — одним объявлением в `formKinds`
   (`internal/domain/human_session.go:432`); признак одного вида на глаголе другого не предъявим.

### §2.5 «Последнее использование» способа второго фактора — столбец `user_login_methods.last_used_at`

**Измерено:** столбцы таблицы — `user_id, kind, verifier, created_at` (`20260915111233_*.sql:127`),
плюс `state`, `last_accepted_step` (`20260917160000_*.sql`); столбца момента использования нет.
`last_accepted_step` для `totp.lastUsedAt` не годится: подтверждение пишет шаг
(`activateTOTPTx`, `login_method_repo.go:442`), а SUA-40 требует отсутствия момента после
подтверждения.

**Решение.** Новая миграция: `ALTER TABLE kaname.user_login_methods ADD COLUMN last_used_at
timestamptz` (NULL — «не использовали») и `CHECK (last_used_at IS NULL OR kind IN ('totp',
'lookup_secret'))`: момент пароля невыразим (SUA §6 — пароль вне предмета). Строка перечня
`check_value_lanes.go` — полоса дефекта службы. Проверки «момент не раньше `created_at`» нет
намеренно: моменты ставят часы разных реплик, и отказ схемы на верном предъявлении был бы хуже
отсутствия проверки. Откат снимает столбец: моменты — не материал входа, после повторного
наката читаются «не использовали».

| писатель | что пишет | основание |
|---|---|---|
| `recordAcceptedStepTx` (`login_method_repo.go:511`) | `last_used_at = $at` **тем же** условным `UPDATE`, что принятый шаг — только на принятом предъявлении | вход с `secondFactor`, повышение, перевыпуск набора — все через `presenter.settle` (`sf_present.go:168`) |
| `consumeLookupElementTx` (`:493`) | `last_used_at = $at` тем же `UPDATE`, что снятие элемента | SUA-02, SUA-61 |
| `replaceLookupSetTx` (`:453`) | `last_used_at = NULL` при вставке и при замене; `created_at` — момент выпуска (уже так) | `backupCodes.issuedAt` = `created_at` строки набора; перевыпуск гасит момент траты (SUA-61) |
| `upsertPendingTOTPTx` (`:414`) | `last_used_at = NULL` при замене не-`active` строки | новое заведение не наследует момент прежнего |
| `activateTOTPTx` (`:437`) | не пишет | SUA-40 |

Момент приносит вызывающий (`now` use-case) аргументом; порты `Writer.RecordAcceptedStep` и
`Writer.ConsumeLookupElement` (`humansession/iface.go:363`, `:367`) получают параметр момента.
Читатель — `scanLoginMethod` и запросы строки способа (`login_method_repo.go:148`, `:476`, `:597`);
`domain.LoginMethod` несёт момент с отдельным признаком присутствия. Перешифровка материала
(`secondfactorwrap`, `login_method_repo.go:646`) столбец не трогает.

Страница F8-S7 читает эти три момента из `GET /iam/v1/auth/second-factor`; момент ключа — уже в
`AccessKey.lastUsedAt` (писатель — `AdvanceSignCount`, §2.3).

### §2.6 «Ключи выключены» — один предикат, шесть читателей

`webauthnverify.Binding` получает метод `Disabled()`: `Origins != nil && len(Origins) == 0` —
единственное написание решения. `nil` по-прежнему значит «не объявлено» и отвергается при сборке
(`access_keys/deps.go:84`, `humansession/access_key_login.go:102`). `AccessKeysConfig.Nobody()`
(`config/access_keys.go:154`) остаётся предикатом **ручки** конфигурации и до решений в коде
полос не доходит.

Читатели:

1. `BeginRegistration` Ф7 — до чеканки и `InsertChallenge`: `FAILED_PRECONDITION`, reason
   `ACCESS_KEYS_DISABLED`;
2. выдача Ф13 `POST /iam/v1/auth/access-key/begin` — до счёта по источнику и до
   `IssueChallenge` (SUA-24: попытка не записана);
3. новая выдача повышения — до чтения удостоверений;
4. `accessKeys.available` в чтении состояния — `!Disabled()`;
5. `stepUpMethods` — `webauthn` только при `!Disabled()` и ≥ 1 строке ключа;
6. заведённые для `assurance` (`enrolledMethods`, `second_factor.go:393`) — `webauthn` при тех же
   двух условиях; строку ключа читает тот же оператор `accessKeyEnrolled`
   (`pg/access_key_repo.go:591`), что ось «заведено» обнуления счёта.

Текст `access keys are turned off on this installation` и reason `ACCESS_KEYS_DISABLED` объявлены
**один** раз — сентинелом в `webauthnverify` рядом с `Disabled()` (оба пакета полос его
импортируют); транспорт каждой полосы отображает сентинел своей формой (gRPC — `status` с
`ErrorInfo`; полоса формы — `writeError`, 400 `code` 9). Предикат единственности текста:
`git grep -c 'access keys are turned off on this installation' -- internal ':!*_test.go'` → 1.

Ось обнуления счёта (`enrolledForCompletion`, `completed_login.go:137`) этим решением **не**
меняется: она уже читает строку ключа без условия о выключенности, и правка её — предмет Ф3/Ф12,
а не SUA.

`missingForLevel2` (`assuranceViewOf`, `second_factor.go:355`) судит недостающий способ правилом
над `presentationsOf(предъявленное) ∪ {m}`, где `m` берётся **в худшем исходе флагов** — как
`GuaranteedLevels` (`assurance/level.go:279`): ключ в худшем исходе даёт «2», и `webauthn` у
сессии «1» человека с ключом называется (SUA-33). Для этого наружу выводится существующая
`worstPresentation` (`level.go:327`) — без новой таблицы «способ → уровень».

### §2.7 Наблюдаемость и журнал

- журнал: `emitStepUpJournal` / `emitStepUpRefusal` (`step_up.go`) с `method: webauthn` — тот же вид
  `iam.session.step_up` (`second_factor.go:250`);
- клетки предъявления: `PresentationCells()` (`second_factor.go:287`) дописывается парами
  `{webauthn, matched}`, `{webauthn, mismatched}`; `SecondFactorMethods()` (`:273`) — `webauthn`;
- отказы состояния: `SecondFactorRefusals()` (`:316`) — `access-key-not-registered`,
  `access-keys-disabled`;
- причина суждённого отказа ключа — словарём клеток полосы Ф13 (`AccessKeyLoginOutcome`,
  `observer.go:76–91`: `origin`, `rp-id-hash`, `presence`, `signature`, `counter`,
  `credential-unknown`, `user-handle`) с меткой полосы повышения; второго словаря причин нет;
- сигнал клонирования — §2.3;
- ни кода, ни материала утверждения, ни носителя в записях нет.

---

## §3 Отказы и их тексты (д)

Тексты — контракт (`api-conventions.md` `api-error-tone`); каждый производит одна константа.

| где | исход | ответ | попытка | журнал |
|---|---|---|---|---|
| форма церемонии | нет `method` | 400 `code` 3 `Illegal argument method: required` | нет | нет |
| форма церемонии | способ вне словаря | 400 `code` 3 `Illegal argument method: must be one of password\|totp\|lookup_secret\|webauthn` | нет | нет |
| форма церемонии | `webauthn` без `credential` | 400 `code` 3 `Illegal argument credential: required` | нет | нет |
| форма церемонии | поле другого способа | 400 `code` 3 `Illegal argument <поле>: not accepted with method <способ>` | нет | нет |
| форма `credential` | поля и написания | тексты Ф13-07 тем же разборщиком (`credential.response.userHandle: required`, `… must be base64url without padding`, …) | нет | нет |
| обе формы | признак формы | прежний `FORM_TOKEN_REJECTED` | нет | нет |
| выдача | положение подтверждения | прежний отказ положения (`admitted`) | нет | нет |
| обе | нет живой сессии | 401 `code` 16 `authentication failed` (`resolveLiveSession`) | нет | нет |
| церемония | частота | 429 `code` 8 `TOO_MANY_ATTEMPTS` `too many attempts; try again later`, `Retry-After` | нет | нет |
| выдача (+ Ф7 `BeginRegistration`, Ф13 `begin`) | ключи выключены | 400 `code` 9 (gRPC — `FAILED_PRECONDITION`) `ACCESS_KEYS_DISABLED` `access keys are turned off on this installation` | нет | нет |
| выдача | ключей ноль | 400 `code` 9 `ACCESS_KEY_NOT_REGISTERED` `no access key is registered: register an access key first` | нет | нет |
| церемония | испытания этой сессии нет | 400 `code` 9 `CHALLENGE_NOT_ISSUED` `step-up challenge was not issued: begin step-up again` | нет | нет |
| церемония | уже предъявлено | 400 `code` 9 `CHALLENGE_ALREADY_PRESENTED` `step-up challenge was already presented: begin step-up again` | нет | нет |
| церемония | истекло | 400 `code` 9 `CHALLENGE_EXPIRED` `step-up challenge expired: begin step-up again` | нет | нет |
| церемония | суждённые (таблица §2.2) | 401 `code` 16 `authentication failed` — тот же сентинел `ErrAuthenticationFailed` | да, обе оси | `refused` |
| обе | хранилище не ответило | 503 `request not performed; try again later` | нет | нет |

Тексты испытаний повышения — свои константы в доме отказов полосы (`humansession`), не
переиспользование текстов регистрации Ф7 (`access_keys/refusals.go:34–36`): другое слово
церемонии; reason-токены — те же три значения словаря, что у Ф7 (`:52–54`).

---

## §4 Рёбра и направления (ж)

| ребро | вид | направление | что меняется |
|---|---|---|---|
| повышение → проверяющий Ф7 | внутрисервисное | use-case → `VerifyAssertion` | третий вызывающий; объявление одно (`TestAssertionVerificationIsDeclaredOnce`) |
| повышение → хранилище ключей | внутрисервисное, одна транзакция | `PersonWriter` → `AdvanceSignCount` | §2.3 |
| край `kacho` → `kaname` (ретрансляция формы) | межсервисное, существующее | потребитель → владелец | **одна запись** в объявлении края: `{Verb: "step-up-access-key-begin", Path: LoginLanePathStepUpAccessKeyBegin, Target: RelayTargetForm}` в `gateway/internal/middleware/login_lane_paths.go` (рядом с `:343`, запись `step-up`); `relayWhenUnanswered` — нет (глагол читает носитель, как `step-up`), `openBeforeAddressConfirmation` — нет (служба — `PathRefusedInVerification`) |

Проба края `PRO-Robotech/kacho@8514270c4:TestLoginLanePaths_F6b_11_EveryRecordCountedAndNineOpenBeforeAddressConfirmation`
(`login_lane_paths_test.go:228`) меняет числа **26 / 23 / 3 / 9 → 27 / 24 / 3 / 9**: записей 27,
глаголов формы 24, координат выдачи 3, открытых до подтверждения адреса — по-прежнему 9; в
`loginLaneWant` — строка `"step-up-access-key-begin"`. Семейство входа ключом
(`accessKeyFamily = "/iam/v1/auth/access-key/"`, `login_lane_paths_test.go:79`) путь повышения не
задевает: приставка другая, `PRO-Robotech/kacho@8514270c4:TestLoginLanePaths_F13_28_TwoAccessKeyVerbsAndNoThird` остаётся
зелёной без правки. Измерено @`kacho@8514270c4`:
`git show origin/main:gateway/internal/middleware/login_lane_paths.go | grep -c 'Target: RelayTarget'` → 26.

Носитель записи края — `PRO-Robotech/kacho#3230` (F8-S7, «ретрансляция нового пути краем»).
**Нового межсервисного ребра, внешнего вызова, асинхронного пути изменение не заводит.**

---

## §5 Маршрут работ — порядок исполнения

Состояния у маршрута нет — оно у трекера. Слои — в порядке зависимостей; в одной строке «∥» —
параллельно.

| # | полоса | дом | зависит от | что делает |
|---|---|---|---|---|
| **L1** | схема | kaname | — | две миграции (§2.1, §2.5) с шапкой «Санкция»; строки `check_value_lanes.go`; предмет реестра и уборщик (§2.1 п. 6) |
| **L2** | хранилище | kaname | L1 | адаптер испытаний повышения; общий оператор сдвига счётчика и `humansession.Writer.AdvanceSignCount`; писатели и читатели `last_used_at` (§2.5) |
| **L3** | домен и use-case | kaname | L2 | `Binding.Disabled()` и сентинел (§2.6); выдача повышения; ветвь `webauthn` (§2.2, §2.3); акт в `presentInSession` (Р4); чтение состояния (Р6); отказ `ACCESS_KEYS_DISABLED` у Ф7 и Ф13 выдач |
| **L4** ∥ **L5** | полоса формы ∥ наблюдаемость | kaname | L3 | путь, вид признака, положение, общий разборщик `credential`, `stepUpForm`, тело состояния (§2.4, Р1, Р6) ∥ клетки и сигнал (§2.7) |
| **L6** | провязка | kaname | L4, L5 | `cmd/kaname/loginlane.go` (`NewStepUpUseCase` — `:663`, уборщик — рядом с `:236`): зависимости ветви ключа, уборщик реестра |
| **L7** | пробы | kaname | L6 | integration в `internal/handler/loginlanehttp` — все ID SUA §8 п.1 плюс §1а; newman `kaname-login-lane.py` / `kaname-access-keys.py` (минимум §8 п.2; SUA-80 — `_finish_assertion(count="same")`, `kaname-access-keys.py:1238`, рекомендация круга 3); SUA-22 — на своём стенде в пространстве имён внешнего кластера (`deploy-engineer`), снятие тем же шагом |
| **L8** ∥ **L9** | документация ∥ край | kaname ∥ `kacho` | L4 ∥ — | `docs/content/api/auth-lane.mdx`, страница ключей, ведомость `ResponseObjectKeys` и `client_page_auth_lane_test.go` (§8 пп. 3–4) ∥ запись края и F6b_11 (§4), `kacho#3230` |

Падающая проба — до кода каждой полосы (ban #12). Сквозной newman через край (L7) зависит от L9 на
стенде.

---

## §6 Что замысел вносит (триггеры `change-graph.md` §4)

- **новое хранилище** — таблица `access_key_step_up_challenges` и столбец
  `user_login_methods.last_used_at`, обе новыми миграциями;
- **новые записи закрытых перечней** — путь полосы, вид признака формы, строка положения, два
  reason-токена (`ACCESS_KEYS_DISABLED`, `ACCESS_KEY_NOT_REGISTERED`), клетки §2.7, предмет реестра
  уборки, запись края;
- **новое значение «отсутствия»** — момент с признаком присутствия у `LoginMethod` и в
  `StatusOutput` (Р6 «отсутствие — отсутствие ключа»);
- **новая поверхность** — один путь (Р11);
- **новое межсервисное ребро, внешний вызов, асинхронный путь, зависимость модуля** — нет.

---

## §7 Заказы вне полос и допущения

- `tooling-maintainer` — гейт «предикат “ключи выключены” читается в одном месте»
  (`git grep -n 'len(.*Origins)' -- internal ':!*_test.go'` вне `webauthnverify` → 0) и гейт полноты
  хвоста суждения у вызывающих `VerifyAssertion` (таблица §2.2). До них держат пробы SUA-22/23/24 и
  пробы ветвей.
- **Допущение (Р-1 Ф13 не исполнено):** «годный к предъявлению ключ» = строка ключа; признак
  обнаружимости у строки не хранится (`git grep -niE 'discoverab' -- internal/migrations internal/repo
  | wc -l` → 0 @`6a82d3198`). `allowCredentials`, `stepUpMethods` и `level2Reachable` считают строки.
  Снятие допущения — исполнение Ф7 Р12, не этого изменения.
- **Допущение (порядок отказов выдачи):** `ACCESS_KEYS_DISABLED` отвечает раньше
  `ACCESS_KEY_NOT_REGISTERED` — Р7 называет отказ трёх выдач безусловно, до выдачи испытания.

---

## §8 Границы текста этого документа

Документ лежит в публичном репозитории и выдерживает публикацию (`security-disclosure.md`): он
называет решения и следствия для контракта. Единый отказ описан тем, что он **един**; порядок
сверок внутри проверяющего контрактом не является; величины частоты, срок испытания и перечень
происхождений — величины профиля. Координаты символов — места исполнения решений; рецепта обхода
из них не собрать.
