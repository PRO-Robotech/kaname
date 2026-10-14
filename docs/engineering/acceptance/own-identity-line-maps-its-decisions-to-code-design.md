# Замысел линии `kn-296`: решения приёмок набора → механизм в коде → проба

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующего одобрения нет — оно выводится из внешнего события
> и записи пересверки `class-exposure-analyst` на ОТПЕЧАТОК набора замыслов линии
> (`change-graph.md` §2, §4), а не из слова в шапке.
> **Владелец истины:** отображение пунктов разбора классов в механизм и держатель
> (`change-graph.md` §1). Наблюдаемое поведение — у приёмок; здесь оно **не переоткрывается** и
> нового механизма не заводится (`flow-acceleration.md` fa-b3-last-design-pass-maps-only).
> **Предмет:** набор приёмок линии эпика `kaname#296` — 27 документов, отпечаток набора
> `e47cb0e484539c70dd88d4207f5278090c7b9790f35aa3d06641931584b2a175` (предикат —
> `acceptance_set_predicate` манифеста пакета `kn-296`, база `8a84dcff`, голова `68d24ae6`).
> Этот документ отображает **26** приёмок набора — все, кроме приёмки Ф13: её пункты `F13-*`
> отображает её собственный замысел `passwordless-login-with-access-key-design.md`.
> **Перечень пунктов:** первичный разбор классов набора `e47cb0e4…` — 98 пунктов; здесь — 83
> (98 минус 15 пунктов Ф13).
> **Дом:** `PRO-Robotech/kaname`, `docs/engineering/acceptance/`.
> **Issue:** [PRO-Robotech/kaname#785](https://github.com/PRO-Robotech/kaname/issues/785) · эпик `kaname#296`
> **Ревизия измерений:** голова ветки эпика `kaname@68d24ae66fe4530dcccebf36f82ad70f1c976eae`
> (`origin/296`). Координата `путь:строка` — на этой ревизии; сдвинется голова — перемерь.
> **История редакций (только дописывается):** редакция 1 (эта) — первое отображение.

---

## §0 Как читать строку

Строка — **один пункт разбора** (идентификатор — как в записи разбора). Столбцы:

- **решение** — решение приёмки, из которого пункт выведен (номер `Р*` либо нормы приёмки);
- **механизм** — место в коде головы, которое исполняет условие пункта (`путь:строка`);
- **проба** — функция, держащая условие (`go test -run '^<имя>$'`), либо модуль сквозных
  кейсов; где держателя нет — сказано словом и строка вынесена в §28.

Классы — разделы скилла `code-authoring` по имени: **U** «Умолчание, которое становится
утверждением», **R** «Решение и его следствие разнесены», **CH** «Чужой ответ: классификация и
бюджет», **P** «Порядок операций внутри кода», **K** «Контракт, который нельзя выразить»,
**UN** «Унификация и стоимость», **I** «Инвариант и оснастка — это тоже прод-код».

Опора каждой приёмки — отпечаток её содержимого на голове (первые 8 знаков `sha256`; полный —
`git show 68d24ae6:<путь> | sha256sum`).

---

## §1 `access-keys-are-ours.md` (Ф7) — `5ea26ad0`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| AK-1 | R | Р1, Р8 — потолок числа ключей | списание слота — триггер той же транзакции, что вставка строки ключа: `internal/migrations/20260917221000_access_keys_are_our_record.sql:118`; отказ потолка доезжает с названным шагом — `internal/apps/kaname/api/access_keys/finish_registration.go:263` | `TestAccessKey_F7_37_F7_38_CeilingIsJudgedByTheStore`, `TestAccessKey_F7_38_SubordinateResourceAnchoredByTheKeysTable` |
| AK-2 | U | Р2, Р9 — три ручки посадки без умолчания; литералы церемонии — константы контракта | `internal/apps/kaname/config/access_keys.go:85`…`:87` (таблица ключей), `:125`, `:205`, `:244` (отказ старта с именем ключа) | `TestAccessKeys_F7_13_EachRefusalNamesItsOwnKnob`, `TestAccessKeys_F7_13_KnobTableCarriesAllThree`, `TestAccessKey_Declared_ContractLiteralsEqualTheDecisions` |
| AK-3 | U | Р6 — ноль счётчика не судится, положительный обязан расти | `internal/webauthnverify/verify.go:542` (`JudgeCounter`); сдвиг с условием на прежнее значение — `internal/repo/kaname/pg/access_key_repo.go:512` | `TestAccessKey_F7_17_F7_18_F7_19_CounterDiscipline` |
| AK-4 | K | Р10, Р11 — адрес `ak-…`; полы каталога шести глаголов | `internal/apps/kaname/api/access_keys/finish_registration.go:149` (общий генератор), CHECK формы — `20260917221000_*.sql:87`; разбор формы на снятии — `revoke.go:112` | `TestAccessKey_F7_47_RevokeJudgesTheIdForm`, `TestAccessKey_Declared_CatalogCopyCarriesTheDecidedLanes`, `TestAccessKey_Declared_CatalogDescriptorsCarryTheDecidedLanes` |
| AK-5 | U | Р12 — признак обнаружимости, три состояния; страж считает годные | **не исполнено** — расхождение Р-1 (§28): признак не хранится, страж `revoke.go:227` считает строки | **держателя нет** (Ф7-56, Ф7-57 — проб ноль) |
| AK-6 | P | Р5 — регистрация и снятие в окне свежести | `begin_registration.go:86` (регистрация), `revoke.go:117` (снятие); суждение — `begin_registration.go:127` | `TestAccessKey_F7_04_RegistrationRequiresFreshness`, `TestAccessKey_F7_36_RevokeRequiresFreshness`, `TestAccessKey_F7_04_F7_36_FreshnessRefusalIsThePermissionDeniedPair` |

## §2 `access-beyond-login-needs-a-verified-address.md` — `2abf9de5`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| ABV-1 | U | Р1, Р3, Р4 — положение из текущей отметки на каждом запросе; один отказ | рубеж на обоих слушателях читает отметку на каждом вызове — `internal/authzguard/address_gate.go:204`; текст отказа — одно объявление `internal/admission/admission.go:63`, производитель — `:163` | `TestEV61_AdmissionBeforeArgumentParsing`, `TestEV14_RefusalNamesTheStepAndTheStepLiftsIt` |
| ABV-2 | K | Р2 — что доступно в положении подтверждения, перечень закрыт | закрытая таблица внутреннего слушателя — `address_gate.go:93`; метод вне таблицы получает отказ положения — `address_gate.go:204`…`:212` (fail-closed) | `TestEV62_EdgeCircleOnTheInternalListener`, `TestEV64_SelfRevokeIsAvailableAndOthersIsNot` |
| ABV-3 | P | Р5, Р5а, Р5б — токен судит текущую отметку владельца на предъявлении | `internal/tokenrevocation/rule.go:195`; `internal/revocationpolicy/revocationpolicy.go:231` | `TestEV65_TokenEndpointRefusesTheKeyOfAPersonWithoutTheMark`, `TestEV68_OurTokenAtTheEdgeCheck`, `TestEV79_RefreshReplayBeforeTheMarkAndUnansweredQuestion` |
| ABV-4 | R | Р7, Р10, Р15 — код однократен, последний жив, предел попыток; одна транзакция | один условный оператор предъявления — `internal/repo/kaname/pg/verification_code_repo.go:143`, вызов — `:158` | `TestEV35_TheCodeIsSingleUse`, `TestEV34_OnlyTheLastCodeIsAlive`, `TestEV36c_ParallelWrongPresentationsCountAtMostTheLimit`, `TestEV43_ConcurrentPresentationOfOneCode`, `TestEV40_PresentationByTheVerified` |
| ABV-5 | U | Р9 — предел писем числами, свои ручки | таблица ключей — `internal/apps/kaname/config/login_lane.go:112`; потолок срока — `:357` | `TestEV90_FiveKnobsWithoutDefaults`, `TestEV90_KnobsBeyondTheirBoundsRefuseTheStart` |
| ABV-6 | K | Р11, Р12, Р13 — приглашение активируется подтверждением; посев — на подтверждённый адрес; посадка не пишет в записи людей | `internal/apps/kaname/api/user/mirror_tx.go:528`; перепись писателей строк людей — `internal/check/address_admission_gates.go:373` | `TestEV72_VerificationActivatesTheInvite`, `TestEV80_UnverifiedSeedAddressGetsNoGrant`, `TestEV86_LandingWritesNothingIntoPeopleRows` |

## §3 `account-id-may-be-supplied-at-create.md` — `8c45cb50`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| AID-1 | P | Р1, Р2, Р3 — форма синхронно до операции и до вопроса о праве; право — только при непустом | `internal/apps/kaname/api/account/create.go:244`…`:259` | `TestAccountID05_UseCaseRefusesAMalformedIDBeforeTheRightsQuestion`, `TestAccountID02_WithoutIDTheModelIsNotAsked`, `TestAccountID08_UseCaseRefusesANonAdminBeforeAnyReadOrOperation` |
| AID-2 | R | Р4, Р5 — занятый или выданный — `ALREADY_EXISTS`; реестр не очищается | реестр выданных — `internal/migrations/20261002120000_account_ids_are_issued_once.sql:111` (первичный ключ `:113`) | `TestAccountID14_ConcurrentCreatesWithOneIDLetExactlyOneThrough`, `TestAccountID18_EveryProducerEntersTheRegistryAndDeletionDoesNotFree` |
| AID-3 | K | Р6, Р7 — источник id в событии аудита | `create.go:129`, `:130` (закрытый набор), `:391` (событие) | `TestAccountID26_CreationEventNamesTheIDSource` |

## §4 `active-identity-has-a-way-in.md` — `6763b971`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| AWI-1 | R | инв. 3, 4 — инвариант держит база | отложенный составной ключ `users_active_has_a_way_in_fk` — `internal/migrations/20261005030000_active_identity_has_a_way_in.sql:108` | `TestIntegration_AWI01_ActiveWithoutAWayInIsNotCommitted`, `TestIntegration_AWI04_LastPasswordOfActiveCannotBeRemoved`, `TestIntegration_AWI_06_UnblockWithoutAWayInIsRefused` |
| AWI-2 | K | инв. 2 — перенос не меняет статуса | перенос ставит только открытый путь, статус не трогает — `20261005030000_*.sql:92` | `TestIntegration_AWI11_TransferOpensThePathAndChangesNothingElse`, `TestIntegration_AWIRollbackKeepsPeopleAndStatuses` |

## §5 `admission-rate-carrier-is-fixed-at-registration.md` — `f85ce731`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| A197-1 | U | Р1, Р2 — носитель окна фиксирован при чеканке, только у нашей полосы | колонка — `internal/migrations/20261006152443_admission_carrier_is_fixed_when_the_identity_is_minted.sql:66`; триггер неизменности — `:104`; CHECK связи пустой строки с полосой — `:114` | `TestA197_05_CarrierIsFixedAtTheDatabaseLevel`, `TestA197_08_OwnLaneIdentityWithoutACarrierIsImpossible`, `TestA197_09_SentForeignCarrierIsRefusedNotOverwritten` |
| A197-2 | K | Р3, Р5 — окна переносятся без сброса | обратное заполнение носителя — `20261006152443_*.sql:109`, окна не трогает | `TestA197_06_ExistingWindowsAreCarriedOverWithoutReset` |

## §6 `assurance-level-is-declared-by-our-session.md` (Ф11) — `b39219bc`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| AL-1 | UN | Р1, Р2, Р4 — уровень из множества предъявленного одним правилом | `internal/assurance/level.go:240` (`LevelOf`); производитель в выдаче — `internal/apps/kaname/api/humansession/issue.go:77`; гейт единственного писателя — `internal/check/assurance_level_sole_writer.go` | `TestLevelOf_WholeTableMatchesRuleR2`, `TestLevelSoleWriterGateRedsOnEveryProductionForm`, `TestLevelSoleWriterGateStaysSilentOnReads` |
| AL-2 | U | Р3 — «3» только ключ с проверкой пользователя без резервного копирования | `level.go:201` | `TestLevel3_TellsTheKeyByItsAssertionFlags` |
| AL-3 | K | Р7 — уровень читается только из ответа службы | свидетельство уровня — из записи сессии вопроса: `internal/service/session_record_check.go:142` | `TestF11_39_BodyDoesNotOverrideTheRecord`, `TestF11_34_EvidenceComesFromTheRecordOfTheQuestionsSession` |
| AL-4 | I | Р8, Р9, Р11 — словарь закрыт; одна форма ответа на недостаток уровня | словарь — `level.go:139`; текст — одно объявление `internal/errors/step_up.go:29` | `TestVocabulary_IsClosedByConstruction`, `TestF11_49_RESTFrontAnswersTheStepUpIndication`, `TestF11_50_GRPCAnswersTheStepUpIndication` |

## §7 `ceremony-pace-is-named-by-number.md` — `5053bb03`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| PACE-1 | U | Р1, Р2, Р8 — величины числом, без умолчания | `internal/apps/kaname/config/client_token.go:104` (`ValidateCeremonyPace`), `:250` | `TestKNPACE01_UndeclaredValueRefusesStartNamingTheKey`, `TestKNPACE03_ZeroValueIsNotAValue` |
| PACE-2 | P | Р3, Р12 — порядок решений на токен-эндпоинте; неверный метод — одна форма | `internal/handler/clienttokenhttp/handler.go:276` (метод) → `:287` (потолок тела) → `:296` (разбор формы) → `:305` (вид выдачи) → `:314` (оси) | `TestKNPACE28_PaceSpendsAnyOutcomeButTheMethodRefusal`, `TestKNPACE46b_AuthorizeWrongMethodIsTheOneForm`, `TestKNPACE10_CeilingDoesNotHideRequestFormRefusals` |
| PACE-3 | R | П1 — потолок одновременных обменов; место освобождается при любом исходе | `handler.go:327` (занятие места и проверка — одна операция над каналом), освобождение — `:328` | `TestKNPACE11_PlaceIsReleasedOnAnyOutcome`, `TestKNPACE07_ExchangeAboveTheCeilingIs503BeforeVerification` |
| PACE-4 | CH | Р5 — П3 считает отказ доказательства клиента | исход полосы `LaneProofRefused` — `handler.go:338` | `TestKNPACE22_CeremonyInvalidGrantIsNotCountedInvalidClientIs`, `TestKNPACE23_OurSideRefusalsAreNotCounted`, `TestKNPACE37_PaceOutcomesAreSeededWithZeroes` |

## §8 `cloud-administrator-resets-login-methods.md` — `120ae199`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| LMR-1 | K | Р1, Р2 — глагол-действие, `Operation`; вправе только администратор облака | `internal/apps/kaname/api/user/reset_access_keys.go:150`; запись каталога — держит гейт дерева | `TestResetAccessKeys_LMR08_CatalogEntryIsTheIdentitySuspender` |
| LMR-2 | R | Р4 — сессии гаснут отсечкой, событие с обоими акторами | одна транзакция: `reset_access_keys.go:199` (писатель) → `:228` (отсечка) → `:233` (событие) → `:246` (фиксация) | `TestResetAccessKeys_LMR01_ResetIsOneTransaction`, `TestResetAccessKeys_LMR01_AnyFailedWriteChangesNothing` |
| LMR-3 | U | Р5 — «нечего сбрасывать» — синхронный `FAILED_PRECONDITION` | `reset_access_keys.go:173`, `:261` | `TestResetAccessKeys_LMR04_NothingToResetIsOneSyncRefusal`, `TestResetAccessKeys_LMR04_NothingToResetRefusesSynchronously` |
| LMR-4 | R | Р7, Р8 — сброс и регистрация из сессии до сброса сериализованы базой; пароль не снимается | писатель сброса берёт строку человека — `reset_access_keys.go:199`; снятие только ключей — `:219` | `TestResetAccessKeys_LMR07b_ResetRacesARegistrationFromACutSession`, `TestResetAccessKeys_LMR08_ReasonIsDeclaredOnceAndNoPasswordRemover` |

## §9 `cluster-admins-on-the-public-surface.md` — `37e25926`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| CA-1 | UN | Р1, Р3 — публичный близнец зовёт те же сценарии | `internal/apps/kaname/api/clusterpublic/handler.go:43` (близнец над ядром), `:53`, `:58` | `TestClusterPublic_CAP20_OneWritePathBothTransports`, `TestClusterPublic_CAP03_GrantHumanThroughTheTwin` |
| CA-2 | I | Р5, Р6 — порог уверенности на обеих полосах; право проверяется трижды | полы из контракта — `internal/authzguard/acr_floor.go`; регистрация близнеца — `cmd/kaname/grpc_register.go:112` | `TestACRFloorClusterAdminFloorsComeFromTheContract`, `TestACRFloorClusterAdminFloorPredicateCanFail`, `TestClusterPublic_CAP18_ModelUnavailableRefuses` |
| CA-3 | K | Р7, Р8 — перечень межпроектный; внутренний близнец остаётся внутренним | внутренний сервис регистрируется только блоком внутреннего слушателя — `cmd/kaname/grpc_register.go:187` | `TestClusterPublic_CAP23_RosterOrderThroughTheTwin`, `TestSurfaceRouteCatchesAnInternalDoorOnThePublicObject` |

## §10 `credential-verbs-refusal-outcomes.md` — `98f727e2`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| CRV-1 | K | Р1, Р2, Р4 — отзыв отсутствующего — `NOT_FOUND` одной формы у трёх видов, синхронно | `internal/apps/kaname/api/access_keys/refusals.go:45`; `internal/apps/kaname/api/user_tokens/usecases.go:833`; `internal/apps/kaname/api/sa_keys/usecases.go:1069` | `TestCredentialRevoke_CVR10_ThreeKindsShareOneRefusalForm`, `TestRevoke_CVR11_ConcurrentRevokesYieldOneSuccess`, `TestRevokeSAKey_CVR12_UnansweredStoreIsUnavailableNotNotFound` |

## §11 `email-change-is-confirmed-from-the-new-address.md` — `9dc900c9`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| EC-ALL | R | E1…E11 записи разбора пары `41723d6b…+9dc900c9…` — условия без изменений | запрос — `internal/apps/kaname/api/humansession/email_change.go:328`; подтверждение — `:468`; один условный оператор предъявления — `internal/repo/kaname/pg/email_change_repo.go:212`, вызов — `:224`; темп и запись запроса — `:98`, `:128`; законные писатели адреса — `internal/check/people_address_lawful_writers.go` | `TestEC01_RequestQueuesACodeToTheNewAddressAndChangesNothingElse`, `TestEC02_PresentingTheCodeChangesTheAddressInOneOutcome`, `TestEC24_ASecondAddressWriterIsRedAndTheLawfulOneIsSilent`, `TestEC32_KeyHolderNeedsLevelTwoAndAPersonWithoutOneDoesNot`, `TestEC33_UnreadableEnrolledIsAStoreRefusalNotNothingEnrolled`; пробелы держателей — §28, П-2, П-3 |

## §12 `expired-invitation-keeps-the-address-until-the-inviter-acts.md` — `34f7a09e`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| A198-1 | U | Р1, Р2 — истёкшая строка остаётся | истечение вычисляется, строка не удаляется — `internal/repo/kaname/pg/user_repo.go:716` | `TestA198_01_ExpiredInviteAddressIsTheOneRefusalAndNothingChanges`, `TestA198_03_RemovingTheRowReleasesTheRegistration` |
| A198-2 | UN | Р3, Р5 — продление одним правилом | одно выражение срока на всех ветвях — `user_repo.go:629`…`:631` | `TestA198_05_TheSecondVerbExtendsTheDeadlineTheSameWay`, `TestA198_06_ReInvitingNeverShortensTheDeadline`, `TestA198_07_ReInvitingARedeemedRowChangesNothing` |

## §13 `first-password-from-a-live-session.md` — `72825c63`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| FP-1 | R | Р2, Р3 — заведение ≠ смена; строка есть — отказ состояния | решает ограничение уникальности при вставке — `internal/repo/kaname/pg/login_method_repo.go:397`; вызов — `internal/apps/kaname/api/humansession/password_enroll.go:137` | `TestFP02_EnrollmentIsRefusedWhenAPasswordRowExists`, `TestFP08_TwoEnrollmentsRaceAndOneRowRemains` |
| FP-2 | UN | Р4, Р5, Р7 — то же правило и тот же хешер; строка и событие одной транзакцией; в счёт неверных не идёт | `password_enroll.go:127` (хешер), `:146`, `:157` | `TestFP07_NewPasswordIsJudgedByTheOneRule`, `TestFP07c_BreachedPasswordIsJudgedByTheOneRule`, `TestFP09_AuditRefusalRollsTheRowBack`, `TestFP11_EnrollmentLeavesTheFailureCountUntouched` |

## §14 `level-two-is-enrolled-at-level-two.md` — `41723d6b`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| L2-ALL | U | D1…D9 записи разбора пары `41723d6b…+9dc900c9…` — условия без изменений | суждение уровня — `internal/apps/kaname/api/humansession/sf_enroll_level.go:83`, порог из правила — `:112`; у смены адреса — `email_change_level.go:106`; текст — `internal/errors/step_up.go:29` | `TestKN747_FloorOfKeyVerbsIsNotBelowLevelTwo`, `TestKN747_FloorPredicateCanFail`, `TestKN747_EnrollDecidesOnTheKeyListReadInsideItsWriter`, `TestKN747_17_EnrollWithUnreadableKeyListIsAStoreRefusal`, `TestKN747_InternalListenerDoesNotServeKeyVerbs`; пробел держателя — §28, П-1 |

## §15 `login-lane-issues-our-session-and-logout-ends-it-server-side.md` (Ф3) — `20ccad56`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| F3-1 | K | Р1, Р3 — запись сессии закрытого состава; носитель непрозрачен | `internal/domain/human_session.go:192` | `TestHumanSessionRepo_F3_08_TwoIssuesAreTwoRecordsResolvedByTheirOwnBearer` |
| F3-2 | R | Р4, Р6 — выход — один исход одной транзакции; смена пароля — четыре записи одним исходом | `internal/apps/kaname/api/humansession/logout.go:81` → `:95` → `:101` → `:113`; смена пароля — `change_password.go:199` | `TestLogout_F3_16_ThreeRecordsAreOneOutcome`, `TestChangePassword_F3_19_21_FourRecordsOneOutcome` |
| F3-3 | R | Р5, Р7 — момент первой аутентификации одним писателем; ответ о сессии отсечку не применяет | единственный вызов писателя — `issue.go:103`; отсечка — отдельным правилом `internal/tokenrevocation/rule.go:177` | `TestHumanSessionRepo_F3_50_FirstAuthenticationIsTheMinimumUnderConcurrency`, `TestResolve_F3_10_OneAnswerForFourReasons` |
| F3-4 | UN | Р9, Р17 — пять причин отзыва — один отказ; огибающая по популяции | `internal/apps/kaname/api/humansession/resolve.go:49`; огибающая — `login.go:259` | `TestResolveHandler_F3_27_FiveCausesOneWireAnswer`, `TestLogin_F3_31_RefusalTimeIsIndistinguishableAcrossCostClasses` |
| F3-5 | U | Р10, Р13 — два окна частоты; величины без умолчания | `internal/apps/kaname/api/humansession/rate.go:31` (`Validate`), `:70` | `TestLoginLane_F3_28_33_41_EveryKnobRefusesByNameUnderOwn`, `TestHumanSessionRepo_F3_28_FailureCountIsPerScopeAndWindow` |
| F3-6 | CH | Р11 — проверка по базе утечек, три состояния, недоступность — проход громко | `internal/apps/kaname/api/humansession/password_rule.go:96`…`:113` (отдельная клетка «недоступно») | `TestPasswordRule_F3_34_UnavailableAuthorityPassesLoudlyMisconfiguredRefuses`, `TestBreachCheck_F3_34_ThreeOutcomesByType` |
| F3-7 | K | Р12, Р16 — признак формы привязан к контексту и виду; слушатель допускает ровно край | `internal/apps/kaname/api/humansession/form_token.go:56`; допуск — `internal/handler/loginlanehttp/handler.go:564` | `TestFormToken_F3_35_40_ContextAndKind`, `TestLane_F3_29_51_OnlyTheGatewayIsAdmitted`, `TestLoginLane_F3_44_ListenerModeIsMutualOrTheStartIsRefused` |

## §16 `login-session-and-credentials-are-our-contract.md` (Ф1) — `0f758d32`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| F1-1 | U | Р1, Р2 — проверяющий следует хранимому значению; проверка утечек объявляется явно | `internal/passwordverify/verifier.go:147`; ручки — `internal/apps/kaname/config/login_lane.go:103`, `:104` | `TestVerify_EachFormatOfTheRegistryIsReadByItsOwnVerifier`, `TestVerify_FormatOutsideTheRegistryIsOurErrorWithAPositiveControl`, `TestLoginLane_F3_28_33_41_EveryKnobRefusesByNameUnderOwn` |
| F1-2 | CH | Р3 — отказ не различает «нет личности» и «пароль не тот» | `internal/apps/kaname/api/humansession/refusals.go:44`; приманка при отсутствующем материале — `verifier.go:147` | `TestLogin_F3_02_OneRefusalForEveryCause`, `TestVerifier_F3_31_AbsentMaterialIsComputedAgainstADecoy` |
| F1-3 | R | Р4, Р5 — смена гасит прочие, восстановление — все; следствия регистрации одной транзакцией | `change_password.go:199`; `recovery_complete.go:461`; регистрация — `internal/apps/kaname/api/registration/register.go:249`, `:289` | `TestChangePassword_F3_19_21_FourRecordsOneOutcome`, `TestRegister_F4_01_ThreeConsequencesInOneWriterInDeclaredOrder` |
| F1-4 | K | Р6, Р7 — защита каждой формы, меняющей состояние; срок сессии и атрибуты печенья — наша настройка | `internal/handler/loginlanehttp/handler.go:542` (`judgeForm`), печенье — `:1274` | `TestFormToken_F3_35_40_ContextAndKind`, `TestLane_F3_01_LoginIssuesTheSessionCookieAndANewFormContext` |

## §17 `model-generated-from-manifest.md` — `3e7daf12`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| MGM-1 | I | нормы 1…3, 6, 8 — блоки из манифеста, побайтовая сверка, канон из дерева, ничейный блок объявлен | `internal/modelrender/sweep.go:227` (`Sweep`), сторона расхождения — `:501`; ничейные типы выводятся — `internal/modelrender/canon.go:222` | `TestModelCanonCheckOnTheRealTreeComparesEveryOwnedBlock`, `TestB06AnAddedTypeOutsideModulesIsAFinding`, `TestB06TypesOutsideModulesAreDerivedNotWritten` |
| MGM-2 | I | нормы 4, 5, 7 — ноль находок отличим от нуля прочитанного; исходов три | перепись осмотренного — `sweep.go:168` | `TestC08NothingToRenderIsVoidNotSuccess`, `TestC08NothingToRenderWithoutTheWaiverIsAFinding`, `TestSweepCauseParity_CanFailAndStaysSilent` |

## §18 `own-account-and-identity-are-removed-in-order.md` — `f10f3e86`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| OAR-1 | K | Р2, Р3 — ресурсы платформы — отказ с названным шагом, не каскад | `internal/repo/kaname/pg/pgmaperr.go:496` | `TestKN664_11_AccountWithAProjectIsRefused`, `TestKN664_31_PersonWhoStillOwnsTheAccountIsRefused` |
| OAR-2 | U | Р4, Р8, Р11 — мягкие ссылки; реестр выданных id людей | `internal/migrations/20261011061435_own_account_and_identity_are_removed_in_order.sql:90` (`ON DELETE SET NULL DEFERRABLE`), `:123` (реестр) | `TestKN664_01_MigrationBreaksTheCycleAndKeepsEveryRow`, `TestKN664_33_35_RecordsThatOutliveThePerson`, `TestKN664_41c_InvitationOfARemovedIdentifierIsRefused` |
| OAR-3 | R | Р5, Р6, Р10 — намерения модели прав той же транзакцией | `internal/apps/kaname/api/user/delete.go:199` | `TestKN664_37_IntentRefusalLeavesThePerson`, `TestKN664_15_IntentRefusalLeavesNothing` |
| OAR-4 | I | Р7, Р9, Р12 — перепись ключей на `users` выводится из схемы | `internal/migrations/person_and_account_keys.go:100` | `TestKN664_60_EveryKeyOnPersonAndAccountIsLedgered`, `TestKN664_61_NewRestrictKeyWithoutALedgerRowIsFound`, `TestPersonAndAccountKeysJudgeBothWays` |

## §19 `own-sessions-are-listed-and-ended-by-their-owner.md` — `63333cc2`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| OS-1 | K | Р1, Р3 — один новый вид признака; поле описания клиента | вид — `internal/domain/human_session.go` (`FormSessionEnd`); CHECK поля — `internal/migrations/20261007104910_own_sessions_are_listed_and_ended_by_their_owner.sql:44` | `TestOS04_ClientDescriptionAsSentTruncatedByRunesInvalidBytesReplaced`, `TestOS04_ClientDescriptionNormalization`, `TestOS11_FormFieldsNamedForeignKindRejected` |
| OS-2 | P | Р4, Р5 — постранично в порядке выдачи; разбор курсора раньше замыкания пустой выдачи | `internal/apps/kaname/api/humansession/own_sessions.go:102`, `:232` | `TestOS05_PaginationAndParameterRefusals`, `TestOS09_ForeignUnknownEndedExpiredAreOneRefusalByteForByte` |
| OS-3 | CH | Р6, Р7, Р9 — снятие одной транзакцией; хранилище недоступно — не «сессии нет» | `own_sessions.go:366`; отказ хранилища — `:180`, `:249` | `TestOS15_StoreUnavailableOnResolveAndAuditFailureRollsBackTheEnd`, `TestOS14_RacesOneRecordOneEndCrossEndOthersLeavesExactlyOne` |

## §20 `password-verifier-follows-the-stored-value.md` — `64726612`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| PWV-ALL | CH | §7 приёмки — 28 классов, каждый со своим сценарием | `internal/passwordverify/verifier.go:147`, `:182`; запись формата — `internal/passwordverify/hasher.go` | `TestOutcomes_DictionaryIsClosedAndEveryOutcomeIsDistinct`, `TestVerify_UnparsableBodyNeverMatches`, `TestVerify_MissingMaterialIsNotAMismatch`, `TestVerify_ParametersAboveTheCeilingAreRefusedWithoutComputing`, `TestHasher_F3_41_WritesTheDeclaredFormatAndTheVerifierReadsItBack` |

## §21 `recovery-of-access.md` (Ф5) — `fa1f12bd`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| F5-1 | R | Р1, Р4 — код однократен, срок и однократность держит база | `internal/repo/kaname/pg/recovery_code_repo.go:122` | `TestRecoveryCodes_F5_03_05_ConsumeIsOneOperatorAndWinsOnce`, `TestRecoveryCodes_F5_04_ExpiredIsRefusedAndDoesNotRevive` |
| F5-2 | R | Р2 — ответ не ждёт постановки письма | постановка вне пути ответа — `internal/apps/kaname/api/humansession/recovery_request.go:157`; исходы наблюдателя — `:179`, `:186` | `TestLane_F5_01_02_RequestAnswersTheSameBodyWhateverTheOutcome`, `TestRecoveryCodes_F5_09_MailIntentIsAtomicWithTheCodeRow` |
| F5-3 | K | Р3 — второй вид письма новой миграцией | `internal/migrations/20260917015400_recovery_code_is_our_record.sql:66` | `TestRecoveryCodes_F5_09_MailIntentIsAtomicWithTheCodeRow` |
| F5-4 | CH | Р7, Р8, Р10 — ответ запроса один для всех исходов | `recovery_request.go:143`…`:152` | `TestLane_F5_01_02_RequestAnswersTheSameBodyWhateverTheOutcome`, `TestRecovery_F5_20_21_22_RequestTimeIsIndistinguishableAndTheInjectionIsRed`, `TestLaneIntegration_F5_27_SourceRequestWindow` |
| F5-5 | R | Р5, Р9 — новый пароль тем же обращением; `ACTIVE` без способа входа возвращается восстановлением | `internal/apps/kaname/api/humansession/recovery_complete.go:387`, фиксация — `:526` | `TestLaneIntegration_F5_34_RecoveryCreatesTheMissingPasswordRow`, `TestLaneIntegration_F5_34_ConcurrentPresentationsCreateOneRow`, `TestRecovery_F5_33_RefusalInsideCompletionRollsEverythingBack` |

## §22 `registration-and-its-three-consequences.md` (Ф4) — `295e0c73`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| F4-1 | R | Р1, Р8 — одна транзакция, четыре следствия | `internal/apps/kaname/api/registration/register.go:161`…`:289` | `TestRegister_F4_01_ThreeConsequencesInOneWriterInDeclaredOrder`, `TestRegisterIntegration_F4_02_04_RefusedConsequenceLeavesNothing` |
| F4-2 | R | Р2 — материализация прав не гейтит годность сессии | сессия выдаётся в транзакции регистрации — `register.go:249`; намерения модели прав — очередью | `TestRegisterIntegration_F4_01_05_SuccessGivesAllThreeConsequences` |
| F4-3 | UN | Р3, Р7 — занятый адрес — единый отказ, время не различает | `register.go:337` | `TestRegisterIntegration_F4_11_24_OccupiedAddressIsOneRefusal`, `TestRegisterTiming_F4_14_16_CriterionOnSyntheticSamples` |
| F4-4 | I | Р4, Р5, Р9 — полоса перечислена одним местом; префикс `personal-cloud-` зарезервирован | `internal/apps/kaname/api/registration/lanes.go:65`; резерв — `internal/apps/kaname/api/account/create.go:285` | `TestF4d10_BootRefusalProbeWalksTheDeclaredTable`, `TestCreateAccount_F4_29_ReservedPrefixRejected`, `TestUpdateAccount_F4_30_ReservedPrefixRejectedOnRename` |

## §23 `second-factor-totp-and-recovery-codes.md` (Ф12) — `c6ea4897`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| F12-1 | K | Р1, Р2 — строки двух видов с состоянием; секрет обёрнут | состояние — `internal/domain/login_method.go:73`, `:76`; обёртка — `internal/totpverify/verifier.go:244`, вызов — `internal/apps/kaname/api/humansession/sf_enroll.go:119` | `TestF12_01_EnrollMintsAPendingRowAndShowsTheSecretOnce`, `TestF12_02_ConfirmActivatesMintsCodesAndIsAPresentation` |
| F12-2 | R | Р5, Р6 — повтор кода невозможен; запасные однократны, набор целиком | `internal/repo/kaname/pg/human_session_repo.go:1293` (шаг), `:1289` (элемент), `:1281` (набор) | `TestF12_22_ReplayIsAPropertyOfTheRowNotTheSession`, `TestF12_23_26_BackupCodesOnceEachDownToZero`, `TestF12_25_RegenerateReplacesTheSetWhole` |
| F12-3 | R | Р7 — подбор ограничен тем же счётом, что пароль | `internal/apps/kaname/api/humansession/rate.go:109` | `TestF12_31_32_WrongCodesShareTheAttemptCountWithThePassword` |
| F12-4 | P | Р8, Р9, Р10 — свежесть; самосброс гасит прочие; сброс администратором | `sf_enroll.go:88`; `sf_enroll_level.go:83`; `sf_remove.go:125`; `internal/apps/kaname/api/user/reset_second_factor.go` | `TestF12_09_10_EnrollRequiresAFreshSessionAndAPresentationRefreshesIt`, `TestF12_28_29_RemoveEndsOtherSessionsAndKeepsTheCurrentAtTwo`, `TestF12_36_SelfServiceFreshnessIsAKnobWithoutADefault`, `TestResetSecondFactor_F12_30_ResetIsOneTransaction` |

## §24 `service-manifest-seeds-its-own-groups.md` — `c72db75e`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| MRW-1 | UN | Р1, Р1а — группу объявляет манифест; форма субъекта — у канона | `internal/repo/kaname/pg/module_seed_writer.go:37`…`:43` (форма — `domain.FGASubjectRef`) | `TestMRW20_GroupRecipientSubjectCarriesTheMembershipSigil`, `TestMRW21_ServiceAccountRecipientSubjectHasNoSigil` |
| MRW-2 | R | Р2, Р3, Р4 — свой манифест первым; идемпотентность держит естественный ключ | `internal/apps/kaname/moduleseed/apply.go:227`; `module_seed_writer.go:180`, `:206`, `:232` | `TestMRW02_SecondStartWritesNothing`, `TestMRW04_OwnManifestIsAppliedBeforeTheDeliveredOnes`, `TestMRW04_OwnGroupIsSeededBeforeTheDeliveredJoin` |
| MRW-3 | K | Р6, Р7 — снятие двумя стадиями; применённая не правится | `internal/migrations/20260916150000_quota_readers_group_leaves_the_baseline.sql` | `TestMRW25_DownRestoresTheSeedGroupAndTheReapplyConverges`, `TestMRW18_DeliveryStillJoiningTheRetiredGroupGetsANamedRefusal` |

## §25 `subject-cutoff-writes-both-records-under-one-lock.md` — `b72c19f1`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| SCL-1 | R | Р1, Р2, Р3 — зеркальная запись той же транзакцией триггером первой | `internal/migrations/20261003202945_*.sql:167` | `TestSubjectCutoff_KN_SCL_07_BareFirstRecordWritesTheSecond`, `TestSubjectCutoff_KN_SCL_08_FirstRecordTheSecondRefusesDoesNotLand`, `TestSubjectCutoff_KN_SCL_11_DoorAndBlockRaceOnOnePerson` |
| SCL-2 | P | Р4, Р5, Р6 — граница правила отзыва включающая | `internal/tokenrevocation/rule.go:177` | `TestIntrospect_KN_SCL_17_CutoffEqualToIatIsInactive`, `TestPresented_KN_SCL_18_CutoffEqualToIatIsRefused`, `TestSubjectCutoff_KN_SCL_13_ApplyConvergesRowsAndTheRoundTripHolds` |

## §26 `unverified-address-passes-to-the-mailbox-owner.md` — `79e0f15a`

| пункт | класс | решение | механизм | проба |
|---|---|---|---|---|
| A458-1 | UN | Р1, Р2, Р9 — правило выдачи кода одно | `internal/apps/kaname/api/humansession/recovery_request.go:232` (одно объявление, один вызов — `:147`) | `TestA458_01_CodeIsIssuedToTheUnverifiedAddressOfARecordWithAPassword`, `TestRecovery_F5_31_UnverifiedAddressWithAPasswordStillGetsNoCode` |
| A458-2 | R | Р3, Р4, Р5 — ветвь решают отметка и удостоверения, прочитанные в транзакции исхода | `recovery_complete.go:302` (чтение отметки в транзакции исхода) | `TestRecovery_A458_BranchIsDecidedByTheCredentialsOfTheRecord`, `TestA458_02_Race_VerifiedInFlightIsOrdinaryRecovery`, `TestA458_09_Concurrent_NoSessionOnTheOldPasswordSurvivesTheClaim` |
| A458-3 | K | Р6, Р7, Р8 — своё слово причины `address-claimed` | `internal/migrations/20261012120000_address_claimed_ends_the_sessions_of_the_previous_holder.sql` | `TestA458_10_AddressClaimedIsAWordOfTheSessionEndVocabulary`, `TestA458_06_InvalidInvitationRefusesTheOutcomeAndChangesNothing` |

---

## §27 Счёт отображения

| приёмка | пунктов | отображено с держателем | без держателя |
|---|---|---|---|
| 26 приёмок §1…§26 | 83 | 82 | 1 (AK-5) |

Предикат счёта строк (перемерь):
`grep -cE '^\| (AK|ABV|AID|AWI|A197|AL|PACE|LMR|CA|CRV|EC|A198|FP|L2|F3|F1|MGM|OAR|OS|PWV|F5|F4|F12|MRW|SCL|A458)-' own-identity-line-maps-its-decisions-to-code-design.md`
→ 83. Каждый пункт отображён ровно одной строкой; у AK-5 механизма, исполняющего решение, на
голове нет — это не пропуск отображения, а расхождение кода с приёмкой (§28).

---

## §28 Расхождения кода с приёмками и пробелы держателей — переданы как находки к коду

Замысел расхождений **не сглаживает**: строка ниже — факт о дереве головы, а не решение.
Исход — у исполнителя кода либо у круга приёмки владельца решения.

| № | пункт | что требует приёмка | что на голове | чем измерено |
|---|---|---|---|---|
| **Р-1** | AK-5 (и F13-N3 замысла Ф13) | Ф7 Р12: признак обнаружимости **хранится** тремя состояниями; страж последнего способа считает **годные к предъявлению**; держатели Ф7-56, Ф7-57 | колонки признака нет (`internal/migrations/20260917221000_access_keys_are_our_record.sql:74`, перечень колонок чтения — `internal/repo/kaname/pg/access_key_repo.go:50`); «не сообщено» принимается и не записывается (`finish_registration.go:144`); страж считает строки (`internal/apps/kaname/api/access_keys/revoke.go:227`) | `git grep -niE 'discoverab' -- internal/migrations internal/repo \| wc -l` → 0; `git grep -nE 'F7_5[67]\|Ф7-5[67]' -- '*_test.go' \| wc -l` → 0 |
| **П-1** | L2-ALL (D7 записи разбора) | инв. 2 «и у любого нового способа» — множество охраняемых глаголов выводится из дерева | закрытый перечень трёх глаголов; держится вниманием | запись разбора пары `41723d6b…+9dc900c9…`, строка D7 |
| **П-2** | EC-ALL (E2 записи разбора) | ожидающее заведение способом не считается | условие исполнено (`second_factor.go:402`), пробы, различающей клетку «код ожидает», нет | та же запись, строка E2 |
| **П-3** | EC-ALL (E9 п. 7 записи разбора) | в журналах и аудите нет адресов | исполнено чтением; пробы `NotContains(журнал, адрес)` нет | та же запись, строка E9 п. 7 |

Строки П-1…П-3 — пробелы держателей при исполненном условии (держится вниманием); Р-1 —
неисполненное решение. Расхождения приёмки Ф13 с кодом — в её замысле, §6а.

---

## §29 Что этот замысел вносит

Ничего сверх отображения: ни нового механизма, ни хранилища, ни внешнего вызова, ни ребра.
Каждый механизм выше уже посажен линией либо её базой; каждая проба уже лежит в дереве.

## §30 Границы текста этого документа

Документ лежит в публичном репозитории и выдерживает публикацию (`security-disclosure.md`):
он называет решение, место его исполнения и пробу. Сборки «координата + условие, при котором
защита не действует + следствие для постороннего» в нём нет: расхождение Р-1 названо тем, какое
решение не исполнено, а не тем, как этим воспользоваться.
