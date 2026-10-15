# Выдача удостоверений и субъект федерации — одно правило на всех страницах — Acceptance

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** 2026-10-15 · круг 1 · CHANGES_REQUESTED · 614a1ecb359c98d0747bee440d5d0bb6397cd72e643f9b1a86d5664c7ba12794 · docs/specs/reviews/credential-issuance-and-federated-subject-described-once/614a1ecb359c98d0747bee440d5d0bb6397cd72e643f9b1a86d5664c7ba12794.yaml; 2026-10-15 · круг 2 · CHANGES_REQUESTED · 57bfc0aa1c17ba958d03378eeed0968c9c987a9234746f7d751926682ecb911e · docs/specs/reviews/credential-issuance-and-federated-subject-described-once/57bfc0aa1c17ba958d03378eeed0968c9c987a9234746f7d751926682ecb911e.yaml (только дописывается)
> **Дата:** 2026-10-15
> **Эпик/issue:** kaname#746 · kaname#752 · kaname#798

## Обзор

Контракт выдачи удостоверений описан в трёх местах (страница удостоверений, страница прав,
комментарий контракта ключей служебной учётки), и в двух предметах места расходятся: какой
порог уровня аутентификации держит выдача для служебной учётки и какой формы субъект
федеративного удостоверения. Поведение службы в обоих предметах уже однозначно (производители
ниже); приёмка фиксирует его как контракт, и тексты приводятся к нему. Наблюдаемое поведение
службы не меняется.

## Что НЕ входит

- Прочие задачи полосы L2 (kaname#751, #750, #753, #738, #740, #729) — эта приёмка их поведения
  НЕ санкционирует. Где задача меняет наблюдаемое поведение (по переписи — #740: другой текст
  отказа; #750 — перечень уровней), она садится только по своей одобренной приёмке; где задача —
  приведение текста к уже производимому, приёмка не нужна (ban01, смена контракта отсутствует).
- Страница края kacho `gateway/docs/content/architecture/authn.mdx` — другой репозиторий; её
  приведение — задачей в kacho.
- Изменение порога или формы субъекта: обе величины остаются, какие есть.

## Полоса и фикстуры (общие для CIF-01…05)

**Полоса:** собственный публичный фронт kaname (REST `/iam/v1/…`), вызывающий предъявляет своё
удостоверение сам — полоса предъявленного (`callerorigin.PresentedCredential`). Порог уровня на
ней производит `internal/authzguard/public_caller_policy.go` (ветвь `IsPresentedCredential`),
пообъектный вопрос к модели — `internal/authzguard/own_door.go` (`OwnDoor.Unary`), отображение
указания повысить уровень в HTTP — `internal/restfront` (`stepUpErrorHandler`,
`withAuthenticationChallenge`). Край kacho в этих сценариях не участвует.

**Фикстуры собственного стенда** (`tests/authz-fixtures/seed_own_stand.py`,
`tests/authz-fixtures/seed_ceremony.py`; соответствие предъявителя субъекту —
`tests/authz-fixtures/principal_pairings.py` `PRINCIPAL_PAIRINGS`):

| имя в окружении | кто это | откуда отношение |
|---|---|---|
| `jwtAccountAdminA` | служебная учётка, распорядитель аккаунта A, базовый токен | посев `seed_own_stand.py` (`grant_role`, `sa_token`) |
| `svaAId` | служебная учётка аккаунта A — цель выдачи | посев `seed_own_stand.py` (`make_service_account`) |
| `jwtHumanCeremony` | человек церемонии, сессия уровня «1» (только пароль); отношения на `svaAId` нет, `system_admin` не выдан | `seed_ceremony.py` (`person("main")`, `ceremony_bearer(..., "1")`); отсутствие выдачи — самопроверка посева «system_admin выдан ровно надзору облака, человеку стенда — нет» |
| `jwtSANoGrant` / `svaNoGrantId` | служебная учётка без единой выдачи | посев `seed_own_stand.py`; пара — `PRINCIPAL_PAIRINGS` |

Уровень машинного субъекта для порога не значим: общее правило повышения освобождает его первой
ветвью до сравнения уровней (`seed_own_stand.py`, комментарий у `jwtAccountAdminAStepUp`).

## Сценарий 01: базовый токен служебной учётки выпускает удостоверение

**ID:** CIF-01

**Given** `jwtAccountAdminA` — служебная учётка с отношением `v_update` на `svaAId` (распорядитель
аккаунта A), предъявлен базовый токен
**When** клиент вызывает `POST /iam/v1/serviceAccounts/{{svaAId}}/keys` (`SAKeyService.Issue`)
с `Authorization: Bearer {{jwtAccountAdminA}}` и телом:

```json
{ "serviceAccountId": "{{svaAId}}", "description": "cif-01", "credentialKind": "CREDENTIAL_KIND_SECRET" }
```

**Then** `200`, тело — `Operation` (`id` непуст); полл `GET /operations/{id}` под тем же
предъявителем до `done=true`, `error` отсутствует
**And** заголовка `WWW-Authenticate` в ответе выдачи нет — порог `required_acr_min = "2"`
машинного субъекта не судит.

## Сценарий 02: базовый токен человека выпустить удостоверение не может (близнец CIF-03)

**ID:** CIF-02 — отличается от CIF-03 ровно видом субъекта: человек уровня «1» вместо служебной
учётки; отношения на `svaAId` нет у обоих, вызов и тело те же. По оси порога CIF-03 — проходящая
сторона (указания повысить уровень нет), CIF-02 — отвергнутая. От CIF-01 CIF-02 отличается двумя
фактами (вид и отношение) и его близнецом не объявляется; цепочка CIF-01 → CIF-03 → CIF-02 меняет
на каждом шаге ровно один факт.

**Given** `jwtHumanCeremony` — человек, сессия уровня «1», отношения на `svaAId` нет
**And** порог уровня судится раньше пообъектного вопроса: на публичном слушателе
`publicCallerPolicy.Unary()` стоит перед `publicObjectDoor.Unary()` (`cmd/kaname/serve.go`,
сборка `publicUnary`) — отсутствие отношения исхода CIF-02 не меняет, и отказ приходит от порога,
а не от двери.

> Допущение (решение диспетчера, круг 3): человек уровня «1» с `system_admin` в фикстурах есть
> только в слотах администраторов облака (`seed_ceremony.py` `ADMIN_SLOTS`, ключи `slot_keys`), и
> все девять слотов читаются соседними наборами (`iam-account`, `iam-user`,
> `kaname-cluster-admins`); чужой слот брать нельзя, свой — правка посева вне предмета этой
> приёмки. Поэтому Given честно без отношения, а близнец — CIF-03.

**When** тот же вызов с `Authorization: Bearer {{jwtHumanCeremony}}` и телом CIF-01
(`"description": "cif-02"`)
**Then** `401`, тело побайтово:
`{"code":16,"message":"authentication level is insufficient: step up with a second factor, or present a credential of another kind","details":[]}`
**And** `WWW-Authenticate` побайтово:
`Bearer error="insufficient_user_authentication", error_description="Required ACR 2 for this resource; presented ACR 1", acr_values="2"`
**And** удостоверение не выпущено: `GET /iam/v1/serviceAccounts/{{svaAId}}/keys` под
`jwtAccountAdminA` не содержит ключа с `description = "cif-02"`.

## Сценарий 03: освобождение от порога прав не даёт (близнец CIF-01)

**ID:** CIF-03 — отличается от CIF-01 ровно отсутствием отношения на `svaAId`; вид субъекта тот
же (служебная учётка), вызов и тело те же. Он же — близнец CIF-02 по оси порога.

**Given** `jwtSANoGrant` — служебная учётка без единой выдачи
**When** тот же вызов с `Authorization: Bearer {{jwtSANoGrant}}` и телом CIF-01
(`"description": "cif-03"`)
**Then** ответ — отказ пообъектного вопроса, а не указание повысить уровень: код в теле не `16`,
заголовка `WWW-Authenticate` нет
**And** пара (HTTP-статус, тело) побайтово равна ответу того же предъявителя на
`GET /iam/v1/serviceAccounts/{{svaAId}}` — тот же ответ, что промах по объекту (сокрытие
существования общего звена; конкретная пара — `(403, code 7)` либо `(404, code 5)` — определяется
таблицей текстов владельца, и кейс её не перевыводит)
**And** удостоверение не выпущено (как в CIF-02, `description = "cif-03"`).

> Допущение (снимается первым прогоном кейса): какую из двух пар отдаёт общее звено на этом
> объекте, приёмка не фиксирует — фиксируется равенство с ответом на чтение, которое и есть
> контракт сокрытия. Если прогон покажет, что пары различаются, сценарий возвращается в приёмку.

## Сценарий 04: субъект федерации — точная строка, принимается

**ID:** CIF-04

**Given** `jwtAccountAdminA`, цель `svaAId`; стенд прогона — автономный стенд
`.github/scripts/stand-own.sh` (задание `stand-ceremony` в `.github/workflows/e2e-newman.yml`),
на нём собственная выдача включена: `KANAME_AUTHN__CLIENT_TOKEN__ENABLED=true` →
`Config.SAKeyIssuanceIsOurs` (`internal/apps/kaname/config/sakey_binding.go`) → `ownIssuance`
выдачи (`cmd/kaname/wiring.go`, `saKeyIssuanceIsOurs`); без неё федеративный вид отвергался бы
синхронно до записи — `internal/apps/kaname/api/sa_keys/usecases.go`, `shared.ExchangeEndpointAbsent`
**And** кейс в pre-request порождает пару ключей P-256 и кладёт открытую часть PEM в
`{{cifPubPem}}`
**When** клиент вызывает `POST /iam/v1/serviceAccounts/{{svaAId}}/keys` под
`jwtAccountAdminA` с телом:

```json
{
  "serviceAccountId": "{{svaAId}}",
  "description": "cif-04",
  "credentialKind": "CREDENTIAL_KIND_FEDERATED",
  "trustedSubjects": [{
    "issuer": "https://ci.kacho.example",
    "subjectPattern": "^repo:acme/infra:ref:refs/heads/main$",
    "publicKeyPem": "{{cifPubPem}}",
    "keyAlgorithm": "ES256"
  }]
}
```

**Then** `200`, `Operation`; полл до `done=true` без `error`.

## Сценарий 05: образец вместо точного субъекта отвергнут (близнец CIF-04)

**ID:** CIF-05 — отличается от CIF-04 ровно `"subjectPattern": "^repo:acme/infra:ref:.*$"`
(и `"description": "cif-05"`).

**When** тот же вызов
**Then** `400`, тело несёт `code = 3` и `message` побайтово:
`trusted_subjects[0]: Illegal argument subject_pattern: must be a literal anchored subject (^...$, no wildcards)`
**And** отказ синхронный (Operation не создаётся) и не зависит от собственной выдачи: проверка
перечня стоит раньше проверки вида (`usecases.go`, цикл `TrustedSubjects` перед
`ExchangeEndpointAbsent`)
**And** ключ не выдан (`List`, как в CIF-02).

## Сценарий 06: тексты контракта называют одно правило

**ID:** CIF-06

**Then** комментарий поля `TrustedSubject.subject_pattern` в
`proto/kaname/cloud/iam/v1/sa_key_service.proto` и раздел федерации `docs/content/api/tokens.mdx`
называют одно правило: точный субъект в форме `^…$`, без метасимволов образца, сверяемый с `sub`
дословно; слов «регулярное выражение» / «regex» о поле нет ни в одном из них
**And** `docs/content/api/tokens.mdx` (раздел перехода, пункт об уровне базового токена) и
`docs/content/architecture/authz.mdx` (раздел Step-up) называют один исход: базовый токен
человека выдачу и отзыв удостоверений не исполняет (уровень `1` ниже порога `2`), служебная
учётка от порога освобождена и судится только отношением.

## Сценарий → производитель

| ID | что производит «Тогда» | координата в дереве | чем измерено |
|---|---|---|---|
| CIF-01 | освобождение машинного субъекта от порога на полосе предъявленного | `internal/authzguard/public_caller_policy.go` ветвь `IsPresentedCredential` → corelib `grpcsrv.EvaluateStepUp`, ветвь 1 (`PrincipalTypeServiceAccount`); выдача — `internal/apps/kaname/api/sa_keys/handler.go` `Issue` | `go list -m github.com/PRO-Robotech/corelib` → v1.14.0 (пин kaname `go.mod`); `grpcsrv/acr.go:181` @v1.14.0; `public_caller_policy.go:357-363` @c032a0274 |
| CIF-02 | указание повысить уровень: код 16, текст, вызов; порог раньше двери | `cmd/kaname/serve.go` порядок `publicUnary` (`publicCallerPolicy.Unary()` перед `publicObjectDoor.Unary()`); `public_caller_policy.go` → `stepUpRequired` (`iamerr.TextStepUpRequired`, `iamerr.StepUpChallenge`), `internal/errors/step_up.go:29,51`; HTTP-рендеринг — `internal/restfront` `stepUpErrorHandler`; порог — аннотация `required_acr_min = "2"` у `SAKeyService.Issue` | `git show origin/746:proto/kaname/cloud/iam/v1/sa_key_service.proto` (стр. 50-65); `internal/restfront/stepup_test.go` `TestStepUp_IndicationIsRenderedWithTheChallenge` (форма тела) @c032a0274 |
| CIF-03 | отказ пообъектного вопроса | `internal/authzguard/own_door.go` `OwnDoor.Unary` (общее звено `pkg/authz.Interceptor`, сокрытие существования — таблица текстов владельцев) | прочитано в `own_door.go` (шапка, «# Почему это ПРОВЯЗКА») @c032a0274 |
| CIF-04, CIF-05 | приём точного субъекта; отказ образцу с префиксом позиции; включённая собственная выдача стенда | `internal/domain/service_account_oauth_client.go` `TrustedSubject.Validate` (стр. 162), `LiteralSubject`; префикс — `internal/apps/kaname/api/sa_keys/usecases.go:332`; выдача — `.github/scripts/stand-own.sh:367` → `internal/apps/kaname/config/sakey_binding.go:31` | `git show origin/746:internal/domain/service_account_oauth_client.go`, `…/usecases.go`; `grep -n CLIENT_TOKEN__ENABLED .github/scripts/stand-own.sh` @c032a0274 |
| CIF-06 | совпадение текстов | правка текстов полосы L2 (комментарий `.proto`, две страницы) | предикаты DoD ниже |

## DoD

- **CIF-01…CIF-05** — newman-кейсы в существующем наборе собственного фронта
  `tests/newman/cases/kaname-own-rest-front.py` (адресуется к `{{ownRestBaseUrl}}`, уже читает
  `jwtAccountAdminA` и `svaAId`; новой коллекции не заводится), ID сценария — в `id` кейса
  (`IAM-OWNREST-CIF-01-…` и т.д.); каждый утверждает пару «HTTP-статус + `code`» и текст
  дословно, как в «Тогда». Набор края платформы (`iam-service-account.py`) держателем не является:
  он судит край kacho, а не названных производителей службы.
- **Волна прогона — церемония.** Кейс CIF-02 читает `jwtHumanCeremony`, ключ церемонии
  (`.github/scripts/newman-suite-debt.py` `is_ceremony_key`, префикс `jwtHuman`), поэтому
  коллекция `kaname-own-rest-front` гонится волной церемонии — заданием `stand-ceremony`
  (`.github/workflows/e2e-newman.yml`) на автономном стенде `stand-own.sh`, после машинного посева
  (`seed_own_stand.py` даёт `jwtAccountAdminA`, `svaAId`, `jwtSANoGrant`); строка ведомости
  набора в `newman-suite-debt.py` переписывается тем же изменением. Кейсы и строку заводит
  производитель проб (`qa-test-engineer`), не полоса текстов.
- **CIF-04** — держатель один: newman-кейс там же; собственная выдача на этом стенде включена
  (`stand-own.sh`, `KANAME_AUTHN__CLIENT_TOKEN__ENABLED=true`), и ответ CIF-04, отличный от
  `200`, — красный, а не «условие не создано».
- **Вердикт порога без стенда** (второй держатель CIF-01/02 на уровне полосы):
  проба в `internal/authzguard` на `SAKeyService/Issue` фикстурой `presentedCredentialCtx`
  (`public_level_two_second_lock_test.go`): `("service_account", "")` → проход,
  `("user", "1")` → `requireStepUpToTwo`.
- **CIF-06**, предикаты на голове полосы:
  - блок комментария поля (от `// TrustedSubject —` до `string subject_pattern = 2;`):
    `git show HEAD:proto/kaname/cloud/iam/v1/sa_key_service.proto | awk '/^\/\/ TrustedSubject —/{f=1} f{print} f&&/string subject_pattern = 2;/{exit}'`
    — строк больше `0`; в нём `grep -c -i -E 'regex|регулярн'` → `0` и
    `grep -c -i -E 'literal|дословн|точн'` → не меньше `1` (на базе @c032a0274: `1` и `0` — красный);
  - раздел `#### Федерация SA-ключа` до следующего заголовка:
    `git show HEAD:docs/content/api/tokens.mdx | awk '/^#### Федерация SA-ключа/{f=1;next} f&&/^#/{exit} f{print}'`
    — строк больше `0`; в нём `grep -c -i -E 'regex|регулярн'` → `0` и
    `grep -c -i -E 'дословн|точн'` → не меньше `1`;
  - `git grep -c -E 'служебн.{0,40}(освобожден|не судит)' -- docs/content/api/tokens.mdx docs/content/architecture/authz.mdx` → не меньше `1` в каждом файле.
- Правка `.proto` (только комментарий) — регенерацией (`proto-sync`), `buf lint` и
  `buf breaking` зелёные.
- Задача kacho о странице края `authn.mdx` (п. 4 «Уровень аутентификации») заведена со ссылкой на
  эту приёмку.
