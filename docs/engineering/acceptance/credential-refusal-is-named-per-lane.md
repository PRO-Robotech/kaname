# Отказ удостоверению назван по полосе, которая его производит — Acceptance

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** — (только дописывается)
> **Дата:** 2026-10-16
> **Эпик/issue:** kaname#746 · kaname#718

## Обзор

Отказ аутентификации у службы и у края платформы — два разных ответа двух производителей:
собственный публичный фронт службы отвечает телом
`{"code":16,"message":"credential is not accepted","details":[]}`, край — своим телом с
причиной в `details` (контракт края, kacho). Тексты kaname местами называют один ответ на обе
полосы: описание `UserService.Delete` (контракт и страница) приписывает человеку, который ходит
через край, текст службы; обзор API объявляет, что отсутствующее и непринятое удостоверение
получают один ответ, хотя собственный фронт отвечает на отсутствие другим текстом
(«назовись»). Поведение обеих полос однозначно (производители ниже); приёмка закрепляет его
контрактом **по полосам**, и тексты приводятся к нему. Утверждение «побайтово равный отказ»
остаётся там, где оно истинно, — между причинами негодности **на одной полосе**. Наблюдаемое
поведение службы не меняется.

## Что НЕ входит

- Тело отказа края и страница края `gateway/docs/content/architecture/authn.mdx` (kacho): это
  контракт другого репозитория; его утверждение «побайтово равны» о службе и крае снимается
  задачей в kacho со ссылкой на эту приёмку. Тексты kaname тела края не воспроизводят — только
  ссылаются на страницу края.
- `docs/content/architecture/identity.mdx`, раздел «`UNAUTHENTICATED` (401) приходит по четырём
  причинам», описывает полосу края (`api-gateway` проверяет удостоверение) и его тело не
  называет; он не правится.
- Указание повысить уровень (`authentication level is insufficient: …`) — уже одно на все
  поверхности и не меняется.
- Прочие задачи полосы (kaname#721, #755, #749).

## Полоса и фикстуры (общие для RCL-01…03)

**Полоса:** собственный публичный фронт kaname (`{{ownRestBaseUrl}}`). Фикстура —
`existingAccountId` машинного посева (`tests/authz-fixtures/seed_own_stand.py`) и годный
предъявитель `jwtAccountAdminA` того же посева для контроля «тот же путь обслуживается».
Негодные предъявители порождает кейс сам: строка `not-a-credential` и строка формы JWT с
негодной подписью `eyJhbGciOiJSUzI1NiJ9.e30.bad`.

## Сценарий 01: негодное удостоверение — один текст на все причины

**ID:** RCL-01

**Given** путь `GET /iam/v1/accounts/{{existingAccountId}}` обслуживается под `jwtAccountAdminA`
(`200`, тело несёт `createdAt`) — положительный контроль
**When** тот же запрос с `Authorization: Bearer not-a-credential`
**Then** `401`, тело побайтово `{"code":16,"message":"credential is not accepted","details":[]}`,
заголовок `WWW-Authenticate: Bearer`
**And** тот же запрос с `Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.e30.bad` даёт тело, побайтово
равное первому, и отличное от тела положительного контроля.

## Сценарий 02: удостоверения нет — другой текст (близнец RCL-01)

**ID:** RCL-02 — отличается от RCL-01 ровно отсутствием заголовка `Authorization`.

**When** `GET /iam/v1/accounts/{{existingAccountId}}` без `Authorization`
**Then** `401`, тело побайтово
`{"code":16,"message":"no credential presented; authenticate with authorization: Bearer <token>","details":[]}`,
заголовок `WWW-Authenticate: Bearer`
**And** тело отлично от тела RCL-01 — различаются два состояния **запроса**, известные самому
вызывающему, а не причины негодности предъявленного.

> Допущение (снимается первым прогоном кейса): на посадке стенда фронт дозванивается до
> собственного gRPC-слушателя под клиентским листом службы — именно на этом пути ветвь
> безымянного вызывающего отвечает `UNAUTHENTICATED` (проба
> `TestOwnRESTFrontHop_UnnamedCallerIsStillToldToIdentifyItself`). Если прогон покажет `403`,
> сценарий возвращается в приёмку, а не ослабляется до `oneOf`.

## Сценарий 03: тексты называют отказ по полосе

**ID:** RCL-03

**Then** описание `rpc Delete` в `proto/kaname/cloud/iam/v1/user_service.proto` (абзац
«EVERYTHING ISSUED TO THE IDENTITY ENDS WITH IT») и тот же абзац на странице
`docs/content/api/user.mdx` (раздел удаления личности) называют полосу отказа: на собственном
фронте службы — `UNAUTHENTICATED` с текстом `credential is not accepted`, через край — отказ края
(ссылкой на его страницу, без воспроизведения тела)
**And** `docs/content/api/rest-surface.mdx` (раздел о негодном удостоверении) называет оба
текста своего фронта — негодному и отсутствующему — и говорит, что тело края другое и
принадлежит контракту края
**And** `docs/content/api/overview.mdx` не объявляет отсутствие удостоверения одним ответом с
непринятым: раздел о способах предъявления и строка `UNAUTHENTICATED` таблицы кодов называют
текст «назовись» собственного фронта отдельно.

## Сценарий → производитель

| ID | что производит «Тогда» | координата в дереве | чем измерено |
|---|---|---|---|
| RCL-01 | единственный текст отказа негодному на всех причинах, без приложений | `internal/presentedcred/reader.go:90` (`RefusalMessage`), `:719` (`refusal()`, `status.Error` без деталей; оба пути — `:698`, `:712`); заголовок — `internal/restfront/challenge.go:52,98` (`AuthenticationChallenge = "Bearer"` на всяком `401`) | прочитано @b20866a67; держатель на стенде уже есть — `IAM-OWNREST-NEG-BAD-CREDENTIAL` (`tests/newman/cases/kaname-own-rest-front.py:456`) утверждает текст и побайтовое равенство двух причин |
| RCL-02 | «назовись» безымянному | `internal/authzguard/public_caller_policy.go:155` (`UnnamedCallerMessage`), ветвь `:414-415` | `TestOwnRESTFrontHop_UnnamedCallerIsStillToldToIdentifyItself` (`own_rest_front_hop_test.go`), `TestUnnamedCaller_*` (`unnamed_caller_test.go:88,123` — тексты двух половин различны) @b20866a67 |
| RCL-03 | совпадение текстов | правка комментария `.proto` и трёх страниц полосой реализации | предикаты DoD ниже |

## DoD

- **RCL-01** — держатель уже в дереве (`IAM-OWNREST-NEG-BAD-CREDENTIAL`); тело утверждается
  целиком побайтово, а не полем `message`, — это дописывается в тот же кейс.
- **RCL-02** — newman-кейс `IAM-OWNREST-RCL-02-UNNAMED` в
  `tests/newman/cases/kaname-own-rest-front.py`: пара «`401` + `code 16`», тело побайтово, заголовок,
  неравенство с телом RCL-01. Существующий `IAM-OWNREST-NEG-ANONYMOUS` (допуск `oneOf([401, 403])`)
  сужается этим же изменением до `401` — после RCL-02 допуск принимал бы исход, которого фронт не
  производит. Кейсы заводит производитель проб (`qa-test-engineer`).
- **RCL-03**, предикаты на голове полосы (база @b20866a67 — в скобках, красный):
  - `git show HEAD:proto/kaname/cloud/iam/v1/user_service.proto | awk '/EVERYTHING ISSUED TO THE IDENTITY ENDS WITH IT/{f=1} f{print} f&&/rpc Delete /{exit}' | grep -c -i -E 'front|edge'`
    → не меньше `2` (база: `0`);
  - `git show HEAD:docs/content/api/user.mdx | awk '/^Вместе с личностью уходят/{f=1} f&&/^$/{exit} f{print}' | grep -c -E 'фронт|кра[йюе]'`
    → не меньше `2` (база: `0`);
  - `git show HEAD:docs/content/api/rest-surface.mdx | grep -c 'no credential presented'` → не
    меньше `1` (база: `0`); `git show HEAD:docs/content/api/rest-surface.mdx | awk '/^Негодное удостоверение получает/{f=1} f&&/^<\/CodeBlock>/{exit} f{print}' | grep -c -E 'кра[йюе]'`
    → не меньше `1` (база: `0`);
  - `git show HEAD:docs/content/api/overview.mdx | tr '\n' ' ' | grep -o 'ответ на все один' | wc -l`
    → `0` (база: `1`); `git show HEAD:docs/content/api/overview.mdx | grep -c 'удостоверения нет либо оно неизвестно'`
    → `0` (база: `1`); `git show HEAD:docs/content/api/overview.mdx | grep -c 'no credential presented'`
    → не меньше `1` (база: `0`).
- Правка `.proto` (только комментарий) — регенерацией (`proto-sync`), `buf lint` и `buf breaking`
  зелёные; сборка сайта документации — 0 битых ссылок.
- Задача kacho о странице края `authn.mdx` заведена со ссылкой на эту приёмку.
