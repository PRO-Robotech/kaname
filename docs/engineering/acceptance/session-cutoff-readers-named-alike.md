# Читатели отсечки сессии названы одинаково в контракте и на странице церемонии — Acceptance

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** — (только дописывается)
> **Дата:** 2026-10-16
> **Эпик/issue:** kaname#746 · kaname#749

## Обзор

Комментарий контракта `InternalHumanSessionService` говорит: «One reader of the cutoff, and it is
on the edge». Страница церемонии говорит, что точка авторизации службы отвечает `login_required`
на сессию старше отсечки, — то есть отсечку читает и служба. Верна страница: сам глагол
`Resolve` отсечку не применяет (это и хотел сказать комментарий), но служба судит её на своих
путях — на выдаче кода церемонии и на перечне сессий человека. Читателей двое по полосам: край —
на предъявлении сессии к краю (`SessionCutoffOf`), служба — на выдаче из сессии. Приёмка
закрепляет исход точки авторизации контрактом, и комментарий приводится к нему. Наблюдаемое
поведение службы не меняется.

## Что НЕ входит

- Сравнение отсечки краем и форма `SessionCutoffOf` — не меняются; страница края — kacho.
- Поведение `Resolve` (отсечку не применяет, «нет сессии» — один ответ) — не меняется; меняется
  только число читателей, названное в его комментарии.
- Прочие задачи полосы (kaname#721, #755, #718).

## Полоса и фикстуры (общие для SCR-01…02)

**Полоса:** поверхность выдачи службы (`{{iamRegistryTokenBaseUrl}}`, точка авторизации
`GET /iam/v1/authorize`) и собственный публичный фронт (`{{ownRestBaseUrl}}`) для глагола,
ставящего отсечку. Набор — `tests/newman/cases/kaname-authorization-code.py` (его помощники
запроса авторизации: печенье только явным заголовком, перенаправлению прогонщик не следует).

**Фикстуры** — волна церемонии (`tests/authz-fixtures/seed_ceremony.py --wave`):

| имя в окружении | кто это | откуда |
|---|---|---|
| `oauthClientId`, `oauthRedirectUri` | конфиденциальный клиент `ACTIVE` и его адрес возврата | посев церемонии (`create_confidential`) |
| `jwtBootstrap` | машинный `system_admin` облака (держит `identity_suspender`; от порога уровня освобождён) | `bootstrap(stand)` |
| `ceremonyCutoffUserId`, `ceremonyCutoffSession` | **новый слот**: отдельный человек со вторым фактором и носителем своей сессии уровня «2» | заводит производитель проб тем же изменением, что и кейс: `person("cutoff")`, затем `level2_session` (`seed_ceremony.py:790`); человек отдельный, потому что отсечка, поставленная ему, оборвала бы выданное людям соседних кейсов |

Отсечку ставит `POST /iam/v1/users/{{ceremonyCutoffUserId}}:resetSecondFactor` — сброс второго
фактора администратором облака: запись сессии он **не снимает**, а покрывает отсечкой (контракт
глагола: «EVERY session of the person is covered by a cutoff at `now`»). Поэтому после него
сессия `ceremonyCutoffSession` жива как запись и отрезана только отсечкой — ровно предмет
сценария. Повторный прогон получает свежий слот из посева.

## Сценарий 01: сессия до отсечки — код выдан (контроль)

**ID:** SCR-01

**Given** `ceremonyCutoffSession` — живая сессия человека `ceremonyCutoffUserId`, отсечки нет
**When** браузер вызывает `GET /iam/v1/authorize` с `client_id={{oauthClientId}}`,
`redirect_uri={{oauthRedirectUri}}`, `response_type=code`, `scope` набора, `state` длиной 22 знака,
PKCE `S256`, с печеньем `kaname_session={{ceremonyCutoffSession}}`
**Then** `302`, `Location` — адрес возврата с параметрами `code` (непуст) и `state` дословно.

## Сценарий 02: сессия старше отсечки — `login_required` (близнец SCR-01)

**ID:** SCR-02 — отличается от SCR-01 ровно одним фактом: человеку поставлена отсечка.

**Given** `POST /iam/v1/users/{{ceremonyCutoffUserId}}:resetSecondFactor` с телом `{}` под
`jwtBootstrap` → `200`, `Operation`; полл до `done=true` без `error`
**When** тот же запрос авторизации с тем же печеньем и новым `state`
**Then** `302`, `Location` — адрес возврата с `error=login_required` и `state` дословно; параметра
`code` в нём нет.

## Сценарий 03: контракт и страница называют читателей одинаково

**ID:** SCR-03

**Then** комментарий `InternalHumanSessionService` (`proto/kaname/cloud/iam/v1/human_session_service.proto`,
пункт «It does NOT apply the revocation cutoff») не называет край единственным читателем
отсечки и называет оба: край — на предъявлении сессии (через `SessionCutoffOf`), службу — на
выдаче из сессии (код церемонии) и на перечне сессий человека
**And** строка таблицы ответов `docs/content/api/oauth-ceremony.mdx` о `login_required` по-прежнему
называет сессию старше отсечки (держатель исхода SCR-02 на странице не снимается).

## Сценарий → производитель

| ID | что производит «Тогда» | координата в дереве | чем измерено |
|---|---|---|---|
| SCR-01 | выдача кода живой сессии | `internal/handler/ceremonyhttp/authorize.go` (ветвь `VerdictIssued`, `302` с `Location`); вариант использования — `internal/apps/kaname/api/oauth_ceremony/authorize.go` | прочитано @b20866a67 |
| SCR-02 | `login_required` на сессию, отрезанную отсечкой | чтение сессии отсечку не применяет (`oauth_ceremony/session_authority.go`, шапка `SessionResolver`); выдача судит её в операторе: `internal/repo/kaname/pg/oauth_ceremony_repo.go:313` (`sessionCutOffBySubjectSQL`, сравнение включающее, как у края) → `domain.ErrCeremonySessionNotLive` → `VerdictLoginRequired` (`oauth_ceremony/authorize.go:233-237`) → `302` с `error=login_required` (`ceremonyhttp/authorize.go`); отсечку ставит `internal/apps/kaname/api/user/reset_second_factor.go:225` (`RevokeBefore: now`) | прочитано @b20866a67; тот же предикат стоит в перечне сессий (`human_session_repo.go:173`) и в хранилище кодов (`oauth_ceremony_vaults.go:424`) — `git grep -n 'sessionCutOffBySubjectSQL' -- internal ':!*_test.go'` |
| SCR-03 | совпадение текстов | правка комментария полосой реализации | предикаты DoD ниже |

## DoD

- **SCR-01, SCR-02** — newman-кейс `IAM-AUTHCODE-SCR-02-CUTOFF-LOGIN-REQUIRED` в
  `tests/newman/cases/kaname-authorization-code.py` (шаг контроля SCR-01 и шаг SCR-02 — в одном
  кейсе, та же сессия); ключи слота `cutoff` в посеве церемонии и строка самопроверки посева
  «у слота живая сессия уровня «2» и заведённый второй фактор» — тем же изменением. Заводит
  производитель проб (`qa-test-engineer`). Если коллекция гонится волной, где `jwtBootstrap`
  не посеян, ключ — «условие не создано» помеченным утверждением, а не зелёное.
- **SCR-03**, предикаты на голове полосы (база @b20866a67 — в скобках, красный):
  - `git show HEAD:proto/kaname/cloud/iam/v1/human_session_service.proto | grep -c -i 'One reader of the cutoff'`
    → `0` (база: `1`);
  - пункт комментария (от `It does NOT apply the revocation cutoff` до `It does NOT distinguish`):
    `git show HEAD:proto/kaname/cloud/iam/v1/human_session_service.proto | awk '/It does NOT apply the revocation cutoff/{f=1} f&&/It does NOT distinguish/{exit} f{print}' | grep -c -i -E 'issu|authorization code|this service'`
    → не меньше `1` (база: `0`);
  - `git show HEAD:docs/content/api/oauth-ceremony.mdx | grep -c 'сессия старше отсечки'` → `1`
    (база: `1`, не снимается).
- Довод пункта о Ф1-56 («UNIMPLEMENTED only about the cutoff — pass loudly») переписывается в
  терминах глагола: `Resolve` отсечку не применяет, и это остаётся; ложным был только счёт
  читателей.
- Правка `.proto` (только комментарий) — регенерацией (`proto-sync`), `buf lint` и `buf breaking`
  зелёные.
