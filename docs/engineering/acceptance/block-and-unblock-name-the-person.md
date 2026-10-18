# Block и Unblock — предмет один: личность, а не членство — Acceptance

> **Статус:** DRAFT
> **Статическая форма:** DRAFT; действующий вердикт выводится из внешнего события и записи ревью
> **История review:** — (только дописывается)
> **Дата:** 2026-10-16
> **Эпик/issue:** kaname#746 · kaname#721

## Обзор

Контракт `UserService` описывает предмет блокировки в четырёх местах по-разному: `Block` —
«личность больше не входит нигде на платформе», а `Unblock`, оба сообщения запроса и абзац об
идемпотентности — «строка членства» и «вход в этот аккаунт». Поведение службы однозначно и
совпадает с первым описанием: состояние `inviteStatus` одно на человека, `Block` и `Unblock`
переключают его для всей платформы и строк членства не трогают ни в одну сторону. Приёмка
закрепляет это поведение контрактом; тексты приводятся к нему. Наблюдаемое поведение службы
не меняется.

Понятия «вход в аккаунт» на проводе нет: удостоверение выдаётся человеку, а не членству,
поэтому «человек снова входит в оба аккаунта» наблюдается черным ящиком как пара фактов —
состояние личности и нетронутые членства, — а на уровне службы как исход двери выдачи для
каждого аккаунта (второй держатель ниже).

## Что НЕ входит

- Прочие задачи полосы (kaname#755, #718, #749) — у каждой своя приёмка.
- Смена радиуса блокировки (пер-аккаунтная блокировка). Аккаунту служит `RemoveFromAccount`;
  эта приёмка его поведения не меняет.
- Комментарии Go в `internal/apps/kaname/api/user/set_blocked.go` поведения не определяют,
  но называют тот же предмет неверно; их приведение — в DoD этой приёмки (полоса реализации).

## Полоса и фикстуры (общие для BUP-01…03)

**Полоса:** собственный публичный фронт kaname (`{{ownRestBaseUrl}}`, REST `/iam/v1/…`),
полоса предъявленного удостоверения. Край kacho в сценариях не участвует.

**Фикстуры** — волна церемонии (`tests/authz-fixtures/seed_ceremony.py --wave`, `seed_cap`) и
машинный посев (`tests/authz-fixtures/seed_own_stand.py`):

| имя в окружении | кто это | откуда |
|---|---|---|
| `jwtHumanCapAdminStepUp` | человек слота `CapAdmin`, `system_admin` облака, сессия уровня «2» (держит `identity_suspender`) | `seed_ceremony.py` `ADMIN_SLOTS`, `grant_cluster_admin` |
| `ceremonyCapAdminAccountId` | личный аккаунт этого человека | `seed_cap` (`resolve_tenant`) |
| `ceremonyCapBlockedUserId` | человек, которого блокирует набор администраторов облака | `seed_cap`, `person("cap-blocked")` |
| `ceremonyCapBlockedEmail` | адрес того же человека | **новый ключ**: `seed_cap` уже получает его из `person(...)` и не сохраняет; ключ добавляет производитель проб тем же изменением, что и кейсы |
| `jwtAccountAdminA` / `accountAId` | служебная учётка — распорядитель аккаунта A | `seed_own_stand.py` |

**Второе членство заводится кейсом, а не посевом.** До BUP-01 кейс вызывает
`POST /iam/v1/memberships` с телом `{"accountId": "{{ceremonyCapAdminAccountId}}", "email": "{{ceremonyCapBlockedEmail}}"}`
под `jwtHumanCapAdminStepUp` и тот же вызов с `{"accountId": "{{accountAId}}", …}` под
`jwtAccountAdminA`; каждый шаг доводит Operation до `done=true` и утверждает отсутствие `error`.
Затем кейс читает `GET /iam/v1/accounts/{{ceremonyCapAdminAccountId}}/memberships` и
`GET /iam/v1/accounts/{{accountAId}}/memberships` (тем же предъявителем, что заводил) и
запоминает `state` строки с `userId = {{ceremonyCapBlockedUserId}}` в каждом — значения
`S_cap`, `S_a`. Строк человека в каждом перечне ровно одна; иначе шаг красный с текстом
«условие не создано: членство не заведено».

**Уборка** — в том же кейсе и на падении: `Unblock` (если состояние `BLOCKED`), затем
`POST /iam/v1/users/{{ceremonyCapBlockedUserId}}:removeFromAccount` по каждому из двух аккаунтов
(тем же предъявителем, что заводил членство). Кейс живёт в коллекции
`kaname-cluster-admins` (тот же человек уже читается её кейсом CAP-12, и порядок внутри одной
коллекции последовательный), после CAP-12.

## Сценарий 01: Block переключает личность, членства не тронуты

**ID:** BUP-01

**Given** `ceremonyCapBlockedUserId` — действующая личность (`inviteStatus = ACTIVE`) с членствами
в двух аккаунтах, `S_cap` и `S_a` запомнены
**When** клиент вызывает `POST /iam/v1/users/{{ceremonyCapBlockedUserId}}:block` с телом `{}` под
`jwtHumanCapAdminStepUp`
**Then** `200`, тело — `Operation` (`id` непуст); полл `GET /operations/{id}` до `done=true`,
`error` отсутствует, `response.inviteStatus = "BLOCKED"`, `response.id = {{ceremonyCapBlockedUserId}}`
**And** `GET /iam/v1/users/{{ceremonyCapBlockedUserId}}` → `200`, `inviteStatus = "BLOCKED"`
**And** строка человека в перечне членств аккаунта `ceremonyCapAdminAccountId` несёт `state = S_cap`,
в перечне аккаунта `accountAId` — `state = S_a`: блокировка членства не трогает ни в одном аккаунте.

## Сценарий 02: Unblock переключает ту же личность обратно (близнец BUP-01)

**ID:** BUP-02 — отличается от BUP-01 ровно глаголом (`:unblock` вместо `:block`); Given — исход
BUP-01 (личность `BLOCKED`), предъявитель и тело те же.

**When** `POST /iam/v1/users/{{ceremonyCapBlockedUserId}}:unblock` с телом `{}` под
`jwtHumanCapAdminStepUp`
**Then** `200`, `Operation`; полл до `done=true` без `error`, `response.inviteStatus = "ACTIVE"`
**And** `GET /iam/v1/users/{{ceremonyCapBlockedUserId}}` → `inviteStatus = "ACTIVE"`
**And** строки человека в обоих перечнях членств несут `state = S_cap` и `state = S_a` — снятие
блокировки тоже не трогает членств, и аргумент глагола — личность, а не строка одного аккаунта.

## Сценарий 03: Unblock действующей личности — успех (идемпотентность)

**ID:** BUP-03 — отличается от BUP-02 ровно исходным состоянием (`ACTIVE` вместо `BLOCKED`).

**Given** исход BUP-02 — личность `ACTIVE`
**When** тот же вызов `:unblock`
**Then** `200`, `Operation`; полл до `done=true` без `error`, `response.inviteStatus = "ACTIVE"`.

## Сценарий 04: четыре места контракта называют один предмет

**ID:** BUP-04

**Then** в `proto/kaname/cloud/iam/v1/user_service.proto` описание `rpc Unblock`, комментарии
полей `BlockUserRequest.user_id` и `UnblockUserRequest.user_id` и абзацы об идемпотентности обоих
глаголов называют предмет так же, как описание `rpc Block`: личность (`User`) на всей платформе;
слов «строка членства», «членство» и «вход в этот аккаунт» о предмете блокировки в них нет
**And** то же — в шапках типов `BlockUserUseCase`, `UnblockUserUseCase` и их конструкторов
(`internal/apps/kaname/api/user/set_blocked.go`).

## Сценарий → производитель

| ID | что производит «Тогда» | координата в дереве | чем измерено |
|---|---|---|---|
| BUP-01, BUP-02 | одно состояние на человека и его запись без касания членств | `internal/apps/kaname/api/user/set_blocked.go` `setInviteStatusUseCase` (поле `target`, стр. 128; оба направления — одна реализация); глобальные ключи личности `users_identity_email_uniq`, `users_identity_external_id_uniq` (миграция 20260823050000) | прочитано в `set_blocked.go` @b20866a67; `TestUserBlock_ReachesEveryAccountBecauseThePersonIsOneRow` (`internal/apps/kaname/api/audit/user_block_integration_test.go:204`) утверждает обе стороны: дверь выдачи `AccountForUser` и разрешение субъекта отказывают после `Block` и снова отвечают после `Unblock`, а `membershipStates` до, после `Block` и после `Unblock` — `{accA: ACTIVE, accB: ACTIVE}` |
| BUP-03 | запись состояния, а не перехода | тот же use-case: отказ только `PENDING` (`set_blocked.go:192-193`, `pendingRefusal` — `helpers.go:32`), иначе запись целевого состояния | прочитано @b20866a67 |
| BUP-04 | совпадение текстов | правка комментариев полосы реализации | предикаты DoD ниже |

## DoD

- **BUP-01…BUP-03** — newman-кейс в `tests/newman/cases/kaname-cluster-admins.py` (ID —
  `IAM-USER-BLOCK-BUP-01-…` и т.д.), утверждения — пара «HTTP-статус + `code`» на синхронной
  полосе и исход Operation по `response`, как в «Тогда»; ключ `ceremonyCapBlockedEmail` в
  `seed_cap` и строка самопроверки посева «адрес сохранён и равен адресу заведённого человека» —
  тем же изменением. Кейс и ключ заводит производитель проб (`qa-test-engineer`).
- **Вход в оба аккаунта** — второй держатель на уровне службы, уже в дереве и зелёный:
  `TestUserBlock_ReachesEveryAccountBecauseThePersonIsOneRow`. Его утверждения не ослабляются.
- **BUP-04**, предикаты на голове полосы (база @b20866a67 — значение в скобках, красный):
  - `git show HEAD:proto/kaname/cloud/iam/v1/user_service.proto | grep -c -i -E 'block(ing)? a membership|membership (that is already blocked|was suspended)|this membership was|unblocks the specified user membership|unblocking an active membership|membership row to (un)?block|suspended membership|authenticate into that'`
    → `0` (база: `8`);
  - блок описания `rpc Unblock` (от `// Unblocks the specified` до `rpc Unblock`):
    `git show HEAD:proto/kaname/cloud/iam/v1/user_service.proto | awk '/^  \/\/ Unblocks the specified/{f=1} f{print} f&&/rpc Unblock /{exit}' | grep -c -i -E 'platform|everywhere|every Account'`
    → не меньше `1` (база: `0`) — радиус снятия назван, а не только снято неверное слово;
  - поля запросов: `git show HEAD:proto/kaname/cloud/iam/v1/user_service.proto | awk '/^message (Block|Unblock)UserRequest/{f=1} f{print} f&&/^}/{f=0}' | grep -c -i membership`
    → `0` (база: `2`);
  - `git show HEAD:internal/apps/kaname/api/user/set_blocked.go | grep -c -E 'the membership may|already-blocked membership|This membership was suspended'`
    → `0` (база: `7`).
- Правка `.proto` (только комментарии) — регенерацией (`proto-sync`), `buf lint` и `buf breaking`
  зелёные; сайт документации (`docs/content/api/user.mdx`, раздел «Block / Unblock») уже называет
  радиус «вся платформа» и не правится.
