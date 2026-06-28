# 03. User

## Назначение

**User** — mirror identity-сущности из внешнего IdP (Ory Kratos). В Kachō
у User'а нет паролей и MFA-настроек — этим занимается IdP. Сервис `kacho-iam`
хранит только то, что нужно для авторизации и audit'a: `external_id` (subject
из OIDC-токена), `email`, `display_name`, `account_id`, `invite_status`.

Особенность: **публичный** `UserService` НЕ имеет метода `Create` — пользователи
создаются ТОЛЬКО двумя путями:

1. **Self-signup** через OIDC-callback (Ory Kratos logged in → api-gateway вызывает
   `InternalUserService.UpsertFromIdentity`).
2. **Invite-flow** через `UserService.Invite` — admin создает PENDING-запись с
   `external_id=""`, Kratos шлет magic-link, при первом login заполняется
   `external_id`.

**Use-cases:**
- Mirror identity для AccessBinding (`subject_type=user`, `subject_id=usr_*`).
- Audit-trail: principal в operations / audit_outbox.
- Invite-flow для tenant-onboarding'a (admin приглашает по email).

**Ограничения:**
- `external_id` immutable (изменение → identity-mismatch).
- `account_id` immutable.
- Создавать User напрямую нельзя — только через Invite или UpsertFromIdentity.

## Доменная модель

| Поле           | Тип              | Обязательное | Immutable | Описание                                                            |
|----------------|------------------|--------------|-----------|---------------------------------------------------------------------|
| `id`           | `UserID`         | да           | да        | `usr<17-char>`. Длина 20.                                           |
| `account_id`   | `AccountID`      | да           | **да**    | FK → `accounts(id)`.                                                |
| `external_id`  | `ExternalSubject`| зависит от status | **да** | OIDC `sub` (Ory). PENDING → "", ACTIVE/BLOCKED → non-empty.         |
| `email`        | `Email`          | да           | нет       | `^[^\s@]+@[^\s@]+\.[^\s@]+$`, ≤254.                                 |
| `display_name` | `DisplayName`    | нет          | нет       | len 1..128.                                                          |
| `invite_status`| `InviteStatus`   | да           | нет       | `PENDING | ACTIVE | BLOCKED`.                                       |
| `invited_by`   | `UserID`         | нет          | да        | Кто пригласил (для PENDING). "" если self-signup.                   |
| `created_at`   | `time.Time`      | да (server)  | да        | UTC.                                                                |

**DB CHECK `users_invite_status_consistency`:**
```
PENDING ⇔ external_id = '';  ACTIVE/BLOCKED ⇔ external_id <> ''
```

**Partial UNIQUE:** `users_account_external_id_unique ON (account_id, external_id) WHERE external_id <> ''`.

**ID prefix:** `usr`.
**DB table:** `kacho_iam.users` (миграция 0001:1199).

**FK contract:**

```
accounts(id) ──RESTRICT── users.account_id
users(id) ──RESTRICT── accounts.owner_user_id  (circular at bootstrap — см. раздел «Подробности реализации»)
users(id) ──RESTRICT── access_bindings.subject_id (когда subject_type='user')
```

## Sequence diagram — Invite-flow

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Tenant admin
    participant GW as api-gateway
    participant IAM as kacho-iam :9090
    participant DB as Postgres
    participant Kratos as Kratos
    participant Invitee as Invitee inbox
    participant Ory as Ory

    Admin->>GW: POST /iam/v1/users:invite<br/>{"account_id":"acc","email":"bob@x","role_id":"rol_..."}
    GW->>IAM: gRPC UserService.Invite
    IAM->>IAM: AntiAnonymous + Validate (email)
    IAM->>DB: BEGIN
    IAM->>DB: INSERT INTO operations
    IAM->>DB: INSERT INTO users (status=PENDING, external_id='', invited_by=$admin)
    IAM->>DB: INSERT INTO access_bindings (subject=user:usr_pending, role_id, scope=project)
    IAM->>DB: INSERT INTO fga_outbox (role-tuple + hierarchy)
    IAM->>DB: COMMIT
    IAM->>Kratos: POST /admin/recovery/link (magic-link delivery)
    Kratos->>Invitee: Email с magic-link
    IAM-->>GW: Operation
    GW-->>Admin: 200 {operationId, userId:"usr_pending"}

    Note over Invitee,Ory: ─── ASYNC: invitee кликает по link ───
    Invitee->>Ory: clicks link → OIDC login flow
    Ory->>GW: OIDC callback (id_token c "sub":"ory-sub-xyz", email)
    GW->>IAM: gRPC InternalUserService.UpsertFromIdentity<br/>{external_id:"ory-sub-xyz", email:"bob@x"}
    IAM->>DB: SELECT user WHERE account_id=? AND email=? AND status=PENDING
    alt Existing PENDING
        IAM->>DB: UPDATE users SET external_id=$sub, status=ACTIVE WHERE id=usr_pending
    else No PENDING row
        IAM->>DB: INSERT users (status=ACTIVE, external_id=$sub, ...)
    end
    IAM-->>GW: User (ACTIVE, usr_id)
    GW-->>Invitee: Set-Cookie session ; 302 → tenant-UI
```

## Sequence diagram — UpsertFromIdentity (self-signup bootstrap)

```mermaid
sequenceDiagram
    autonumber
    participant User as Browser
    participant GW as api-gateway
    participant Ory
    participant IAM as kacho-iam :9091
    participant DB as Postgres

    User->>Ory: OIDC login (first time)
    Ory-->>GW: id_token (sub, email)
    GW->>IAM: InternalUserService.UpsertFromIdentity<br/>{external_id, email, display_name}
    IAM->>DB: SELECT user by (account_id IS NULL, external_id) → not found
    Note over IAM,DB: Bootstrap path (новый user без Account)
    IAM->>DB: BEGIN
    IAM->>DB: INSERT users (status=ACTIVE, external_id, email)
    IAM->>DB: INSERT accounts (owner_user_id=$new_user)
    IAM->>DB: INSERT projects (account_id=$new_account, name='default')
    IAM->>DB: INSERT access_bindings (subject=$user, role=account-admin)
    IAM->>DB: INSERT fga_outbox (owner + hierarchy + role)
    IAM->>DB: COMMIT
    IAM-->>GW: User (usr_*, account_id=acc_*)
```

## API surface

### Public gRPC (порт 9090)

| RPC      | Sync/Async | Описание                                              |
|----------|------------|-------------------------------------------------------|
| `Get`    | sync       | Получает User по id.                                  |
| `List`   | sync       | Список (filter by `account_id`).                      |
| `Invite` | async      | Создает PENDING-User + AccessBinding + Kratos magic-link |
| `Delete` | async      | Удаление. RESTRICT-FK если есть AccessBinding.        |
| ~~`Create`~~ | — | **Намеренно отсутствует.** Используйте Invite или OIDC self-signup. |

### Internal gRPC (порт 9091)

| RPC                    | Описание                                                    |
|------------------------|-------------------------------------------------------------|
| `UpsertFromIdentity`   | OIDC-callback creates/updates User (+ bootstrap Account/Project). |
| `Get`                  | Admin Get.                                                  |

### REST mapping

| HTTP    | Path                              | gRPC mapping              |
|---------|-----------------------------------|----------------------------|
| GET     | `/iam/v1/users/{userId}`          | `UserService.Get`         |
| GET     | `/iam/v1/users`                   | `UserService.List`        |
| POST    | `/iam/v1/users:invite`            | `UserService.Invite`      |
| DELETE  | `/iam/v1/users/{userId}`          | `UserService.Delete`      |

## Конфигурация

| Env var                         | YAML key                            | Default                  | Описание                                  |
|---------------------------------|--------------------------------------|--------------------------|-------------------------------------------|
| `KACHO_IAM_KRATOS_ADMIN_URL`    | `extapi.kratos.admin-url`           | (none)                   | URL Kratos admin API для magic-link.      |
| `KACHO_IAM_KRATOS_ADMIN_TOKEN`  | `extapi.kratos.admin-token`         | (none)                   | Bearer token для Kratos admin.            |

В dev без Kratos используется stub-клиент (`clients.NewKratosAdminStub()`) —
invite создает User, но magic-link не отправляется (логируется как WARN).

## Как пользоваться

### Invite (curl)

```bash
# Создает PENDING-User в Account acc_xxx с role rol_viewer на project prj_yyy.
curl -X POST http://localhost:18080/iam/v1/users:invite \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id":"acc_xxx",
    "email":"bob@example.com",
    "role_id":"rol_viewer",
    "resource_type":"project",
    "resource_id":"prj_yyy"
  }'
# → {operationId, user_id:"usr_..."}
```

### Get / List

```bash
curl http://localhost:18080/iam/v1/users/usr_xxx -H "Authorization: Bearer $TOKEN"
curl "http://localhost:18080/iam/v1/users?account_id=acc_xxx" -H "Authorization: Bearer $TOKEN"
```

### gRPC InternalUpsertFromIdentity (admin only)

```bash
grpcurl -plaintext -d '{
  "external_id":"ory-sub-xyz",
  "email":"alice@example.com",
  "display_name":"Alice"
}' localhost:9091 kacho.cloud.iam.v1.InternalUserService/UpsertFromIdentity
```

### Идемпотентность

`UpsertFromIdentity` идемпотентен по `(account_id, external_id)`: повторный
вызов с тем же `external_id` возвращает уже созданный User row без `ALREADY_EXISTS`.

### Типичные ошибки

| Сценарий                                  | gRPC code             | HTTP | Текст                                          |
|-------------------------------------------|------------------------|------|------------------------------------------------|
| Email занят в Account (PENDING)           | `ALREADY_EXISTS`       | 409  | `User with email already invited`              |
| Email невалиден                           | `INVALID_ARGUMENT`     | 400  | `Illegal argument email: invalid format`       |
| Delete user, на которого ссылается binding| `FAILED_PRECONDITION`  | 412  | `user is referenced by access_bindings`        |
| Update с `external_id` (через internal)   | `INVALID_ARGUMENT`     | 400  | `external_id is immutable after User.Create`   |

## Как воспроизвести локально

```bash
cd kacho-deploy && make dev-up
kubectl -n kacho port-forward svc/api-gateway 18080:8080 &

cd kacho-iam && SERVICE=iam-user ./tests/newman/scripts/run.sh

# psql:
cd kacho-deploy && make psql SVC=iam
# > SELECT id, account_id, email, invite_status, external_id FROM kacho_iam.users LIMIT 10;

# Integration: invite-flow + UpsertFromIdentity.
cd kacho-iam && GOWORK=off go test -short -count=1 -timeout 120s \
  -run "TestUser|TestUpsertFromIdentity|TestInvite" \
  ./internal/repo/kacho/pg/...
```

## Подробности реализации

- **Use-cases:** `internal/apps/kacho/api/user/{get,list,delete,invite,upsert_from_identity}.go`.
- **Handler:** `internal/apps/kacho/api/user/handler.go` (public) + `internal_handler.go` (Internal).
- **Repo:** `internal/repo/kacho/pg/user_repo.go` + `user_pool_repo.go` (Hydra hooks).
- **Kratos client:** `internal/clients/kratos_admin.go` (production HTTP) + stub.
- **Bootstrap path:** `UpsertFromIdentity` создает User + Account + Project +
  AccessBindings в одной transaction, минуя per-resource `CreateUseCase`.
  FGA tuples — все в одном `fga_outbox` batch.
- **Invite-flow:** `users.invited_by` хранит admin'а; на match'е (`account_id,
  email, status=PENDING`) Upsert обновляет PENDING-row → ACTIVE с
  `external_id := <new sub>`.
- **DB:** таблица `users` со столбцами `id, account_id, external_id, email,
  display_name, invite_status, invited_by, created_at`.
- **Indexes:** PK; partial UNIQUE `users_account_external_id_unique`; INDEX
  `users_account_email_idx`.
- **CHECK:** `users_invite_status_consistency` (PENDING ⇔ external_id='').

## Gotchas / известные ограничения

- **PENDING row blocks email re-invite** — если Bob уже приглашен (PENDING),
  повторный `Invite` с тем же email вернет `ALREADY_EXISTS`. Admin должен
  Delete + повторить, либо ждать первого login (PENDING → ACTIVE автоматом).
- **Bootstrap circular FK** — Account.owner_user_id → users(id); first User
  создается ДО Account (within-tx INSERT users → INSERT accounts с
  owner_user_id=just-created). Postgres допускает forward-ref внутри одной TX.
- **Email — НЕ уникален** глобально (даже не per-Account, кроме PENDING).
  Один человек может быть User'ом в N аккаунтах через одну email-у.
- **Self-signup vs invite race** — если Bob делает self-signup в момент,
  когда Alice его invite'ит, есть окно, в котором создаются 2 row:
  bootstrap (ACTIVE, отдельный Account) + PENDING-invite. Деталь в работе.

## Связанные компоненты

- [`01-account.md`](01-account.md) — Account создается вместе с первым User'ом.
- [`08-access-binding.md`](08-access-binding.md) — bindings на `subject_type=user`.
- [`21-internal-iam.md`](21-internal-iam.md) — `UpsertFromIdentity` детали.

## Ссылки на код

- `internal/domain/user.go`
- `internal/apps/kacho/api/user/`
- `internal/repo/kacho/pg/user_repo.go`, `user_pool_repo.go`
- `internal/clients/kratos_admin.go`
- `internal/migrations/0001_initial.sql:1199-1219`
- `tests/newman/cases/iam-user-*.py`
