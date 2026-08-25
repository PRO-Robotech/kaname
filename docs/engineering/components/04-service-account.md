# 04. ServiceAccount

## Назначение

**ServiceAccount** (SA) — это machine identity внутри Account / Project. SA
получает токены не через интерактивный OIDC login, а через **OAuth2
client_credentials** (Ory Hydra) по выпущенным SA-ключам (private_key_jwt,
см. [`05-sa-keys.md`](05-sa-keys.md)).

Каждый SA backed Hydra OAuth client'ом (хранится в Hydra, не в kacho-iam).
kacho-iam держит только запись с id, именем и account_id.

**Use-cases:**
- Сервисная учетка для CI/CD pipeline (терраформ применяет ресурсы как SA).
- Машинная учетка для нагрузки в кластере (Pod аутентифицируется выданным SA-ключом).
- Backend-к-backend RPC (один из сервисов Kachō зовет другой как SA).

**Ограничения:**
- `account_id` immutable.
- Имя уникально per-Account.
- SA-ключи (`sa_keys`) — отдельный sub-resource (см. [`05-sa-keys.md`](05-sa-keys.md)).
- `enabled=false` закрывает КАЖДЫЙ путь выдачи нового токена или ключа
  (token-hook `client_credentials`, федеративная ассерция, `SAKeyService.Issue`,
  docker-token). Уже выданные access-токены НЕ инвалидируются — они доживают
  свой срок; останавливается чеканка новых.

## Доменная модель

| Поле          | Тип                       | Обязательное | Immutable | Описание                                          |
|---------------|---------------------------|--------------|-----------|---------------------------------------------------|
| `id`          | `ServiceAccountID`        | да           | да        | `sva<17-char>`. Длина 20.                         |
| `account_id`  | `AccountID`               | да           | **да**    | FK → `accounts(id) ON DELETE RESTRICT`.           |
| `name`        | `SvcAccountName`          | нет°         | нет       | `^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$` (DNS label, RFC 1123). ° Пустое — сервер подставит имя от `id`. |
| `description` | `Description`             | нет          | нет       | len ≤256.                                          |
| `enabled`     | `bool`                    | да           | нет       | default `true`. Меняется ТОЛЬКО действиями `Disable`/`Enable`, НЕ через `Update`. |
| `created_at`  | `time.Time`               | да (server)  | да        | UTC.                                              |

**ID prefix:** `sva`.
**DB table:** `kacho_iam.service_accounts` (`CREATE TABLE kacho_iam.service_accounts` в `0001_initial.sql`).

**FK contract:**

```
accounts(id) ──RESTRICT── service_accounts.account_id
service_accounts(id) ──CASCADE── service_account_oauth_clients.service_account_id
service_accounts(id) ──RESTRICT── access_bindings.subject_id (когда subject_type='service_account')
```

## Sequence diagram — Create + первый Issue ключа

```mermaid
sequenceDiagram
    autonumber
    participant Admin
    participant GW as api-gateway
    participant IAM as kacho-iam :9090
    participant DB as Postgres
    participant Hydra as Ory Hydra
    participant Out as fga_outbox

    Admin->>GW: POST /iam/v1/serviceAccounts<br/>{"account_id":"acc","name":"ci-pipeline"}
    GW->>IAM: ServiceAccountService.Create
    IAM->>DB: BEGIN
    IAM->>DB: INSERT operations + service_accounts (id=sva_..., enabled=true)
    IAM->>Out: INSERT fga_outbox (parent: iam_account → iam_service_account)
    IAM->>DB: COMMIT
    IAM-->>GW: Operation
    GW-->>Admin: 200 {operationId} → poll → {sva_id}

    Note over Admin,Hydra: ─── Создаем первый OAuth-ключ ───
    Admin->>GW: POST /iam/v1/serviceAccounts/{sva_id}/keys
    GW->>IAM: SAKeyService.Issue
    IAM->>DB: BEGIN
    IAM->>DB: INSERT operations (done=false)
    IAM->>Hydra: POST /admin/clients<br/>{grant_types:["client_credentials"], scope:"kacho.api", audience:[...]}
    Hydra-->>IAM: 201 {client_id, client_secret}
    IAM->>DB: INSERT service_account_oauth_clients (sva_id, public_key_pem, declared_audiences)
    IAM->>DB: UPDATE operations done=true,<br/>response={client_id, client_secret}
    IAM->>DB: COMMIT
    IAM-->>GW: Operation (done=true, response=IssueSAKeyResponse)
    GW-->>Admin: 200 {client_id, client_secret}<br/>!! Это первый и последний раз secret показан !!

    Note over Admin: ─── OpsResponseRedactor ───
    IAM->>DB: UPDATE operations<br/>SET response_data=redact(response, "client_secret")<br/>WHERE id=$opId
    Note over DB: При повторном GET /operations — client_secret уже "<redacted>"
```

## API surface

### Public gRPC (порт 9090)

| RPC       | Sync/Async | Описание                                        |
|-----------|------------|-------------------------------------------------|
| `Create`  | async      | Создает SA в Account (опционально в Project).   |
| `Get`     | sync       | Получает SA по id.                              |
| `List`    | sync       | Список (filter by `account_id`).                |
| `Update`  | async      | UpdateMask: `name`, `description`, `labels`.    |
| `Disable` | async      | Учётка больше не аутентифицируется. Идемпотентно; `v_update` + порог повышенной аутентификации. |
| `Enable`  | async      | Учётка аутентифицируется снова. Идемпотентно; тот же гейт. |
| `Delete`  | async      | RESTRICT-FK если есть active bindings/ключи.    |

**Почему `enabled` НЕ поле маски.** У `Update` пустая маска по конвенции платформы
означает полную замену объекта, а `bool` в proto3 неотличим от неприсланного —
поэтому очевидный вариант «ещё одно поле маски» позволил бы клиенту отключить
учётку, просто его не заполнив. Поле не добавляли. Плюс отключение — событие
(«учётку вывели из эксплуатации»), а не правка атрибута, и в журнале оно обязано
читаться событием: `iam.service_account.disabled` / `.enabled`.

**Про порог повышенной аутентификации.** Он ИНТЕРАКТИВНЫЙ: машинный принципал от
него освобождён платформенным правилом, поэтому для служебной учётки эти RPC
стоят ровно столько же, сколько `Update`. Кто вправе вызвать — решает отношение
`v_update`, то же самое и на том же объекте, что у `Update`.

**Порядок между двумя одновременными запросами не гарантирован** — мутации
асинхронные, поэтому `Enable`, отправленный РАНЬШЕ, может закоммититься ПОЗЖЕ
`Disable`. В инциденте состояние следует перечитывать (`Get` отдаёт `enabled`), а
не полагаться на то, что применён последний отправленный запрос.

SA-ключи — отдельный service (см. [`05-sa-keys.md`](05-sa-keys.md)).

### REST mapping

| HTTP    | Path                                          | gRPC mapping                       |
|---------|-----------------------------------------------|------------------------------------|
| POST    | `/iam/v1/serviceAccounts`                     | `ServiceAccountService.Create`     |
| GET     | `/iam/v1/serviceAccounts/{saId}`              | `ServiceAccountService.Get`        |
| GET     | `/iam/v1/serviceAccounts`                     | `ServiceAccountService.List`       |
| PATCH   | `/iam/v1/serviceAccounts/{saId}`              | `ServiceAccountService.Update`     |
| POST    | `/iam/v1/serviceAccounts/{saId}:disable`      | `ServiceAccountService.Disable`    |
| POST    | `/iam/v1/serviceAccounts/{saId}:enable`       | `ServiceAccountService.Enable`     |
| DELETE  | `/iam/v1/serviceAccounts/{saId}`              | `ServiceAccountService.Delete`     |

## Конфигурация

| Env var                              | YAML key                              | Default | Описание                                |
|--------------------------------------|---------------------------------------|---------|-----------------------------------------|
| `KACHO_IAM_HYDRA_ADMIN_URL`          | `extapi.hydra.admin-url`              | —       | URL Hydra admin API.                    |
| `KACHO_IAM_HYDRA_ADMIN_TOKEN`        | `extapi.hydra.admin-token`            | —       | Bearer token для Hydra admin.           |
| `KACHO_IAM_HYDRA_ISSUER`             | `authn.hydra-issuer`                  | `https://hydra.<domain>` | Hydra issuer URL.    |

## Как пользоваться

### REST (curl)

```bash
# Create.
RESP=$(curl -s -X POST http://localhost:18080/iam/v1/serviceAccounts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id":"acc_xxx","name":"ci-pipeline"}')
SA_ID=...

# Get.
curl http://localhost:18080/iam/v1/serviceAccounts/$SA_ID -H "Authorization: Bearer $TOKEN"

# Disable — учётка перестаёт получать новые токены и ключи.
# Действие, а не поле маски: маску можно забыть, действие — нет.
# Требует сессии с повышенной аутентификацией (acr=2).
curl -X POST http://localhost:18080/iam/v1/serviceAccounts/$SA_ID:disable \
  -H "Authorization: Bearer $STEPUP_TOKEN" -d '{}'

# Enable — обратно. Оба действия идемпотентны: запрос состояния, в котором
# учётка уже находится, успешен.
curl -X POST http://localhost:18080/iam/v1/serviceAccounts/$SA_ID:enable \
  -H "Authorization: Bearer $STEPUP_TOKEN" -d '{}'
```

### gRPC

```bash
grpcurl -plaintext -H "Authorization: Bearer $TOKEN" \
  -d '{"account_id":"acc_xxx","name":"ci-pipeline"}' \
  localhost:9090 kacho.cloud.iam.v1.ServiceAccountService/Create
```

### Идемпотентность

Не идемпотентен (имя занято → AlreadyExists).

### Типичные ошибки

| Сценарий                                          | gRPC code             | HTTP | Текст                                                    |
|---------------------------------------------------|------------------------|------|----------------------------------------------------------|
| Имя занято в Account                              | `ALREADY_EXISTS`       | 409  | `ServiceAccount with name ci-pipeline already exists`    |
| Delete при active key                             | `FAILED_PRECONDITION`  | 400  | `service_account has active oauth clients`               |
| Delete при active AccessBinding                   | `FAILED_PRECONDITION`  | 400  | `service_account is referenced by access_bindings`       |

## Как воспроизвести локально

Команды запускаются **от корня репозитория**.

```bash
make -C deploy dev-up
kubectl -n kacho port-forward svc/api-gateway 18080:8080 &

# Newman:
./services/iam/tests/newman/scripts/run.sh --service iam-service-account

# psql:
make -C deploy psql SVC=iam
# > SELECT id, account_id, name, enabled FROM kacho_iam.service_accounts;

# Integration:
go test -short -count=1 -timeout 120s -run TestServiceAccount \
  ./services/iam/internal/repo/kacho/pg/...
```

## Подробности реализации

- **Use-cases:** `internal/apps/kacho/api/service_account/{create,get,list,update,delete,set_enabled}.go`.
- **Handler:** `internal/apps/kacho/api/service_account/handler.go`.
- **Repo:** `internal/repo/kacho/pg/service_account_repo.go`.
- **Hydra integration:** SA сам по себе не делает запросы в Hydra — только
  IssueSAKey (см. [`05-sa-keys.md`](05-sa-keys.md)). Сам SA — просто запись в БД.
- **DB:** `service_accounts(id, account_id, name, description, labels, enabled, created_at)`.
- **Indexes:** PK, UNIQUE `service_accounts_account_name_unique`, INDEX по account/project.
- **CHECK:** имя через `kacho_labels_valid`-style helper.

## Gotchas / известные ограничения

- **`enabled=false` НЕ revokes уже выданные access_tokens** — они валидны до
  expires_at (обычно 1h). Только новые requests блокируются. Для немедленного
  отзыва — Delete сервис-аккаунта или revoke его OAuth-clients в Hydra.
- **Проектной области у SA нет.** Поле `project_id` снято с контракта и из схемы
  (миграция 0071): его не принимал ни один запрос, не писала ни одна запись и не
  выбирало чтение агрегата — значение было пустым всегда и у всех, а claim,
  который из него выводился, не читал никто. Понадобятся проектные служебные
  учётки — их заводит отдельная подсистема со своей приёмкой.
- **Delete cascade на oauth_clients** — при Delete SA удаляются и записи в
  `service_account_oauth_clients` (через CASCADE FK), но **в Hydra** OAuth
  clients остаются — sa_keys.RevokeUseCase должен очистить их явно (см.
  [`05-sa-keys.md`](05-sa-keys.md)).

## Связанные компоненты

- [`05-sa-keys.md`](05-sa-keys.md) — выпуск/отзыв OAuth-ключей.
- [`08-access-binding.md`](08-access-binding.md) — bindings на subject_type=service_account.

## Ссылки на код

- `internal/domain/service_account.go`
- `internal/apps/kacho/api/service_account/`
- `internal/repo/kacho/pg/service_account_repo.go`
- `internal/migrations/0001_initial.sql` — DDL `service_accounts`
