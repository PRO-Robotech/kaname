# 00. Обзор сервиса kacho-iam

## Назначение

`kacho-iam` — **identity & access management** сервис платформы Kachō. Он владеет
полной ресурсной моделью identity и поверх нее реализует runtime-авторизацию для
всего кластера.

**Ресурсная модель** (схема `kacho_iam`, источник истины для всех сервисов):

- **Account** — top-level tenant (организация). Глобально-уникальное имя; владелец —
  единственный User (`owner_user_id`).
- **Project** — рабочее пространство-контейнер ресурсов внутри Account; уникальное имя
  per-Account; операция Move (atomic CAS).
- **User** — mirror identity, заполняется AuthN-хуком при первом входе.
- **ServiceAccount** — машинная identity; backing OAuth2-клиент в Ory Hydra.
- **Group** — набор субъектов (User / ServiceAccount) для group-grant.
- **Role** — набор permission'ов формата `<module>.<resource>.<verb>`; system-роли
  (seed с детерминированными id) + custom-роли per-Account.
- **AccessBinding** — грант `(subject) ↔ role ↔ (resource)`; runtime-эффект гранта
  материализуется в OpenFGA через `fga_outbox`.

**Плоскость авторизации** (живет поверх ресурсной модели):

- **OpenFGA ReBAC** — единый decision-движок. Каждый AccessBinding-грант
  транслируется в FGA-tuple'ы; проверка прав — OpenFGA Check.
- **AuthorizeService** (public PDP) — sync-проверка решений: `Check` / `BatchCheck` /
  `ListObjects` / `ListSubjects` / `ExpandRelations` / `WhoAmI`.
- **InternalIAMService.Check** — authz-gate, который каждый control-plane сервис
  (`kacho-vpc`, `kacho-compute`, `kacho-nlb`, `kacho-geo`) зовет перед мутацией.
- **ConditionsService** — ABAC-overlay поверх ReBAC: условные гранты на CEL-выражениях
  (`Evaluate` в request-time).
- **PermissionCatalogService** — грантуемая таксономия `<module>.<resource>.<verb>`
  (backend-driven каталог прав для UI и валидации Role).
- **Cluster-admin grants** — internal-only `InternalClusterService`: time-bombed либо
  permanent привязки cluster-admin.

**AuthN-плоскость** (интеграция с Ory):

- **Hooks-listener** принимает webhooks Ory Hydra (`token` / `refresh`) и Ory Kratos
  (`provision`): на регистрации/входе вызывается `UpsertFromIdentity` — bootstrap
  Account/Project/AccessBinding для нового identity либо активация PENDING-invite.
- **SAKeyService** выдает Class A static service-account-ключи через OAuth2
  client-credentials Ory Hydra.
- **jwks-rotator** — отдельный бинарник, ротирующий OIDC JWKS-ключи подписи в БД.

**Что делает:**

- хранит идентичности, проекты, роли, гранты;
- проводит мутации как async-операции (LRO) с polling-контрактом;
- авторизует запросы (OpenFGA Check + Conditions CEL);
- синхронизирует гранты в OpenFGA через `fga_outbox` drainer внутри writer-tx;
- обслуживает AuthN-хуки Ory и выдает SA-ключи.

**Что НЕ делает:**

- не валидирует JWT — это работа `api-gateway` (Hydra JWKS) и самой Ory Hydra;
- не управляет паролями пользователей — Ory Kratos;
- не хранит OAuth `client_secret` в plaintext — Hydra хранит, kacho-iam отдает один раз
  и redact'ит;
- не пишет в OpenFGA синхронно из request-path — пишет в `fga_outbox`, async drainer
  применяет.

## Топология процесса

`kacho-iam` (бинарник `cmd/kacho-iam`) поднимает четыре сетевых слушателя и набор
фоновых worker'ов в одном процессе. Параллельный запуск — через
`github.com/H-BF/corlib/pkg/parallel.ExecAbstract` с общим shutdown-триггером
(SIGTERM / SIGINT или первая ошибка задачи).

```mermaid
flowchart LR
    subgraph iam[kacho-iam process]
        direction TB
        gRPCpub[":9090 public gRPC<br/>TLS-terminated<br/>tenant API"]
        gRPCint[":9091 internal gRPC<br/>mTLS<br/>admin/peer API"]
        hooks[":9092 HTTP<br/>Ory hooks + health"]
        metrics[":9095 HTTP<br/>Prometheus /metrics"]

        lro[(LRO operations worker<br/>+ orphan-reconciler)]
        fgaDr[(fga_outbox drainer)]
        subjDr[(subject_change drainer)]
        bootDr[(bootstrap-admin reconciler)]
        rsab[(binding reconciler-worker)]
    end

    Tenants -- TLS gRPC --> gRPCpub
    APIGW[api-gateway] -- public RPC + InternalIAM --> gRPCpub
    APIGW -- InternalIAMService.Check --> gRPCint
    VPC[kacho-vpc] -- Check / RegisterResource --> gRPCint
    Compute[kacho-compute] -- Check / RegisterResource --> gRPCint
    NLB[kacho-nlb] -- Check / RegisterResource --> gRPCint

    Hydra[Ory Hydra] -- token / refresh hook --> hooks
    Kratos[Ory Kratos] -- provision hook --> hooks

    fgaDr -- WriteTuples --> OpenFGA[(OpenFGA store)]
    subjDr -- InvalidateSubject --> APIGW

    iam --- Postgres[("Postgres<br/>schema kacho_iam")]
```

Фоновые worker'ы:

- **LRO operations worker** — гоняет async-мутации к терминалу; orphan-reconciler
  закрывает осиротевшие `done=false`-операции умершего процесса по committed-реальности.
- **fga_outbox drainer** — слушает `kacho_iam_fga_outbox` через LISTEN/NOTIFY и
  применяет owner/grant-tuple'ы в OpenFGA (идемпотентно, с backoff и poison-обработкой).
- **subject_change drainer** — пушит инвалидацию authz-кеша на api-gateway
  (`InvalidateSubject`) при изменении грантов субъекта.
- **bootstrap-admin reconciler** — выдает `system_admin@cluster` пользователю из
  `KACHO_IAM_BOOTSTRAP_ROOT_EMAIL` (best-effort, no-op при пустом env).
- **binding reconciler-worker** — пере-материализует label-selector и by-name гранты
  при смене меток ресурса, доводит PENDING→ACTIVE и истекает TTL-гранты.

## Port-mapping (по умолчанию)

| Порт | Протокол | Назначение                                          | Конфиг-ключ                      |
|------|----------|-----------------------------------------------------|----------------------------------|
| 9090 | gRPC+TLS | public-API (tenant)                                 | `api-server.endpoint`            |
| 9091 | gRPC+mTLS| internal-API (admin, peer-call)                     | `api-server.internal-endpoint`   |
| 9092 | HTTP     | Ory hooks (Hydra token/refresh, Kratos provision) + `/healthz` `/readyz` | `authn.hooks-http-endpoint` |
| 9095 | HTTP     | Prometheus `/metrics`                               | `api-server.metrics-endpoint`    |

Все четыре слушателя поддерживают per-edge TLS (default-off в dev, fail-closed в
production: internal :9091 и public :9090 обязаны нести mTLS/TLS, иначе процесс не
стартует).

`api-gateway` (отдельный сервис) — единственная внешняя точка входа: он валидирует JWT
(Hydra JWKS), резолвит principal и проксирует JSON/REST `/iam/v1/<resource>` в `:9090`
через grpc-gateway. Tenant-вызовы из CLI/UI всегда идут через api-gateway, не напрямую в
порт 9090.

## Архитектурная диаграмма (C4-context)

```mermaid
C4Context
    title kacho-iam — C4 Context

    Person(tenant, "Tenant user / Service account", "Через api-gateway")
    Person(admin, "Cluster admin / oncall", "Через internal-tooling")
    System_Ext(kratos, "Ory Kratos", "Identity / login")
    System_Ext(hydra, "Ory Hydra", "OAuth2 / OIDC tokens, SA keys")
    System_Ext(openfga, "OpenFGA", "ReBAC store")

    System_Boundary(kacho, "Kachō cluster") {
        System(apigw, "kacho-api-gateway", "Edge REST/gRPC, JWT")
        System(iam, "kacho-iam", "Identity & access")
        System(vpc, "kacho-vpc", "Network")
        System(compute, "kacho-compute", "Compute")
        System(nlb, "kacho-nlb", "Load balancing")
        SystemDb(pg, "Postgres", "schema kacho_iam")
    }

    Rel(tenant, apigw, "HTTPS")
    Rel(admin, iam, "internal-grpc, port-forward")
    Rel(apigw, iam, "public RPC :9090 + InternalIAM :9091")
    Rel(vpc, iam, "Check / RegisterResource :9091")
    Rel(compute, iam, "Check / RegisterResource :9091")
    Rel(nlb, iam, "Check / RegisterResource :9091")
    Rel(kratos, iam, "provision hook")
    Rel(hydra, iam, "token / refresh hook")
    Rel(iam, hydra, "OAuth2 client (SA key issue)")
    Rel(iam, openfga, "Check / WriteTuples (через drainer)")
    Rel(iam, pg, "pgxpool (master + read-replica)")
```

## Плоскость авторизации (как принимается решение)

1. **Грант** — `AccessBindingService.Create` пишет 5-tuple в `kacho_iam` И в той же
   транзакции кладет FGA-tuple в `fga_outbox` (transactional outbox, без dual-write).
2. **Синхронизация** — `fga_outbox` drainer применяет tuple в OpenFGA (sub-second через
   LISTEN/NOTIFY). Параллельно `subject_change` drainer инвалидирует authz-кеш gateway.
3. **Проверка** — на каждом RPC:
   - публичный путь: api-gateway зовет `AuthorizeService.Check` (PDP);
   - peer-путь: `kacho-vpc` / `kacho-compute` / `kacho-nlb` / `kacho-geo` зовут
     `InternalIAMService.Check` перед мутацией (mTLS, fail-closed).
   - Оба упираются в один OpenFGA Check над материализованными tuple'ами.
4. **ABAC-overlay** — если на гранте висит Condition, `ConditionsService` вычисляет
   CEL-выражение (IP-CIDR / время / атрибуты запроса) и может сузить решение.
5. **Owner-tuple'ы** — consumer-сервисы регистрируют владение своими ресурсами через
   `InternalIAMService.RegisterResource` / `UnregisterResource` (fgaproxy): модули не
   ходят в OpenFGA напрямую, only через iam.

Детали — [`19-authorize.md`](19-authorize.md), [`21-internal-iam.md`](21-internal-iam.md),
[`29-openfga-check.md`](29-openfga-check.md).

## Внутренняя структура (Clean Architecture)

`internal/` строго разделен на слои:

```
domain/              # entities + newtypes + Validate(). stdlib + multierr only.
apps/kacho/
  api/<resource>/    # use-cases per RPC (slice-per-RPC).
  config/            # viper YAML config + env-resolvers.
  seed/              # system-role seed, bootstrap-admin, backfill/verify, workers.
repo/kacho/          # Reader/Writer port-interfaces (CQRS).
repo/kacho/pg/       # pgxpool + dto-mapping. Реализует Reader/Writer.
clients/             # peer-clients (OpenFGA, Hydra).
handler/             # тонкий gRPC transport (operation handler).
handler/iamhooks/    # HTTP-хуки Ory (token / refresh / provision) + health.
authzguard/          # caller-policy + anti-anonymous + viewer/acr-floor интерсепторы.
migrations/          # embed.FS goose-миграции.
errors/              # sentinel + WrapPgErr.
```

### Зарегистрированные RPC-сервисы

| Listener  | Сервис                          | Назначение                                             |
|-----------|---------------------------------|--------------------------------------------------------|
| `:9090`   | `AccountService`                | CRUD Account                                            |
| `:9090`   | `ProjectService`                | CRUD Project + Move                                     |
| `:9090`   | `UserService`                   | read/CRUD User (mirror)                                 |
| `:9090`   | `ServiceAccountService`         | CRUD ServiceAccount                                     |
| `:9090`   | `SAKeyService`                  | Issue / List / Revoke SA-ключей (Hydra)                |
| `:9090`   | `GroupService`                  | CRUD Group + member-операции                           |
| `:9090`   | `RoleService`                   | CRUD Role (system seed + custom)                       |
| `:9090`   | `AccessBindingService`          | Create / Delete (immutable)                            |
| `:9090`   | `ConditionsService`             | CRUD + CEL `Evaluate` (ABAC overlay)                   |
| `:9090`   | `AuthorizeService`              | public PDP: Check / BatchCheck / ListObjects / ListSubjects |
| `:9090`   | `PermissionCatalogService`      | грантуемая таксономия прав                              |
| `:9090`   | `OperationService`              | LRO Get / List / Cancel (corelib)                      |
| `:9091`   | `InternalIAMService`            | Check + Register/UnregisterResource (fgaproxy)         |
| `:9091`   | `InternalAuthorizeService`      | admin authz (write/read tuples)                        |
| `:9091`   | `AuthorizeService`              | тот же PDP-handler для peer list-filter (ListObjects)  |
| `:9091`   | `InternalClusterService`        | cluster-admin grants (time-bombed / permanent)         |
| `:9091`   | `InternalUserService`           | `UpsertFromIdentity` (mirror identity)                 |
| `:9091`   | `InternalOperationsService`     | cluster-wide admin operations feed                     |
| `:9091`   | `InternalSessionRevocationsService` | logout / force-logout + hot-path IsRevoked         |

`AuthorizeService` дополнительно зарегистрирован на internal-listener: тот же PDP-handler
переиспользуется consumer-сервисами для per-object list-filter (`ListObjects`) поверх
уже-установленного mTLS-ребра `:9091`. Это не нарушает internal-vs-external (запрет #6):
запрещено публиковать `Internal.*` на external endpoint, а обратное — публичный сервис,
дополнительно доступный на cluster-internal listener, — штатный service→service-паттерн.

## Жизненный цикл запроса (типичный)

Создание ресурса через REST:

```mermaid
sequenceDiagram
    participant Cli as Tenant CLI / UI
    participant GW as api-gateway
    participant IAM as kacho-iam :9090
    participant DB as Postgres
    participant Drainer as fga_outbox drainer
    participant OFGA as OpenFGA

    Cli->>GW: POST /iam/v1/accounts<br/>Authorization: Bearer <JWT>
    GW->>GW: Validate JWT (Hydra JWKS)
    GW->>GW: Resolve principal (InternalIAMService.LookupSubject)
    GW->>IAM: gRPC AccountService.Create<br/>+ x-kacho-principal-* metadata
    IAM->>IAM: PrincipalExtract + AntiAnonymous guard
    IAM->>IAM: domain.Account.Validate()
    IAM->>DB: BEGIN; INSERT accounts; INSERT operations; INSERT fga_outbox; COMMIT
    IAM-->>GW: Operation (done=false, id="iop_..")
    GW-->>Cli: 200 {operationId}

    Note over Drainer,OFGA: async (sub-second via LISTEN/NOTIFY)
    DB-->>Drainer: NOTIFY kacho_iam_fga_outbox
    Drainer->>DB: SELECT ... FOR UPDATE SKIP LOCKED
    Drainer->>OFGA: WriteTuples (account owner)
    Drainer->>DB: DELETE fga_outbox row

    Note over IAM,DB: async (LRO worker)
    IAM->>DB: UPDATE operations SET done=true, response=Account

    loop poll
        Cli->>GW: GET /iam/v1/operations/iop_..
        GW->>IAM: gRPC OperationService.Get
        IAM->>DB: SELECT operation
        IAM-->>GW: Operation (done=true, response=Account)
        GW-->>Cli: 200 {done:true, response:{id, name, ...}}
    end
```

## Зависимости

**Build-зависимости (Go):**

- `github.com/PRO-Robotech/kacho-corelib` — ids, operations (LRO table + worker),
  db (pgxpool), grpcsrv, observability, outbox/drainer, safeconv; а также shared-proto
  stubs (operation/validation/authz_options).
- `github.com/PRO-Robotech/kacho-iam/proto/gen/go/kacho/cloud/iam/v1` — собственные
  доменные proto-stubs (генерируются локально из `proto/`).
- `github.com/jackc/pgx/v5` — Postgres driver.
- `github.com/spf13/viper` — конфиг.
- `github.com/H-BF/corlib/pkg/parallel` — параллельный запуск задач.
- `go.uber.org/multierr` — cumulative validation errors.

**Runtime-зависимости (peer):**

- Postgres 16 — schema `kacho_iam`.
- OpenFGA — ReBAC store (authz Check + tuple-write через drainer).
- Ory Hydra — OAuth2/OIDC tokens, backing-клиенты ServiceAccount, SA-ключи.
- Ory Kratos — identity / login (provision-хук).
- api-gateway — edge JWT-валидация и REST-проекция.

## Дальнейшее чтение

- Конкретный ресурс → [`01-account.md`](01-account.md) … [`10-operations.md`](10-operations.md).
- Authz-плоскость → [`19-authorize.md`](19-authorize.md),
  [`20-internal-authorize.md`](20-internal-authorize.md),
  [`21-internal-iam.md`](21-internal-iam.md),
  [`28-fgahook.md`](28-fgahook.md),
  [`29-openfga-check.md`](29-openfga-check.md).
- Conditions (CEL ABAC) → [`09-conditions.md`](09-conditions.md).
- Production deploy / эксплуатация → [`31-deployment.md`](31-deployment.md),
  [`32-observability.md`](32-observability.md), [`33-runbook.md`](33-runbook.md).
