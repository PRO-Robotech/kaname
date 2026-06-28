# kacho-iam — Документация компонентов (RU)

Полная техническая документация всех компонентов сервиса `kacho-iam` —
identity & access management платформы Kachō. Целевая аудитория — оператор,
devops, архитектор: все, что нужно, чтобы поднять, настроить, обслужить и
расширить сервис в проде, **без чтения исходников**.

> Sequence-диаграммы — в Mermaid; GitHub рендерит их автоматически. Если
> работаете вне GitHub — используйте [Mermaid Live Editor](https://mermaid.live).

## Capability map

`kacho-iam` поднимает 4 сетевых слушателя (порты конфигурируются):

| Слушатель      | Порт  | Протокол  | Назначение                                                                       |
|----------------|-------|-----------|----------------------------------------------------------------------------------|
| public-gRPC    | 9090  | gRPC+TLS  | tenant-facing RPC: Account/Project/User/SA/Group/Role/AccessBinding/Conditions/Authorize/PermissionCatalog/SAKey/Operation |
| internal-gRPC  | 9091  | gRPC+mTLS | admin/peer-call RPC: InternalIAM/InternalAuthorize/InternalCluster/InternalUser/InternalOperations/InternalSessionRevocations |
| hooks-HTTP     | 9092  | HTTP      | Ory Kratos provision-хук + Ory Hydra token/refresh OAuth2-хуки (cluster-internal) |
| metrics-HTTP   | 9095  | HTTP      | Prometheus `/metrics` (cluster-internal)                                          |

Плюс `api-gateway` (внешний HTTP) транслирует public-gRPC в REST
(`/iam/v1/...`); в локальном стенде доступен через port-forward на `18080`.

## Группы документации

### Навигация
- [`00-overview.md`](00-overview.md) — обзор сервиса, port-mapping, архитектурная диаграмма (C4-context), список 28 internal-пакетов.

### Ядро ресурсной модели (Account / Project / IAM-сущности)
- [`01-account.md`](01-account.md) — Account (top-level tenant; глобально-уникальное имя; owner_user_id RESTRICT).
- [`02-project.md`](02-project.md) — Project (child Account-а; Move через atomic CAS; уникальность per-Account).
- [`03-user.md`](03-user.md) — User (mirror Ory Kratos identity; Invite-flow; immutable external_id).
- [`04-service-account.md`](04-service-account.md) — ServiceAccount (Hydra OAuth-client backing).
- [`05-sa-keys.md`](05-sa-keys.md) — SA Keys (Hydra OAuth client_id/secret; OpsResponseRedactor; ротация Delete+Create).
- [`06-group.md`](06-group.md) — Group + GroupMember (триггер `group_members_member_exists_trg`).
- [`07-role.md`](07-role.md) — Role (58 system seed; custom per-Account; multi-scope XOR; permissions JSONB).
- [`08-access-binding.md`](08-access-binding.md) — AccessBinding (5-tuple; idempotent INSERT; atomic emit-in-tx FGA + subject_change).
- [`09-conditions.md`](09-conditions.md) — Access Binding Conditions (ABAC overlay: IP-CIDR/time/device-trust + standalone Conditions).
- [`10-operations.md`](10-operations.md) — LRO Operations (`iop`-prefix; async-API contract; principal extension).

### Authorization
- [`19-authorize.md`](19-authorize.md) — Public AuthorizeService.Check (sync; high-throughput; cache-friendly).
- [`20-internal-authorize.md`](20-internal-authorize.md) — InternalAuthorizeService (Cascade Check; ClusterAdminGrant fast-path).
- [`21-internal-iam.md`](21-internal-iam.md) — InternalIAMService (UpsertFromIdentity / PollSubjectChanges / WriteCreatorTuple).

### Cross-cutting / infrastructure
- [`28-fgahook.md`](28-fgahook.md) — `fgahook.WriteHierarchyTuple` (best-effort post-commit FGA-tuple emit).
- [`29-openfga-check.md`](29-openfga-check.md) — OpenFGA REBAC Check + `fga_outbox` drainer + propagation chain.

### Operations / Runbook / Deployment
- [`31-deployment.md`](31-deployment.md) — Полный deployment guide (helm umbrella, env vars, secrets, миграции).
- [`32-observability.md`](32-observability.md) — Metrics / logs / tracing (slog → OTel, FGA-lag).
- [`33-runbook.md`](33-runbook.md) — Production runbook (типичные P1/P2/P3 инциденты и действия).

## Как читать

1. Если впервые — [`00-overview.md`](00-overview.md) (15 мин чтения).
2. Если конкретный ресурс/RPC — открыть соответствующий файл из ядра / governance.
3. Если нужно поднять в проде — [`31-deployment.md`](31-deployment.md) + [`33-runbook.md`](33-runbook.md).
4. Если нужно понять authz-цепочку — [`19-authorize.md`](19-authorize.md) → [`29-openfga-check.md`](29-openfga-check.md).

## Источники истины (для самостоятельной проверки)

- `internal/domain/*.go` — entities, валидация, regex'ы, длины.
- `internal/repo/kacho/pg/*.go` — SQL, scan-функции, error-mapping.
- `internal/apps/kacho/api/*/` — use-cases (slice-per-RPC).
- `internal/handler/*.go` + `internal/apps/kacho/api/*/handler.go` — gRPC transport.
- `cmd/kacho-iam/{main,wiring,serve,...}.go` — composition root.
- `internal/migrations/0001_initial.sql` — squashed schema (46 таблиц, 101 индекс, 7 триггеров, 62 FK).
- `README.md` (корень репозитория) — высокоуровневый overview.
