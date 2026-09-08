# kaname — Документация компонентов (RU)

Полная техническая документация всех компонентов сервиса `kaname` —
identity & access management платформы Kachō. Целевая аудитория — оператор,
devops, архитектор: все, что нужно, чтобы поднять, настроить, обслужить и
расширить сервис в проде, **без чтения исходников**.

> Sequence-диаграммы — в Mermaid; GitHub рендерит их автоматически. Если
> работаете вне GitHub — используйте [Mermaid Live Editor](https://mermaid.live).

## Capability map

`kaname` поднимает 4 сетевых слушателя (порты конфигурируются):

| Слушатель      | Порт  | Протокол  | Назначение                                                                       |
|----------------|-------|-----------|----------------------------------------------------------------------------------|
| public-gRPC    | 9090  | gRPC+TLS  | tenant-facing RPC: Account/Project/User/SA/Group/Role/AccessBinding/Conditions/Authorize/PermissionCatalog/SAKey/Operation |
| internal-gRPC  | 9091  | gRPC+mTLS | admin/peer-call RPC: InternalIAM/InternalCluster/InternalUser/InternalOperations/InternalSessionRevocations |
| hooks-HTTP     | 9092  | HTTP      | Ory Kratos provision-хук + Ory Hydra token/refresh OAuth2-хуки (cluster-internal) |
| metrics-HTTP   | 9095  | HTTP      | Prometheus `/metrics` (cluster-internal)                                          |

Плюс `api-gateway` (внешний HTTP) транслирует public-gRPC в REST
(`/iam/v1/...`); в локальном стенде доступен через port-forward на `18080`.

## Группы документации

### Навигация
- [`00-overview.md`](00-overview.md) — обзор сервиса, port-mapping, архитектурная диаграмма (C4-context), раскладка internal-пакетов.

### Ядро ресурсной модели (Account / Project / IAM-сущности)
- [`01-account.md`](01-account.md) — Account (top-level tenant; глобально-уникальное имя; owner_user_id RESTRICT).
- [`02-project.md`](02-project.md) — Project (child Account-а; Move через atomic CAS; уникальность per-Account).
- [`03-user.md`](03-user.md) — User (mirror Ory Kratos identity; Invite-flow; immutable external_id).
- [`04-service-account.md`](04-service-account.md) — ServiceAccount (Hydra OAuth-client backing).
- [`05-sa-keys.md`](05-sa-keys.md) — SA Keys (Hydra OAuth client_id/secret; OpsResponseRedactor; ротация Delete+Create).
- [`06-group.md`](06-group.md) — Group + GroupMember (триггер `group_members_member_exists_trg`).
- [`07-role.md`](07-role.md) — Role (58 system seed; custom per-Account; multi-scope XOR; permissions JSONB).
- [`08-access-binding.md`](08-access-binding.md) — AccessBinding (5-tuple; idempotent INSERT; эмиссия намерения и сброса кэша в той же транзакции).
- Условия на привязку (ABAC-overlay) — главы нет. Отдельной главы про условия в этом каталоге нет, и это не пропуск оформления: поля условия сняты с контракта привязки (`reserved 6, 7` в `proto/kaname/cloud/iam/v1/access_binding_service.proto` — их никто не вычислял, и запрос обещал гейт, которого нет). Имя ненаписанной главы не воспроизводится как ссылка: она читается как существующая.
- [`10-operations.md`](10-operations.md) — LRO Operations (`iop`-prefix; async-API contract; principal extension).

### Authorization
- [`19-authorize.md`](19-authorize.md) — публичный `AuthorizeService` (sync-проверка, `ExpandRelations`, снятые с контракта поля).
- [`21-internal-iam.md`](21-internal-iam.md) — InternalIAMService (UpsertFromIdentity / PollSubjectChanges / RegisterResource).

### Cross-cutting / infrastructure
- [`29-relational-verdict.md`](29-relational-verdict.md) — вердикт реляционной формой + журнал намерений + родительский указатель.

### Operations / Runbook / Deployment
- [`31-deployment.md`](31-deployment.md) — Полный deployment guide (helm umbrella, env vars, secrets, миграции).
- [`32-observability.md`](32-observability.md) — Metrics / logs / tracing (slog → OTel, латентность вердикта).
- [`33-runbook.md`](33-runbook.md) — Production runbook (типичные P1/P2/P3 инциденты и действия).

## Как читать

1. Если впервые — [`00-overview.md`](00-overview.md) (15 мин чтения).
2. Если конкретный ресурс/RPC — открыть соответствующий файл из ядра / governance.
3. Если нужно поднять в проде — [`31-deployment.md`](31-deployment.md) + [`33-runbook.md`](33-runbook.md).
4. Если нужно понять authz-цепочку — [`19-authorize.md`](19-authorize.md) → [`29-relational-verdict.md`](29-relational-verdict.md) → [`../architecture/failure-domains.md`](../architecture/failure-domains.md).

## Источники истины (для самостоятельной проверки)

- `internal/domain/*.go` — entities, валидация, regex'ы, длины.
- `internal/repo/kaname/pg/*.go` — SQL, scan-функции, error-mapping.
- `internal/apps/kaname/api/*/` — use-cases (slice-per-RPC).
- `internal/handler/*.go` + `internal/apps/kaname/api/*/handler.go` — gRPC transport.
- `cmd/kaname/{main,wiring,serve,...}.go` — composition root.
- `internal/migrations/0001_initial.sql` — squashed schema (46 таблиц, 101 индекс, 7 триггеров, 62 FK).
- `README.md` (корень репозитория) — высокоуровневый overview.
