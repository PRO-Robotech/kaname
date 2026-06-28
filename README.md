# kacho-iam

IAM-сервис Kachō: control-plane для identity & access. Управляет ресурсной
моделью **Account, Project, User, ServiceAccount, Group, Role, AccessBinding** и
несет runtime-авторизацию поверх нее:

- **AuthZ (OpenFGA ReBAC)** — публичный `AuthorizeService` (PDP) + internal
  `Check` (authz-gate, который зовут остальные сервисы). Гранты `AccessBinding`
  транслируются в FGA-tuples через transactional-outbox внутри writer-tx.
- **Условные гранты** — `ConditionsService` (CEL-выражения, request-time `Evaluate`).
- **Permission catalog** — `PermissionCatalogService`: грантуемая таксономия `<module>.<resource>.<verb>`.
- **Service-account keys** — `SAKeyService` (static SA-ключи через Ory Hydra).
- **Cluster-admin grants** — internal `InternalClusterService` (time-bombed/permanent).
- **AuthN-интеграция** — webhooks Ory Kratos (provision) + Hydra (token/refresh);
  User mirror через `InternalUserService.UpsertFromIdentity`.

## Quick start (локальный стенд)

```bash
# 1. Поднять полный стенд (kind + helm + Postgres + все сервисы):
cd ../kacho-deploy && make dev-up

# 2. Прокинуть api-gateway наружу
kubectl -n kacho port-forward svc/api-gateway 18080:8080 &

# 3. Smoke:
curl 'http://localhost:18080/iam/v1/accounts?pageSize=5'
```

Перезапуск только IAM после изменений в коде:

```bash
cd ../kacho-deploy && make reload-svc SVC=iam
make logs-svc SVC=iam
make psql SVC=iam            # psql kacho_iam
```

## Архитектура

Clean Architecture (`domain → service/api → handler/repo/clients`); `cmd/kacho-iam/main.go` —
composition root, `cmd/migrator/main.go` — отдельный CLI миграций.
Структура `internal/`:

- `domain/`            — newtypes + self-validating `Validate()`.
- `apps/kacho/api/`    — use-cases per ресурс (slice-per-RPC).
- `apps/kacho/config/` — viper YAML config.
- `repo/kacho/`        — CQRS Repository / Reader / Writer + pg-impl.
- `dto/`               — generic table-driven DTO трансферы.
- `handler/`           — тонкий gRPC transport-слой.
- `clients/`           — peer-клиенты (TTL+LRU): Ory (Hydra/Kratos), OpenFGA Check, SPIRE SVID.
- `migrations/`        — Postgres goose-миграции (sequential, `0001_initial.sql` — baseline).
- `errors/`            — sentinel errors + `WrapPgErr` (SQLSTATE → service.Err\*).

## Ссылки

- Лицензия: [`LICENSE`](LICENSE)
- Как контрибьютить: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- ER-диаграмма доменной модели: [`docs/architecture/er-diagram.md`](docs/architecture/er-diagram.md)
- Proto-контракты: `proto/kacho/cloud/iam/v1/`
