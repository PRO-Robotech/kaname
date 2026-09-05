# kacho-iam

IAM-сервис Kachō: control-plane для identity & access. Управляет ресурсной
моделью **Account, Project, User, ServiceAccount, Group, Role, AccessBinding** и
несет runtime-авторизацию поверх нее:

- **AuthZ (реляционная форма в своей базе)** — публичный `AuthorizeService` (PDP)
  + internal `Check` (authz-gate, который зовут остальные сервисы). Вердикт
  вычисляется **в той же базе**, что и остальное состояние службы
  (`internal/authzcascade` поверх `repo/kacho/pg/relverdict`); внешнего движка
  отношений в пути решения нет — он снят целиком стадией S6 эпика #747, и его
  возвращение стережёт гейт `internal/repohygiene/authzengineretired.go`. Гранты
  `AccessBinding` кладутся строками журнала намерений (`kacho_iam.fga_outbox`)
  тем же writer-tx, что меняет выдачу, — журнал остался, снят его прежний
  потребитель.
- **Permission catalog** — `PermissionCatalogService`: грантуемая таксономия `<module>.<resource>.<verb>`.
- **Service-account keys** — `SAKeyService` (static SA-ключи через Ory Hydra).
- **Cluster-admin grants** — internal `InternalClusterService` (time-bombed/permanent).
- **AuthN-интеграция** — webhooks Ory Kratos (provision) + Hydra (token/refresh);
  User mirror через `InternalUserService.UpsertFromIdentity`.

## Quick start (локальный стенд)

Команды запускаются **от корня репозитория**: дерево одно, соседних репозиториев
стенда рядом с ним нет.

```bash
# 1. Поднять полный стенд (kind + helm + Postgres + все сервисы):
make -C deploy dev-up

# 2. Прокинуть api-gateway наружу
kubectl -n kacho port-forward svc/api-gateway 18080:8080 &

# 3. Smoke:
curl 'http://localhost:18080/iam/v1/accounts?pageSize=5'
```

Перезапуск только IAM после изменений в коде:

```bash
make -C deploy reload-svc SVC=iam
make -C deploy logs-svc SVC=iam
make -C deploy psql SVC=iam            # psql kacho_iam
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
- `clients/`           — peer-клиенты (TTL+LRU) к Ory Hydra (admin/OAuth/сессии/
                         обмен токенов) + порты вопроса о доступе (`relations.go`);
                         реализация портов — своя база, не сетевой сосед.
- `migrations/`        — Postgres goose-миграции (sequential, `0001_initial.sql` — baseline).
- `errors/`            — sentinel errors + `WrapPgErr` (SQLSTATE → service.Err\*).

## Ссылки

- Лицензия: [`LICENSE`](LICENSE)
- Как контрибьютить: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Соглашение о вкладе (подтверждается `git commit -s`): [`CLA.md`](CLA.md)
- ER-диаграмма доменной модели: [`docs/architecture/er-diagram.md`](docs/architecture/er-diagram.md)
- Proto-контракты: `proto/kacho/cloud/iam/v1/`
