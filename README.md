# kaname

IAM-сервис Kachō: control-plane для identity & access. Управляет ресурсной
моделью **Account, Project, User, ServiceAccount, Group, Role, AccessBinding** и
несет runtime-авторизацию поверх нее:

- **AuthZ (реляционная форма в своей базе)** — публичный `AuthorizeService` (PDP)
  + internal `Check` (authz-gate, который зовут остальные сервисы). Вердикт
  вычисляется **в той же базе**, что и остальное состояние службы
  (`internal/authzcascade` поверх `repo/kaname/pg/relverdict`); внешнего движка
  отношений в пути решения нет — он снят целиком стадией S6 эпика #747, и его
  возвращение стережёт гейт `internal/repohygiene/authzengineretired.go`. Гранты
  `AccessBinding` кладутся строками журнала намерений (`kaname.fga_outbox`)
  тем же writer-tx, что меняет выдачу, — журнал остался, снят его прежний
  потребитель.
- **Permission catalog** — `PermissionCatalogService`: грантуемая таксономия `<module>.<resource>.<verb>`.
- **Service-account keys** — `SAKeyService` (static SA-ключи через Ory Hydra).
- **Cluster-admin grants** — internal `InternalClusterService` (time-bombed/permanent).
- **AuthN-интеграция** — webhooks Ory Kratos (provision) + Hydra (token/refresh);
  User mirror через `InternalUserService.UpsertFromIdentity`.

## Что можно запустить

Перечень целей печатает сам модуль — он выводится из рецепта, а не из этой
страницы, поэтому не расходится с ним молча:

```bash
make help          # то же, что просто `make`
```

Первая строка ответа называет **посадку**: модуль внутри монорепо либо
самостоятельный клон. Цели, помеченные `[монорепо]`, зовут соседей по дереву —
корневой рецепт прогона, каталог общих контрактов, копию каталога прав у края.
Вне монорепо они отказывают словами, называя, что запускать вместо.

Сборка и пробы работают в обеих посадках:

```bash
make build             # бинарь службы          -> bin/kaname
make build-migrator    # бинарь мигратора       -> bin/<мигратор>
make vet lint          # статический разбор
make docker            # образ kaname:dev
go test ./... -short   # пробы без контейнеров
```

> **Часть проб в отдельном клоне не исполняется, и они говорят это сами.** Пробы,
> сверяющие домен с каталогом контрактов, читают его ИЗ ДЕРЕВА: в монорепо
> контракты лежат рядом, в отдельном клоне они приезжают зависимостью, и читать
> их из дерева нечем. Такая проба печатает «НЕ ВЫПОЛНИЛОСЬ … Это не вердикт о
> продукте» — третий исход, который не засчитывается ни в зелёное, ни в красное.
> Здесь это остаток, а не поломка: он снимается вместе с тем, как контракты
> станут приезжать зависимостью и для чтения тоже.

> **Клеймо ревизии в образе.** Величина «из какого дерева собран образ»
> объявлена один раз на дерево — в корне монорепо, и в поставку модуля она не
> входит. Самостоятельный клон соберёт образ **без** клейма, и `make docker`
> говорит об этом вслух. Подробности и предикат снятия — `provenance.mk`.

## Локальный стенд

Стенд — предмет **монорепо**: он поднимает kind, Postgres и все службы платформы
разом, поэтому его рецепт живёт в корне дерева, а не в модуле. Каталог `deploy/`
этого модуля несёт **Helm-чарт самой службы**, а не стенд, и своего рецепта не
имеет.

Из полного чекаута монорепо (команды — от корня дерева):

```bash
# 1. Поднять полный стенд (kind + helm + Postgres + все сервисы):
make -C deploy dev-up

# 2. Прокинуть api-gateway наружу
kubectl -n kacho port-forward svc/api-gateway 18080:8080 &

# 3. Smoke:
curl 'http://localhost:18080/iam/v1/accounts?pageSize=5'
```

Перезапуск только этой службы после изменений в коде:

```bash
make -C deploy reload-svc SVC=iam
make -C deploy logs-svc SVC=iam
make -C deploy psql SVC=iam            # psql kaname
```

Из самостоятельного клона службу ставят её чартом в свой кластер:

```bash
helm upgrade --install kaname ./deploy -f deploy/values.prod.yaml
```

## Архитектура

Clean Architecture (`domain → service/api → handler/repo/clients`); `cmd/kaname/main.go` —
composition root, `cmd/migrator/main.go` — отдельный CLI миграций.
Структура `internal/`:

- `domain/`            — newtypes + self-validating `Validate()`.
- `apps/kaname/api/`    — use-cases per ресурс (slice-per-RPC).
- `apps/kaname/config/` — viper YAML config.
- `repo/kaname/`        — CQRS Repository / Reader / Writer + pg-impl.
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
- Proto-контракты: `proto/kaname/cloud/iam/v1/`
