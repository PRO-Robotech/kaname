# 28. fgahook — post-commit FGA Tuple Emit Helper

## Назначение

> [!warning] Пакет под этим именем в дереве отсутствует — глава описывает ДВА разных механизма
> Замер 2026-08-06: каталога с именем из заголовка в сервисе нет. Под то, что глава
> описывает, сегодня приходятся **две разные** вещи, и путать их нельзя:
> **(а)** регистрация ресурса чужим сервисом идёт RPC `InternalIAMService.RegisterResource`
> (`internal/apps/kacho/api/internal_iam/register_resource.go`) — по внутреннему листенеру,
> идемпотентно, через собственный outbox вызывающего (см. правило топологии, раздел про
> рёбра рантайма); **(б)** IAM пишет родительские tuple **своим** ресурсам помощником
> `internal/apps/kacho/api/relationhook/` — он именно про Group / ServiceAccount / Role /
> AccessBinding и наружу не предназначен.
> Имя из заголовка не воспроизводится в тексте как путь: процитированное, оно читается как
> живой пакет. Ниже — прежнее описание; читать как историю замысла, сверяя с двумя адресами
> выше.

Помощник, через который
**другие Kachō-сервисы** (vpc/compute/loadbalancer) могут опубликовать
FGA-hierarchy tuple после создания собственного ресурса. Это
post-commit best-effort — failure НЕ rollback'ит исходную DB-операцию
(она уже COMMIT'ed в чужой БД).

Главный метод — `WriteHierarchyTuple(user, resource_type, resource_id, parent_type, parent_id)`.
Под капотом вызывает `InternalIAMService.WriteCreatorTuple` (см.
[`21-internal-iam.md`](21-internal-iam.md)) или напрямую `clients.OpenFGAClient`.

**Use-cases:**
- `kacho-vpc` после INSERT Network → emit `(iam_account:acc_x, parent, vpc_network:vpn_y)`.
- `kacho-compute` после INSERT Instance → emit hierarchy.
- Backfill для existing ресурсов.

**Ограничения:**
- Best-effort: failure logged как WARN, не fatal.
- Lazy validation — id-prefix check (но без deep validation).
- Каждый caller-сервис сам решает, использовать ли fgahook или прямо
  `InternalIAMService.WriteCreatorTuple` (предпочтительно).

## API

```go
// fgahook.WriteHierarchyTuple emits a parent/owner tuple after a peer's
// resource Create commit. Non-fatal on failure (logs WARN).
//
//   user        — "user:usr_alice" or "service_account:sva_*"
//   resource    — e.g. "vpc_network:vpn_xxx"
//   parent      — e.g. "iam_project:prj_yyy"
//   logger      — for failure trace
func WriteHierarchyTuple(
    ctx context.Context,
    writer fga.TupleWriter,
    user, resource, parent string,
    logger *slog.Logger,
) error
```

## Sequence diagram — типичный flow (kacho-vpc после Network.Create)

```mermaid
sequenceDiagram
    autonumber
    participant VPCSvc as kacho-vpc Network.Create UseCase
    participant DB_VPC as kacho_vpc DB
    participant Hook as fgahook.WriteHierarchyTuple
    participant IAM as InternalIAMService
    participant FGA as OpenFGA

    VPCSvc->>DB_VPC: BEGIN; INSERT vpc_networks; COMMIT
    VPCSvc->>VPCSvc: после commit — post-emit
    VPCSvc->>Hook: WriteHierarchyTuple(user:usr_alice, vpc_network:vpn_xxx, iam_project:prj_yyy)
    Hook->>IAM: WriteCreatorTuple {user_id, resource_type, resource_id}
    IAM->>FGA: WriteTuples [(user:usr_alice, creator, vpc_network:vpn_xxx)]
    FGA-->>IAM: 200 (или 400 already_exists — GREEN idempotent)
    IAM-->>Hook: Operation done=true
    Hook-->>VPCSvc: nil (success) | WARN logged on failure
    Note over VPCSvc: VPC mutation остается applied даже при FGA fail
```

## Что делать при failure (operator)

Backfill через admin tooling:

```bash
# 1. Список ресурсов без owner-tuple в OpenFGA (через ReadTuples filter).
grpcurl ... ReadTuples '{"object":"vpc_network:vpn_xxx"}' → ничего

# 2. Re-emit:
grpcurl ... WriteCreatorTuple '{"user_id":"usr_alice","resource_type":"vpc_network","resource_id":"vpn_xxx"}'
```

Альтернатива — общий **fgahook backfill job** (отдельный CRON), который
сканирует БД пиров и компенсирует missing tuples.

## Подробности реализации

- **Package:** см. предупреждение в начале главы — под этим именем каталога нет.
- **Caller responsibility:** caller-сервис сам строит `user` / `resource` /
  `parent` строки в FGA-notation.
- **Idempotency:** OpenFGA `WriteTuples` возвращает 400 `already-exists` на
  дубликат — обрабатывается как GREEN.

## Gotchas / известные ограничения

- **Best-effort means возможна потеря tuple** — при agressive network
  partition; план — outbox-pattern (`fga_outbox`) для guaranteed.
- **fgahook НЕ участвует** в kacho-iam writes (там — `fga_outbox` через
  drainer).
- **Per-call latency** — добавляет 1 RTT на kacho-iam; для high-throughput
  Create операций — async-fire-and-forget pattern в caller.

## Связанные компоненты

- [`21-internal-iam.md`](21-internal-iam.md) — WriteCreatorTuple host.
- [`29-openfga-check.md`](29-openfga-check.md) — общая propagation chain.

## Ссылки на код

- `internal/apps/kacho/api/internal_iam/register_resource.go` — регистрация ресурса
  чужим сервисом (то, ради чего глава заводилась).
- `internal/apps/kacho/api/relationhook/relationhook.go` — родительские tuple для
  собственных ресурсов IAM.
- Вызывающие — сервисы vpc / compute / nlb / storage / registry монорепо.
