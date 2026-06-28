# 20. InternalAuthorizeService

## Назначение

**InternalAuthorizeService** — internal-only (порт 9091) RPC для admin- и
inter-service operation'ов на OpenFGA store / model:

- `WriteTuples` — explicit batch write + delete tuples (одна транзакционная
  FGA `Write`).
- `ReadTuples` — debug/admin: list tuples по фильтру.
- `ReloadModel` — hot-reload Authorization Model + condition-каталог после
  `WriteAuthorizationModel`.
- `GetFGAStoreInfo` — store_id / model_id / tuple_count / model age.

Использование:

- kacho-iam outbox-worker применяет `WriteTuples` на AccessBinding-lifecycle
  событиях (worker — единственный легитимный `tuple_writer`).
- Admin-UI / oncall tooling через port-forward (`ReadTuples` / `GetFGAStoreInfo`).
- `openfga-bootstrap-job` после `WriteAuthorizationModel` вызывает `ReloadModel`.

Cluster-admin grant дает **short-circuit** в `InternalIAMService.Check`: если
subject имеет ACTIVE `cluster_admin` grant — allowed без обращения к FGA.

**Ограничения:**
- Internal-only (запрет #6).
- Не выставлять на external TLS.

## API surface

### Internal gRPC (порт 9091) — InternalAuthorizeService

| RPC                | Sync/Async       | Описание                                          |
|--------------------|------------------|---------------------------------------------------|
| `WriteTuples`      | async (LRO)      | Batch write + delete tuples в OpenFGA.            |
| `ReadTuples`       | sync             | List tuples по фильтру.                           |
| `ReloadModel`      | sync             | Hot-reload model + condition-каталог; pin new model_id. |
| `GetFGAStoreInfo`  | sync             | store_id, model_id, tuple_count, model age.       |

**Нет REST mapping** — internal-only.

## Sequence diagram — WriteTuples (outbox-worker / admin-tooling)

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin tool / kacho-iam (LRO Worker)
    participant IAM as InternalAuthorizeService :9091
    participant FGA as OpenFGA
    participant DB

    Admin->>IAM: WriteTuples {writes:[(user, relation, object), ...], deletes:[...]}
    IAM->>FGA: HTTP POST /stores/$store/write {writes, deletes}
    alt 400 already-exists / cannot-delete
        FGA-->>IAM: 400 (idempotent — GREEN)
    end
    FGA-->>IAM: 200
    IAM->>DB: INSERT operations done=true response=WriteTuplesResult
    IAM-->>Admin: Operation
```

## Sequence diagram — cluster-admin short-circuit (InternalIAMService.Check)

```mermaid
sequenceDiagram
    autonumber
    participant Backend as kacho-vpc / compute
    participant IAM as InternalIAMService.Check
    participant DB
    participant FGA

    Backend->>IAM: Check(subject=user:usr_sre, action="vpc.network.delete", resource=...)
    IAM->>DB: SELECT * FROM cluster_admin_grants<br/>WHERE subject_id=$user AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>NOW)
    alt row found
        IAM-->>Backend: ALLOW (short-circuit)
    else not found
        IAM->>FGA: Check(subject, relation, object)
        FGA-->>IAM: allowed | denied
        IAM-->>Backend: ALLOW | DENY
    end
```

## Конфигурация

См. [`19-authorize.md`](19-authorize.md) — те же OpenFGA env vars.

## Как пользоваться

```bash
kubectl -n kacho port-forward svc/kacho-iam 9091:9091 &

# WriteTuples (admin).
grpcurl -plaintext -d '{
  "writes":[{"subject":"user:usr_alice","relation":"viewer","object":"project:prj_yyy"}]
}' localhost:9091 kacho.cloud.iam.v1.InternalAuthorizeService/WriteTuples

# ReadTuples by filter.
grpcurl -plaintext -d '{"object":"project:prj_yyy"}' localhost:9091 \
  kacho.cloud.iam.v1.InternalAuthorizeService/ReadTuples

# Reload model после WriteAuthorizationModel.
grpcurl -plaintext -d '{"new_model_id":"01HXXXX..."}' localhost:9091 \
  kacho.cloud.iam.v1.InternalAuthorizeService/ReloadModel

# Get store info.
grpcurl -plaintext -d '{}' localhost:9091 \
  kacho.cloud.iam.v1.InternalAuthorizeService/GetFGAStoreInfo
```

## Подробности реализации

- **Handler:** `internal/apps/kacho/api/internal_authorize/handler.go`.
- **FGATupleWriter:** `internal/service/fga_tuple_writer.go` — обертка над `OpenFGAClient`.
- **Cluster-admin short-circuit:** `internal/service/authorize_service.go`
  (`cluster_admin_grants` lookup перед FGA Check).
- **OpenFGA HTTP client:** `internal/clients/openfga_*.go`
  (`openfga_read.go`, `openfga_expand.go`, `openfga_write.go`).

## Связанные компоненты

- [`19-authorize.md`](19-authorize.md) — public read-side.
- [`21-internal-iam.md`](21-internal-iam.md) — потребитель cluster-admin short-circuit.
- [`29-openfga-check.md`](29-openfga-check.md) — propagation chain.

## Ссылки на код

- `internal/apps/kacho/api/internal_authorize/handler.go`
- `internal/service/fga_tuple_writer.go`
- `internal/service/authorize_service.go`, `internal/clients/openfga_*.go`
