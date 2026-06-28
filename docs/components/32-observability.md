# 32. Observability

## Назначение

Гайд по metrics и logs для kacho-iam. Две плоскости:

- **Logs** — структурированный slog (JSON), общий пакет `kacho-corelib/observability`.
- **Metrics** — Prometheus (`client_golang`), собственный adapter
  `internal/observability/metrics`. Экспорт — на отдельном cluster-internal
  HTTP-порту, никогда на публичной tenant-поверхности.

## Logs

### Format

Логгер строится через `observability.NewSloggerLevel(os.Stdout, level)` —
это `slog.NewJSONHandler`, то есть запись всегда в JSON:
`{time, level, msg, ...attrs}`. Уровень берется из `logger.level`
(default `INFO`, см. `31-deployment.md`).

### Уровни

- `DEBUG` — детальная диагностика (включается понижением `logger.level`).
- `INFO` — старт/останов listener'ов и фоновых воркеров, прогресс drainer'ов и
  reconciler'ов, результат verify-gate'а owner-binding.
- `WARN` — graceful degradation: режим `authn.mode=production` (анонимные
  отклоняются), частичная неудача backfill/reconcile-sweep (повтор на следующем
  проходе), отклоненный анонимный вызов на public listener.
- `ERROR` — отказ критичного пути: drainer вышел с ошибкой или паникнул,
  internal gRPC server остановился.

### Атрибуты

| Attr             | Когда                                                            |
|------------------|-----------------------------------------------------------------|
| `component`      | На каждом фоновом воркере — значение из списка ниже.             |
| `principal_type` | При отклонении анонимного/неаутентифицированного вызова.         |
| `principal_id`   | То же — вместе с `principal_type` (anti-anonymous gate).         |
| `err`            | На ERROR/WARN-записях с причиной отказа.                         |

`component` принимает значения фоновых воркеров: `fga_outbox_drainer`,
`subject_change_drainer`, `bootstrap_admin_reconciler`, `rsab_reconciler`,
`p8_backfill`, `p8_verify_gate`. Reconciler-backstop LRO логируется без
выделенного `component` (сообщение `LRO orphan reconciler backstop started`).

### Пример выборки из Loki

```bash
# Tail подов.
kubectl -n kacho logs -l app=kacho-iam -f --max-log-requests 10

# Loki query — только записи fga_outbox-drainer'а уровня WARN и выше.
{namespace="kacho",app="kacho-iam"} |= "fga_outbox_drainer" | json | level="WARN"
```

## Metrics

### Экспорт

Метрики отдаются `promhttp`-хендлером на **отдельном cluster-internal HTTP-listener**
(`KACHO_IAM_METRICS_ENDPOINT`, default `tcp://0.0.0.0:9095`; `metrics.enable`,
default `true`). Это не публичная gRPC-поверхность: кардинальность внутренних
лейблов не должна светиться наружу. Listener по умолчанию plaintext; включается
mTLS отдельной per-edge настройкой (см. `31-deployment.md`). Pod несет
scrape-аннотации `prometheus.io/scrape`, `prometheus.io/port: 9095`,
`prometheus.io/path: /metrics`.

Registry приватный (`prometheus.NewRegistry()`, не глобальный default) — это
держит тесты герметичными и исключает duplicate-register панику при рестартах
сервера в одном процессе.

### Собственные метрики

Все имена несут префикс `kacho_iam_`.

| Metric                                          | Type      | Labels                              | Описание                                                       |
|-------------------------------------------------|-----------|-------------------------------------|----------------------------------------------------------------|
| `kacho_iam_grpc_server_handled_total`           | counter   | grpc_service, grpc_method, grpc_code | Завершенные gRPC-запросы на сервере (оба listener'а).          |
| `kacho_iam_grpc_server_handling_seconds`        | histogram | grpc_service, grpc_method           | Latency обработки gRPC-запросов.                               |
| `kacho_iam_authz_check_duration_seconds`        | histogram | rpc, allowed                        | Latency authz Check hot-path (FGA Check + транспорт). SLO ≤30ms p95. |
| `kacho_iam_authz_check_decisions_total`         | counter   | rpc, decision                       | Решения Check по исходу (`allow`/`deny`/`error`).             |
| `kacho_iam_lro_inflight`                         | gauge     | —                                   | Операции, выданные пулу воркеров прямо сейчас.                 |
| `kacho_iam_lro_terminal_write_retries_total`    | counter   | op_type                             | Retry durable terminal-write (`MarkDone`/`MarkError`).        |
| `kacho_iam_lro_terminal_write_failures_total`   | counter   | op_type                             | Terminal-write, исчерпавший retry-бюджет (зависшая операция). |
| `kacho_iam_lro_orphans_recovered_total`         | counter   | outcome                             | Осиротевшие операции, поднятые reconciler'ом.                 |
| `kacho_iam_lro_reconcile_runs_total`            | counter   | —                                   | Проходы reconciler-sweep.                                     |
| `kacho_iam_lro_reconcile_errors_total`          | counter   | —                                   | Проходы reconciler-sweep, завершившиеся ошибкой.             |

Дополнительно registry несет стандартные runtime-коллекторы Go (`go_*`) и процесса
(`process_*`).

### Где они снимаются

- **gRPC-метрики** — `Registry.UnaryServerInterceptor`, зарегистрирован первым в
  цепочке обоих listener'ов (public :9090 + internal :9091), поэтому покрывает весь
  chain.
- **Authz-метрики** — decorator `InstrumentedAuthorizer` оборачивает
  relation-authz порт (`CheckRelation`); use-case остается чистым и не знает про
  Prometheus (instrumentation на границе adapter'а).
- **LRO-метрики** — `LRORecorder` реализует `operations.Recorder` из corelib и
  подключается к LRO-воркеру/reconciler'у в composition root. Без него сигналы
  зависающей операции (retry/fail terminal-write, in-flight, orphan-recovery)
  были бы невидимы на `/metrics`.

### Рекомендуемые alert-правила

```yaml
- alert: KachoIAMAuthzCheckSlow
  expr: histogram_quantile(0.95, sum by (le) (rate(kacho_iam_authz_check_duration_seconds_bucket[5m]))) > 0.03
  for: 5m
  annotations:
    summary: "authz Check p95 > 30ms — превышен SLO hot-path авторизации"

- alert: KachoIAMAuthzCheckErrors
  expr: rate(kacho_iam_authz_check_decisions_total{decision="error"}[5m]) > 1
  for: 10m
  annotations:
    summary: "authz Check возвращает error — backend OpenFGA недоступен/деградирует"

- alert: KachoIAMLROStranded
  expr: increase(kacho_iam_lro_terminal_write_failures_total[15m]) > 0
  annotations:
    summary: "LRO terminal-write исчерпал retry-бюджет — операция зависла (op_type={{ $labels.op_type }})"

- alert: KachoIAMLROBacklog
  expr: kacho_iam_lro_inflight > 1000
  for: 5m
  annotations:
    summary: "LRO inflight > 1000 — backlog воркер-пула"

- alert: KachoIAMReconcileErrors
  expr: rate(kacho_iam_lro_reconcile_errors_total[10m]) > 0
  for: 10m
  annotations:
    summary: "reconciler-sweep падает — осиротевшие операции не подбираются"

- alert: KachoIAMRPCErrorRate
  expr: |
    sum(rate(kacho_iam_grpc_server_handled_total{grpc_code!="OK"}[5m]))
      / sum(rate(kacho_iam_grpc_server_handled_total[5m])) > 0.05
  for: 10m
  annotations:
    summary: "доля не-OK gRPC-ответов > 5%"
```

## Healthcheck

HTTP-пробы поднимаются на cluster-internal hooks-listener (`:9092`, тот же, что
несет Ory-вебхуки):

| HTTP             | Что проверяет                                                     |
|------------------|------------------------------------------------------------------|
| `GET /healthz`   | Чистый liveness — pod жив (всегда 200).                           |
| `GET /readyz`    | Readiness — ping БД и поднятый LRO-worker; при падении → 503.     |

```bash
curl http://kacho-iam:9092/healthz
# → 200 OK
```

В деплое liveness/readiness Kubernetes-пробы сконфигурированы как `tcpSocket` на
gRPC-порт (`:9090`); HTTP `/healthz` и `/readyz` доступны для ручной проверки и
внешнего мониторинга через hooks-listener.

## Подробности реализации

- **Logger:** `observability.NewSloggerLevel(os.Stdout, level)` (corelib) — JSON,
  `slog.SetDefault` в `cmd/kacho-iam/serve.go`.
- **Metrics:** `internal/observability/metrics` (Prometheus `client_golang`,
  приватный registry); HTTP-listener и интерсепторы — в composition root
  `cmd/kacho-iam/serve.go`.
- **Health:** `internal/handler/iamhooks/http_server.go` (`/healthz`, `/readyz`),
  набор `ReadinessChecker` собирается в `cmd/kacho-iam/hooks_mux.go`.

## Связанные компоненты

- [`33-runbook.md`](33-runbook.md) — что делать при alert.
- [`31-deployment.md`](31-deployment.md) — env vars, порты и mTLS для observability.
- [`29-openfga-check.md`](29-openfga-check.md) — latency-бюджет authz Check hot-path.

## Ссылки на код

- corelib: `kacho-corelib/observability/` (slog), `kacho-corelib/operations` (Recorder).
- `internal/observability/metrics/{metrics,lro_recorder,authz_decorator}.go`
- `cmd/kacho-iam/serve.go` — wiring logger / metrics-listener / интерсепторов.
- `internal/handler/iamhooks/http_server.go` — `/healthz` / `/readyz`.
