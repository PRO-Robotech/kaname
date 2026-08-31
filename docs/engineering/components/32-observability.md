# 32. Observability

## Назначение

Гайд по metrics и logs для kacho-iam. Две плоскости:

- **Logs** — структурированный slog (JSON), общий пакет `pkg/observability`.
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

`component` принимает значения фоновых воркеров: `subject_change_drainer`,
`bootstrap_admin_reconciler`, `rsab_reconciler`,
`p8_backfill`, `p8_verify_gate`. Reconciler-backstop LRO логируется без
выделенного `component` (сообщение `LRO orphan reconciler backstop started`).

### Пример выборки из Loki

```bash
# Tail подов.
kubectl -n kacho logs -l app=kacho-iam -f --max-log-requests 10

# Loki query — только записи дренажа сброса кэша уровня WARN и выше.
{namespace="kacho",app="kacho-iam"} |= "subject_change_drainer" | json | level="WARN"
```

## Metrics

### Экспорт

Метрики отдаются `promhttp`-хендлером на **отдельном cluster-internal HTTP-listener**
(`KACHO_IAM_API_SERVER__METRICS_ENDPOINT` — ключ `api-server.metrics-endpoint`,
точка → `__`, дефис → `_`; default `tcp://0.0.0.0:9095`; `metrics.enable`,
default `true`). Это не публичная gRPC-поверхность: кардинальность внутренних
лейблов не должна светиться наружу. Listener по умолчанию plaintext; включается
mTLS отдельной per-edge настройкой (см. `31-deployment.md`). Pod несет
scrape-аннотации `prometheus.io/scrape`, `prometheus.io/port: 9095`,
`prometheus.io/path: /metrics`.

Registry приватный (`prometheus.NewRegistry()`, не глобальный default) — это
держит тесты герметичными и исключает duplicate-register панику при рестартах
сервера в одном процессе.

### Задержка обслуженного вызова — ПЛАТФОРМЕННАЯ серия, не своя

Свои серии `kacho_iam_grpc_server_handled_total` и
`kacho_iam_grpc_server_handling_seconds` **сняты**. Их предмет — тот же, что у
платформенного измерителя `pkg/grpcsrv.ServerLatency`, а два места об одном
предмете расходятся: снятая пара смешивала отказ с успехом в одном ряду, не
различала полосу слушателя и брала сетку корзин по умолчанию (первая граница —
пять миллисекунд), то есть складывала все чтения из своей базы в одну корзину.

Теперь iam берёт тот же измеритель, что и остальные шесть сервисов:

| Metric | Type | Labels | Описание |
|---|---|---|---|
| `kacho_grpc_server_handled_total` | counter | grpc_service, grpc_method, listener, grpc_code | Обслуженные вызовы обоих слушателей, включая оборванные подписки. |
| `kacho_grpc_server_handling_seconds` | histogram | grpc_service, grpc_method, listener, outcome | Задержка ОДИНОЧНОГО вызова. `outcome` ∈ {ok, error}: быстрый отказ занижает хвост, медленный завышает, поэтому смешивать их нельзя. |
| `kacho_grpc_server_stream_seconds` | histogram | grpc_service, grpc_method, listener, outcome | Срок жизни серверного стрима — ДРУГАЯ величина, поэтому и серия другая, со своей сеткой корзин. |

Домен читается из метки `grpc_service` (полное имя метода начинается с пакета
контракта), поэтому отдельной метки сервиса нет. Полоса `listener` ∈
{public, internal, unknown} различает два слушателя: `OperationService` и пара
`Internal*` служатся обоими, и слитый ряд был бы средним двух разных величин.

Провязка — в композиционном корне (`cmd/kacho-iam/serve.go`): слушателей iam
строит сам, минуя носитель входящего пути, поэтому отказ старта О13
(`servicecontract.New`) сюда не достаёт. Свойство держит обход дерева
`internal/repohygiene.TestEveryGRPCListenerObservesItsLatency`.

### Собственные метрики

Все имена несут префикс `kacho_iam_`.

| Metric                                          | Type      | Labels                              | Описание                                                       |
|-------------------------------------------------|-----------|-------------------------------------|----------------------------------------------------------------|
| `kacho_iam_authz_check_duration_seconds`        | histogram | rpc, allowed                        | Latency authz Check hot-path (FGA Check + транспорт). SLO ≤30ms p95. |
| `kacho_iam_authz_check_decisions_total`         | counter   | rpc, decision                       | Решения Check по полосе и исходу (`allow`/`deny`/`error`).    |
| `kacho_iam_lro_inflight`                         | gauge     | —                                   | Операции, выданные пулу воркеров прямо сейчас.                 |
| `kacho_iam_lro_terminal_write_retries_total`    | counter   | op_type                             | Retry durable terminal-write (`MarkDone`/`MarkError`).        |
| `kacho_iam_lro_terminal_write_failures_total`   | counter   | op_type                             | Terminal-write, исчерпавший retry-бюджет (зависшая операция). |
| `kacho_iam_lro_orphans_recovered_total`         | counter   | outcome                             | Осиротевшие операции, поднятые reconciler'ом.                 |
| `kacho_iam_lro_reconcile_runs_total`            | counter   | —                                   | Проходы reconciler-sweep.                                     |
| `kacho_iam_lro_reconcile_errors_total`          | counter   | —                                   | Проходы reconciler-sweep, завершившиеся ошибкой.             |
| `kacho_iam_identities_total`                    | counter   | —                                   | Личности, которых платформа видела за всё время (журнал `kacho_iam.identity_journal`). |
| `kacho_iam_identity_ledger_samples_total`       | counter   | outcome                             | Исходы фонового замера журнала (`ok`/`error`) — то, чем ноль в предыдущем ряду отличается от неснятого замера. |

### Метка `rpc` — ЗАКРЫТЫЙ словарь из трёх полос

Полосы принадлежат РАЗНЫМ вызывающим, и складывать их без разбора нельзя:

| `rpc` | кто спрашивает | единица счёта |
|---|---|---|
| `Check` | **край** (`AuthorizeService/Check`, :9090) | один вопрос на входящий запрос арендатора |
| `BatchCheck` | сужатель списочной выдачи модулей (`AuthorizeService/BatchCheck`) | вопрос на КАЖДЫЙ объект страницы (страница контрактно бывает до 1000) |
| `CheckRelation` | пообъектное звено решения модулей (`InternalIAMService/Check`, :9091) | вопрос на RPC |

Единица счёта у полос разная намеренно. На полосе пачки метка `allowed` у
**гистограммы** отвечает «вызов состоялся», а не «вопрос разрешён»: ответов в
пачке много, и один ярлык на всех был бы ложью о каждом; на «чем кончился
вопрос» отвечает счётчик решений, по вопросу на каждый.

> До #772 производитель был у ОДНОЙ полосы из трёх (`CheckRelation`), а
> `Check` был назван в комментарии типа наблюдения и не эмитировался ничем.
> Следствие: всякое «проверок в секунду», снятое с iam, было занижено — на пути
> чтения по идентификатору ровно вдвое, потому что проверок там две. Полоса без
> производителя присутствует нулём и выглядит исправным наблюдением, поэтому
> словарь теперь сверяется с производителями пробой
> `TestEveryDeclaredLaneHasAProducer`.

Дополнительно registry несет стандартные runtime-коллекторы Go (`go_*`) и процесса
(`process_*`).

### Рост числа личностей — страховка, а не мера

Потолок на число аккаунтов ОДНОЙ личности (миграция `484002`) обходится
заведением личностей: регистрация самообслуживаемая и стоит подтверждённого
адреса. Потолок темпа удорожает автоматизацию, но не ловит МЕДЛЕННОЕ накопление,
и до `#619` его не производила ни одна величина.

**Отказа по этому порогу НЕТ и он не подразумевается.** Отказ пришёл бы
следующему честному человеку, а не тому, кто исчерпал полку, — поэтому здесь
сначала ВИДНО, а решение об отказе принимается отдельно и владельцем. Записью
каталога потолков это не является: у потолка платформы нет носителя, внешнего по
отношению к предмету счёта, — кластер и есть предмет.

**Величина накопительная, а не мгновенная**, и это не стиль. Мгновенный счёт
личностей немонотонен: человек уходит, и величина падает. На падающем ряде рост
не определён — `increase()` молчит там, где рост и был, — а «личностей ноль»
перестаёт быть утверждением о всей жизни платформы и становится утверждением о
текущем мгновении. Журнал `kacho_iam.identity_journal` рядов не снимает никогда,
в том числе при уходе человека.

**Почему рядов ДВА.** `kacho_iam_identities_total` читается фоновым замером и до
первого успешного замера равен нулю — то есть «личностей за всё время ноль» и
«замер не работает» дают на витрине одну и ту же картину. Различает их только
`kacho_iam_identity_ledger_samples_total{outcome="ok"}`: пока он растёт, ноль в
первом ряду означает ноль.

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
    summary: "authz Check возвращает error — база kacho_iam недоступна или деградирует"
    description: "Вердикт складывается реляционной формой в собственной базе службы;
      отказ означает fail-closed по всем доменам — см. engineering/architecture/failure-domains.md"

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

- alert: KachoIAMIdentityGrowthSpike
  # Порог наблюдения, а не отказа: превышение НЕ отвергает регистрацию, оно
  # зовёт человека посмотреть. Величина порога — продуктовая; она названа здесь
  # и меняется здесь же, потому что читателя у ряда ровно один.
  expr: increase(kacho_iam_identities_total[1h]) > 100
  for: 15m
  annotations:
    summary: "личностей за час прибавилось больше 100 — потолок на аккаунты личности обходится заведением личностей"
    description: "Ряд накопителен: падать ему некуда, поэтому всплеск здесь означает
      именно появление, а не перезапуск счётчика. Проверить источник регистраций
      прежде, чем менять пороги."

- alert: KachoIAMIdentityLedgerUnsampled
  # Ноль в kacho_iam_identities_total законен: платформа могла не увидеть ни
  # одной личности. Незаконно — НЕ ЗНАТЬ, ноль это или неснятый замер. Тревога
  # звонит именно на второе: успешных замеров не прибавляется.
  expr: increase(kacho_iam_identity_ledger_samples_total{outcome="ok"}[10m]) == 0
  for: 10m
  annotations:
    summary: "журнал личностей не замеряется — kacho_iam_identities_total перестал что-либо утверждать"
    description: "Пока успешные замеры не идут, ноль и любое застывшее число в ряду
      роста неотличимы от действительности. Смотреть outcome=\"error\" того же
      семейства и журнал службы."

- alert: KachoIAMRPCErrorRate
  # Отбор по grpc_service, а не по имени серии: серия теперь общая на платформу,
  # и без отбора тревога считала бы долю по всем семи сервисам сразу.
  expr: |
    sum(rate(kacho_grpc_server_handled_total{grpc_service=~"kacho\\.cloud\\.iam\\..*",grpc_code!="OK"}[5m]))
      / sum(rate(kacho_grpc_server_handled_total{grpc_service=~"kacho\\.cloud\\.iam\\..*"}[5m])) > 0.05
  for: 10m
  annotations:
    summary: "доля не-OK gRPC-ответов iam > 5%"
```

## Healthcheck

HTTP-пробы поднимаются на cluster-internal hooks-listener (`:9092`, тот же, что
несет Ory-вебхуки):

| HTTP             | Что проверяет                                                            |
|------------------|--------------------------------------------------------------------------|
| `GET /healthz`   | Живость — процесс жив (200); на гашении 503.                              |
| `GET /readyz`    | Готовность — ping БД и поднятый LRO-worker; упавшие названы в теле → 503. |

Оба маршрута объявляют метод в образце: обращение не тем методом отвергает сам
мультиплексор (`405`).

```bash
curl -i http://kacho-iam:9092/healthz
# → 200 ok

curl -i http://kacho-iam:9092/readyz
# → 200 {"status":"ready"}
# либо 503 {"status":"not_ready","dependencies":[{"name":"database","status":"down"}]}
```

В чарте `readinessProbe` спрашивает `GET /readyz`, а `livenessProbe` — `GET
/healthz`, обе на порт `http-hooks`. Разведение намеренное: готовность знает про
зависимости, живость — только про процесс, иначе блип зависимости читался бы
как смерть процесса и давал шторм перезапусков.

### Носитель — ОБЩИЙ, и это решение (задача продукта #1729)

Живость и готовность отдаёт `pkg/observability/health` — тот же носитель, что у
остальных шести сервисов. Собственной формы у iam больше нет: она обходила
зависимости по очереди и называла первую упавшую, не ограничивала чекер сроком
(молчащая зависимость подвешивала обработчик целиком) и не имела состояния
гашения вовсе.

Последнее для листа графа дороже, чем для любого другого сервиса: к владельцу
прав на каждом вызове ходят все прочие, и гасящийся под, продолжающий объявлять
себя готовым, отправляет в отказ соединения ЧУЖИЕ проверки доступа. Теперь
`SetShuttingDown` переводит `/readyz` в 503 первым действием гашения — до
остановки слушателей.

Довод в пользу собственной формы — «iam лист графа, набор зависимостей у него
другой» — опровергнут замером: у общего носителя **ноль** зависимостей вне
stdlib, поэтому его импорт не добавляет листу ни ребра, ни чужой библиотеки.

```sh
comm -23 <(go list -deps ./pkg/observability/health | sort) <(go list std | sort)
# → только сам пакет
```

Свойство держит гейт `internal/repohygiene`
`TestReadinessIsServedByASingleCarrier`: он считает объявления носителя по
структуре (`Name string` плюс `Check func(context.Context) error`) и печатает
перепись двумя величинами — носителей всего и из них общих.

## Подробности реализации

- **Logger:** `observability.NewSloggerLevel(os.Stdout, level)` (corelib) — JSON,
  `slog.SetDefault` в `cmd/kacho-iam/serve.go`.
- **Metrics:** `internal/observability/metrics` (Prometheus `client_golang`,
  приватный registry); HTTP-listener и интерсепторы — в composition root
  `cmd/kacho-iam/serve.go`.
- **Health:** маршруты монтирует `internal/handler/iamhooks/http_server.go`
  (`/healthz`, `/readyz`); набор `health.Checker` и сам агрегатор собирает
  `cmd/kacho-iam/hooks_mux.go`, а перевод готовности в отказ на гашении —
  `cmd/kacho-iam/serve.go`.

## Связанные компоненты

- [`33-runbook.md`](33-runbook.md) — что делать при alert.
- [`31-deployment.md`](31-deployment.md) — env vars, порты и mTLS для observability.
- [`29-relational-verdict.md`](29-relational-verdict.md) — latency-бюджет authz Check hot-path.

## Ссылки на код

- общий фундамент: `pkg/observability/` (slog + OTel), `pkg/operations/` (Recorder).
- `internal/observability/metrics/{metrics,lro_recorder,authz_decorator}.go`
- `cmd/kacho-iam/serve.go` — wiring logger / metrics-listener / интерсепторов.
- `internal/handler/iamhooks/http_server.go` — `/healthz` / `/readyz`.
