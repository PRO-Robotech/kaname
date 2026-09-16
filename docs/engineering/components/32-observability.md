# 32. Observability

## Назначение

Гайд по metrics и logs для kaname. Две плоскости:

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
kubectl -n kacho logs -l app=kaname -f --max-log-requests 10

# Loki query — только записи дренажа сброса кэша уровня WARN и выше.
{namespace="kacho",app="kaname"} |= "subject_change_drainer" | json | level="WARN"
```

## Metrics

### Экспорт

Метрики отдаются `promhttp`-хендлером на **отдельном cluster-internal HTTP-listener**
(`KANAME_API_SERVER__METRICS_ENDPOINT` — ключ `api-server.metrics-endpoint`,
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

Свои серии `kaname_grpc_server_handled_total` и
`kaname_grpc_server_handling_seconds` **сняты**. Их предмет — тот же, что у
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

Провязка — в композиционном корне (`cmd/kaname/serve.go`): слушателей iam
строит сам, минуя носитель входящего пути, поэтому отказ старта О13
(`servicecontract.New`) сюда не достаёт. Свойство держит обход дерева
`internal/repohygiene.TestEveryGRPCListenerObservesItsLatency`.

### Собственные метрики

Все имена несут префикс `kaname_` — тот же, которым продукт называет себя.

| Metric                                          | Type      | Labels                              | Описание                                                       |
|-------------------------------------------------|-----------|-------------------------------------|----------------------------------------------------------------|
| `kaname_authz_check_duration_seconds`        | histogram | rpc, allowed                        | Latency authz Check hot-path (FGA Check + транспорт). SLO ≤30ms p95. |
| `kaname_authz_check_decisions_total`         | counter   | rpc, decision                       | Решения Check по полосе и исходу (`allow`/`deny`/`error`).    |
| `kaname_lro_inflight`                         | gauge     | —                                   | Операции, выданные пулу воркеров прямо сейчас.                 |
| `kaname_lro_terminal_write_retries_total`    | counter   | op_type                             | Retry durable terminal-write (`MarkDone`/`MarkError`).        |
| `kaname_lro_terminal_write_failures_total`   | counter   | op_type                             | Terminal-write, исчерпавший retry-бюджет (зависшая операция). |
| `kaname_lro_orphans_recovered_total`         | counter   | outcome                             | Осиротевшие операции, поднятые reconciler'ом.                 |
| `kaname_lro_reconcile_runs_total`            | counter   | —                                   | Проходы reconciler-sweep.                                     |
| `kaname_lro_reconcile_errors_total`          | counter   | —                                   | Проходы reconciler-sweep, завершившиеся ошибкой.             |
| `kaname_build_info`                          | gauge     | version, revision                   | Метаданные сборки (постоянная 1). Значения ставит СБОРКА (`-ldflags -X`, из тех же аргументов, что клеймо образа), а не ручка профиля. `unstamped` в метке — не версия, а отсутствие штампа. |
| `kaname_identities_total`                    | counter   | —                                   | Личности, которых платформа видела за всё время (журнал `kaname.identity_journal`). |
| `kaname_identity_ledger_samples_total`       | counter   | outcome                             | Исходы фонового замера журнала (`ok`/`error`) — то, чем ноль в предыдущем ряду отличается от неснятого замера. |
| `kaname_provider_mirror_rows`                | gauge     | table                               | Строки удостоверений, чьё зеркало клиента у прежнего внешнего OAuth-сервера ещё предъявимо, по таблице (`service_account_oauth_clients`, `user_oauth_clients`). Предикат у таблиц РАЗНЫЙ — свой контур служебных учёток кладёт в зеркальную колонку наше имя; оба названы на странице решения `architecture/provider-mirror-column-retirement.md`. Ноль в обоих рядах — измеренная половина предиката снятия компонента (kacho#2564). |
| `kaname_provider_mirror_samples_total`       | counter   | outcome                             | Исходы фонового замера окна (`ok`/`error`). Ноль в предыдущем ряду открывает необратимое снятие, поэтому без этого ряда он не утверждает ничего. |
| `kaname_client_token_outcomes_total`          | counter   | outcome                             | Исходы обращений к токен-эндпоинту платформы. Набор значений — закрытый словарь `clientassertion.Outcomes()`; печатаются ВСЕ объявленные, включая нулевые, поэтому «ноль отказов» отличимо от «полоса не исполнялась ни разу». Наружу все отказы отдают один и тот же ответ — различимость для оператора живёт только в этой метке. |
| `kaname_expired_credential_reclaim_enabled`    | gauge     | —                                   | Включено ли снятие истёкших удостоверений (1/0). Заводится ДО развилки выключателя: у выключенного уборщика прогонов не будет вовсе, и его состояние выражается только этим рядом. |
| `kaname_expired_credential_reclaim_passes_total` | counter | outcome                             | Прогоны снятия истёкших удостоверений (`ok`/`dry-run`/`failed`). Полоса величин та же, что у первого уборщика по сроку. |
| `kaname_expired_credential_reclaim_rows_found_total` | counter | —                              | Строк найдено подлежащими снятию. Отдельно от снятых: «снято 0» не отличает «нечего снимать» от «нашёл и не снял». |
| `kaname_expired_credential_reclaim_rows_reclaimed_total` | counter | —                          | Строк снято; каждая возвращает место под потолком числа удостоверений на принципала. |
| `kaname_authn_hook_requests_total`            | counter   | route, outcome                      | Обращения поставщика личности к полосе хуков (`token`/`refresh`/`provision`/`recovery` × `ok`/`refused`/`failed`). У исходов три владельца починки: `refused` — провязка на стороне поставщика, `failed` — наша. Клетки заводятся нулём при провязке, поэтому «за час ноль обращений» выразимо как условие тревоги. |
| `kaname_readiness_dependency_checks_total`    | counter   | dependency, outcome                 | Оценки готовности по КАЖДОЙ объявленной зависимости (`ready`/`unready`). Метка `dependency` и есть класс починки: `database` — сломан продукт либо среда, `schema-version` — условие не создано (накат не прогнан либо откат поставил прежний образ на новую схему), `lro-worker` — идёт старт. Клетки заводятся нулём при регистрации, поэтому ноль во всех рядах означает «готовность не оценивалась ни разу». |

### Версия сборки — со ШТАМПА, а не с ручки

`kaname_build_info` кормится переменными `buildVersion`/`buildRevision`
(`cmd/kaname/buildstamp.go`), которые подставляет компоновщик:

```
go build -ldflags "-X main.buildVersion=$KACHO_IMAGE_VERSION -X main.buildRevision=$KACHO_IMAGE_REVISION"
```

Обе величины сборка берёт из ТЕХ ЖЕ аргументов, из которых делает клеймо образа
(`org.opencontainers.image.version` / `.revision`) и файл `/etc/kacho/image-revision`.
Источник один, поэтому витрина и образ разойтись не могут, а оператор сверяет
строки дословно.

Ручкой профиля величина не является намеренно: объявленную оператором он вправе
объявить любой, и первый же откат выкатки, забывший её поправить, сделал бы ряд
лживым ровно тогда, ради чего он заведён.

Незаданный штамп называет себя словом `unstamped`, а не `dev` и не пустой
меткой: и то и другое читалось бы как ответ, а это отсутствие измерения.

Держат это две пробы: `TestBuildStampReachesTheBinaryItLabels` разбирает
ИСПОЛНЯЕМУЮ часть `Dockerfile` и требует, чтобы у каждой подстановки была цель —
переменная уровня пакета (компоновщик о промахе `-X` молчит); соседний файл
инъекций доказывает, что она краснеет, когда `-ldflags` осталось обещанием в
комментарии.

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
текущем мгновении. Журнал `kaname.identity_journal` рядов не снимает никогда,
в том числе при уходе человека.

**Почему рядов ДВА.** `kaname_identities_total` читается фоновым замером и до
первого успешного замера равен нулю — то есть «личностей за всё время ноль» и
«замер не работает» дают на витрине одну и ту же картину. Различает их только
`kaname_identity_ledger_samples_total{outcome="ok"}`: пока он растёт, ноль в
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

### Правила тревоги — где они живут

**Здесь их нет, и это решение.** Правила везёт чарт объектом
`PrometheusRule` — `deploy/templates/prometheusrule.yaml`; тот же набор
пересказан на опубликованной странице `docs/content/advanced/observability.mdx`,
и два эти места сверяются в обе стороны при сборке
(`TestDeliveredAlertRulesMatchThePublishedPage`). Правя одно, правь второе —
третьей копии не заводи.

Здесь копия стояла и разошлась молча: она осталась исходником переноса правил на
страницу и с тех пор не сверялась ничем. За четыре правки объекта она отстала на
тринадцать правил, у двух назвала другие имена (`KanameAuthzCheckSlow` вместо
`KanameAuthzSlow`), а два держала у себя при том, что поставка их не везла вовсе.
Дежурный и инженер получали разные имена одной тревоги. Возврат копии сюда —
находка `TestAlertRulesAreDeclaredByOneProducer`; объяснить действующее правило
прозой этот документ по-прежнему вправе, чем и заняты три абзаца ниже.

**Цена копии оказалась не текстовой.** Её читал действующий держатель:
`TestIdentityGrowthMetricsHaveANamedReader` искал читателя ряда роста личностей
здесь и находил правило, которого поставка не везла. Гейт был зелен, а свойства
не было: у того, кто поставил продукт, оповещения не существовало. Теперь
держатель наведён на производителя, и красное, которое он дал при наведении,
снялось заведением правила в поставку.

#### Что известно о правилах сверх того, что написано в них самих

**Отказ вердикта о доступе (`KanameAuthzErrors`) — это fail-closed по всем
доменам.** Вердикт складывается реляционной формой в собственной базе службы,
поэтому её недоступность отказывает не одному домену, а каждому; порядок разбора
— `engineering/architecture/failure-domains.md`.

**Отбора по `grpc_service` в поставляемом `KanameRPCErrorRate` НЕТ — намеренно.**
Ряд `kacho_grpc_server_handled_total` заводит фундамент, а не служба, и он общий
на платформу. Поставка адресована тому, кто поставил ОДНУ службу: у него этот ряд
производит только она, и отбирать не от чего. Ставя службу рядом с платформой,
сузь правило меткой `grpc_service` — иначе доля считается по всем сервисам
сразу: `grpc_service=~"kaname\\.cloud\\.iam\\..*"`.

**Эта строка НЕ памятка — она под гейтом, и это единственная причина, по которой
её можно здесь держать.** Имя в отборе — имя КОНТРАКТА, а не имя
продукта, и переезд контракта его меняет: отбор, не совпавший ни с одним
контрактом, даёт пустой ряд и в числителе, и в знаменателе, поэтому порог не
превышается ни при каком состоянии продукта, а молчание такой тревоги неотличимо
от нормы. Так уже было — отбор пережил переезд пакета. Держит это
`TestAlertSelectorsNameAContractTheTreeProduces`: он сверяет отбор с
`ServiceDesc.ServiceName` сгенерированных стабов, то есть с той самой строкой,
которую слушатель кладёт в метку. Отсутствие отбора находкой у него не является
— именно потому, что для одиночной установки оно верно.

**Порог `KanameIdentityGrowthSpike` — величина наблюдения, а не отказа.**
Превышение ничего не отвергает, оно зовёт человека посмотреть, откуда взялись
личности: потолок на аккаунты обходится их заведением. Ряд накопителен, падать
ему некуда, поэтому всплеск означает именно появление, а не перезапуск счётчика.
Величина продуктовая и меняется в объекте.

## Healthcheck

HTTP-пробы поднимаются на cluster-internal hooks-listener (`:9092`, тот же, что
несет Ory-вебхуки):

| HTTP             | Что проверяет                                                     |
|------------------|------------------------------------------------------------------|
| `GET /healthz`   | Чистый liveness — pod жив (всегда 200).                           |
| `GET /readyz`    | Readiness — ping БД и поднятый LRO-worker; при падении → 503.     |

```bash
curl http://kaname:9092/healthz
# → 200 OK
```

В деплое liveness/readiness Kubernetes-пробы сконфигурированы как `tcpSocket` на
gRPC-порт (`:9090`); HTTP `/healthz` и `/readyz` доступны для ручной проверки и
внешнего мониторинга через hooks-listener.

## Подробности реализации

- **Logger:** `observability.NewSloggerLevel(os.Stdout, level)` (corelib) — JSON,
  `slog.SetDefault` в `cmd/kaname/serve.go`.
- **Metrics:** `internal/observability/metrics` (Prometheus `client_golang`,
  приватный registry); HTTP-listener и интерсепторы — в composition root
  `cmd/kaname/serve.go`.
- **Health:** живость и готовность строит ОБЩИЙ носитель `pkg/observability/health`
  (#1752) — тот же, что у шести остальных сервисов; `internal/handler/iamhooks/http_server.go`
  только монтирует его обработчики на `/healthz` и `/readyz`. Набор именованных
  проверок (`health.Checker`: база, версия схемы, LRO-worker) собирается в
  композиционном корне `cmd/kaname/hooks_mux.go`, а `SetShuttingDown` дёргается
  из `cmd/kaname/serve.go` — готовность уходит в 503 ДО остановки серверов.

  Прежде здесь стоял свой тип `ReadinessChecker` той же формы, объявленный в
  handler-слое: об одном предмете высказывались два места, и одно из них
  (шапка `pkg/observability/health`) объявляло себя единственным. Разойтись им
  было нечем — копии не собираются вместе и друг друга не читают.

## Связанные компоненты

- [`33-runbook.md`](33-runbook.md) — что делать при alert.
- `docs/content/advanced/observability.mdx` — ОПУБЛИКОВАННАЯ страница: то же,
  но для того, кто поставил продукт и кода не читает. Она обязана называть только
  ряды, у которых есть производитель, и нести порядок разбора, исполнимый без
  остальных компонентов платформы; держит это `TestObservabilityPagePromisesOnlyWhatTheServiceProduces`.
  Её правила тревоги ВЕЗЁТ ЧАРТ объектом `PrometheusRule` (ручка `alertRules.enabled`),
  а не переносит руками оператор; совпадение объекта со страницей сверяется в обе
  стороны — `TestDeliveredAlertRulesMatchThePublishedPage`.

  Набор правил ЗДЕСЬ и набор правил ТАМ сегодня РАЗНЫЕ — и по составу, и по именам
  (`KanameAuthzCheckSlow` против `KanameAuthzSlow`). Это два места об одном предмете,
  и сведение их — отдельная работа: поставку везёт опубликованная страница, поэтому
  расхождение сегодня стоит дежурному не мёртвой тревоги, а разного словаря.
- [`31-deployment.md`](31-deployment.md) — env vars, порты и mTLS для observability.
- [`29-relational-verdict.md`](29-relational-verdict.md) — latency-бюджет authz Check hot-path.

## Ссылки на код

- общий фундамент: `pkg/observability/` (slog + OTel), `pkg/operations/` (Recorder).
- `internal/observability/metrics/{metrics,lro_recorder,authz_decorator}.go`
- `cmd/kaname/serve.go` — wiring logger / metrics-listener / интерсепторов.
- `internal/handler/iamhooks/http_server.go` — `/healthz` / `/readyz`.
