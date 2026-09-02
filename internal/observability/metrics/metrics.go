// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package metrics is the kacho-iam Prometheus observability adapter.
//
// It lives at the cmd/adapter boundary (Clean Architecture): the prometheus
// client is imported ONLY here and in the composition root (cmd/kacho-iam) —
// never in domain/ or in the AuthorizeService use-case. The use-case stays a
// pure FGA-Check pipeline; instrumentation is layered on via the
// InstrumentedAuthorizer decorator (authz_decorator.go) and a gRPC server
// interceptor.
//
// Surfaces:
//   - Registry.Handler() — promhttp.Handler served on a SEPARATE internal port
//     (KACHO_IAM_METRICS_ENDPOINT, default :9095). Never on the public tenant
//     gRPC surface (it would expose internal cardinality — security.md).
//   - Registry.ObserveAuthz — the authz Check hot-path histogram + decision
//     counter (the documented ≤30ms p95 budget on AuthorizeService.Check /
//     CheckRelation was previously un-instrumented).
//   - Registry.UnaryServerInterceptor — per-RPC request count + latency + code,
//     registered on BOTH gRPC listeners (public :9090 + internal :9091).
//
// All metric names carry the `kacho_iam_` prefix (naming convention; the env
// domain segment is IAM).
package metrics

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// Registry owns a private *prometheus.Registry and the kacho-iam collectors.
// It is created once in the composition root and shared by the metrics HTTP
// listener, the authz decorator and the gRPC interceptors. A private registry
// (not the global default) keeps tests hermetic and avoids duplicate-register
// panics across server restarts in the same process (integration tests).
type Registry struct {
	reg *prometheus.Registry

	authzDuration  *prometheus.HistogramVec
	authzDecisions *prometheus.CounterVec

	// authzStoreAttempts — исход КАЖДОЙ попытки обращения к хранилищу прав.
	//
	// Заведён по #720: до него отказ хранилища был снаружи ОДНИМ событием —
	// вызывающий получал `unavailable`, и «хранилище перезапускали»,
	// «хранилище молчит» и «оборвалось соединение из пула» выглядели
	// одинаково. Различить их можно было только чтением журнала построчно,
	// уже после того как отказ истолкован; на прогоне из 736 запросов с одним
	// отказом это означает найти одну строку среди тысяч.
	authzStoreAttempts *prometheus.CounterVec

	// compensationOnce/compensation — единственный экземпляр коллекторов
	// компенсации. Их потребители (writer намерений и дренаж) собираются в
	// разных местах композиционного корня, а prometheus.MustRegister падает на
	// повторной регистрации — поэтому экземпляр один и берётся через
	// CompensationRecorder(), а не создаётся каждым потребителем.
	compensationOnce sync.Once
	compensation     *CompensationRecorder

	// outboxOnce/outbox — единственный экземпляр коллекторов состояния очередей.
	// Очередей у kacho-iam три (fga_outbox, subject_change_outbox,
	// provider_compensation_outbox), их сканеры собираются в разных местах
	// композиционного корня, а серии у них ОБЩИЕ и различаются лейблом `table`.
	// Второй конструктор уронил бы старт на duplicate-register.
	outboxOnce sync.Once
	outbox     *OutboxRecorder

	// registryTokenKindOnce/registryTokenKind — единственный экземпляр счётчика
	// исходов докерной полосы по виду предъявленного удостоверения (#1143).
	// Серии у него общие и различаются лейблом `outcome`; второй конструктор
	// уронил бы старт на duplicate-register.
	registryTokenKindOnce sync.Once
	registryTokenKind     *RegistryTokenCredentialKindRecorder

	// inviteActivationOnce/inviteActivation — единственный экземпляр счётчика
	// исходов активации приглашения. Потребителей два и собираются они в разных
	// местах композиционного корня: gRPC-путь (buildServices) и ЖИВОЙ путь входа
	// (buildHooksMux). Второй конструктор уронил бы старт на duplicate-register.
	inviteActivationOnce sync.Once
	inviteActivation     *InviteActivationRecorder

	// inviteMailOnce/inviteMail — единственный экземпляр счётчика исходов
	// ОТПРАВКИ письма приглашения. Он про другой предмет, чем сосед выше:
	// активация отвечает на «выкупили ли приглашение», отправка — на «ушло ли
	// письмо и почему нет». Потребитель сегодня один (применитель очереди), но
	// единственность держится тем же способом: второй конструктор уронил бы
	// старт на повторной регистрации ровно тогда, когда механизм провязали
	// целиком.
	inviteMailOnce sync.Once
	inviteMail     *InviteMailRecorder
}

// NewRegistry constructs the registry, registers the Go + process runtime
// collectors and the kacho-iam collectors.
func NewRegistry() *Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	r := &Registry{
		reg: reg,
		authzDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "kacho_iam_authz_check_duration_seconds",
			Help: "Latency of the authz Check hot path (FGA Check + transport), by rpc lane and outcome. " +
				"SLO budget: <=30ms p95. On the BatchCheck lane `allowed` means the CALL completed, not that a " +
				"question was allowed: one batch carries many answers, and a single label over all of them would " +
				"be false about each. Per-question outcomes live in the decisions counter.",
			// Buckets sized around the ≤30ms p95 budget, with headroom to spot
			// regressions/timeouts (FGA Check ≤10ms target).
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.02, 0.03, 0.05, 0.1, 0.25, 0.5, 1},
		}, []string{"rpc", "allowed"}),
		authzDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_authz_check_decisions_total",
			Help: "Authz Check decisions by rpc and outcome (allow|deny|error).",
		}, []string{"rpc", "decision"}),
		authzStoreAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_authz_store_attempts_total",
			Help: "Attempts against the authorization store by operation, outcome " +
				"(ok|store_rejected|store_error|store_unreachable|pooled_conn_dropped|" +
				"conn_dropped|store_timeout|decode_failed) and whether the connection " +
				"came from the idle pool. Distinguishes a store outage from a dead " +
				"pooled connection — indistinguishable from the caller's side.",
		}, []string{"op", "outcome", "reused"}),
	}
	reg.MustRegister(r.authzDuration, r.authzDecisions, r.authzStoreAttempts)
	return r
}

// Namespace — префикс имён ВСЕХ серий этого сервиса. Отдельная константа, а не
// литерал по месту: имя серии — контракт с панелями и правилами тревог, и
// собранное в двух местах оно разъедется на первом переименовании.
const Namespace = "kacho_iam"

// RegisterPoolStats подключает к этому реестру состояние ОДНОГО пула соединений
// под именем `poolName` (`primary`, `replica`).
//
// # Зачем
//
// Насыщение пула до этого не наблюдалось ничем: снаружи «запрос ждал свободного
// соединения» и «запрос сам по себе медленный» дают одну и ту же растянутую
// задержку RPC, а лечатся противоположным. Разбор величин и того, какая пара из
// них различает эти два случая, — у самого коллектора (`pkg/db`); здесь только
// провязка.
//
// # Почему НЕ MustRegister
//
// Повторная регистрация того же пула — ошибка сборки, а не причина ронять
// процесс: наблюдение, убивающее сервис, который оно наблюдает, хуже
// отсутствующего. Повтор поэтому проглатывается, а серии остаются от первой
// регистрации — они те же самые.
//
// Всякий ДРУГОЙ отказ регистрации означает несогласованное объявление (то же имя
// с другой размерностью), и он остаётся паникой: пропустить его молча значило бы
// поднять процесс с семейством, которого на /metrics не будет никогда.
//
// `pool == nil` допустим: коллектор просто не отдаёт ни одной серии — см. его
// разбор. Ветка «а есть ли пул» поэтому не нужна вызывающему.
func (r *Registry) RegisterPoolStats(poolName string, pool *pgxpool.Pool) {
	err := r.reg.Register(coredb.NewPoolStatsCollector(Namespace, poolName, pool))
	if err == nil {
		return
	}
	var already prometheus.AlreadyRegisteredError
	if errors.As(err, &already) {
		return
	}
	panic(fmt.Sprintf("metrics: register pool stats %q: %v", poolName, err))
}

// Handler returns the promhttp handler exposing this registry. Mount it on the
// dedicated internal metrics listener only.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// Registerer отдаёт реестр этого сервиса как ПРИЁМНИК регистрации.
//
// # Зачем окно наружу, если рядом есть именованные
//
// Соседние окна (`RegisterAuthzCache`, `RegisterListNarrow`, `RegisterPoolStats`)
// принимают ЧИТАТЕЛЯ готовых величин: они существуют, чтобы этот пакет не
// импортировал доменные. Здесь предмет обратный — носителю входящего пути надо
// ЗАВЕСТИ своё семейство серий, а не отдать читателя, и заводит он его СВОИМИ
// руками. Тогда несогласованное объявление (то же имя с другой размерностью)
// становится отказом подъёма, а не молчаливой пропажей семейства со скрейпа.
//
// Разбор решения — у поля, ради которого окно открыто:
// `pkg/servicecontract.Spec.Metrics` (отказ старта О13). Здесь он не
// пересказывается: два места об одном предмете расходятся на первом уточнении.
//
// Отдаётся именно `Registerer`, а не сам реестр: собирать величины через это
// окно нельзя, и сузить его до одной операции дешевле, чем потом выяснять, кто
// ещё им воспользовался.
func (r *Registry) Registerer() prometheus.Registerer { return r.reg }

// AuthzObservation is a single recorded authz Check outcome.
type AuthzObservation struct {
	// RPC — полоса, которой задан вопрос. Значения — ЗАКРЫТЫЙ словарь
	// [DeclaredAuthzLanes]; каждое обязано иметь производителя, и это держит
	// проба `TestEveryDeclaredLaneHasAProducer`. Прежняя редакция называла
	// значения в этом комментарии, и одно из двух названных не производилось
	// ничем: полоса присутствовала нулём и выглядела исправным наблюдением.
	RPC      string
	Allowed  bool    // decision allowed
	Err      bool    // backend/validation error (overrides allow/deny in the decision counter)
	Duration float64 // seconds
}

// ObserveAuthz records one authz Check outcome: the duration histogram (labelled
// rpc + allowed) plus the decision counter (allow|deny|error).
func (r *Registry) ObserveAuthz(o AuthzObservation) {
	r.ObserveAuthzDuration(o.RPC, o.Allowed, o.Duration)
	r.ObserveAuthzDecision(o.RPC, o.Allowed, o.Err)
}

// ObserveAuthzDuration записывает ТОЛЬКО длительность одного вызова.
//
// Отделено от решения потому, что у пачки вопросов эти две величины считаются
// по-разному: длительность принадлежит ВЫЗОВУ (делить её на вопросы значило бы
// утверждать про каждый то, чего никто не измерял), а решения — ВОПРОСАМ
// (страница контрактно бывает до тысячи объектов, и счёт по вызовам занизил бы
// нагрузку от списочной выдачи в тысячу раз).
func (r *Registry) ObserveAuthzDuration(rpc string, allowed bool, seconds float64) {
	r.authzDuration.WithLabelValues(rpc, strconv.FormatBool(allowed)).Observe(seconds)
}

// ObserveAuthzDecision записывает ТОЛЬКО исход одного вопроса.
func (r *Registry) ObserveAuthzDecision(rpc string, allowed, failed bool) {
	decision := "allow"
	switch {
	case failed:
		decision = "error"
	case !allowed:
		decision = "deny"
	}
	r.authzDecisions.WithLabelValues(rpc, decision).Inc()
}

// ObserveAuthzStoreAttempt records ONE attempt against the authorization store.
//
// Принимает плоские значения, а не тип адаптера хранилища: иначе один адаптер
// импортировал бы другой ради метки счётчика (dependency-rule). Перевод делает
// композиционный корень — единственное место, которое знает обоих.
func (r *Registry) ObserveAuthzStoreAttempt(op, outcome string, reused bool) {
	if op == "" {
		op = "unknown"
	}
	if outcome == "" {
		outcome = "unknown"
	}
	r.authzStoreAttempts.WithLabelValues(op, outcome, strconv.FormatBool(reused)).Inc()
}

// Задержка обслуженного вызова наблюдается НЕ ЗДЕСЬ.
//
// Здесь стояла своя пара серий (`kacho_iam_grpc_server_handling_seconds` и
// `kacho_iam_grpc_server_handled_total`) со своим интерсептором и своим
// разбором полного имени метода. Предмет у неё тот же, что у платформенного
// измерителя `pkg/grpcsrv.ServerLatency`, — а два места об одном предмете
// расходятся: эта пара смешивала отказ с успехом в одном ряду (быстрый отказ
// занижает хвост, медленный завышает), не различала полосу слушателя и брала
// сетку корзин по умолчанию, начинающуюся с пяти миллисекунд, — то есть
// складывала все чтения из своей базы в одну корзину.
//
// Теперь iam берёт тот же измеритель, что и остальные шесть сервисов, и его
// ряды лежат в общем семействе платформы: вопрос «где во всей платформе вырос
// хвост» стал одним запросом, а не семью. Провязка — в композиционном корне
// (`cmd/kacho-iam/serve.go`), потому что слушателей iam строит сам, минуя
// носитель входящего пути.
