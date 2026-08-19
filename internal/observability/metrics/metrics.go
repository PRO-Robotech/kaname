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
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
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

	grpcHandled  *prometheus.CounterVec
	grpcDuration *prometheus.HistogramVec

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

	// inviteActivationOnce/inviteActivation — единственный экземпляр счётчика
	// исходов активации приглашения. Потребителей два и собираются они в разных
	// местах композиционного корня: gRPC-путь (buildServices) и ЖИВОЙ путь входа
	// (buildHooksMux). Второй конструктор уронил бы старт на duplicate-register.
	inviteActivationOnce sync.Once
	inviteActivation     *InviteActivationRecorder
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
			Help: "Latency of the authz Check hot path (FGA Check + transport), by rpc and decision. SLO budget: ≤30ms p95.",
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
		grpcHandled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_grpc_server_handled_total",
			Help: "Total gRPC requests completed on the server, by service, method and resulting status code.",
		}, []string{"grpc_service", "grpc_method", "grpc_code"}),
		grpcDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kacho_iam_grpc_server_handling_seconds",
			Help:    "Latency of gRPC requests handled on the server, by service and method.",
			Buckets: prometheus.DefBuckets,
		}, []string{"grpc_service", "grpc_method"}),
	}
	reg.MustRegister(r.authzDuration, r.authzDecisions, r.authzStoreAttempts, r.grpcHandled, r.grpcDuration)
	return r
}

// Handler returns the promhttp handler exposing this registry. Mount it on the
// dedicated internal metrics listener only.
func (r *Registry) Handler() http.Handler {
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// AuthzObservation is a single recorded authz Check outcome.
type AuthzObservation struct {
	RPC      string  // "Check" | "CheckRelation"
	Allowed  bool    // decision allowed
	Err      bool    // backend/validation error (overrides allow/deny in the decision counter)
	Duration float64 // seconds
}

// ObserveAuthz records one authz Check outcome: the duration histogram (labelled
// rpc + allowed) plus the decision counter (allow|deny|error).
func (r *Registry) ObserveAuthz(o AuthzObservation) {
	allowed := strconv.FormatBool(o.Allowed)
	r.authzDuration.WithLabelValues(o.RPC, allowed).Observe(o.Duration)

	decision := "allow"
	switch {
	case o.Err:
		decision = "error"
	case !o.Allowed:
		decision = "deny"
	}
	r.authzDecisions.WithLabelValues(o.RPC, decision).Inc()
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

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that records the
// per-RPC request count (with the resulting status code) and handling latency.
// Register it on both the public and internal gRPC listeners.
func (r *Registry) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		svc, method := splitFullMethod(info.FullMethod)
		code := status.Code(err)
		r.grpcHandled.WithLabelValues(svc, method, code.String()).Inc()
		r.grpcDuration.WithLabelValues(svc, method).Observe(time.Since(start).Seconds())
		return resp, err
	}
}

// splitFullMethod splits "/pkg.Service/Method" into ("pkg.Service", "Method").
// A malformed value yields ("unknown", fullMethod) so labels stay bounded.
func splitFullMethod(fullMethod string) (service, method string) {
	trimmed := strings.TrimPrefix(fullMethod, "/")
	idx := strings.LastIndex(trimmed, "/")
	if idx < 0 {
		return "unknown", fullMethod
	}
	return trimmed[:idx], trimmed[idx+1:]
}
