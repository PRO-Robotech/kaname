// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// http_server.go — компоновка всех webhook handlers в один HTTP mux.
//
// Endpoints:
//
//	POST /iam/v1/hooks/token          — Hydra access_token webhook.
//	POST /iam/v1/hooks/refresh        — Hydra refresh_token webhook.
//	POST /iam/v1/hooks/provision      — Kratos registration/login user-provisioning webhook.
//	GET  /healthz                     — liveness probe.
//	GET  /readyz                      — readiness probe.
//
// Hook-endpoints (token/refresh/provision) require Bearer X-Kacho-Hook-Token.
// Listener — cluster-internal-only (ban #6: Internal.* not on external endpoint).
//
// # Живость и готовность строит ОБЪЯВЛЕННЫЙ носитель, а не этот пакет (#1752)
//
// Здесь стояли СВОЙ тип именованной проверки (`{Name string; Check func(ctx) error}`)
// и свои обработчики `/healthz` / `/readyz`. Форма совпадала с
// `pkg/observability/health` дословно, а шапка того пакета объявляет его
// ЕДИНСТВЕННЫМ в дереве носителем разведённых живости и готовности: об одном
// предмете высказывались два места, и одно из них объявляло себя единственным.
//
// Расходиться им было нечем by construction — копии не собираются вместе и друг
// друга не читают, — поэтому расхождение пришло бы не отказом, а тишиной. И
// пришло бы оно в том, что общий носитель УЖЕ решил, а своя форма не несла:
//
//	срок на чекер            — зависший `Ping` держал обработчик до probe-timeout
//	                           kubelet'а, а не считался недоступной зависимостью;
//	«носитель не провязан»   — `health.ErrDependencyNotWired`: окно старта своей
//	                           формой молча зачитывалось в готовность;
//	503 на гашении           — `SetShuttingDown` снимает под из ротации ДО
//	                           остановки серверов; своя форма гасла молча;
//	зеркало в счётчик        — `WithResultObserver`;
//	пустой набор проверок    — своя форма отвечала 200 («пусто = готов»),
//	                           то есть fail-open ровно там, где ответ неизвестен.
//
// Держит единственность гейт дерева `internal/repohygiene`
// `TestEveryServiceServingReadyzBuildsItWithTheDeclaredCarrier`: файл,
// монтирующий `/readyz`, обязан отдать туда обработчик, произведённый носителем.
package iamhooks

import (
	"context"
	"errors"
	"net/http"

	"github.com/PRO-Robotech/kacho/pkg/observability/health"
)

// errHealthCarrierNotWired — носитель готовности не передан композиционным
// корнем. Это ошибка сборки, а не состояние среды, и ответ на неё —
// fail-closed: под объявляет себя НЕ готовым и называет причину.
//
// Умолчание выбрано так же, как у `health.Slot`: неустановленный носитель есть
// «ответа нет», а неполученный ответ не является «да». Прежняя форма на пустом
// наборе проверок отвечала 200 — то есть непровязанная готовность была
// неотличима от исправной.
var errHealthCarrierNotWired = errors.New("readiness carrier not wired by the composition root")

// Handlers — bundle всех hook handlers.
type Handlers struct {
	TokenHook     http.Handler
	RefreshHook   http.Handler
	ProvisionHook http.Handler
	// RecoveryHook — завершение восстановления пароля. Появился позже трёх
	// соседних: до него провайдер бил в легаси gRPC-порт с REST-подобным путём,
	// и событие не доезжало никогда (см. recovery_hook_handler.go).
	RecoveryHook http.Handler
	// Health — объявленный носитель разведённых живости и готовности. ЧТО именно
	// проверяет каждая зависимость, знает композиционный корень (он один знает,
	// какая база своя и к кому сервис ходит); этот пакет только монтирует.
	//
	// nil означает «корень не провязал» и даёт fail-closed готовность, а не
	// молчаливые 200 (см. errHealthCarrierNotWired).
	Health *health.Aggregator
}

// NewMux собирает Handlers в один http.ServeMux. Каждый handler уже несет
// auth-проверку — mux только маршрутизирует.
func NewMux(h Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	agg := h.Health
	if agg == nil {
		agg = health.New([]health.Checker{{
			Name:  "readiness-carrier",
			Check: func(context.Context) error { return errHealthCarrierNotWired },
		}})
	}
	// Образец с методом (`GET /healthz`) — та же форма, что у шести соседних
	// сервисов: не-GET получает 405 от самого маршрутизатора, и отдельная ветка
	// в обработчике не нужна.
	mux.Handle("GET /healthz", agg.LiveHandler())
	mux.Handle("GET /readyz", agg.ReadyHandler())
	if h.TokenHook != nil {
		mux.Handle("/iam/v1/hooks/token", h.TokenHook)
	}
	if h.RefreshHook != nil {
		mux.Handle("/iam/v1/hooks/refresh", h.RefreshHook)
	}
	if h.ProvisionHook != nil {
		mux.Handle("/iam/v1/hooks/provision", h.ProvisionHook)
	}
	if h.RecoveryHook != nil {
		mux.Handle("/iam/v1/hooks/recovery", h.RecoveryHook)
	}
	return mux
}

// LoggerMiddleware — minimal access log wrapper.
func LoggerMiddleware(h http.Handler, logFn func(method, path string, status int)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: 200}
		h.ServeHTTP(sw, r)
		if logFn != nil {
			logFn(r.Method, r.URL.Path, sw.status)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(s int) {
	w.status = s
	w.ResponseWriter.WriteHeader(s)
}
