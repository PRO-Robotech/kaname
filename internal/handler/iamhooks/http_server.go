// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// http_server.go — компоновка всех webhook handlers в один HTTP mux.
//
// Endpoints:
//
//	POST /iam/v1/hooks/token          — Hydra access_token webhook.
//	POST /iam/v1/hooks/refresh        — Hydra refresh_token webhook.
//	POST /iam/v1/hooks/provision      — Kratos registration/login user-provisioning webhook.
//	POST /iam/v1/hooks/recovery       — Kratos recovery-completed webhook.
//
// Перечень выше — ОПИСЬ ПОЛОСЫ, и её полноту держит проба
// `route_prose_names_every_route_test.go`: маршрут восстановления приехал позже
// трёх соседних, и обе описи пакета молча остались трёхстрочными.
//
// Hook-endpoints (token/refresh/provision/recovery) require Bearer X-Kacho-Hook-Token.
// Listener — cluster-internal-only (ban #6: Internal.* not on external endpoint).
//
// # Живости и готовности на этом слушателе НЕТ (kaname#360)
//
// Они жили здесь, и из-за этого слушатель нельзя было снять под посадкой
// `own`, где поставщика нет: пробы пода шли в его порт. Живость и готовность
// переехали на диагностическую поверхность (`internal/handler/diagnostics`),
// которая есть при любой посадке, вместе со своими пробами. Второй копии здесь
// не остаётся — её отсутствие держит `no_diagnostic_routes_test.go`.
package iamhooks

import (
	"net/http"
)

// Handlers — bundle всех hook handlers.
type Handlers struct {
	TokenHook     http.Handler
	RefreshHook   http.Handler
	ProvisionHook http.Handler
	// RecoveryHook — завершение восстановления пароля. Появился позже трёх
	// соседних: до него провайдер бил в легаси gRPC-порт с REST-подобным путём,
	// и событие не доезжало никогда (см. recovery_hook_handler.go).
	RecoveryHook http.Handler
	// LaneObserver — приёмник исходов полосы (#2495). Без него у живого пути
	// входа человека нет ни одной величины, и «полоса отказывает» неотличимо от
	// «поставщик не настроен звать хук»: в первом случае растут строки журнала,
	// во втором их нет вовсе, а отсутствие строк тревогой не бывает.
	//
	// Порт, а не готовый счётчик: этот пакет не знает ни реестра величин, ни
	// prometheus. Нулевое значение — законное состояние пробы пакета, и полоса
	// при нём обслуживает вход как обычно.
	LaneObserver LaneObserver
}

// NewMux собирает Handlers в один http.ServeMux. Каждый handler уже несет
// auth-проверку — mux только маршрутизирует.
func NewMux(h Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	// Съём исхода надевается ПО МАРШРУТУ, а не общей обёрткой вокруг
	// мультиплексора: общая обёртка знала бы только путь запроса, и обращение по
	// пути, которого полоса не несёт, пришло бы в ряд несуществующего маршрута —
	// то есть метка перестала бы утверждать что-либо о самих маршрутах.
	if h.TokenHook != nil {
		mux.Handle("/iam/v1/hooks/token", observeRoute(RouteToken, h.TokenHook, h.LaneObserver))
	}
	if h.RefreshHook != nil {
		mux.Handle("/iam/v1/hooks/refresh", observeRoute(RouteRefresh, h.RefreshHook, h.LaneObserver))
	}
	if h.ProvisionHook != nil {
		mux.Handle("/iam/v1/hooks/provision", observeRoute(RouteProvision, h.ProvisionHook, h.LaneObserver))
	}
	if h.RecoveryHook != nil {
		mux.Handle("/iam/v1/hooks/recovery", observeRoute(RouteRecovery, h.RecoveryHook, h.LaneObserver))
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
