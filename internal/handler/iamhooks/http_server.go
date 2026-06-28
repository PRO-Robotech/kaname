// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
package iamhooks

import (
	"context"
	"encoding/json"
	"net/http"
)

// ReadinessChecker — именованная проверка критичной зависимости для /readyz.
type ReadinessChecker struct {
	Name  string
	Check func(context.Context) error
}

// Handlers — bundle всех hook handlers.
type Handlers struct {
	TokenHook     http.Handler
	RefreshHook   http.Handler
	ProvisionHook http.Handler
	// Readiness — проверки зависимостей для /readyz (DB-ping, LRO-worker, …).
	// Пустой список → /readyz деградирует до liveness (200), как было раньше.
	Readiness []ReadinessChecker
}

// NewMux собирает Handlers в один http.ServeMux. Каждый handler уже несет
// auth-проверку — mux только маршрутизирует.
func NewMux(h Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", livenessHandler)
	mux.HandleFunc("/readyz", readinessHandler(h.Readiness))
	if h.TokenHook != nil {
		mux.Handle("/iam/v1/hooks/token", h.TokenHook)
	}
	if h.RefreshHook != nil {
		mux.Handle("/iam/v1/hooks/refresh", h.RefreshHook)
	}
	if h.ProvisionHook != nil {
		mux.Handle("/iam/v1/hooks/provision", h.ProvisionHook)
	}
	return mux
}

func livenessHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// readinessHandler возвращает 503, если любая зависимость не готова (с ее именем в
// теле, без leak деталей ошибки), иначе 200. /healthz остается чистым liveness,
// чтобы деградация зависимости не вызывала restart-storm.
func readinessHandler(checkers []ReadinessChecker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		for _, c := range checkers {
			if err := c.Check(r.Context()); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]any{"ready": false, "failed": c.Name})
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": true})
	}
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
