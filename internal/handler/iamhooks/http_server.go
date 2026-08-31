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
// Живость и готовность отдаёт ОБЩИЙ носитель `pkg/observability/health` — тот же,
// что у остальных шести сервисов. Собственной формы у владельца прав больше нет:
// см. надгробие ниже и задачу продукта #1729.
//
// Hook-endpoints (token/refresh/provision) require Bearer X-Kacho-Hook-Token.
// Listener — cluster-internal-only (ban #6: Internal.* not on external endpoint).
package iamhooks

import (
	"net/http"

	"github.com/PRO-Robotech/kacho/pkg/observability/health"
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
	// Health — ОБЩИЙ носитель разведённых живости и готовности
	// (`pkg/observability/health`), собранный композиционным корнем: он один
	// знает, какая база у сервиса своя и чей исполнитель операций поднят.
	//
	// Носитель здесь ОБЩИЙ, а не свой, и это решение, а не совпадение: у одного
	// механизма один носитель, иначе правка до второго не доедет (задача продукта
	// #1729, гейт `TestReadinessIsServedByASingleCarrier`). Довод в пользу
	// собственного — «владелец прав лист графа, набор зависимостей у него другой»
	// — опровергнут замером: у общего носителя НОЛЬ зависимостей вне stdlib,
	// поэтому его импорт не добавляет листу ни ребра, ни чужой библиотеки.
	//
	// nil означает «зависимостей не объявлено»: готовность отвечает 200, как и
	// пустой набор чекеров у общего носителя. Что готовность обязана быть
	// построена из ИМЕНОВАННЫХ зависимостей, требует гейт дерева, а не рантайм.
	Health *health.Aggregator
}

// NewMux собирает Handlers в один http.ServeMux. Каждый handler уже несет
// auth-проверку — mux только маршрутизирует.
func NewMux(h Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	agg := h.Health
	if agg == nil {
		agg = health.New(nil)
	}
	// Метод назван В ОБРАЗЦЕ маршрута, а не проверен внутри обработчика: обращение
	// не тем методом отвергает сам мультиплексор, и отвергает одинаково у всех семи
	// сервисов. Прежде эту проверку нёс собственный обработчик владельца прав —
	// одно из отличий, которых больше нет.
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

// ЗДЕСЬ СТОЯЛИ СОБСТВЕННЫЕ ОБРАБОТЧИКИ ЖИВОСТИ И ГОТОВНОСТИ — сняты вместе с
// собственным носителем (задача продукта #1729).
//
// Их снятие закрыло три отличия от общего носителя, и каждое было дефектом, а не
// решением:
//
//   - готовность обходила зависимости ПО ОЧЕРЕДИ и выходила на первой упавшей,
//     называя одну из нескольких: дежурный чинил названную, перекатывал под и
//     узнавал об остальных следующим заходом;
//   - у чекера НЕ БЫЛО собственного срока, поэтому молчащая зависимость (сеть в
//     полуоткрытом состоянии, база под блокировкой) подвешивала обработчик
//     целиком: kubelet не получал ни 200, ни 503 и ждал своего срока, а под всё
//     это время оставался в ротации;
//   - состояния гашения не существовало ВОВСЕ, поэтому готовность не переводилась
//     в отказ перед остановкой слушателей. Для листа, к которому на каждом вызове
//     ходят все прочие сервисы, это дороже всего: гасящийся владелец прав
//     продолжал объявлять себя готовым.

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
