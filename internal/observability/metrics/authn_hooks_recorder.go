// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authn_hooks_recorder.go — исходы полосы хуков поставщика личности (задача
// продукта #2495).
//
// # Почему клетки заводятся нулём при провязке
//
// «Ноль обращений за всю жизнь полосы» здесь невидимо by construction:
// отсутствие строк журнала тревогой не бывает, а ряд, появляющийся вместе с
// первым обращением, не отличает «обращений не было» от «клетки нет». Заведение
// всех клеток при провязке делает условие тревоги «за час ноль обращений»
// выразимым — то есть делает выразимым состояние «поставщик не настроен звать
// хук», которое до этого не наблюдалось ничем.
//
// # Почему наборы приходят доводами
//
// Маршруты и исходы объявляет пакет полосы — он один держит соответствие пути и
// обработчика и разбор состояния ответа. Второй перечень здесь разошёлся бы с
// первым молча, и разошёлся бы в сторону «маршрут без клетки». Переводит один
// набор в другой композиционный корень: он единственный знает обоих.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// AuthnHookRequestsMetric — исходы обращений поставщика личности к полосе хуков.
const AuthnHookRequestsMetric = Namespace + "_authn_hook_requests_total"

// AuthnHooksRecorder — приёмник исходов полосы. Форма метода [HookServed]
// совпадает с портом полосы (`iamhooks.LaneObserver`), поэтому корень отдаёт
// приёмник ей напрямую.
type AuthnHooksRecorder struct {
	requests *prometheus.CounterVec
}

// AuthnHooksRecorder заводит приёмник и СЕЙЧАС ЖЕ клетку на каждую пару
// (маршрут × исход).
//
// Пустой любой из наборов — ОТКАЗ: клеток не будет ни одной, и молчащая витрина
// неотличима от полосы, к которой никто не приходил. Это ровно то неразличение,
// ради устранения которого приёмник заведён.
//
// Повторный вызов возвращает ТОГО ЖЕ приёмника: полоса собирается в прогоне не
// единожды, а второй экземпляр уронил бы старт на повторной регистрации.
func (r *Registry) AuthnHooksRecorder(routes, outcomes []string) *AuthnHooksRecorder {
	if len(routes) == 0 || len(outcomes) == 0 {
		panic("metrics: AuthnHooksRecorder с пустым набором маршрутов либо исходов — " +
			"клеток не будет ни одной, и «за час ноль обращений» останется невыразимым")
	}
	r.authnHooksOnce.Do(func() {
		r.authnHooks = &AuthnHooksRecorder{
			requests: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: AuthnHookRequestsMetric,
				Help: "Requests the identity provider made to the AuthN hook lane, by route " +
					"(token|refresh|provision|recovery) and outcome (ok|refused|failed). This is " +
					"the LIVE human sign-in path, and the three outcomes have three different " +
					"owners: `refused` means the provider's own wiring — shared secret, body " +
					"form, method — was never created or is wrong, and the operator fixes it; " +
					"`failed` means we could not answer, and we fix it. Every cell is seeded at " +
					"wiring time, so \"zero requests in an hour\" is an expressible alarm " +
					"condition: a provider that was never told to call the hook writes no log " +
					"line at all, and an absent log line never becomes an alert.",
			}, []string{"route", "outcome"}),
		}
		r.reg.MustRegister(r.authnHooks.requests)
	})
	for _, route := range routes {
		for _, outcome := range outcomes {
			r.authnHooks.requests.WithLabelValues(route, outcome).Add(0)
		}
	}
	return r.authnHooks
}

// HookServed принимает исход ОДНОГО обращения.
func (a *AuthnHooksRecorder) HookServed(route, outcome string) {
	a.requests.WithLabelValues(route, outcome).Inc()
}
