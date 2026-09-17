// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// access_key_recorder.go — счётчики ключей доступа (фаза Ф7, задача
// PRO-Robotech/kacho#1273; §3.0, Р6). Вызывающий видит ЕДИНЫЙ отказ утверждения
// без причины; причина — только здесь и в журнале. Клетки заводятся НУЛЁМ по
// закрытым словарям производителя: «ноль за всю жизнь» обязано быть отличимо
// от «клетки нет».

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
)

const (
	AccessKeyRefusalsMetric             = Namespace + "_access_key_refusals_total"
	AccessKeyEventsMetric               = Namespace + "_access_key_events_total"
	AccessKeySignCountRegressionsMetric = Namespace + "_access_key_sign_count_regressions_total"
)

// AccessKeyRecorder — приёмник событий ключей (`access_keys.Observer`).
type AccessKeyRecorder struct {
	refusals    *prometheus.CounterVec
	events      *prometheus.CounterVec
	regressions prometheus.Counter
}

// AccessKeyRecorder — единственный экземпляр на реестр.
func (r *Registry) AccessKeyRecorder() *AccessKeyRecorder {
	r.accessKeyOnce.Do(func() {
		rec := &AccessKeyRecorder{
			refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: AccessKeyRefusalsMetric,
				Help: "Access-key refusals by lane (registration, assertion, revoke) and cause. On the " +
					"assertion lane the caller sees ONE refusal without a cause (Ф7 §3.0); the cause is " +
					"visible only here and in the journal.",
			}, []string{"lane", "reason"}),
			events: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: AccessKeyEventsMetric,
				Help: "Access-key lifecycle events: challenges issued, key registered, assertion accepted, " +
					"key revoked, key transferred from the former component.",
			}, []string{"event"}),
			regressions: prometheus.NewCounter(prometheus.CounterOpts{
				Name: AccessKeySignCountRegressionsMetric,
				Help: "Assertions refused because the reported signature counter did not advance past the " +
					"stored one (Ф7 Р6, Ф7-18): a cloned authenticator or a replayed assertion. The caller " +
					"sees the same unified refusal; the signal lives only here.",
			}),
		}
		r.reg.MustRegister(rec.refusals, rec.events, rec.regressions)
		for _, lane := range access_keys.Lanes() {
			for _, reason := range access_keys.Refusals() {
				rec.refusals.WithLabelValues(string(lane), string(reason)).Add(0)
			}
		}
		for _, e := range access_keys.Events() {
			rec.events.WithLabelValues(string(e)).Add(0)
		}
		r.accessKey = rec
	})
	return r.accessKey
}

func (a *AccessKeyRecorder) AccessKeyRefusalObserved(l access_keys.Lane, reason access_keys.Refusal) {
	a.refusals.WithLabelValues(string(l), string(reason)).Inc()
}

func (a *AccessKeyRecorder) AccessKeyEventObserved(e access_keys.Event) {
	a.events.WithLabelValues(string(e)).Inc()
}

func (a *AccessKeyRecorder) SignCountRegressionObserved() { a.regressions.Inc() }

var _ access_keys.Observer = (*AccessKeyRecorder)(nil)
