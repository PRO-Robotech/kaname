// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Семейства своей чеканки токенов (задача #897) и ЗАКРЫТЫЕ наборы их клеток.
//
// Величины выходят наружу по ТОЙ ЖЕ причине, по какой выходят величины зеркала:
// пока наружу выходят одни отказы, ноль в них отвечает сразу на два вопроса —
// «отказов не было» и «сюда никто не приходил», — а различие между ними и есть
// различие между работающим контролем и мёртвым.
const (
	// KeySetOutcomesMetric — исходы НАШЕЙ записи публикуемого набора.
	KeySetOutcomesMetric = "kacho_iam_own_keyset_outcomes_total"
	// KeySetOutcomeServed — набор отдан целиком.
	KeySetOutcomeServed = "served"
	// KeySetOutcomeUnavailable — источник набора не ответил (лечится временем).
	KeySetOutcomeUnavailable = "unavailable"
	// KeySetOutcomeEmpty — ключей нет вовсе. Отдельная клетка, потому что
	// временем это НЕ лечится: нужен ключ, а не повтор.
	KeySetOutcomeEmpty = "empty"

	// IntrospectOutcomesMetric — исходы авторитета отзыва.
	IntrospectOutcomesMetric = "kacho_iam_token_introspection_outcomes_total"
	// IntrospectOutcomeActive — токен признан действительным.
	IntrospectOutcomeActive = "active"
	// IntrospectOutcomeInactive — токен признан недействительным.
	IntrospectOutcomeInactive = "inactive"
	// IntrospectOutcomeUnavailable — ответить не смогли. ТРЕТИЙ исход, а не
	// оттенок второго: смешать его с «недействителен» значило бы сделать сбой
	// базы неотличимым от отзыва.
	IntrospectOutcomeUnavailable = "unavailable"

	// SigningKeyEventsMetric — события жизненного цикла подписного ключа.
	SigningKeyEventsMetric = "kacho_iam_signing_key_events_total"
	// SigningKeyEventGenerated — ключ порождён и положен в набор.
	SigningKeyEventGenerated = "generated"
	// SigningKeyEventActivated — ключ стал подписывающим.
	SigningKeyEventActivated = "activated"
	// SigningKeyEventRetired — ключ выведен из подписи, но остаётся в наборе.
	SigningKeyEventRetired = "retired"
	// SigningKeyEventRemoved — отсрочка истекла, ключ снят из набора.
	SigningKeyEventRemoved = "removed"
	// SigningKeyEventCompromised — ключ объявлен утёкшим; отдельная клетка,
	// потому что это решение другой цены, чем вывод из ротации.
	SigningKeyEventCompromised = "compromised"
	// SigningKeyEventFailure — ключница не смогла выполнить действие.
	SigningKeyEventFailure = "failure"
)

// KeySetOutcomes / IntrospectOutcomes / SigningKeyEvents — закрытые наборы.
var (
	KeySetOutcomes     = []string{KeySetOutcomeServed, KeySetOutcomeUnavailable, KeySetOutcomeEmpty}
	IntrospectOutcomes = []string{IntrospectOutcomeActive, IntrospectOutcomeInactive, IntrospectOutcomeUnavailable}
	SigningKeyEvents   = []string{
		SigningKeyEventGenerated, SigningKeyEventActivated, SigningKeyEventRetired,
		SigningKeyEventRemoved, SigningKeyEventCompromised, SigningKeyEventFailure,
	}
)

// OwnKeySetCounts — величины нашей записи набора, прочитанные у публикатора.
type OwnKeySetCounts struct {
	Served      uint64
	Unavailable uint64
	Empty       uint64
}

// IntrospectCounts — величины авторитета отзыва.
type IntrospectCounts struct {
	Active      uint64
	Inactive    uint64
	Unavailable uint64
}

// SigningKeyCounts — величины ключницы.
type SigningKeyCounts struct {
	Generated   uint64
	Activated   uint64
	Retired     uint64
	Removed     uint64
	Compromised uint64
	Failures    uint64
}

type labelledCollector struct {
	desc *prometheus.Desc
	read func() map[string]uint64
}

func (c *labelledCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

// Collect отдаёт ВСЕ клетки закрытого набора, включая нулевые: клетка, которую
// не печатают, пока она нулевая, неотличима от клетки, которой нет.
func (c *labelledCollector) Collect(ch chan<- prometheus.Metric) {
	for label, value := range c.read() {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(value), label)
	}
}

func (r *Registry) newLabelled(name, help, label string, cells []string, read func() map[string]uint64) {
	if read == nil {
		// nil-источник — ОТКАЗ: вечный ноль выглядит как работающее
		// наблюдение и утверждает неправду о подсистеме, которую просто
		// забыли подключить.
		panic("metrics: " + name + " без источника величин — вечный ноль неотличим от нетронутой подсистемы")
	}
	c := &labelledCollector{
		desc: prometheus.NewDesc(name,
			help+" Cells ("+strings.Join(cells, "|")+") are all reported, including zeros, "+
				"so \"never refused\" stays distinguishable from \"never executed\".",
			[]string{label}, nil),
		read: read,
	}
	r.reg.MustRegister(c)
}

// NewOwnKeySetCollector регистрирует читателя величин нашей записи набора.
func (r *Registry) NewOwnKeySetCollector(read func() OwnKeySetCounts) {
	r.newLabelled(KeySetOutcomesMetric,
		"Outcomes of serving the platform's own verification key set, by outcome.",
		"outcome", KeySetOutcomes, func() map[string]uint64 {
			c := read()
			return map[string]uint64{
				KeySetOutcomeServed:      c.Served,
				KeySetOutcomeUnavailable: c.Unavailable,
				KeySetOutcomeEmpty:       c.Empty,
			}
		})
}

// NewTokenIntrospectionCollector регистрирует читателя величин авторитета отзыва.
func (r *Registry) NewTokenIntrospectionCollector(read func() IntrospectCounts) {
	r.newLabelled(IntrospectOutcomesMetric,
		"Outcomes of answering whether a presented token is still live, by outcome.",
		"outcome", IntrospectOutcomes, func() map[string]uint64 {
			c := read()
			return map[string]uint64{
				IntrospectOutcomeActive:      c.Active,
				IntrospectOutcomeInactive:    c.Inactive,
				IntrospectOutcomeUnavailable: c.Unavailable,
			}
		})
}

// NewSigningKeyCollector регистрирует читателя величин ключницы.
func (r *Registry) NewSigningKeyCollector(read func() SigningKeyCounts) {
	r.newLabelled(SigningKeyEventsMetric,
		"Signing-key lifecycle events, by event.",
		"event", SigningKeyEvents, func() map[string]uint64 {
			c := read()
			return map[string]uint64{
				SigningKeyEventGenerated:   c.Generated,
				SigningKeyEventActivated:   c.Activated,
				SigningKeyEventRetired:     c.Retired,
				SigningKeyEventRemoved:     c.Removed,
				SigningKeyEventCompromised: c.Compromised,
				SigningKeyEventFailure:     c.Failures,
			}
		})
}
