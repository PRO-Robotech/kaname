// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

// ── Три коллектора, а не один обобщённый ────────────────────────────────────
//
// Обобщённый коллектор, читающий пары «метка → величина» из отображения,
// собирался короче и был СНЯТ: со стороны разбора синтаксиса метка в нём
// приходит ИЗ ДАННЫХ, и гейт закрытого словаря справедливо это находит.
// Возражение «у нас-то ключи константные» здесь не работает: свойство обязано
// быть видно тому, кто читает код, и тому, кто его проверяет, — иначе первый
// же следующий коллектор возьмёт метку из арендатора, и счётчик превратится в
// перечень обслуженных.
//
// Поэтому каждый коллектор перебирает СВОЙ набор с константными ключами, и все
// клетки печатаются всегда, включая нулевые: клетка, которую не печатают, пока
// она нулевая, неотличима от клетки, которой нет.

type ownKeySetCollector struct {
	read func() OwnKeySetCounts
	desc *prometheus.Desc
}

// NewOwnKeySetCollector регистрирует читателя величин нашей записи набора.
//
// nil-источник — ОТКАЗ: вечный ноль выглядит как работающее наблюдение и
// утверждает неправду о подсистеме, которую просто забыли подключить.
func (r *Registry) NewOwnKeySetCollector(read func() OwnKeySetCounts) {
	if read == nil {
		panic("metrics: NewOwnKeySetCollector без источника величин — " +
			"вечный ноль неотличим от неподключённого публикатора")
	}
	r.reg.MustRegister(&ownKeySetCollector{
		read: read,
		desc: prometheus.NewDesc(KeySetOutcomesMetric,
			"Outcomes of serving the platform's own verification key set, by outcome ("+
				strings.Join(KeySetOutcomes, "|")+"). Successful answers are counted alongside "+
				"refusals, so \"never refused\" stays distinguishable from \"never reached\"; "+
				"an empty key set is its own bucket because, unlike an outage, waiting never fixes it.",
			[]string{"outcome"}, nil),
	})
}

func (c *ownKeySetCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *ownKeySetCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	for outcome, value := range map[string]uint64{
		KeySetOutcomeServed:      counts.Served,
		KeySetOutcomeUnavailable: counts.Unavailable,
		KeySetOutcomeEmpty:       counts.Empty,
	} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(value), outcome)
	}
}

type introspectCollector struct {
	read func() IntrospectCounts
	desc *prometheus.Desc
}

// NewTokenIntrospectionCollector регистрирует читателя величин авторитета отзыва.
func (r *Registry) NewTokenIntrospectionCollector(read func() IntrospectCounts) {
	if read == nil {
		panic("metrics: NewTokenIntrospectionCollector без источника величин — " +
			"вечный ноль неотличим от неподключённого авторитета отзыва")
	}
	r.reg.MustRegister(&introspectCollector{
		read: read,
		desc: prometheus.NewDesc(IntrospectOutcomesMetric,
			"Outcomes of answering whether a presented token is still live, by outcome ("+
				strings.Join(IntrospectOutcomes, "|")+"). \"Could not answer\" is a THIRD "+
				"outcome, not a shade of \"inactive\": collapsing them would make a database "+
				"failure indistinguishable from a revocation.",
			[]string{"outcome"}, nil),
	})
}

func (c *introspectCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *introspectCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	for outcome, value := range map[string]uint64{
		IntrospectOutcomeActive:      counts.Active,
		IntrospectOutcomeInactive:    counts.Inactive,
		IntrospectOutcomeUnavailable: counts.Unavailable,
	} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(value), outcome)
	}
}

type signingKeyCollector struct {
	read func() SigningKeyCounts
	desc *prometheus.Desc
}

// NewSigningKeyCollector регистрирует читателя величин ключницы.
func (r *Registry) NewSigningKeyCollector(read func() SigningKeyCounts) {
	if read == nil {
		panic("metrics: NewSigningKeyCollector без источника величин — " +
			"вечный ноль неотличим от неподключённой ключницы")
	}
	r.reg.MustRegister(&signingKeyCollector{
		read: read,
		desc: prometheus.NewDesc(SigningKeyEventsMetric,
			"Signing-key lifecycle events, by event ("+strings.Join(SigningKeyEvents, "|")+
				"). \"Compromised\" is its own bucket because declaring a key leaked and "+
				"retiring it from rotation are decisions of different cost.",
			[]string{"event"}, nil),
	})
}

func (c *signingKeyCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *signingKeyCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	for event, value := range map[string]uint64{
		SigningKeyEventGenerated:   counts.Generated,
		SigningKeyEventActivated:   counts.Activated,
		SigningKeyEventRetired:     counts.Retired,
		SigningKeyEventRemoved:     counts.Removed,
		SigningKeyEventCompromised: counts.Compromised,
		SigningKeyEventFailure:     counts.Failures,
	} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(value), event)
	}
}
