// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// JWKSMirrorOutcomesMetric / JWKSMirrorOutcomes — имя семейства и ЗАКРЫТЫЙ набор
// его клеток зеркала публичных ключей проверки.
const (
	JWKSMirrorOutcomesMetric = "kacho_iam_jwks_mirror_outcomes_total"

	// JWKSMirrorOutcomeServed — обращение к верхнему хопу дало набор ключей.
	JWKSMirrorOutcomeServed = "served"
	// JWKSMirrorOutcomeUnavailable — верхний хоп не ответил полезно (лечится временем).
	JWKSMirrorOutcomeUnavailable = "unavailable"
	// JWKSMirrorOutcomeMisconfigured — по адресу не тот эндпоинт (временем не лечится).
	JWKSMirrorOutcomeMisconfigured = "misconfigured"
)

// JWKSMirrorOutcomes — закрытый набор клеток семейства.
var JWKSMirrorOutcomes = []string{
	JWKSMirrorOutcomeServed,
	JWKSMirrorOutcomeUnavailable,
	JWKSMirrorOutcomeMisconfigured,
}

// JWKSMirrorCounts — три числа зеркала ключей, прочитанные у самого зеркала.
type JWKSMirrorCounts struct {
	// Served — обращений к верхнему хопу, давших набор ключей.
	Served uint64
	// Unavailable — отказов, потому что верхний хоп не ответил полезно.
	Unavailable uint64
	// Misconfigured — отказов, потому что по адресу не набор ключей.
	Misconfigured uint64
}

type jwksMirrorCollector struct {
	read func() JWKSMirrorCounts
	desc *prometheus.Desc
}

// NewJWKSMirrorCollector регистрирует читателя счётчиков зеркала ключей.
//
// ПОЧЕМУ ВЫДАННЫЕ СЧИТАЮТСЯ НАРАВНЕ С ОТКАЗАМИ. Зеркало отказывает закрыто: не
// ответил верхний хоп — плоскость данных отвергает каждый токен. Пока наружу
// выходят одни отказы, ноль в них отвечает сразу на два вопроса — «отказов не
// было» и «сюда никто не приходил», — а различие между ними и есть различие
// между работающим зеркалом и мёртвым. Отдельно держатся и две ПРИЧИНЫ отказа:
// «не ответил» проходит со временем, «по адресу не то» — никогда, и смешивать их
// в одном ряду значит прятать настройку под сбой.
//
// nil-источник — ОТКАЗ по той же причине, что и у соседнего коллектора: вечный
// ноль выглядит как работающее наблюдение и утверждает неправду о зеркале,
// которое просто забыли подключить.
func (r *Registry) NewJWKSMirrorCollector(read func() JWKSMirrorCounts) {
	if read == nil {
		panic("metrics: NewJWKSMirrorCollector без источника величин — " +
			"вечный ноль неотличим от нетронутого зеркала")
	}
	c := &jwksMirrorCollector{
		read: read,
		desc: prometheus.NewDesc(
			JWKSMirrorOutcomesMetric,
			"Outcomes of the cluster-internal JWKS mirror, by outcome ("+
				strings.Join(JWKSMirrorOutcomes, "|")+"). Successful fetches are counted "+
				"alongside refusals, so \"never refused\" is distinguishable from \"never "+
				"reached\"; a misconfigured address is its own bucket because, unlike an "+
				"outage, it never heals on its own.",
			[]string{"outcome"}, nil,
		),
	}
	r.reg.MustRegister(c)
}

// Describe — семейство видно и до первого сбора.
func (c *jwksMirrorCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

// Collect отдаёт все три клетки закрытого набора, читая живые счётчики.
func (c *jwksMirrorCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	for outcome, value := range map[string]uint64{
		JWKSMirrorOutcomeServed:        counts.Served,
		JWKSMirrorOutcomeUnavailable:   counts.Unavailable,
		JWKSMirrorOutcomeMisconfigured: counts.Misconfigured,
	} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(value), outcome)
	}
}
