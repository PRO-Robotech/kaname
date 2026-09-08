// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// presented_credential_collector.go — исходы приёма удостоверения,
// ПРЕДЪЯВЛЕННОГО арендатором на публичном слушателе (задача продукта #2077).
//
// # Почему рядов ТРИ, а не один
//
// Ряд отвергнутых без ряда принятых отвечает сразу на два вопроса: «отказов не
// было» и «сюда никто не приходил». Различить их по одному ряду нечем, а
// вопросы эти чинятся в разных местах: первый не чинится вовсе, второй означает,
// что арендатор до службы не доезжает.
//
// Третий ряд — «ответить не смогли» — не оттенок отказа: негодный токен чинит
// предъявитель, недоступный авторитет чинит оператор. Смешать их значило бы
// сделать сбой хранилища неотличимым от подделанного удостоверения.
//
// # Почему ряды эмитируются ВСЕГДА, включая нулевые
//
// Читатель отдаёт величины снимком, и коллектор печатает все три независимо от
// значений. Ряд, появляющийся только вместе с первым событием, делает ноль
// невыразимым: отсутствующий ряд и нулевой выглядят одинаково у того, кто
// смотрит на график.
package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// PresentedCredentialOutcomesMetric — исходы приёма предъявленного.
	PresentedCredentialOutcomesMetric = "kaname_presented_credential_outcomes_total"
	// PresentedCredentialOutcomeAccepted — предъявленное принято, вызывающий назван.
	PresentedCredentialOutcomeAccepted = "accepted"
	// PresentedCredentialOutcomeRefused — предъявленное отвергнуто.
	PresentedCredentialOutcomeRefused = "refused"
	// PresentedCredentialOutcomeUnavailable — ответить не смогли: реестр ключей
	// либо авторитет отзыва недоступны. ТРЕТИЙ исход.
	PresentedCredentialOutcomeUnavailable = "unavailable"
)

// PresentedCredentialOutcomes — закрытый набор исходов.
var PresentedCredentialOutcomes = []string{
	PresentedCredentialOutcomeAccepted,
	PresentedCredentialOutcomeRefused,
	PresentedCredentialOutcomeUnavailable,
}

// PresentedCredentialCounts — величины читателя предъявленного.
type PresentedCredentialCounts struct {
	Accepted    uint64
	Refused     uint64
	Unavailable uint64
}

type presentedCredentialCollector struct {
	read func() PresentedCredentialCounts
	desc *prometheus.Desc
}

// NewPresentedCredentialCollector регистрирует читателя величин.
//
// Источник обязателен: вечный ноль неотличим от непровязанного читателя, а
// именно «читатель не провязан» и есть то состояние, ради обнаружения которого
// на этот график смотрят.
func (r *Registry) NewPresentedCredentialCollector(read func() PresentedCredentialCounts) {
	if read == nil {
		panic("metrics: NewPresentedCredentialCollector без источника величин — " +
			"вечный ноль неотличим от непровязанного читателя предъявленного")
	}
	r.reg.MustRegister(&presentedCredentialCollector{
		read: read,
		desc: prometheus.NewDesc(PresentedCredentialOutcomesMetric,
			"Outcomes of reading a credential the caller PRESENTED on the public listener, by "+
				"outcome ("+strings.Join(PresentedCredentialOutcomes, "|")+"). \"Refused\" never "+
				"names WHICH check failed — that would tell the presenter which half is wrong, and "+
				"the detail belongs in this installation's log instead. \"Could not answer\" is a "+
				"THIRD outcome, not a shade of refusal: a bad credential is the presenter's to fix, "+
				"an unreachable authority is the operator's.",
			[]string{"outcome"}, nil),
	})
}

func (c *presentedCredentialCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *presentedCredentialCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	for outcome, value := range map[string]uint64{
		PresentedCredentialOutcomeAccepted:    counts.Accepted,
		PresentedCredentialOutcomeRefused:     counts.Refused,
		PresentedCredentialOutcomeUnavailable: counts.Unavailable,
	} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(value), outcome)
	}
}
