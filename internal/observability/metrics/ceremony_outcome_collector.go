// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_outcome_collector.go — читатель переписи исходов поверхности
// церемонии OAuth (эндпоинт авторизации и полосы `authorization_code` и
// `refresh_token`; задача PRO-Robotech/kaname#423, приёмка LINE-A-1 Р10, DoD 17).
//
// Наружу отказы церемонии неразличимы — после именования кода все отдают
// `invalid_grant`, до доверия цели все показывают одну страницу. Различимость
// для оператора живёт здесь: ряд на каждый исход закрытого словаря, НУЛЁМ в том
// числе, — «ноль отказов за всю жизнь полосы» обязан отличаться от «полоса не
// исполнялась ни разу».
package metrics

import "github.com/prometheus/client_golang/prometheus"

// CeremonyOutcomesMetric — исходы обращений к поверхности церемонии.
const CeremonyOutcomesMetric = Namespace + "_ceremony_outcomes_total"

type ceremonyOutcomeCollector struct {
	outcomes []string
	read     func() map[string]uint64
	desc     *prometheus.Desc
}

// NewCeremonyOutcomeCollector регистрирует читателя переписи. Источник и
// непустой набор исходов обязательны — по тем же основаниям, что у читателя
// переписи токен-эндпоинта (NewClientTokenOutcomeCollector).
func (r *Registry) NewCeremonyOutcomeCollector(outcomes []string, read func() map[string]uint64) {
	if read == nil {
		panic("metrics: NewCeremonyOutcomeCollector без источника переписи — " +
			"вечный ноль неотличим от непровязанного читателя")
	}
	if len(outcomes) == 0 {
		panic("metrics: NewCeremonyOutcomeCollector с пустым набором исходов — " +
			"на витрину не выйдет ни одного ряда")
	}
	declared := make([]string, len(outcomes))
	copy(declared, outcomes)
	r.reg.MustRegister(&ceremonyOutcomeCollector{
		outcomes: declared,
		read:     read,
		desc: prometheus.NewDesc(CeremonyOutcomesMetric,
			"Outcomes of the OAuth ceremony surface: the authorization endpoint and the "+
				"authorization_code and refresh_token grants of the token endpoint, by outcome from "+
				"the closed dictionary. Every DECLARED outcome is printed, including the zero ones. "+
				"Refusals after a code is named are one answer on the wire; this is where they differ.",
			[]string{"outcome"}, nil),
	})
}

func (c *ceremonyOutcomeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *ceremonyOutcomeCollector) Collect(ch chan<- prometheus.Metric) {
	census := c.read()
	for _, outcome := range c.outcomes {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue,
			float64(census[outcome]), outcome)
	}
}
