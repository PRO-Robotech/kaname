// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authorization_ceremony_outcome_collector.go — читатель переписи исходов
// церемонии OAuth 2.1 `authorization_code` (под-фаза LINE-A-1,
// PRO-Robotech/kacho#2721).
//
// # Предмет
//
// Наружу отказы церемонии неразличимы намеренно: после того, как назван код,
// ответ один (`invalid_grant`), до того, как доверена цель, — тоже один. Вся
// различимость для НАС живёт здесь и в журнале: без читателя переписи «ноль
// повторов кода за всю жизнь» неотличим от «полоса обмена не исполнялась», а
// отзыв семейства, не случившийся ни разу, — от отзыва, которого нет.
//
// Ряд печатается по ОБЪЯВЛЕННОМУ набору исходов, а не по ключам снимка: полнота
// витрины не зависит от чужого засева, отсутствующий исход печатается нулём.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// AuthorizationCeremonyOutcomesMetric — исходы запросов церемонии: выдача кода,
// обмен кода, ротация обновляющего удостоверения.
const AuthorizationCeremonyOutcomesMetric = Namespace + "_authorization_ceremony_outcomes_total"

type authorizationCeremonyOutcomeCollector struct {
	outcomes []string
	read     func() map[string]uint64
	desc     *prometheus.Desc
}

// NewAuthorizationCeremonyOutcomeCollector регистрирует читателя переписи.
// Источник и непустой набор исходов обязательны — по тем же доводам, что у
// читателя исходов токен-эндпоинта.
func (r *Registry) NewAuthorizationCeremonyOutcomeCollector(outcomes []string, read func() map[string]uint64) {
	if read == nil {
		panic("metrics: NewAuthorizationCeremonyOutcomeCollector без источника переписи — " +
			"вечный ноль неотличим от непровязанного читателя")
	}
	if len(outcomes) == 0 {
		panic("metrics: NewAuthorizationCeremonyOutcomeCollector с пустым набором исходов — " +
			"на витрину не выйдет ни одного ряда")
	}
	declared := make([]string, len(outcomes))
	copy(declared, outcomes)
	r.reg.MustRegister(&authorizationCeremonyOutcomeCollector{
		outcomes: declared,
		read:     read,
		desc: prometheus.NewDesc(AuthorizationCeremonyOutcomesMetric,
			"Outcomes of the authorization_code ceremony: code issuance at the authorization "+
				"endpoint, code exchange and refresh-token rotation at the token endpoint, by "+
				"outcome from the closed dictionary. Refusals are indistinguishable on the wire "+
				"by design; this series is where they are told apart. A replayed code or "+
				"refresh token revokes its authorization family.",
			[]string{"outcome"}, nil),
	})
}

func (c *authorizationCeremonyOutcomeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *authorizationCeremonyOutcomeCollector) Collect(ch chan<- prometheus.Metric) {
	census := c.read()
	for _, outcome := range c.outcomes {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(census[outcome]), outcome)
	}
}
