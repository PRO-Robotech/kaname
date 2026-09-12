// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_outcome_collector.go — читатель переписи исходов токен-эндпоинта
// платформы (задача продукта #2501).
//
// # Предмет
//
// Обработчик нёс перепись с пред-засевом по каждому объявленному исходу и
// экспортированный аксессор — то есть работа была сделана на девять десятых.
// Читателя у переписи не было: разбивка отказов (склад однократности недоступен ·
// перечень доверия недоступен · издатель не доверен · адресат не разрешён …) жила
// только в памяти процесса и уходила вместе с ним.
//
// Через эту полосу в отдельной установке выдаётся ВСЯКОЕ арендаторское
// удостоверение, и «ноль отказов за всю жизнь полосы» здесь неотличимо от
// «полоса не исполнялась ни разу» — ровно то, что `security.md` §Hardening п. 8
// требует сделать заметным.
//
// # Почему ряд печатается по ОБЪЯВЛЕННОМУ набору, а не по ключам снимка
//
// Снимок сегодня полон: обработчик засевает словарь целиком. Но коллектор,
// печатающий ключи снимка, остался бы зелёным, перестань обработчик засевать, — и
// клетка снова появлялась бы при первом попадании. Объявленный набор приходит
// доводом, поэтому полнота витрины не зависит от чужого засева: отсутствующий в
// снимке исход печатается НУЛЁМ.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// ClientTokenOutcomesMetric — исходы обращений за токеном по учётным данным
// клиента.
const ClientTokenOutcomesMetric = Namespace + "_client_token_outcomes_total"

type clientTokenOutcomeCollector struct {
	outcomes []string
	read     func() map[string]uint64
	desc     *prometheus.Desc
}

// NewClientTokenOutcomeCollector регистрирует читателя переписи.
//
// Источник обязателен: вечный ноль неотличим от непровязанного читателя, а
// именно «читатель не провязан» и есть то состояние, ради обнаружения которого на
// этот график смотрят. Пустой набор исходов — тот же отказ с другой стороны: на
// витрину не вышло бы ни одного ряда.
func (r *Registry) NewClientTokenOutcomeCollector(outcomes []string, read func() map[string]uint64) {
	if read == nil {
		panic("metrics: NewClientTokenOutcomeCollector без источника переписи — " +
			"вечный ноль неотличим от непровязанного читателя")
	}
	if len(outcomes) == 0 {
		panic("metrics: NewClientTokenOutcomeCollector с пустым набором исходов — " +
			"на витрину не выйдет ни одного ряда, и молчание будет выглядеть исправностью")
	}
	declared := make([]string, len(outcomes))
	copy(declared, outcomes)
	r.reg.MustRegister(&clientTokenOutcomeCollector{
		outcomes: declared,
		read:     read,
		desc: prometheus.NewDesc(ClientTokenOutcomesMetric,
			"Outcomes of requests to the platform token endpoint (client-credentials and "+
				"JWT-bearer grants), by outcome from the closed dictionary. Every DECLARED "+
				"outcome is printed, including the zero ones: this is the lane through which a "+
				"standalone installation issues EVERY tenant credential, and \"no refusals in "+
				"the lifetime of the lane\" must be told apart from \"the lane never ran\". "+
				"Refusals that our side owns (the replay store or the trust list being "+
				"unreachable, issuance failing) are the operator's; the rest are the presenter's.",
			[]string{"outcome"}, nil),
	})
}

func (c *clientTokenOutcomeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *clientTokenOutcomeCollector) Collect(ch chan<- prometheus.Metric) {
	census := c.read()
	for _, outcome := range c.outcomes {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue,
			float64(census[outcome]), outcome)
	}
}
