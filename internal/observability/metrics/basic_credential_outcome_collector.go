// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_outcome_collector.go — читатель переписи исходов полосы
// базового секрета внутреннего слушателя (задача kaname#379).
//
// # Предмет
//
// Полоса отвечает краю одним отказом на любую причину: отсечка отзыва-всех
// владельца, «строки нет», «секрет не тот», «строка не наша» неразличимы на
// проводе, и так и должно быть. Различимы они только здесь. Без этого ряда
// контроль отсечки, сработавший тысячу раз, выглядит так же, как не
// сработавший ни разу, — а «ноль отказов за всю жизнь контроля» обязано быть
// заметно.
//
// # Почему ряд печатается по ОБЪЯВЛЕННОМУ набору, а не по ключам снимка
//
// Тот же довод, что у переписи токен-эндпоинта: коллектор, печатающий ключи
// снимка, остался бы зелёным, перестань обработчик засевать перепись, — и
// клетка снова появлялась бы при первом попадании. Набор клеток приходит
// доводом, отсутствующая в снимке печатается нулём.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// BasicCredentialOutcomesMetric — исходы глаголов полосы базового секрета.
const BasicCredentialOutcomesMetric = Namespace + "_basic_credential_outcomes_total"

// BasicCredentialCell — клетка ряда: глагол и исход, строками. Типов
// обработчика реестр не знает — перевод делает композиционный корень.
type BasicCredentialCell struct {
	Verb    string
	Outcome string
}

type basicCredentialOutcomeCollector struct {
	cells []BasicCredentialCell
	read  func() map[BasicCredentialCell]uint64
	desc  *prometheus.Desc
}

// NewBasicCredentialOutcomeCollector регистрирует читателя переписи.
//
// Источник обязателен: вечный ноль неотличим от непровязанного читателя. Пустой
// набор клеток — тот же отказ с другой стороны: на витрину не вышло бы ни
// одного ряда, и молчание выглядело бы исправностью.
func (r *Registry) NewBasicCredentialOutcomeCollector(
	cells []BasicCredentialCell, read func() map[BasicCredentialCell]uint64,
) {
	if read == nil {
		panic("metrics: NewBasicCredentialOutcomeCollector без источника переписи — " +
			"вечный ноль неотличим от непровязанного читателя")
	}
	if len(cells) == 0 {
		panic("metrics: NewBasicCredentialOutcomeCollector с пустым набором клеток — " +
			"на витрину не выйдет ни одного ряда, и молчание будет выглядеть исправностью")
	}
	declared := make([]BasicCredentialCell, len(cells))
	copy(declared, cells)
	r.reg.MustRegister(&basicCredentialOutcomeCollector{
		cells: declared,
		read:  read,
		desc: prometheus.NewDesc(BasicCredentialOutcomesMetric,
			"Outcomes of the basic-credential lane of the internal listener, by verb (resolve: a "+
				"presented secret; liveness: an open connection asking by identifier) and by outcome "+
				"from the closed dictionary: accepted, one value per refusal reason, a refusal whose "+
				"reason the authority did not name, and the authority not answering. Every declared "+
				"cell is printed, including the zero ones. The caller receives ONE refusal whatever "+
				"the reason; the reason is visible only here and in this installation's log.",
			[]string{"verb", "outcome"}, nil),
	})
}

func (c *basicCredentialOutcomeCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *basicCredentialOutcomeCollector) Collect(ch chan<- prometheus.Metric) {
	census := c.read()
	for _, cell := range c.cells {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue,
			float64(census[cell]), cell.Verb, cell.Outcome)
	}
}
