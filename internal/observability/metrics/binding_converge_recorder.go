// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// BindingConvergeOutcomes — ЗАКРЫТЫЙ набор клеток семейства.
//
// Собран из констант производителя ([seed.BindingConvergeOutcomeConverged],
// [seed.BindingConvergeOutcomeFailed]), а не выписан здесь литералами.
var BindingConvergeOutcomes = []string{
	seed.BindingConvergeOutcomeConverged,
	seed.BindingConvergeOutcomeFailed,
}

// BindingConvergeRecorder — исходы сводящего прохода по выдачам, по одной
// выдаче за проход (kaname#1006).
//
// # Зачем счётчик, если есть перепись в журнале
//
// У выдачи одному субъекту сводящий проход — единственный путь, которым
// снимается лишний кортеж после смены вычисления. Его отказ доступа не
// отнимает, он его ОСТАВЛЯЕТ: лишнее право живёт, и снаружи это не видно
// никак. Строка журнала говорит о событии одного прохода; рост `failed` между
// проходами при неподвижном `converged` — это состояние, по которому ставится
// тревога.
//
// # Зачем считать успехи
//
// Счётчик одних отказов не отличает «отказов не было» от «прохода не было
// вовсе». Знаменатель считается наравне с числителем.
//
// Набор меток ЗАКРЫТ: outcome приходит из констант прохода
// (converged|failed), никогда из запроса.
type BindingConvergeRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewBindingConvergeRecorder регистрирует коллектор в этом реестре.
// Звать один раз на старте.
func (r *Registry) NewBindingConvergeRecorder() *BindingConvergeRecorder {
	rec := &BindingConvergeRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_binding_converge_total",
			Help: "Исходы сводящего прохода по выдачам, по одной выдаче за проход: " +
				"converged — выдача сведена к текущему вычислению; failed — не сведена " +
				"и после повтора, её лишний кортеж живёт до следующего прохода. " +
				"Ноль failed значим только вместе с растущим converged.",
		}, []string{"outcome"}),
	}
	// Клетки закрытого набора заводятся нулём ПРИ РЕГИСТРАЦИИ: вектор без детей
	// не отдаёт на провод ничего.
	for _, outcome := range BindingConvergeOutcomes {
		rec.outcomes.WithLabelValues(outcome)
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// IncBindingConverge — исход сведения одной выдачи. Реализует порт
// seed.BindingConvergeObserver.
func (rec *BindingConvergeRecorder) IncBindingConverge(outcome string) {
	rec.outcomes.WithLabelValues(outcome).Inc()
}
