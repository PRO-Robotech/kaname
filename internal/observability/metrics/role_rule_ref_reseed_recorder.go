// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// RuleRefReseedRecorder — исходы пересчёта проекции ОБЪЯВЛЕННЫХ СЕГМЕНТОВ
// правила (`kacho_iam.role_rule_ref`) на старте, по одной системной роли.
//
// # Зачем считать УСПЕХИ, а не только отказы
//
// Счётчик одних отказов не отличает «отказов не было» от «пересчёта не было
// вовсе»: и там и там ноль, и путь, умерший целиком, выглядел бы здоровее всех.
// Знаменатель считается наравне с числителем.
//
// # Почему это ОТДЕЛЬНЫЙ счётчик, а не метка у счётчика глаголов
//
// У полос разные предметы, и смешение сделало бы неразличимым именно то, ради
// чего счётчик заводится. Проекция глаголов — то, из чего собирается ответ
// «разрешено ли действие»: её отказ отнимает доступ. Проекция сегментов — страж
// целостности правила: её отказ доступа не отнимает, он снимает проверку. Одна
// метка на два предмета означала бы, что тревога поднимается одинаково там, где
// арендатор получает отказ, и там, где перестаёт работать наша собственная
// проверка.
//
// Набор меток ЗАКРЫТ: outcome приходит из констант досева (reseeded|failed),
// никогда из запроса, поэтому кардинальность не растёт с трафиком.
type RuleRefReseedRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewRuleRefReseedRecorder регистрирует коллектор в этом реестре.
// Звать один раз на старте.
func (r *Registry) NewRuleRefReseedRecorder() *RuleRefReseedRecorder {
	rec := &RuleRefReseedRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_role_rule_ref_reseeds_total",
			Help: "Исходы пересчёта проекции объявленных сегментов правила " +
				"(kacho_iam.role_rule_ref) на старте, по одной системной роли: " +
				"reseeded — транзакция роли закоммичена; failed — откачена. " +
				"Ноль failed значим только вместе с ненулевым reseeded: без него " +
				"ноль означает, что пересчёта не было вовсе.",
		}, []string{"outcome"}),
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// IncRuleRefReseed — исход пересчёта одной роли. Реализует порт
// seed.RuleRefReseedObserver.
func (rec *RuleRefReseedRecorder) IncRuleRefReseed(outcome string) {
	rec.outcomes.WithLabelValues(outcome).Inc()
}
