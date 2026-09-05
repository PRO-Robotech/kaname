// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// RoleVerbReseedRecorder — исходы пересчёта проекции «роль → тип объекта ×
// глагол» на старте, по одной системной роли.
//
// # Зачем считать УСПЕХИ, а не только отказы
//
// Счётчик одних отказов не отличает «отказов не было» от «пересчёта не было
// вовсе»: и там и там ноль, и путь, умерший целиком, выглядел бы здоровее всех.
// Знаменатель считается наравне с числителем.
//
// # Почему это отдельная полоса, а не часть досева выдач
//
// Проекция — то, из чего цепь вердикта собирает ответ «разрешено ли действие».
// Пока её отказ приезжал обёрнутым в чужую ошибку досева, он печатался уровнем
// чужой полосы, и различить «база не ответила» от «механизм не работает» было
// нечем. Метрика даёт ту же различимость машинно: постоянный ненулевой `failed`
// при нулевом `reseeded` — механизм, а не моргание базы.
//
// Набор меток ЗАКРЫТ: outcome приходит из констант досева
// (reseeded|failed), никогда из запроса, поэтому кардинальность не растёт с
// трафиком.
type RoleVerbReseedRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewRoleVerbReseedRecorder регистрирует коллектор в этом реестре.
// Звать один раз на старте.
func (r *Registry) NewRoleVerbReseedRecorder() *RoleVerbReseedRecorder {
	rec := &RoleVerbReseedRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_role_verb_reseeds_total",
			Help: "Исходы пересчёта проекции «роль → тип объекта × глагол» на старте, " +
				"по одной системной роли: reseeded — транзакция роли закоммичена; " +
				"failed — откачена. Ноль failed значим только вместе с ненулевым " +
				"reseeded: без него ноль означает, что пересчёта не было вовсе.",
		}, []string{"outcome"}),
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// IncRoleVerbReseed — исход пересчёта одной роли. Реализует порт
// seed.RoleVerbReseedObserver.
func (rec *RoleVerbReseedRecorder) IncRoleVerbReseed(outcome string) {
	rec.outcomes.WithLabelValues(outcome).Inc()
}
