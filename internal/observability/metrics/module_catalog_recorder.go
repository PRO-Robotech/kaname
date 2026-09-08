// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// ModuleCatalogRecorder — что сделало ПРИМЕНЕНИЕ каталога модуля
// (`modulecatalog.Applier`, задача продукта #1963).
//
// # Зачем метрика, если перепись уже печатается журналом
//
// Перепись печатается на старте, и число оператору достаётся — если он этот
// журнал читает. В три часа ночи вопрос стоит иначе, чем при разборе: «каталог
// отстал» или «продукт сломан». Журнал отвечает после того, как найден нужный
// под, нужный старт и нужная строка; счётчик отвечает сразу.
//
// # Величин ТРИ, и одной не хватает ни на один из трёх вопросов
//
//	применений ноль    → применитель не ходил вовсе (знаменатель)
//	снятий ноль        → каталог не менялся
//	переселений ноль   → снятие БЫЛО, но ни одной роли не задело
//
// Оставь одни переселения — и ноль будет означать сразу три разных состояния, из
// которых одно (мёртвый применитель) выглядело бы здоровее всех. Сложи снятия с
// переселениями — и потеряешь различие, ради которого перепись применителя и
// держит две популяции порознь: «право отобрано» (`role_verb`) и «правило
// перестало резолвиться» (`rule_ref`) — разные события для того, кто разбирает
// последствия.
//
// # Граница названа: отказ на пути СТАРТА этой метрикой не наблюдаем
//
// Исход `failed` производителя имеет — его эмитит всякий отказ применения, — но
// на пути старта он неснимаем by construction: отказ применения есть отказ
// пуска, а слушатель метрик поднимается позже применителя, и процесс до него не
// доживает. Наблюдают такой отказ по отсутствию процесса и по журналу; серия
// нужна второму вызывающему глагола, который отказ переживает.
//
// # Наборы меток ЗАКРЫТЫ
//
// Все три приходят из констант `modulecatalog` (applied|failed,
// resource|verb, rule_ref|role_verb), никогда из запроса, поэтому кардинальность
// не растёт с трафиком.
type ModuleCatalogRecorder struct {
	applies   *prometheus.CounterVec
	retired   *prometheus.CounterVec
	resettled *prometheus.CounterVec
}

// NewModuleCatalogRecorder регистрирует коллекторы в этом реестре.
// Звать один раз на старте.
func (r *Registry) NewModuleCatalogRecorder() *ModuleCatalogRecorder {
	rec := &ModuleCatalogRecorder{
		applies: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_module_catalog_applies_total",
			Help: "Исходы применения манифеста модуля к строкам каталога: applied — " +
				"транзакция модуля закоммичена; failed — применение отвергнуто, каталог " +
				"остался прежним. ЗНАМЕНАТЕЛЬ для двух счётчиков ниже: без него их ноль " +
				"означает сразу и «каталог не менялся», и «применитель не ходил вовсе». " +
				"На пути старта failed неснимаем: отказ применения есть отказ пуска, и " +
				"процесс не доживает до слушателя метрик.",
		}, []string{"outcome"}),
		retired: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_module_catalog_retired_rows_total",
			Help: "Строк каталога помечено снятыми, по виду: resource — строка ресурса; " +
				"verb — строка действия. Снятие есть ПОМЕТКА, а не удаление. Ноль значим " +
				"только вместе с ненулевым applies: без него он означает, что применения " +
				"не было.",
		}, []string{"kind"}),
		resettled: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_module_catalog_resettled_projections_total",
			Help: "Проекций арендаторских ролей переселено в сироты снятием строки " +
				"каталога, по популяции: rule_ref — правило перестало резолвиться; " +
				"role_verb — право отобрано. Популяции РАЗНЫЕ события, и сумма их не " +
				"различает. Ноль при ненулевом retired_rows значим сам по себе: снятие " +
				"было и ни одной роли не задело.",
		}, []string{"population"}),
	}
	r.reg.MustRegister(rec.applies, rec.retired, rec.resettled)
	return rec
}

// IncCatalogApply — исход применения одного манифеста. Реализует порт
// modulecatalog.Observer.
func (rec *ModuleCatalogRecorder) IncCatalogApply(outcome string) {
	rec.applies.WithLabelValues(outcome).Inc()
}

// AddCatalogRetiredRows — снятых строк каталога, по виду. Реализует порт
// modulecatalog.Observer.
func (rec *ModuleCatalogRecorder) AddCatalogRetiredRows(kind string, n int) {
	rec.retired.WithLabelValues(kind).Add(float64(n))
}

// AddCatalogResettledProjections — переселённых проекций, по популяции.
// Реализует порт modulecatalog.Observer.
func (rec *ModuleCatalogRecorder) AddCatalogResettledProjections(population string, n int) {
	rec.resettled.WithLabelValues(population).Add(float64(n))
}
