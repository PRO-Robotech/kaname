// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// CatalogSnapshotOutcomes — ЗАКРЫТЫЙ набор клеток семейства.
//
// Собран из констант производителя ([catalog.RefreshOutcomeRefreshed],
// [catalog.RefreshOutcomeFailed]), а не выписан здесь литералами: второе место
// об одном предмете разошлось бы на первом же новом исходе, и разошлось бы
// молча — незнакомая клетка просто не завелась бы.
var CatalogSnapshotOutcomes = []string{
	catalog.RefreshOutcomeRefreshed,
	catalog.RefreshOutcomeFailed,
}

// CatalogSnapshotRecorder — исходы ОБНОВЛЕНИЯ снимка каталога модуля
// (kacho#1816, IAM-CT-2-03 / -04).
//
// # Зачем считать УСПЕХИ, а не только отказы
//
// Счётчик одних отказов не отличает «отказов не было» от «обновлений не было
// вовсе»: и там и там ноль, и путь, умерший целиком, выглядел бы здоровее всех.
// Снимок при этом продолжает отвечать — прежним, сколь угодно старым множеством,
// — поэтому снаружи мёртвое обновление неотличимо от исправного. Знаменатель
// считается наравне с числителем.
//
// # Зачем считать отказы, если успехи уже считаются
//
// Обратное тоже неверно: растущий ноль удавшихся не говорит, отказывало ли
// обновление или его не запускали. Одна величина отвечает на один вопрос; их
// два.
//
// # Чем это отличается от заполнения на СТАРТЕ
//
// Заполнение снимка на старте здесь НЕ считается: оно идёт тем же чтением, что и
// страж паритета, и его отказ фатален — служба не поднимается. Зачти его — и
// «ноль обновлений за жизнь процесса» станет неотличимо от одного.
//
// Набор меток ЗАКРЫТ: outcome приходит из констант пакета `catalog`
// (refreshed|failed), никогда из запроса, поэтому кардинальность не растёт с
// трафиком.
type CatalogSnapshotRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewCatalogSnapshotRecorder регистрирует коллектор в этом реестре.
// Звать один раз на старте.
func (r *Registry) NewCatalogSnapshotRecorder() *CatalogSnapshotRecorder {
	rec := &CatalogSnapshotRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_catalog_snapshot_refreshes_total",
			Help: "Исходы обновления снимка каталога модуля: refreshed — новое живое " +
				"множество прочитано и подменило прежнее; failed — обновление не удалось, " +
				"снимок остался прежним. Заполнение на старте не считается ни тем, ни " +
				"другим. Ноль failed значим только вместе с ненулевым refreshed: без него " +
				"ноль означает, что обновлений не было вовсе.",
		}, []string{"outcome"}),
	}
	// Клетки закрытого набора заводятся нулём ПРИ РЕГИСТРАЦИИ: вектор без детей
	// не отдаёт на провод ничего, и «механизм не провязан» становится неотличим
	// от «механизм провязан и ни разу не сработал».
	for _, outcome := range CatalogSnapshotOutcomes {
		rec.outcomes.WithLabelValues(outcome)
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// IncCatalogSnapshotRefresh — исход одного обновления. Реализует порт
// catalog.RefreshObserver.
func (rec *CatalogSnapshotRecorder) IncCatalogSnapshotRefresh(outcome string) {
	rec.outcomes.WithLabelValues(outcome).Inc()
}
