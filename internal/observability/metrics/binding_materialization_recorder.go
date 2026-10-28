// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// BindingMaterializationRecorder меряет, НАСКОЛЬКО ВЕЛИКА материализация одной
// привязки: сколько объектов отобрали её селекторы и сколько кортежей эти
// объекты дают.
//
// ЗАЧЕМ ЭТО МЕРЯТЬ. Доступ ниже трёх каскадных уровней материализуется ПО
// ОБЪЕКТУ, поэтому одна выдача разворачивается в столько кортежей, сколько
// объектов отобрал селектор, помноженное на глаголы правила. Этого разворота не
// считал никто, и «выдача разрослась» было неотличимо от «выдача обычная» —
// ровно до того момента, когда размер перестаёт помещаться в то, что держит
// модель. И упирается это не там, где выдачу выписали: разворот пишет
// реконсайлер, поэтому в стену упирается позже чужой запрос, по пути, который
// о привязке ничего не говорит.
//
// ПОЧЕМУ ЗДЕСЬ НЕТ ПОТОЛКА. Величина, которой привязка может достичь, не
// измерена, а предел, назначенный до замера, либо отвергнет законную выдачу,
// либо встанет выше всего и не отвергнет ничего — и вторая ошибка дороже, потому
// что выглядит контролем. Поэтому сперва замер, потом число. Этот приёмник и
// есть замер; он не отвергает ничего.
//
// ПОЧЕМУ ГИСТОГРАММЫ, А НЕ ДАТЧИКИ. Вопрос — о распределении («насколько
// крупными бывают привязки и сдвигается ли хвост»), а не о последнем значении.
// Датчик показал бы ту привязку, которой реконсайлер коснулся последней, и не
// ответил бы ничего о хвосте. Корзины экспоненциальны и доходят до четырёх
// знаков, поэтому привязка на порядок крупнее обычной попадает в свою корзину, а
// не в `+Inf` вместе со всем крупным.
//
// ЕДИНСТВЕННАЯ МЕТКА — ПОЛОСА (`lane`), kaname#157. Материализуют привязки две
// полосы, и они отвечают на разные вопросы: путь запроса (выдача, правка роли,
// привязка владельца, первый вход) — «сколько стоит то, что арендатор сделал
// сейчас», фоновый обход (воркер очереди реконсайла, подмётка, истечение срока,
// догон и проверка на старте) — «сколько стоит поддерживать то, что уже
// выдано». Слитые в один ряд, они не читаются ни так, ни так; ряд только пути
// запроса читался бы как полный, и полоса обхода выглядела бы полосой без
// трафика. Набор полос ЗАКРЫТ ([BindingMaterializationLanes]), и обе клетки
// заводятся нулём при регистрации.
//
// Идентификатор привязки, область и роль меткой не становятся НАМЕРЕННО: это
// неограниченная кардинальность прямо из данных арендатора. На вопрос отвечает
// распределение; назвать конкретную привязку — дело журнала, который
// реконсайлер уже пишет.
type BindingMaterializationRecorder struct {
	objects *prometheus.HistogramVec
	tuples  *prometheus.HistogramVec
}

// BindingMaterializationLane — приёмник ОДНОЙ полосы. Его и получает
// реконсайлер через свой узкий порт: полоса закрепляется при сборке экземпляра,
// а не выбирается на каждом проходе, поэтому записать проход «не в ту полосу»
// реконсайлеру нечем.
type BindingMaterializationLane struct {
	objects prometheus.Observer
	tuples  prometheus.Observer
}

const (
	// BindingMaterializationObjectsMetric — имя семейства числа объектов.
	BindingMaterializationObjectsMetric = Namespace + "_binding_materialization_objects"
	// BindingMaterializationTuplesMetric — имя семейства числа кортежей.
	BindingMaterializationTuplesMetric = Namespace + "_binding_materialization_tuples"

	// BindingMaterializationLaneRequest — материализация на пути запроса.
	BindingMaterializationLaneRequest = "request"
	// BindingMaterializationLaneSweep — материализация фонового обхода.
	BindingMaterializationLaneSweep = "sweep"
)

// BindingMaterializationLanes — ЗАКРЫТЫЙ набор полос; клетки обеих величин
// заводятся по нему.
var BindingMaterializationLanes = []string{BindingMaterializationLaneRequest, BindingMaterializationLaneSweep}

// bindingSizeBuckets — общие корзины для обеих величин. Одинаковые намеренно:
// величины сравнивают друг с другом (кортежей на объект — это их отношение), и
// разные корзины сделали бы сравнение неверным на глаз.
var bindingSizeBuckets = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000}

// BindingMaterializationRecorder возвращает ЕДИНСТВЕННЫЙ приёмник этого
// реестра, регистрируя семейства при первом обращении. Полосы берутся у него
// ([BindingMaterializationRecorder.RequestLane], [BindingMaterializationRecorder.SweepLane])
// в разных местах композиционного корня.
func (r *Registry) BindingMaterializationRecorder() *BindingMaterializationRecorder {
	r.bindingSizeOnce.Do(func() {
		rec := &BindingMaterializationRecorder{
			objects: prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name: BindingMaterializationObjectsMetric,
				Help: "Objects matched by one access binding's selectors during a reconcile pass, " +
					"by lane: request (the tenant's call) or sweep (background reconcile).",
				Buckets: bindingSizeBuckets,
			}, []string{"lane"}),
			tuples: prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name: BindingMaterializationTuplesMetric,
				Help: "Authorization tuples one access binding's reconcile pass materializes " +
					"(objects × the verbs of the rule that matched them), by lane: request or sweep.",
				Buckets: bindingSizeBuckets,
			}, []string{"lane"}),
		}
		// Клетки закрытого набора — нулём ПРИ РЕГИСТРАЦИИ: вектор без детей не
		// отдаёт на провод ничего, и «полоса не провязана» стала бы неотличима
		// от «полоса провязана и ни разу не материализовала».
		for _, lane := range BindingMaterializationLanes {
			rec.objects.WithLabelValues(lane)
			rec.tuples.WithLabelValues(lane)
		}
		r.reg.MustRegister(rec.objects, rec.tuples)
		r.bindingSize = rec
	})
	return r.bindingSize
}

// RequestLane — приёмник полосы пути запроса.
func (rec *BindingMaterializationRecorder) RequestLane() *BindingMaterializationLane {
	return rec.lane(BindingMaterializationLaneRequest)
}

// SweepLane — приёмник полосы фонового обхода.
func (rec *BindingMaterializationRecorder) SweepLane() *BindingMaterializationLane {
	return rec.lane(BindingMaterializationLaneSweep)
}

func (rec *BindingMaterializationRecorder) lane(lane string) *BindingMaterializationLane {
	return &BindingMaterializationLane{
		objects: rec.objects.WithLabelValues(lane),
		tuples:  rec.tuples.WithLabelValues(lane),
	}
}

// ObserveBindingMaterialization записывает размер желаемого набора ОДНОЙ
// привязки в ряд своей полосы.
//
// Проход, не отобравший ничего, записывается тоже — нулём: «эта привязка не
// материализует ничего» — настоящее и интересное состояние, и селектор,
// переставший отбирать, без учёта пустого прохода выглядит ровно как привязка,
// которую никто не согласует.
func (l *BindingMaterializationLane) ObserveBindingMaterialization(objects, tuples int) {
	l.objects.Observe(float64(objects))
	l.tuples.Observe(float64(tuples))
}
