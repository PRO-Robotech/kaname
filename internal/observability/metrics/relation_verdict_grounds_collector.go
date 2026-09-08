// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// Имена семейств разбора оснований вердикта о доступе.
//
// Семейств ТРИ, а не одно с общим лейблом, и это не оформление. Клетки одного
// семейства читаются как РАЗБИЕНИЕ, а здесь разбиения нет: вердикт бывает
// одновременно и основанным на меточной ветви, и прекращённым досрочно
// (см. `relverdict.Grounds`). Слитые в один ряд, они дали бы сумму, которая не
// равна ничему.
const (
	// RelationVerdictLabelArmGroundsMetric — прямых вердиктов, чьим основанием
	// оказалась МЕТОЧНАЯ ВЕТВЬ, по каждой оси отдельно.
	RelationVerdictLabelArmGroundsMetric = "kaname_relation_verdict_label_arm_grounds_total"
	// RelationVerdictEarlyStopsMetric — прямых вердиктов, ответивших ДО того,
	// как набор источников дочитан. Знаменатель к ряду выше.
	RelationVerdictEarlyStopsMetric = "kaname_relation_verdict_early_stopped_total"
	// RelationVerdictUndeclaredTypeDenialsMetric — отказов, данных по основанию
	// «типа объекта нет в словаре модели».
	RelationVerdictUndeclaredTypeDenialsMetric = "kaname_relation_verdict_undeclared_type_denials_total"
)

// Оси меточной ветви — ЗАКРЫТЫЙ набор клеток своего семейства.
//
// Ось выбирается по типу объекта: у типов, чьи строки живут в собственных
// таблицах iam, метки спрашиваются там, у остальных — в зеркале. Разделено
// потому, что предикат равенства форм у осей РАЗНЫЙ, и число, названное для
// одной, доказывает половину и молчит про другую: ровно так дефект «ветвь
// отвечает на одной оси и молчит на второй» и дожил до находки.
const (
	// RelationVerdictLabelAxisMirror — метки спрошены в зеркале чужих объектов.
	RelationVerdictLabelAxisMirror = "mirror"
	// RelationVerdictLabelAxisIAMDirect — метки спрошены в собственной таблице iam.
	RelationVerdictLabelAxisIAMDirect = "iam_direct"
)

// RelationVerdictLabelAxes — закрытый набор клеток семейства оснований.
var RelationVerdictLabelAxes = []string{
	RelationVerdictLabelAxisMirror,
	RelationVerdictLabelAxisIAMDirect,
}

// RelationVerdictGrounds — снимок разбора оснований, прочитанный у самого
// источника вердикта.
//
// Все четыре числа снимаются с ОДНОГО носителя и одним сбором: разнесённые по
// двум коллекторам, они читались бы в разные моменты, и знаменатель относился бы
// не к тому числителю.
type RelationVerdictGrounds struct {
	// LabelArmMirror / LabelArmIAMDirect — оснований, данных меточной ветвью,
	// по осям.
	LabelArmMirror    int64
	LabelArmIAMDirect int64
	// EarlyStops — вердиктов, ответивших до того, как набор источников дочитан.
	EarlyStops int64
	// UndeclaredTypeDenials — отказов по основанию «тип не объявлен моделью».
	UndeclaredTypeDenials int64
}

type relationVerdictGroundsCollector struct {
	read           func() RelationVerdictGrounds
	labelArm       *prometheus.Desc
	earlyStops     *prometheus.Desc
	undeclaredType *prometheus.Desc
}

// NewRelationVerdictGroundsCollector регистрирует читателя величин, которые
// источник вердикта копит на живом пути решения о доступе.
//
// # ПОЧЕМУ ЭТИ ВЕЛИЧИНЫ ВООБЩЕ НАДО ПРЕДЪЯВЛЯТЬ
//
// Копились они с тех пор, когда их читало теневое сравнение форм: тогда «ноль
// оснований меточной ветви» надо было отличать от «ветвь ни разу не спросили»,
// иначе «расхождений с движком нет» ничего не означало. Сравнения больше нет —
// оно снято вместе с внешним движком прав, — но предмет не отпал, а стал
// шире: форма из теневой сделалась ЕДИНСТВЕННЫМ источником вердикта, и те же
// числа считаются теперь на живом пути решения о доступе.
//
// Каждое из них закрывает свой ТИХИЙ отказ, у которого нет иного признака:
//
//   - меточная ветвь перестала спрашиваться на одной из осей — выдачи по меткам
//     на этой оси не действуют, и арендатор видит «прав не выдали», а не ошибку;
//   - отказы по неизвестному типу растут — значит тип называют с опечаткой,
//     доступ пропадает, и выглядит это ровно так же.
//
// Оба состояния снаружи неотличимы от исправной работы. Пока величины не
// выходят наружу, их ноль отвечает сразу и «события не было», и «код, который
// его считает, не исполнялся» (`security.md` §Hardening-инвариант 8).
//
// # ЧТО ЭТИ РЯДЫ НЕ ЗАКРЫВАЮТ — названо, а не скрыто
//
// Знаменатель здесь ЧАСТИЧНЫЙ. Ранний выход прекращает чтение на первом
// безусловном основании, поэтому ненулевые ранние выходы доказывают, что путь
// исполнялся, а вот сочетание «нулевые основания И нулевые ранние выходы»
// по-прежнему означает либо «ветвь спрашивали и она молчала», либо «сюда не
// приходили вовсе». Полное число потребовало бы второго обращения к базе на
// КАЖДОМ вопросе; неопределённость названа прямо, потому что скрыть её было бы
// хуже, чем назвать.
//
// nil-источник — ОТКАЗ по той же причине, что и у соседних коллекторов: вечный
// ноль выглядит как работающее наблюдение и утверждает неправду о разборе,
// который просто забыли подключить.
func (r *Registry) NewRelationVerdictGroundsCollector(read func() RelationVerdictGrounds) {
	if read == nil {
		panic("metrics: NewRelationVerdictGroundsCollector без источника величин — " +
			"вечный ноль неотличим от нетронутого разбора оснований")
	}
	c := &relationVerdictGroundsCollector{
		read: read,
		labelArm: prometheus.NewDesc(
			RelationVerdictLabelArmGroundsMetric,
			"Direct access verdicts whose stopping ground was the label arm, by axis ("+
				strings.Join(RelationVerdictLabelAxes, "|")+"). Both axes are always "+
				"emitted: an axis that stopped being asked at all grants nothing by "+
				"label, and the tenant sees \"not granted\" rather than an error, so a "+
				"summed series would prove one half and stay silent about the other.",
			[]string{"axis"}, nil,
		),
		earlyStops: prometheus.NewDesc(
			RelationVerdictEarlyStopsMetric,
			"Direct access verdicts answered before the source set was exhausted. The "+
				"denominator for the label-arm grounds: reading stops at the first "+
				"unconditional ground, so zero grounds alone cannot tell \"the arm was "+
				"silent\" from \"the arm was never reached\".",
			nil, nil,
		),
		undeclaredType: prometheus.NewDesc(
			RelationVerdictUndeclaredTypeDenialsMetric,
			"Denials given because the object type is not declared by the model. Small "+
				"by design — its lawful source is a question about a withdrawn type. A "+
				"rising count means a real resource type is being named with a typo: "+
				"access disappears while looking like \"rights were never granted\".",
			nil, nil,
		),
	}
	r.reg.MustRegister(c)
}

// Describe — семейства видны и до первого сбора.
func (c *relationVerdictGroundsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.labelArm
	ch <- c.earlyStops
	ch <- c.undeclaredType
}

// Collect отдаёт ОБЕ клетки закрытого набора осей и оба знаменателя, читая живые
// счётчики на каждом сборе.
func (c *relationVerdictGroundsCollector) Collect(ch chan<- prometheus.Metric) {
	g := c.read()
	for axis, value := range map[string]int64{
		RelationVerdictLabelAxisMirror:    g.LabelArmMirror,
		RelationVerdictLabelAxisIAMDirect: g.LabelArmIAMDirect,
	} {
		ch <- prometheus.MustNewConstMetric(c.labelArm, prometheus.CounterValue, float64(value), axis)
	}
	ch <- prometheus.MustNewConstMetric(c.earlyStops, prometheus.CounterValue, float64(g.EarlyStops))
	ch <- prometheus.MustNewConstMetric(c.undeclaredType, prometheus.CounterValue, float64(g.UndeclaredTypeDenials))
}
