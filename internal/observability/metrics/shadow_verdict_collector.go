// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

// ShadowVerdictOutcomesMetric / ShadowVerdictOutcomes — имя семейства и ЗАКРЫТЫЙ
// набор его клеток, объявленные один раз.
//
// Значения приходят из кода сравнителя, никогда из данных запроса, поэтому
// кардинальность не растёт с трафиком. Перечень читают обе стороны: коллектор —
// чтобы отдать каждую клетку на каждом сборе, проба — чтобы утверждать, что
// вывод различает два состояния, а не только что серия существует.
const (
	ShadowVerdictOutcomesMetric = "kacho_iam_shadow_verdict_outcomes_total"

	// ShadowVerdictOutcomeDecisions — знаменатель: решение о доступе, к которому
	// теневой путь был позван, независимо от того, чем это кончилось.
	ShadowVerdictOutcomeDecisions = "decisions"
	// ShadowVerdictOutcomeCompared — ответ получен и сверен с движком.
	ShadowVerdictOutcomeCompared = "compared"
	// ShadowVerdictOutcomeDiverged — ответы разошлись (подмножество сверенных).
	ShadowVerdictOutcomeDiverged = "diverged"
	// ShadowVerdictOutcomeUnfinished — ответа не получено: ни согласие, ни расхождение.
	ShadowVerdictOutcomeUnfinished = "unfinished"
	// ShadowVerdictOutcomeUnaskable — решение, которое форме задать НЕЛЬЗЯ.
	//
	// Своя клетка, а не доля «не выполнилось»: «спросить нечем» — свойство
	// вопроса, «не успели» — свойство прогона, и действия они требуют разного.
	// Условие переключения типа названо долей «спросить нельзя» ПО ЭТОМУ ТИПУ;
	// доля, размазанная по общей корзине, не считается ни для одного.
	ShadowVerdictOutcomeUnaskable = "unaskable"
	// ShadowVerdictOutcomeDivergedFormWider — форма разрешает там, где движок
	// отказывал: РАСШИРЕНИЕ ДОСТУПА. Подмножество `diverged`.
	//
	// На переключённом типе это уже случившееся событие безопасности и повод
	// откатить тип рубильником, а не наблюдение.
	ShadowVerdictOutcomeDivergedFormWider = "diverged_form_wider"
	// ShadowVerdictOutcomeDivergedFormNarrower — форма отказывает там, где движок
	// разрешал: отказ в обслуживании. Подмножество `diverged`.
	ShadowVerdictOutcomeDivergedFormNarrower = "diverged_form_narrower"
	// ShadowVerdictOutcomeVerdictsForm — решений, ПРИНЯТЫХ формой.
	//
	// Считается в точке, где источник выбирается, а не выводится из настройки.
	// Без этого ряда «переключено» и «объявлено переключённым» неразличимы:
	// настройка может не доехать до процесса, и ответы при этом останутся
	// правильными — только их выносит прежний источник.
	ShadowVerdictOutcomeVerdictsForm = "verdicts_form"
	// ShadowVerdictOutcomeVerdictsEngine — решений, принятых движком.
	//
	// Сумма с предыдущим обязана сходиться с `decisions`: у решения ровно один
	// источник, и решение, не попавшее ни в один ряд, не видно ниоткуда.
	ShadowVerdictOutcomeVerdictsEngine = "verdicts_engine"
)

// ShadowVerdictOutcomes — закрытый набор клеток семейства.
//
// Клетки НЕ непересекающиеся, и это намеренно: `diverged` — подмножество
// `compared`, а `decisions` — знаменатель обоих. Разложить их по непересекающимся
// корзинам значило бы потерять именно те два отношения, ради которых величины и
// выходят наружу: доля разошедшихся от сравнённых и доля сравнённых от всех
// решений.
var ShadowVerdictOutcomes = []string{
	ShadowVerdictOutcomeDecisions,
	ShadowVerdictOutcomeCompared,
	ShadowVerdictOutcomeDiverged,
	ShadowVerdictOutcomeUnfinished,
	ShadowVerdictOutcomeUnaskable,
	ShadowVerdictOutcomeDivergedFormWider,
	ShadowVerdictOutcomeDivergedFormNarrower,
	ShadowVerdictOutcomeVerdictsForm,
	ShadowVerdictOutcomeVerdictsEngine,
}

// ShadowVerdictCounts — четыре числа теневого сравнения, прочитанные У САМОГО
// сравнителя.
//
// Это перенос значений, а не вторая их копия: коллектор ничего не накапливает и
// хранить ему нечего. Собственный накопитель рядом с настоящим разошёлся бы с
// ним ровно там, где расхождение не видно, — оба отвечают «ноль» на нулевом
// трафике.
type ShadowVerdictCounts struct {
	// Decisions — знаменатель: решений о доступе, к которым теневой путь был
	// позван. Считается на входе, до того как известен исход, и включает решения,
	// которые форме E задать нельзя вовсе, — иначе доля сравнённого считалась бы
	// от того подмножества, где сравнение и так удавалось.
	Decisions int64
	// Compared — сравнений состоялось (включая разошедшиеся).
	Compared int64
	// Diverged — из состоявшихся сравнений разошлось.
	Diverged int64
	// Unfinished — ответа не получено (срок исчерпан, источник недоступен).
	Unfinished int64
	// Unaskable — решение, которое форме задать нельзя (объект не разобран,
	// область не названа). Отдельно от Unfinished: см. клетку.
	Unaskable int64
	// DivergedFormWider / DivergedFormNarrower — направление расхождения,
	// подмножества Diverged.
	DivergedFormWider    int64
	DivergedFormNarrower int64
	// VerdictsForm / VerdictsEngine — источник решения. Сумма == Decisions.
	VerdictsForm   int64
	VerdictsEngine int64
}

// shadowVerdictCollector отдаёт четыре числа сравнителя на КАЖДОМ сборе, читая их
// в момент сбора.
//
// Коллектор, а не счётчик-приёмник: величины уже считаются на пути запроса
// атомарными счётчиками сравнителя, и заводить рядом второй набор значило бы
// держать два места об одном предмете. Здесь только чтение.
type shadowVerdictCollector struct {
	read func() ShadowVerdictCounts
	desc *prometheus.Desc
}

// NewShadowVerdictCollector регистрирует читателя счётчиков теневого сравнения.
//
// ПОЧЕМУ ЭТО ВООБЩЕ НУЖНО. Сравнение не влияет на ответ вызывающему — в этом
// его смысл и в этом же его опасность: сравнитель, которого не спросили ни разу,
// выглядит снаружи ровно как сравнитель без расхождений. Пока наружу выходит
// одно число «расхождений», ноль в нём означает тишину, а не согласие, и
// переключать источник вердикта на такой отчёт нельзя. Поэтому наружу выходят
// ЧЕТЫРЕ ряда одного семейства, и «сравнений 0» отличимо от «расхождений 0».
//
// Четвёртый ряд — знаменатель. Числа сравнений одного мало: «сравнили тысячу» не
// отвечает, сколько это от всех решений, а зазор между решениями и суммой
// состоявшихся исходов — это ровно те решения, мимо которых сравнение прошло
// молча. Знаменатель из остальных клеток не выводится и потому едет своим рядом.
//
// Каждая клетка закрытого набора отдаётся на каждом сборе, даже нулевая:
// присутствие ряда отвечает «провязано ли», а его ЗНАЧЕНИЕ — «доходило ли до
// него». Отсутствие ряда отвечало бы на оба вопроса сразу и не отвечало бы ни на
// один.
//
// nil-источник — ОТКАЗ, а не тихая регистрация вечного нуля: последняя выглядит
// как работающее наблюдение и утверждает «сравнений не было» о сравнителе,
// которого просто забыли подключить. Это ошибка сборки в корне композиции, и
// место ей — старт процесса, а не отчёт с боевого стенда.
func (r *Registry) NewShadowVerdictCollector(read func() ShadowVerdictCounts) {
	if read == nil {
		panic("metrics: NewShadowVerdictCollector без источника величин — " +
			"вечный ноль неотличим от молчания сравнителя")
	}
	c := &shadowVerdictCollector{
		read: read,
		desc: prometheus.NewDesc(
			ShadowVerdictOutcomesMetric,
			"Outcomes of the shadow verdict comparison, by outcome ("+
				strings.Join(ShadowVerdictOutcomes, "|")+"). Comparisons are counted "+
				"alongside divergences, so \"zero divergences\" is distinguishable from "+
				"\"zero comparisons\"; an answer that never arrived is its own bucket and is "+
				"counted neither as agreement nor as divergence. The buckets deliberately "+
				"overlap: \"decisions\" counts every access decision the shadow path was "+
				"invoked for and is the denominator the compared share is taken against, "+
				"while \"diverged\" is a subset of \"compared\".",
			[]string{"outcome"}, nil,
		),
	}
	r.reg.MustRegister(c)
}

// Describe — семейство объявлено заранее, поэтому оно видно и до первого сбора.
func (c *shadowVerdictCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

// Collect отдаёт все клетки закрытого набора, читая живые счётчики.
func (c *shadowVerdictCollector) Collect(ch chan<- prometheus.Metric) {
	counts := c.read()
	for outcome, value := range map[string]int64{
		ShadowVerdictOutcomeDecisions:            counts.Decisions,
		ShadowVerdictOutcomeCompared:             counts.Compared,
		ShadowVerdictOutcomeDiverged:             counts.Diverged,
		ShadowVerdictOutcomeUnfinished:           counts.Unfinished,
		ShadowVerdictOutcomeUnaskable:            counts.Unaskable,
		ShadowVerdictOutcomeDivergedFormWider:    counts.DivergedFormWider,
		ShadowVerdictOutcomeDivergedFormNarrower: counts.DivergedFormNarrower,
		ShadowVerdictOutcomeVerdictsForm:         counts.VerdictsForm,
		ShadowVerdictOutcomeVerdictsEngine:       counts.VerdictsEngine,
	} {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(value), outcome)
	}
}
