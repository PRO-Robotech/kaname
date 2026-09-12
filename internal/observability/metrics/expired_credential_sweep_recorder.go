// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// expired_credential_sweep_recorder.go — величины ВТОРОГО уборщика по сроку
// (задача продукта #2499).
//
// # Почему полосы двух уборщиков обязаны совпасть
//
// Уборщиков одного вида два: уборка по сроку и снятие истёкших удостоверений. У
// первого три семейства величин, и справка первого прямо объявляет смысл нуля. У
// второго не было ни одной: наблюдение — строка на прогон и предупреждение при
// старте, когда уборщик выключен. Различие никем не решалось, а шапка самого
// файла провязки называет класс, ради которого его провязывали: «механизм,
// написанный и не позванный, — контроль, у которого нет возможности
// исполниться».
//
// # Какие ТРИ состояния различаются
//
//	выключен оператором           ряд включённости на нуле. До этих величин
//	                              состояние объявлялось единожды при старте и
//	                              уходило вместе со сроком хранения журнала;
//	включён и отказывает          клетка исхода `failed` растёт;
//	включён и находит ноль        клетка `ok` растёт, снятых строк нуль. Это
//	                              ЗАКОННОЕ состояние, и отличает его от мёртвой
//	                              петли именно ряд прогонов.
//
// # Почему найденное и снятое — ДВА ряда
//
// «Снято 0» само по себе не отличает «нечего снимать» от «нашёл и не снял»:
// второе наступает при показе без снятия и при отказе посреди партии. Перепись
// прогона несёт два числа, и величины несут их оба.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Имена рядов второго уборщика. Собираются ИЗ КОНСТАНТЫ пространства имён.
const (
	// ExpiredCredentialReclaimEnabledMetric — включён ли уборщик (1/0).
	ExpiredCredentialReclaimEnabledMetric = Namespace + "_expired_credential_reclaim_enabled"
	// ExpiredCredentialReclaimPassesMetric — прогоны по исходам.
	ExpiredCredentialReclaimPassesMetric = Namespace + "_expired_credential_reclaim_passes_total"
	// ExpiredCredentialReclaimFoundMetric — строк найдено подлежащими снятию.
	ExpiredCredentialReclaimFoundMetric = Namespace + "_expired_credential_reclaim_rows_found_total"
	// ExpiredCredentialReclaimReclaimedMetric — строк снято.
	ExpiredCredentialReclaimReclaimedMetric = Namespace + "_expired_credential_reclaim_rows_reclaimed_total"
)

// ExpiredCredentialSweepRecorder — приёмник величин второго уборщика. Форма
// метода [SweepObserved] совпадает с портом уборщика
// (`expiredcredsweep.Observer`), поэтому корень отдаёт приёмник ему напрямую.
type ExpiredCredentialSweepRecorder struct {
	enabled   prometheus.Gauge
	passes    *prometheus.CounterVec
	found     prometheus.Counter
	reclaimed prometheus.Counter
}

// ExpiredCredentialSweepRecorder заводит приёмник и СЕЙЧАС ЖЕ клетку на каждый
// объявленный исход.
//
// Набор исходов приходит доводом из объявляющего пакета: второй перечень
// разошёлся бы с производителем молча. Пустой — ОТКАЗ: клеток не будет ни одной,
// и «отказов не было» останется неотличимым от «клетки нет».
//
// Ряд включённости заводится нулём и здесь: он обязан существовать ДО первого
// прогона, потому что у выключенного уборщика прогонов не будет вовсе — а
// отсутствие ряда читается как отсутствие уборщика.
func (r *Registry) ExpiredCredentialSweepRecorder(outcomes []string) *ExpiredCredentialSweepRecorder {
	if len(outcomes) == 0 {
		panic("metrics: ExpiredCredentialSweepRecorder без набора исходов — клеток не будет " +
			"ни одной, и «ни одного отказа» останется неотличимым от «клетки нет»")
	}
	r.expiredCredSweepOnce.Do(func() {
		rec := &ExpiredCredentialSweepRecorder{
			enabled: prometheus.NewGauge(prometheus.GaugeOpts{
				Name: ExpiredCredentialReclaimEnabledMetric,
				Help: "Whether reclaiming expired credentials is switched on (1) or off (0). A " +
					"sweeper switched off by the operator announced itself ONCE at start-up and " +
					"then left with the log retention window; a silently disabled sweep is " +
					"indistinguishable from a working one that finds nothing.",
			}),
			passes: prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: ExpiredCredentialReclaimPassesMetric,
				Help: "Passes of the expired-credential reclaim, by outcome (ok|dry-run|failed). " +
					"Counting passes is what makes \"found nothing\" different from \"the loop is " +
					"not running at all\": the pass counter grows whether or not there was " +
					"anything to remove.",
			}, []string{"outcome"}),
			found: prometheus.NewCounter(prometheus.CounterOpts{
				Name: ExpiredCredentialReclaimFoundMetric,
				Help: "Rows the reclaim found eligible for removal since process start. Reported " +
					"apart from rows removed because \"removed 0\" alone does not tell \"nothing " +
					"expired\" from \"found them and removed none\" — the latter is what a " +
					"dry-run and a pass that failed mid-batch both look like.",
			}),
			reclaimed: prometheus.NewCounter(prometheus.CounterOpts{
				Name: ExpiredCredentialReclaimReclaimedMetric,
				Help: "Rows the reclaim removed since process start. Each removed row returns a " +
					"slot under the per-principal credential ceiling.",
			}),
		}
		r.reg.MustRegister(rec.enabled, rec.passes, rec.found, rec.reclaimed)
		r.expiredCredSweep = rec
	})
	for _, outcome := range outcomes {
		r.expiredCredSweep.passes.WithLabelValues(outcome).Add(0)
	}
	return r.expiredCredSweep
}

// SetEnabled объявляет состояние выключателя. Зовётся ОДИН раз при старте, до
// первого прогона: выключенный уборщик обязан говорить о себе величиной.
func (x *ExpiredCredentialSweepRecorder) SetEnabled(on bool) {
	value := 0.0
	if on {
		value = 1
	}
	x.enabled.Set(value)
}

// SweepObserved принимает исход ОДНОГО прогона вместе с двумя числами переписи.
func (x *ExpiredCredentialSweepRecorder) SweepObserved(outcome string, found, reclaimed int) {
	x.passes.WithLabelValues(outcome).Inc()
	if found > 0 {
		x.found.Add(float64(found))
	}
	if reclaimed > 0 {
		x.reclaimed.Add(float64(reclaimed))
	}
}
