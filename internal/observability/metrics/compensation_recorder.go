// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// CompensationRecorder — счётчики компенсаций частично исполненной саги
// «зарегистрировать клиента у провайдера → закоммитить свою строку», плюс
// глубина и возраст очереди этих компенсаций.
//
// ЗАЧЕМ СЧЁТЧИК, А НЕ ТОЛЬКО ЛОГ. Компенсация срабатывает редко и только на
// неудачном пути, поэтому «ноль компенсаций за всю жизнь» — нормальное
// состояние здорового облака И одновременно ровно то, что видно у мёртвого
// механизма: очередь не провязана, дренаж не поднят, applier никогда не звали.
// Отличить их можно только если считать ЗАПИСАННЫЕ намерения отдельно от
// ИСПОЛНЕННЫХ: серия, которой нет вовсе, отвечает на «провязано ли», а
// расхождение записанных и исполненных — на «доезжает ли». То же требование,
// что и «ноль доставленных строк за всю жизнь очереди обязано быть заметно».
//
// Возраст самой старой недоставленной строки отвечает на второй обязательный
// вопрос — «висит ли строка дольше N»: без него застрявшая компенсация тиха,
// а занятое у провайдера остаётся занятым.
//
// Набор меток ЗАКРЫТ: origin приходит из констант use-case'ов
// (sa_key|user_token|interactive_client), никогда из запроса, поэтому
// кардинальность не растёт с трафиком.
type CompensationRecorder struct {
	emitted *prometheus.CounterVec
	applied *prometheus.CounterVec
	backlog *prometheus.GaugeVec
	oldest  *prometheus.GaugeVec
	poison  *prometheus.GaugeVec
}

// NewCompensationRecorder регистрирует коллекторы в этом реестре. Звать один раз на старте.
func (r *Registry) NewCompensationRecorder() *CompensationRecorder {
	rec := &CompensationRecorder{
		emitted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_provider_compensations_emitted_total",
			Help: "Компенсирующие намерения, записанные в очередь, по саге-инициатору (origin) " +
				"и исходу записи (ok|error). error означает, что durable-намерение записать не " +
				"удалось и путь деградировал в прямое снятие.",
		}, []string{"origin", "outcome"}),
		applied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_provider_compensations_applied_total",
			Help: "Компенсации, исполненные дренажом (клиент снят у провайдера либо его уже не было), " +
				"по саге-инициатору. Расхождение с emitted — то, что ещё не доехало.",
		}, []string{"origin"}),
		backlog: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kacho_iam_outbox_backlog_depth",
			Help: "Недоставленные строки outbox-таблицы.",
		}, []string{"table"}),
		oldest: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kacho_iam_outbox_oldest_pending_age_seconds",
			Help: "Возраст самой старой недоставленной строки outbox-таблицы. " +
				"Отвечает на «висит ли строка дольше N».",
		}, []string{"table"}),
		poison: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "kacho_iam_outbox_poisoned_count",
			Help: "Отравленные (исчерпавшие попытки) строки outbox-таблицы.",
		}, []string{"table"}),
	}
	r.reg.MustRegister(rec.emitted, rec.applied, rec.backlog, rec.oldest, rec.poison)
	return rec
}

// IncCompensationEmitted — намерение записано (outcome "ok") либо записать не
// удалось (outcome "error", путь деградировал в прямое снятие).
func (rec *CompensationRecorder) IncCompensationEmitted(origin, outcome string) {
	rec.emitted.WithLabelValues(origin, outcome).Inc()
}

// IncCompensationApplied — компенсация исполнена. Реализует
// clients.CompensationObserver.
func (rec *CompensationRecorder) IncCompensationApplied(origin string) {
	rec.applied.WithLabelValues(origin).Inc()
}

// SetBacklogDepth реализует outbox/metrics.Recorder.
func (rec *CompensationRecorder) SetBacklogDepth(table string, depth float64) {
	rec.backlog.WithLabelValues(table).Set(depth)
}

// SetOldestPendingAgeSeconds реализует outbox/metrics.Recorder.
func (rec *CompensationRecorder) SetOldestPendingAgeSeconds(table string, age float64) {
	rec.oldest.WithLabelValues(table).Set(age)
}

// SetPoisonedCount реализует outbox/metrics.Recorder.
func (rec *CompensationRecorder) SetPoisonedCount(table string, count float64) {
	rec.poison.WithLabelValues(table).Set(count)
}

// IncPoisoned реализует outbox/metrics.Recorder.
func (rec *CompensationRecorder) IncPoisoned(table string) {
	// Отравленные строки уже отражены SetPoisonedCount по скану таблицы;
	// отдельного монотонного счётчика здесь не заводим, чтобы не держать две
	// величины об одном предмете, из которых расходиться будет одна.
	_ = table
}

// CompensationRecorder возвращает ЕДИНСТВЕННЫЙ экземпляр коллекторов
// компенсации этого реестра, создавая его при первом обращении.
//
// Потребителей двое и собираются они в разных местах: writer намерений (внутри
// buildServices) и дренаж с метрик-сканером (в runServe). Два независимых
// вызова NewCompensationRecorder уронили бы старт на duplicate-register — и
// уронили бы именно тогда, когда механизм наконец провязали целиком.
func (r *Registry) CompensationRecorder() *CompensationRecorder {
	r.compensationOnce.Do(func() { r.compensation = r.NewCompensationRecorder() })
	return r.compensation
}
