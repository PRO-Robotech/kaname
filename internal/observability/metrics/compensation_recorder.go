// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// CompensationRecorder — счётчики компенсаций частично исполненной саги
// «зарегистрировать клиента у провайдера → закоммитить свою строку».
//
// Состояние самой очереди (глубина, возраст головы, отравленные) здесь БОЛЬШЕ НЕ
// живёт: гейджи размечены лейблом `table` и годятся любой очереди сервиса, а
// очередей у сервиса НЕСКОЛЬКО — держать их в типе с именем «компенсация» значило
// бы объявлять областью действия одну. Числа здесь нет намеренно: оно росло молча
// (в день заведения комментарий говорил «три»), а перечень выводится предикатом —
// см. шапку OutboxRecorder в outbox_recorder.go. Они переехали в OutboxRecorder
// (outbox_recorder.go), который наблюдает все три.
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
// На второй обязательный вопрос — «висит ли ЭТА строка дольше N» — отвечает
// возраст головы очереди из OutboxRecorder. Обе величины нужны, ни одна не
// заменяет другую: расхождение записанных и исполненных говорит «доезжает ли
// вообще», возраст — «застряла ли конкретная».
//
// Набор меток ЗАКРЫТ: origin приходит из констант use-case'ов
// (sa_key|user_token|interactive_client), никогда из запроса, поэтому
// кардинальность не растёт с трафиком.
type CompensationRecorder struct {
	emitted *prometheus.CounterVec
	applied *prometheus.CounterVec
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
	}
	r.reg.MustRegister(rec.emitted, rec.applied)
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

// CompensationRecorder возвращает ЕДИНСТВЕННЫЙ экземпляр коллекторов
// компенсации этого реестра, создавая его при первом обращении.
//
// Потребителей двое и собираются они в разных местах: writer намерений (внутри
// buildServices) и применитель компенсаций (в runServe). Два независимых
// вызова NewCompensationRecorder уронили бы старт на duplicate-register — и
// уронили бы именно тогда, когда механизм наконец провязали целиком.
func (r *Registry) CompensationRecorder() *CompensationRecorder {
	r.compensationOnce.Do(func() { r.compensation = r.NewCompensationRecorder() })
	return r.compensation
}
