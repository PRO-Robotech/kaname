// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// invite_mail_intent_recorder.go — исходы НАМЕРЕНИЯ отправить письмо
// приглашения на пути наших глаголов (приёмка ID-MAIL-1, Р14/Р22, MAIL-25;
// задача продукта #1775).
//
// # Почему второй счётчик, а не клетка в счётчике отправки
//
// `kaname_invite_mail_outcomes_total` считает ПОПЫТКИ ОТПРАВКИ дренажем —
// то, что дошло до очереди и пошло к узлу. Сверхнормативное намерение до
// очереди не доходит by construction, и в том счётчике его нет НИГДЕ. Без
// своей клетки ограничение частоты было бы невидимо: ответ глагола обязан
// быть неотличим от ответа в норме (Р9), значит единственное место, где
// «письмо не ушло по частоте» вообще существует, — этот счётчик.
//
// Успехи считаются НАРАВНЕ с отказами (та же форма, что у зеркала набора
// ключей): ноль `rate_limited` значим только рядом с ненулевым `queued`,
// иначе он означает «сюда никто не приходил».

import "github.com/prometheus/client_golang/prometheus"

const (
	// InviteMailIntentOutcomeQueued — намерение поставлено в очередь.
	InviteMailIntentOutcomeQueued = "queued"
	// InviteMailIntentOutcomeRateLimited — окно адресата полно, письмо не
	// поставлено; ответ глагола при этом тот же, что в норме.
	InviteMailIntentOutcomeRateLimited = "rate_limited"
)

// InviteMailIntentOutcomes — закрытый набор клеток.
var InviteMailIntentOutcomes = []string{
	InviteMailIntentOutcomeQueued,
	InviteMailIntentOutcomeRateLimited,
}

// InviteMailIntentRecorder — счётчик исходов намерения.
type InviteMailIntentRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewInviteMailIntentRecorder регистрирует счётчик в этом реестре.
func (r *Registry) NewInviteMailIntentRecorder() *InviteMailIntentRecorder {
	rec := &InviteMailIntentRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_invite_mail_intents_total",
			Help: "Исходы намерения отправить письмо приглашения на пути глаголов " +
				"приглашения и повторной отправки: queued — поставлено в очередь; " +
				"rate_limited — окно частоты адреса полно, письмо не поставлено, ответ " +
				"глагола тот же, что в норме. Ноль rate_limited значим только рядом с " +
				"ненулевым queued.",
		}, []string{"outcome"}),
	}
	for _, outcome := range InviteMailIntentOutcomes {
		rec.outcomes.WithLabelValues(outcome)
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// IncInviteMailIntent — исход одного намерения. Реализует
// user.InviteMailIntentObserver.
func (rec *InviteMailIntentRecorder) IncInviteMailIntent(outcome string) {
	rec.outcomes.WithLabelValues(outcome).Inc()
}

// InviteMailIntentRecorder возвращает ЕДИНСТВЕННЫЙ экземпляр счётчика этого
// реестра: два глагола делят одну клетку, и второй экземпляр упал бы на
// регистрации.
func (r *Registry) InviteMailIntentRecorder() *InviteMailIntentRecorder {
	r.inviteMailIntentOnce.Do(func() { r.inviteMailIntent = r.NewInviteMailIntentRecorder() })
	return r.inviteMailIntent
}
