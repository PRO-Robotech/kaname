// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// InviteActivationRecorder — исходы активации приглашения на первом входе.
//
// # Зачем считать УСПЕХИ, а не только отказы
//
// Счётчик одних отказов не отличает «отказов не было» от «активаций не было
// вовсе»: и там и там ноль. Путь, умерший целиком, выглядел бы здоровее всех
// (security.md §Hardening-инварианты п.8 — «ноль за всю жизнь» обязано быть
// заметно). Поэтому исходов три, и знаменатель считается наравне с числителем.
//
// # Почему гонка — отдельный исход, а не отказ
//
// Строку, которую уже активировал конкурент, активировать нечем: это ожидаемый
// исход гонки первого входа. Смешав её с отказами, мы получили бы счётчик,
// который всегда не ноль, — то есть тревогу, которую перестают читать.
//
// Набор меток ЗАКРЫТ: outcome приходит из констант use-case'а
// (activated|already_active|failed), никогда из запроса, поэтому кардинальность
// не растёт с трафиком.
type InviteActivationRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewInviteActivationRecorder регистрирует коллектор в этом реестре.
// Звать один раз на старте.
func (r *Registry) NewInviteActivationRecorder() *InviteActivationRecorder {
	rec := &InviteActivationRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kacho_iam_invite_activations_total",
			Help: "Исходы активации приглашения на первом входе человека: activated — " +
				"приглашение активировано; already_active — строку уже активировал " +
				"конкурент (ожидаемая гонка первого входа, не отказ); failed — активация " +
				"не удалась и вход прерван. Ноль failed значим только вместе с ненулевой " +
				"суммой остальных: без них ноль означает, что активаций не было вовсе.",
		}, []string{"outcome"}),
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// IncInviteActivation — исход одной попытки активации. Реализует порт
// user.ActivationObserver.
func (rec *InviteActivationRecorder) IncInviteActivation(outcome string) {
	rec.outcomes.WithLabelValues(outcome).Inc()
}

// InviteActivationRecorder возвращает ЕДИНСТВЕННЫЙ экземпляр счётчика этого
// реестра, создавая его при первом обращении.
//
// Потребителей два и собираются они в разных местах: gRPC-путь
// (InternalUserService, buildServices) и ЖИВОЙ путь первого входа
// (провизион-хук, buildHooksMux). Второй из них и есть тот, ради которого
// счётчик заводится, — пропустить его значило бы получить метрику, всегда
// равную нулю на настоящем трафике.
func (r *Registry) InviteActivationRecorder() *InviteActivationRecorder {
	r.inviteActivationOnce.Do(func() { r.inviteActivation = r.NewInviteActivationRecorder() })
	return r.inviteActivation
}
