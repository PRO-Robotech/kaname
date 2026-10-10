// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// mail_recorder.go — серии почты личности kaname на ленте notify (приёмка
// NTF-2: NTF2-52, Р6; замысел issue-2917 З2, З3, З11).
//
//   - kaname_notifications_enabled — флаг почты kaname: 1 — включён, 0 —
//     выключен. Выставляется из того же разобранного значения mail.Enabled,
//     что идёт в mail.Enqueuer и в сборку сервера ленты (З2). Серия заводится и
//     при 0: «выключено» отличимо от «серии нет».
//   - kaname_mail_intents_total{verb,outcome} — исходы работ окна адресата.
//     Набор меток закрыт словарём производителя (mail.Verbs × mail.IntentOutcomes)
//     и засевается нулём при регистрации.
//
// Серию флага источника ленты corelib (с меткой module) этот приёмник НЕ
// заводит: её регистрирует feed.NewSource (put_source.go), и вторая регистрация
// того же семейства у kaname была бы вторым производителем одной величины.

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail"
)

const (
	// NotificationsEnabledMetric — флаг почты kaname (NTF2-52).
	NotificationsEnabledMetric = Namespace + "_notifications_enabled"
	// MailIntentsMetric — исходы работ окна адресата (Р6).
	MailIntentsMetric = Namespace + "_mail_intents_total"
)

type mailIntentCell struct {
	verb    mail.Verb
	outcome mail.IntentOutcome
}

// MailRecorder — приёмник серий почты личности.
type MailRecorder struct {
	enabled bool
	gauge   prometheus.Gauge
	intents map[mailIntentCell]prometheus.Counter
}

// MailRecorder — единственный приёмник реестра, построенный из флага e.
// Нулевой mail.Enabled — отказ, серия не заводится. Повтор с тем же флагом
// отдаёт тот же приёмник, с другим — отказ: флаг процесса один (З2).
func (r *Registry) MailRecorder(e mail.Enabled) (*MailRecorder, error) {
	if !e.Set() {
		return nil, errors.New("metrics: флаг почты не разобран — " + mail.EnabledKey + " не прочитан корнем")
	}
	r.mailMu.Lock()
	defer r.mailMu.Unlock()
	if r.mail != nil {
		if r.mail.enabled != e.On() {
			return nil, fmt.Errorf("metrics: приёмник почты уже построен с %s=%v, повтор с %v — у процесса одно значение флага",
				mail.EnabledKey, r.mail.enabled, e.On())
		}
		return r.mail, nil
	}
	r.mail = r.newMailRecorder(e.On())
	return r.mail, nil
}

// newMailRecorder регистрирует обе серии, ставит флаг и засевает клетки
// исходов нулём.
func (r *Registry) newMailRecorder(on bool) *MailRecorder {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: NotificationsEnabledMetric,
		Help: "Флаг почты kaname (notifications.enabled): 1 — включён, 0 — выключен. При 0 письма не " +
			"ставятся, глаголы, ставящие письмо, отказывают, сервер ленты не поднят.",
	})
	intents := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: MailIntentsMetric,
		Help: "Исходы работ окна адресата по глаголу (recovery, register, verify-email): queued, " +
			"resent_same, cooldown, capped, floor, trusted_device, dropped_overload. Ответ сверх предела " +
			"тот же, что в норме; исход виден только здесь.",
	}, []string{"verb", "outcome"})
	r.reg.MustRegister(gauge, intents)
	if on {
		gauge.Set(1)
	} else {
		gauge.Set(0)
	}
	cells := make(map[mailIntentCell]prometheus.Counter, len(mail.Verbs())*len(mail.IntentOutcomes()))
	for _, v := range mail.Verbs() {
		for _, o := range mail.IntentOutcomes() {
			c := intents.WithLabelValues(string(v), string(o))
			c.Add(0)
			cells[mailIntentCell{verb: v, outcome: o}] = c
		}
	}
	return &MailRecorder{enabled: on, gauge: gauge, intents: cells}
}

// MailIntentObserved — исход одной работы окна. Значение вне закрытого набора
// производителя — дефект программы (метка, построенная преобразованием строки
// мимо констант пакета mail): паника, а не новая клетка на проводе.
func (m *MailRecorder) MailIntentObserved(v mail.Verb, o mail.IntentOutcome) {
	c, ok := m.intents[mailIntentCell{verb: v, outcome: o}]
	if !ok {
		panic(fmt.Sprintf("metrics: исход работы окна вне закрытого набора: verb=%q outcome=%q", v, o))
	}
	c.Inc()
}
