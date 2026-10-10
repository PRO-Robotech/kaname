// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// mail_recorder_test.go — серии почты личности kaname (приёмка NTF-2, NTF2-52,
// Р6; замысел issue-2917 З2, З3, З11):
//
//   - kaname_notifications_enabled = 0 при флаге false, близнец 1 при true —
//     на свежем реестре, читается с провода (Gather);
//   - kacho_notifications_enabled (серия источника corelib) этим приёмником НЕ
//     заводится: второй регистрации серии фундамента у kaname нет;
//   - kaname_mail_intents_total{verb,outcome}: клетка исхода растёт ровно на
//     событие.

import (
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail"
)

func mailEnabled(t *testing.T, on bool) mail.Enabled {
	t.Helper()
	e, err := mail.EnabledFrom(&on)
	if err != nil {
		t.Fatalf("фикстура: EnabledFrom(%v): %v", on, err)
	}
	return e
}

// gathered — семейства реестра по имени, с провода.
func gathered(t *testing.T, r *Registry) map[string]*dto.MetricFamily {
	t.Helper()
	mfs, err := r.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

// TestNotificationsEnabledGaugeFollowsTheFlag — NTF2-52 (метрика): флаг false
// → 0; близнец true → 1. Серия corelib kacho_notifications_enabled этим
// приёмником не заводится.
func TestNotificationsEnabledGaugeFollowsTheFlag(t *testing.T) {
	for _, c := range []struct {
		on   bool
		want float64
	}{{false, 0}, {true, 1}} {
		r := NewRegistry()
		if _, err := r.MailRecorder(mailEnabled(t, c.on)); err != nil {
			t.Fatalf("флаг %v: %v", c.on, err)
		}
		mfs := gathered(t, r)
		mf, ok := mfs[NotificationsEnabledMetric]
		if !ok {
			t.Fatalf("флаг %v: серии %s на проводе нет", c.on, NotificationsEnabledMetric)
		}
		if got := mf.GetMetric()[0].GetGauge().GetValue(); got != c.want {
			t.Fatalf("флаг %v: %s = %v, ожидалось %v", c.on, NotificationsEnabledMetric, got, c.want)
		}
		if _, dup := mfs["kacho_notifications_enabled"]; dup {
			t.Fatalf("флаг %v: приёмник kaname завёл серию источника corelib kacho_notifications_enabled — она регистрируется feed.NewSource, второй регистрации нет", c.on)
		}
	}
}

// TestMailRecorderRefusesUnparsedFlag — нулевой mail.Enabled («не разобрано»)
// серии не заводит: false из незаданного неотличим от выключенного.
func TestMailRecorderRefusesUnparsedFlag(t *testing.T) {
	r := NewRegistry()
	if _, err := r.MailRecorder(mail.Enabled{}); err == nil {
		t.Fatalf("MailRecorder(Enabled{}) принят")
	}
	if _, ok := gathered(t, r)[NotificationsEnabledMetric]; ok {
		t.Fatalf("при отказе серия %s заведена", NotificationsEnabledMetric)
	}
}

// TestMailRecorderIsOnePerRegistry — приёмник один на реестр; повтор с тем же
// флагом отдаёт его же, повтор с другим — отказ (флаг процесса один, З2).
func TestMailRecorderIsOnePerRegistry(t *testing.T) {
	r := NewRegistry()
	a, err := r.MailRecorder(mailEnabled(t, true))
	if err != nil {
		t.Fatalf("первый вызов: %v", err)
	}
	b, err := r.MailRecorder(mailEnabled(t, true))
	if err != nil || a != b {
		t.Fatalf("повтор с тем же флагом: %v, тот же приёмник %v", err, a == b)
	}
	if _, err := r.MailRecorder(mailEnabled(t, false)); err == nil {
		t.Fatalf("повтор с другим флагом принят — у процесса два значения флага")
	}
}

// TestMailIntentCellGrowsByOne — клетка {verb, outcome} растёт ровно на
// событие, соседние не трогаются.
func TestMailIntentCellGrowsByOne(t *testing.T) {
	r := NewRegistry()
	rec, err := r.MailRecorder(mailEnabled(t, true))
	if err != nil {
		t.Fatalf("%v", err)
	}
	rec.MailIntentObserved(mail.VerbRecovery, mail.IntentCapped)
	var total, hit float64
	for _, m := range gathered(t, r)[MailIntentsMetric].GetMetric() {
		v := m.GetCounter().GetValue()
		total += v
		labels := map[string]string{}
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		if labels["verb"] == "recovery" && labels["outcome"] == "capped" {
			hit = v
		}
	}
	if hit != 1 || total != 1 {
		t.Fatalf("клетка recovery/capped = %v, сумма по семейству %v — ожидалось 1 и 1", hit, total)
	}
}
