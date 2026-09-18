// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// step_up_refusal_record_test.go — ЗАПАСНАЯ ВЕТВЬ записи отказа в церемонии
// повышения (задача PRO-Robotech/kaname#283; приёмка
// `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`
// ред. 5, Ф11-14, Ф11-13, Ф11-30; Р7).
//
// Суждённый отказ пишет след попытки и запись журнала `refused` одной
// транзакцией. Не сложилась она на записи журнала — след попытки обязан лечь
// своей транзакцией: счёт неверных предъявлений есть контроль частоты, и сбой
// журнала его не выключает. Сбой подставляется дублёром (`failOn = "audit"`):
// его писатель копит операции до фиксации и отбрасывает их при откате, как
// настоящий, поэтому след из несложившейся транзакции не доживает до счёта.
//
// Близнец — тот же отказ без подставного сбоя: тот же рост счёта и ровно одна
// запись `refused`. По способу — пароль и код по времени: у них разные
// отказные выходы, и запасная ветвь у обоих одна.
//
// Способность падать: снять из `recordRefusal` запасную запись следа
// (`recordFailureTx`) → красное «счёт по адресу: +1» при подставном сбое;
// близнец остаётся зелёным.
package humansession_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

func TestStepUp_F11_14_JournalFailureStillCountsTheAttempt(t *testing.T) {
	const (
		email    = "k2@example.invalid"
		password = "correct horse battery"
		source   = "203.0.113.7"
	)
	for _, method := range []assurance.Method{assurance.MethodPassword, assurance.MethodTOTP} {
		for _, journalFails := range []bool{true, false} {
			name := method.String() + "/журнал записан"
			if journalFails {
				name = method.String() + "/запись журнала отказала"
			}
			t.Run(name, func(t *testing.T) {
				h := newSFHarness(t)
				_, secret, _ := h.enrolled(t, "usr-k2", email, password)
				login := h.mustLogin(t, email, password)
				require.Equal(t, "1", login.View.Session.AssuranceLevel, "Дано: сессия уровня «1»")

				in := humansession.StepUpInput{Bearer: login.Bearer, Method: method, Source: source}
				switch method {
				case assurance.MethodPassword:
					in.Password = "not the password of this person"
				default:
					in.Code = wrongWindowCode(t, secret, h.step())
				}
				byAddress := h.failures(humansession.FailureByAddress, email)
				bySource := h.failures(humansession.FailureBySource, source)

				if journalFails {
					h.store.failOn = "audit"
				}
				_, err := h.stepUp.Execute(context.Background(), in)
				h.store.failOn = ""

				require.ErrorIs(t, err, humansession.ErrAuthenticationFailed, "отказ наружу тот же при любом исходе записи")
				require.Equal(t, byAddress+1, h.failures(humansession.FailureByAddress, email), "счёт по адресу: +1")
				require.Equal(t, bySource+1, h.failures(humansession.FailureBySource, source), "счёт по источнику: +1")
				want := 1
				if journalFails {
					want = 0
				}
				require.Equal(t, want, refusedRecords(h, login.View.Session.ID),
					"записей журнала `refused` об этой сессии")
			})
		}
	}
}

// refusedRecords — записи журнала повышения с исходом `refused` о сессии.
func refusedRecords(h *sfHarness, session domain.HumanSessionID) int {
	n := 0
	for _, ev := range h.store.audit {
		if ev.EventType == humansession.AuditSessionStepUp &&
			ev.Payload["session_id"] == string(session) && ev.Payload["outcome"] == "refused" {
			n++
		}
	}
	return n
}

// wrongWindowCode — код формы `totp`, не совпадающий ни с одной ступенью окна
// вокруг step с запасом: отказ детерминирован, а не вероятен.
func wrongWindowCode(t *testing.T, secret totpverify.Secret, step int64) string {
	t.Helper()
	near := map[string]bool{}
	for d := int64(-3); d <= 3; d++ {
		near[probeTOTP(t, secret, step+d)] = true
	}
	for d := int64(9); d < 64; d++ {
		if c := probeTOTP(t, secret, step+d); !near[c] {
			return c
		}
	}
	t.Fatal("не найден код, отличный от кодов окна")
	return ""
}
