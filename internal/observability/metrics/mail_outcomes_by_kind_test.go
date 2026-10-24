// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_outcomes_by_kind_test.go — неотправленное письмо КАЖДОГО вида видно своим
// рядом (kaname#733).
//
// Полоса писем одна на все виды: приглашение, восстановление доступа,
// подтверждение адреса, код смены адреса и уведомление о смене. Ряд
// `kaname_invite_mail_outcomes_total{outcome}` считает попытки всех видов
// вместе, и неудача письма восстановления в нём неотличима от неудачи
// приглашения. Утверждается:
//
//	В1  у ряда исходов по виду письма клетка каждой пары «вид × исход» есть с
//	    нулём до первого письма — «не отправлялось» отлично от «ряда нет»;
//	В2  неудача отправки письма восстановления растит клетку ЕГО вида и не
//	    растит клеток других видов;
//	В3  прежний ряд без вида не изменился: он по-прежнему считает попытку
//	    (его читают сквозные пробы полосы восстановления).
package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// failingMailTransport — узел, не принявший письмо по временной причине.
type failingMailTransport struct{}

func (failingMailTransport) Send(context.Context, clients.MailEvent) error {
	return errors.New("relay refused the letter for now")
}

func TestMailOutcomesByKind_EveryCellExistsBeforeTheFirstLetter(t *testing.T) {
	r := NewRegistry()
	require.NotNil(t, r.InviteMailRecorder())
	require.NotEmpty(t, clients.MailEventTypes, "перечень видов пуст — судить нечего")
	cells := 0
	for _, kind := range clients.MailEventTypes {
		for _, outcome := range clients.InviteMailOutcomes {
			_, present := labelledCounter(t, r, MailOutcomesMetric,
				map[string]string{"kind": kind, "outcome": outcome})
			require.Truef(t, present, "клетки %s{kind=%q,outcome=%q} нет до первого письма", MailOutcomesMetric, kind, outcome)
			cells++
		}
	}
	t.Logf("ПЕРЕПИСЬ: видов %d · исходов %d · клеток осмотрено %d", len(clients.MailEventTypes), len(clients.InviteMailOutcomes), cells)
}

func TestMailOutcomesByKind_RecoveryFailureCountsIntoItsKind(t *testing.T) {
	r := NewRegistry()
	apply := clients.NewInviteMailApplier(failingMailTransport{}, r.InviteMailRecorder(), nil)
	err := apply(context.Background(), clients.EventRecoveryMailSend, clients.MailEvent{Code: "123456", To: "person@example.test"})
	require.Error(t, err, "неудача отправки обязана вернуться дренажу")

	got, present := labelledCounter(t, r, MailOutcomesMetric,
		map[string]string{"kind": clients.EventRecoveryMailSend, "outcome": clients.InviteMailOutcomeTransient})
	require.True(t, present, "клетки вида восстановления нет")
	require.Equal(t, 1.0, got, "неудача письма восстановления не видна в клетке его вида")
	for _, kind := range clients.MailEventTypes {
		if kind == clients.EventRecoveryMailSend {
			continue
		}
		v, _ := labelledCounter(t, r, MailOutcomesMetric,
			map[string]string{"kind": kind, "outcome": clients.InviteMailOutcomeTransient})
		require.Zerof(t, v, "неудача письма восстановления посчитана видом %q", kind)
	}
	old, _ := labelledCounter(t, r, InviteMailOutcomesMetric,
		map[string]string{"outcome": clients.InviteMailOutcomeTransient})
	require.Equal(t, 1.0, old, "прежний ряд без вида перестал считать попытку")
}
