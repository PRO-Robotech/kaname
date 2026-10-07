// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

// email_change_mail_test.go — два вида письма смены адреса (kaname#635, приёмка
// `email-change-is-confirmed-from-the-new-address.md`, Р7): код смены на новый
// адрес и уведомление на прежний; оба сдаёт тот же транспорт, ни одно не несёт
// ссылки-предъявителя, уведомление не несёт ни нового адреса, ни кода.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/outbox/drainer"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

var ecRelay = clients.MailRelay{
	From: "kacho@example.invalid", FromName: "Облако", LoginURL: "https://console.example.invalid/login?next=x#frag",
}

func Test_RenderEmailChangeMail_CarriesTheCodeAndTheSettingsScreen(t *testing.T) {
	t.Parallel()
	body := string(clients.RenderEmailChangeMail(ecRelay,
		clients.MailEvent{To: "new@example.invalid", Code: "ABCDE-FGHJK", CodeValidMinutes: 30}))

	assert.Contains(t, body, "To: new@example.invalid\r\n", "письмо с кодом — на новый адрес")
	assert.Contains(t, body, "Код подтверждения смены:\r\n\r\n    ABCDE-FGHJK\r\n",
		"код стоит первой непустой строкой после заголовка — так его читает приёмник стенда")
	assert.Contains(t, body, "30 мин.", "письмо называет срок кода")
	assert.Contains(t, body, "https://console.example.invalid/settings\r\n",
		"адрес экрана параметров — происхождение консоли и путь экрана, без параметров и фрагмента")
	for _, line := range strings.Split(body, "\r\n") {
		if strings.Contains(line, "http") {
			assert.NotContains(t, line, "ABCDE-FGHJK", "код не вплетён в адрес: ссылки-предъявителя нет")
			assert.NotContains(t, line, "?", "адрес без параметров")
			assert.NotContains(t, line, "#", "адрес без фрагмента")
		}
	}
}

func Test_RenderEmailChangedMail_NamesTheMomentAndNothingElse(t *testing.T) {
	t.Parallel()
	body := string(clients.RenderEmailChangedMail(ecRelay,
		clients.MailEvent{To: "old@example.invalid", ChangedAt: "2026-10-07T12:00:00Z"}))

	assert.Contains(t, body, "To: old@example.invalid\r\n", "уведомление — на прежний адрес")
	assert.Contains(t, body, "2026-10-07T12:00:00Z", "уведомление называет момент смены")
	assert.Contains(t, body, "Этот адрес больше не используется для входа и восстановления доступа.\r\n"+
		"\r\nЕсли это были не вы — обратитесь к администратору аккаунта.\r\n",
		"строка о действии стоит первой непустой после строки об адресе — так её читает приёмник стенда")
	assert.NotContains(t, body, "http", "ссылки нет")
	assert.NotContains(t, body, "Код", "кода нет")
}

func Test_MailApplier_EmailChangeKindsAreSentByTheSameTransport(t *testing.T) {
	t.Parallel()
	obs := newRecordingObserver()
	var kinds []string
	apply := clients.NewInviteMailApplier(sendFunc(func(_ context.Context, ev clients.MailEvent) error {
		kinds = append(kinds, ev.Kind)
		return nil
	}), obs, nil)

	require.NoError(t, apply(context.Background(), clients.EventEmailChangeMailSend,
		clients.MailEvent{To: "new@example.invalid", UserID: "usr-1", Code: "ABCDE-FGHJK", CodeValidMinutes: 30}))
	require.NoError(t, apply(context.Background(), clients.EventEmailChangedMailSend,
		clients.MailEvent{To: "old@example.invalid", UserID: "usr-1", ChangedAt: "2026-10-07T12:00:00Z"}))
	assert.Equal(t, []string{clients.EventEmailChangeMailSend, clients.EventEmailChangedMailSend}, kinds,
		"оба вида сдаёт ТОТ ЖЕ транспорт, и вид доезжает до него")
	assert.Equal(t, 2, obs.count(clients.InviteMailOutcomeSent))
}

func Test_MailApplier_EmailChangeRowsOfTheWrongShapeArePermanentlyRefused(t *testing.T) {
	t.Parallel()
	obs := newRecordingObserver()
	apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.MailEvent) error {
		t.Fatal("применитель не вправе сдавать письмо неверной формы")
		return nil
	}), obs, nil)

	err := apply(context.Background(), clients.EventEmailChangeMailSend, clients.MailEvent{To: "new@example.invalid", UserID: "usr-1"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, drainer.ErrPermanent), "письмо с кодом смены без кода — постоянный отказ")

	err = apply(context.Background(), clients.EventEmailChangedMailSend,
		clients.MailEvent{To: "old@example.invalid", UserID: "usr-1", Code: "ABCDE-FGHJK"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, drainer.ErrPermanent), "уведомление с кодом — постоянный отказ: кода у него нет по построению")
	assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeSent))
}
