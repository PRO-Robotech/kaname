// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

// recovery_mail_test.go — ВТОРОЙ вид письма в той же полосе (фаза Ф5, задача
// PRO-Robotech/kacho#1271; приёмка `docs/engineering/acceptance/recovery-of-access.md`,
// Р3, сценарии Ф5-09 (сторона применителя), Ф5-12, Ф5-13).
//
// Утверждается ОБЩНОСТЬ: письмо восстановления сдаёт тот же транспорт, исход
// ложится в те же клетки, отказ по настройке отравляет строку так же. Второй
// отправитель одного вида — находка гейта `TestEveryMailKindHasExactlyOneSender`,
// а не этой пробы: здесь судится поведение применителя, там — дерево.

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

// Test_MailApplier_RecoveryKindIsSentByTheSameTransportIntoTheSameCells —
// Ф5-09 (сторона применителя), Р3: вид `mail.recovery.send` принимается тем же
// применителем, транспорт получает событие с этим видом, клетка «сдано» растёт
// наравне с приглашением.
func Test_MailApplier_RecoveryKindIsSentByTheSameTransportIntoTheSameCells(t *testing.T) {
	t.Parallel()
	obs := newRecordingObserver()
	var got clients.MailEvent
	calls := 0
	apply := clients.NewInviteMailApplier(sendFunc(func(_ context.Context, ev clients.MailEvent) error {
		calls++
		got = ev
		return nil
	}), obs, nil)

	require.NoError(t, apply(context.Background(), clients.EventRecoveryMailSend,
		clients.MailEvent{To: "who@example.invalid", UserID: "usr-1", Code: "ABCDE-FGHJK"}))

	require.Equal(t, 1, calls, "письмо восстановления сдаёт ТОТ ЖЕ транспорт")
	assert.Equal(t, clients.EventRecoveryMailSend, got.Kind, "вид события доезжает до транспорта: по нему выбирается тело письма")
	assert.Equal(t, "ABCDE-FGHJK", got.Code)
	assert.Equal(t, 1, obs.count(clients.InviteMailOutcomeSent), "клетка «сдано» общая для обоих видов")
	assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeTransient))
	assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeMisconfigured))
}

// Test_MailApplier_RecoveryRowWithoutACodeIsPermanentlyRefused — строка вида
// восстановления без кода нерастолковываема: письмо без предъявителя не
// восстанавливает ничего, и повтор этого не изменит. Транспорт не зовётся.
func Test_MailApplier_RecoveryRowWithoutACodeIsPermanentlyRefused(t *testing.T) {
	t.Parallel()
	obs := newRecordingObserver()
	apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.MailEvent) error {
		t.Fatal("применитель не вправе сдавать письмо восстановления без кода")
		return nil
	}), obs, nil)

	err := apply(context.Background(), clients.EventRecoveryMailSend,
		clients.MailEvent{To: "who@example.invalid", UserID: "usr-1"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, drainer.ErrPermanent), "строка без кода — постоянный отказ, не вечный повтор")
	assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeSent))

	// Положительный близнец — приглашение кода не несёт и не обязано.
	sent := 0
	applyOK := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.MailEvent) error {
		sent++
		return nil
	}), obs, nil)
	require.NoError(t, applyOK(context.Background(), clients.EventInviteMailSend,
		clients.MailEvent{To: "who@example.invalid", UserID: "usr-1"}))
	assert.Equal(t, 1, sent)
}

// Test_MailApplier_RecoveryKindSettingsRefusalIsItsOwnCell — Ф5-13 со стороны
// применителя: отказ по настройке на письме восстановления ложится в клетку
// настройки и отравляет строку; временный — в клетку «лечится временем» и
// ретраится. Тот же закрытый набор, что у приглашения (Ф5-12, Р3).
func Test_MailApplier_RecoveryKindSettingsRefusalIsItsOwnCell(t *testing.T) {
	t.Parallel()

	t.Run("по настройке — своя клетка, постоянный отказ", func(t *testing.T) {
		t.Parallel()
		obs := newRecordingObserver()
		apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.MailEvent) error {
			return clients.ErrMailMisconfigured
		}), obs, nil)
		err := apply(context.Background(), clients.EventRecoveryMailSend,
			clients.MailEvent{To: "who@example.invalid", UserID: "usr-1", Code: "ABCDE-FGHJK"})
		require.Error(t, err)
		assert.True(t, errors.Is(err, drainer.ErrPermanent))
		assert.Equal(t, 1, obs.count(clients.InviteMailOutcomeMisconfigured))
		assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeTransient))
	})

	t.Run("временный — лечится временем, ретраится", func(t *testing.T) {
		t.Parallel()
		obs := newRecordingObserver()
		apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.MailEvent) error {
			return errors.Join(clients.ErrMailTransient, context.DeadlineExceeded)
		}), obs, nil)
		err := apply(context.Background(), clients.EventRecoveryMailSend,
			clients.MailEvent{To: "who@example.invalid", UserID: "usr-1", Code: "ABCDE-FGHJK"})
		require.Error(t, err)
		assert.False(t, errors.Is(err, drainer.ErrPermanent))
		assert.Equal(t, 1, obs.count(clients.InviteMailOutcomeTransient))
	})
}

// Test_RenderRecoveryMail_CarriesTheCodeAndNamesNoDelivery — тело письма
// восстановления: несёт код и срок, говорит об ОТПРАВКЕ и не произносит
// «доставлено» (Р15 ID-MAIL-1 — тот же довод, что у приглашения), и код в нём
// НЕ является частью адреса: полоса кодовая, магической ссылки нет (Ф5 §1.2).
func Test_RenderRecoveryMail_CarriesTheCodeAndNamesNoDelivery(t *testing.T) {
	t.Parallel()
	body := string(clients.RenderRecoveryMail(clients.MailRelay{
		From: "kacho@example.invalid", FromName: "Облако", LoginURL: "https://console.example.invalid/login",
	}, clients.MailEvent{To: "who@example.invalid", Code: "ABCDE-FGHJK", CodeValidMinutes: 5}))

	assert.Contains(t, body, "ABCDE-FGHJK", "письмо несёт код — иначе предъявлять нечего")
	assert.Contains(t, body, "5", "письмо называет срок кода (Ф1-25: «с объявленным сроком»)")
	lowered := strings.ToLower(body)
	for _, forbidden := range []string{"доставлен", "delivered"} {
		assert.NotContains(t, lowered, forbidden)
	}
	assert.NotContains(t, body, "ABCDE-FGHJK\n", "заголовки не несут код: он только в теле")
	for _, line := range strings.Split(body, "\r\n") {
		if strings.Contains(line, "ABCDE-FGHJK") {
			assert.NotContains(t, line, "http", "код не вплетён в адрес: ссылки-предъявителя письмо не несёт")
		}
	}
	assert.Contains(t, body, "Облако", "имя отправителя — из настройки, как у приглашения")
}
