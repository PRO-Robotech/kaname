// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

// invite_mail_relay_form_test.go — транспорт не разбирает адрес узла второй
// раз.
//
// Адрес формы URI (`smtp://…`, `smtps://…`) разбирает ОДИН раз страж старта
// (`config.InviteMailConfig.RelayCoordinate`), и до транспорта доезжает
// `узел:порт`. Прежде транспорт срезал схему сам и молча: `smtps://` уходил в
// STARTTLS, часть до «@» — в имя узла, завершающий `/` — в порт. Второй разбор с
// другим смыслом — ровно то «два места об одном предмете», которое расходится
// молча, поэтому адрес, доехавший неразобранным, здесь есть отказ ПО НАСТРОЙКЕ,
// и транспорт даже не набирает его.

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// countingListener — узел, считающий принятые соединения. Проба утверждает, что
// неразобранный адрес НЕ набирается: ноль соединений.
func countingListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return ln.Addr().String(), &accepted
}

func Test_InviteMailSender_UnparsedURIAddressIsASettingNotADial(t *testing.T) {
	t.Parallel()
	addr, accepted := countingListener(t)

	for _, raw := range []string{"smtp://" + addr + "/", "smtps://" + addr} {
		sender := clients.NewInviteMailSender(clients.MailRelay{
			Addr:           raw,
			From:           "kacho@example.invalid",
			AttemptTimeout: 2 * time.Second,
			TLSMode:        clients.MailTLSDisabledForTest,
		})
		err := sender.Send(context.Background(), clients.MailEvent{To: "invitee@example.invalid"})
		require.Error(t, err, "адрес %q доехал до транспорта неразобранным — это отказ", raw)
		assert.True(t, errors.Is(err, clients.ErrMailMisconfigured),
			"неразобранный адрес — НАСТРОЙКА, а не временный сбой: повтор его не вылечит (%q: %v)", raw, err)
	}
	assert.Equal(t, int32(0), accepted.Load(),
		"транспорт не вправе набирать адрес, который не разбирал страж старта")

	// Положительный контроль: тот же узел ГОЛЫМ адресом набирается. Без него
	// «ноль соединений» зеленело бы на транспорте, не набирающем ничего.
	sender := clients.NewInviteMailSender(clients.MailRelay{
		Addr: addr, From: "kacho@example.invalid", AttemptTimeout: 2 * time.Second,
		TLSMode: clients.MailTLSDisabledForTest,
	})
	_ = sender.Send(context.Background(), clients.MailEvent{To: "invitee@example.invalid"})
	assert.Eventually(t, func() bool { return accepted.Load() >= 1 }, 2*time.Second, 10*time.Millisecond,
		"голый адрес узла обязан набираться")
}
