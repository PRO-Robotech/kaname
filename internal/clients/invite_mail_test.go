// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

// invite_mail_test.go — пробы НАШЕГО отправителя письма приглашения.
//
// Предмет — две РАЗНЫЕ величины (приёмка ID-MAIL-1, §4.1 замечание В1):
// собственный предел времени на ПОПЫТКУ и ограниченное число ПОВТОРОВ. Первая
// утверждается MAIL-32, вторая — MAIL-53, и утверждаются они порознь: «повтор
// ограничен» ограничивает ЧИСЛО попыток, каждая из которых вправе висеть вечно,
// — а это `architecture.md` §«Per-call deadline на КАЖДОМ внешнем вызове» в
// чистом виде.
//
// Классификация отказа — закрытый набор клеток (Р25): сдано · временный отказ ·
// отказ по НАСТРОЙКЕ. Настройка отделена от сбоя собственной клеткой, потому что
// недоступность лечится временем, а неверный адрес не лечится никогда
// (`security.md` §Hardening п. 8).

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
)

// recordingObserver — счётчик исходов, закрытый набор клеток.
type recordingObserver struct {
	mu       sync.Mutex
	outcomes map[string]int
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{outcomes: map[string]int{}}
}

func (o *recordingObserver) IncInviteMailOutcome(outcome string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.outcomes[outcome]++
}

func (o *recordingObserver) count(outcome string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.outcomes[outcome]
}

// silentListener — узел, который ПРИНИМАЕТ соединение и не отвечает ничего.
// Это вторая форма недоступности из MAIL-32 и единственная, на которой предел
// времени попытки вообще наблюдаем: на отказе в соединении обрыв даёт ядро, а не
// наша величина.
func silentListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			// Держим соединение открытым и молчим: клиент обязан оборваться
			// СВОИМ пределом, а не дождаться ответа.
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	return ln.Addr().String()
}

// scriptedListener — узел, отвечающий заданными строками SMTP. Нужен, чтобы
// отличить «не тот протокол» (настройка) от «не отвечает» (сбой).
func scriptedListener(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(greeting))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// Test_InviteMailSender_SilentRelayIsBoundedByItsOwnAttemptDeadline — MAIL-32,
// несущая половина: молчащее соединение обрывается СВОИМ пределом попытки.
//
// Проба измеряет ВРЕМЯ, а не текст: утверждение «предел есть» доказывается
// только тем, что попытка закончилась раньше, чем истекло бы терпение
// вызывающего. Без предела этот вызов не вернётся никогда.
func Test_InviteMailSender_SilentRelayIsBoundedByItsOwnAttemptDeadline(t *testing.T) {
	t.Parallel()
	addr := silentListener(t)

	const attempt = 300 * time.Millisecond
	sender := clients.NewInviteMailSender(clients.MailRelay{
		Addr:           addr,
		From:           "kacho@example.invalid",
		AttemptTimeout: attempt,
		TLSMode:        clients.MailTLSDisabledForTest,
	})

	// Родительский срок НАМЕРЕННО много больше предела попытки: если оборвёт он,
	// проба зелена на чужой величине, а не на нашей.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	start := time.Now()
	err := sender.Send(ctx, clients.InviteMailEvent{To: "invitee@example.invalid"})
	elapsed := time.Since(start)

	require.Error(t, err, "молчащий узел обязан дать отказ, а не успех")
	assert.Less(t, elapsed, 10*time.Second,
		"попытка обязана оборваться СВОИМ пределом (%s), а не висеть до срока вызывающего; "+
			"прошло %s", attempt, elapsed)
	assert.GreaterOrEqual(t, elapsed, attempt/2,
		"обрыв раньше половины объявленного предела означает, что оборвала не наша величина")
	assert.Equal(t, clients.InviteMailOutcomeTransient, clients.ClassifyInviteMailOutcome(err),
		"молчащий узел — ВРЕМЕННЫЙ отказ: он лечится временем")
}

// Test_InviteMailSender_PositiveControl_ResponsiveRelayIsNotBoundedAway —
// обратная сторона предыдущей пробы (MAIL-32, «положительный контроль к обеим
// величинам»). Без неё проба выше зелена на отправителе, который отказывает
// ВСЕГДА и укладывается в предел by construction.
func Test_InviteMailSender_PositiveControl_ResponsiveRelayIsNotBoundedAway(t *testing.T) {
	t.Parallel()
	addr, delivered := acceptingRelay(t)

	sender := clients.NewInviteMailSender(clients.MailRelay{
		Addr:           addr,
		From:           "kacho@example.invalid",
		AttemptTimeout: 5 * time.Second,
		TLSMode:        clients.MailTLSDisabledForTest,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	require.NoError(t, sender.Send(ctx, clients.InviteMailEvent{
		To:        "invitee@example.invalid",
		AccountID: "acc-1",
		LoginURL:  "https://console.example.invalid/login",
	}), "отвечающий узел обязан уложиться в предел с первой попытки")

	assert.Equal(t, 1, delivered(), "письмо обязано доехать до узла ровно один раз")
}

// Test_ClassifyInviteMailOutcome_SettingsIsItsOwnCell — MAIL-33.
//
// «По объявленному адресу отвечает НЕ почтовый узел» — это НАСТРОЙКА, и она
// обязана быть отличима от сбоя И по тексту, И по клетке счётчика: недоступность
// проходит со временем, неверный адрес — никогда. Смешать их в одном ряду значит
// сделать постоянную неверную настройку штатным режимом.
func Test_ClassifyInviteMailOutcome_SettingsIsItsOwnCell(t *testing.T) {
	t.Parallel()

	t.Run("не тот протокол по объявленному адресу", func(t *testing.T) {
		t.Parallel()
		addr := scriptedListener(t, "HTTP/1.1 404 Not Found\r\n\r\n")
		sender := clients.NewInviteMailSender(clients.MailRelay{
			Addr:           addr,
			From:           "kacho@example.invalid",
			AttemptTimeout: 3 * time.Second,
			TLSMode:        clients.MailTLSDisabledForTest,
		})
		err := sender.Send(context.Background(), clients.InviteMailEvent{To: "a@example.invalid"})
		require.Error(t, err)
		assert.Equal(t, clients.InviteMailOutcomeMisconfigured, clients.ClassifyInviteMailOutcome(err),
			"ответ не по протоколу почты — НАСТРОЙКА: повтор её не вылечит")
	})

	t.Run("узел не объявлен вовсе", func(t *testing.T) {
		t.Parallel()
		sender := clients.NewInviteMailSender(clients.MailRelay{
			From:           "kacho@example.invalid",
			AttemptTimeout: time.Second,
			TLSMode:        clients.MailTLSDisabledForTest,
		})
		err := sender.Send(context.Background(), clients.InviteMailEvent{To: "a@example.invalid"})
		require.Error(t, err)
		assert.Equal(t, clients.InviteMailOutcomeMisconfigured, clients.ClassifyInviteMailOutcome(err),
			"незаданный узел — НАСТРОЙКА, а не сбой")
	})

	t.Run("вырожденное значение узла считается незаданным", func(t *testing.T) {
		t.Parallel()
		// Р4: пустая строка, пробел и схема без узла — НЕЗАДАННЫЕ значения, а не
		// «непустые». Страж и потребитель обязаны применять ОДИН предикат.
		for _, degenerate := range []string{" ", "\t", ":", ":25", "  :  "} {
			sender := clients.NewInviteMailSender(clients.MailRelay{
				Addr:           degenerate,
				From:           "kacho@example.invalid",
				AttemptTimeout: time.Second,
				TLSMode:        clients.MailTLSDisabledForTest,
			})
			err := sender.Send(context.Background(), clients.InviteMailEvent{To: "a@example.invalid"})
			require.Error(t, err, "вырожденный узел %q обязан дать отказ", degenerate)
			assert.Equal(t, clients.InviteMailOutcomeMisconfigured,
				clients.ClassifyInviteMailOutcome(err),
				"вырожденный узел %q — НАСТРОЙКА", degenerate)
		}
	})

	t.Run("отправитель не объявлен", func(t *testing.T) {
		t.Parallel()
		sender := clients.NewInviteMailSender(clients.MailRelay{
			Addr:           "127.0.0.1:2525",
			AttemptTimeout: time.Second,
			TLSMode:        clients.MailTLSDisabledForTest,
		})
		err := sender.Send(context.Background(), clients.InviteMailEvent{To: "a@example.invalid"})
		require.Error(t, err)
		assert.Equal(t, clients.InviteMailOutcomeMisconfigured, clients.ClassifyInviteMailOutcome(err),
			"незаданный адрес отправителя — НАСТРОЙКА (Р3: встроенного умолчания у него нет)")
	})

	t.Run("положительный контроль: отказ в соединении — ВРЕМЕННЫЙ", func(t *testing.T) {
		t.Parallel()
		// Порт, на котором заведомо никто не слушает. Без этой половины
		// «настройка» зеленела бы на любом отказе, и клетки перестали бы
		// различаться.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		closed := ln.Addr().String()
		require.NoError(t, ln.Close())

		sender := clients.NewInviteMailSender(clients.MailRelay{
			Addr:           closed,
			From:           "kacho@example.invalid",
			AttemptTimeout: 2 * time.Second,
			TLSMode:        clients.MailTLSDisabledForTest,
		})
		serr := sender.Send(context.Background(), clients.InviteMailEvent{To: "a@example.invalid"})
		require.Error(t, serr)
		assert.Equal(t, clients.InviteMailOutcomeTransient, clients.ClassifyInviteMailOutcome(serr),
			"узел не поднят — ВРЕМЕННЫЙ отказ: он лечится временем")
	})
}

// Test_InviteMailApplier_CountsSuccessAlongsideRefusals — MAIL-32, половина,
// без которой «виден счётчиком» ничего не означает.
//
// Успешная отправка счётчик отказов НЕ увеличивает, а счётчик сданных —
// увеличивает. Проба, знающая только отказы, зелена на счётчике, который считает
// всё подряд.
func Test_InviteMailApplier_CountsSuccessAlongsideRefusals(t *testing.T) {
	t.Parallel()
	obs := newRecordingObserver()
	apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.InviteMailEvent) error {
		return nil
	}), obs, nil)

	require.NoError(t, apply(context.Background(), clients.EventInviteMailSend,
		clients.InviteMailEvent{To: "a@example.invalid"}))

	assert.Equal(t, 1, obs.count(clients.InviteMailOutcomeSent),
		"сданное письмо обязано считаться НАРАВНЕ с отказами — иначе ноль отказов "+
			"неотличим от «сюда никто не приходил»")
	assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeTransient))
	assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeMisconfigured))
}

// Test_InviteMailApplier_ClassifiesRefusalIntoItsOwnCell — вторая половина той
// же пары: каждый вид отказа попадает в СВОЮ клетку и ни один не остаётся тихим.
func Test_InviteMailApplier_ClassifiesRefusalIntoItsOwnCell(t *testing.T) {
	t.Parallel()

	t.Run("временный", func(t *testing.T) {
		t.Parallel()
		obs := newRecordingObserver()
		apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.InviteMailEvent) error {
			return fmt.Errorf("dial relay: %w", context.DeadlineExceeded)
		}), obs, nil)

		err := apply(context.Background(), clients.EventInviteMailSend,
			clients.InviteMailEvent{To: "a@example.invalid"})
		require.Error(t, err)
		assert.False(t, errors.Is(err, drainer.ErrPermanent),
			"временный отказ обязан ретраиться, а не отравлять строку")
		assert.Equal(t, 1, obs.count(clients.InviteMailOutcomeTransient))
		assert.Equal(t, 0, obs.count(clients.InviteMailOutcomeSent))
	})

	t.Run("по настройке — отравляет, а не повторяется бесконечно", func(t *testing.T) {
		t.Parallel()
		obs := newRecordingObserver()
		apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.InviteMailEvent) error {
			return clients.ErrMailMisconfigured
		}), obs, nil)

		err := apply(context.Background(), clients.EventInviteMailSend,
			clients.InviteMailEvent{To: "a@example.invalid"})
		require.Error(t, err)
		assert.True(t, errors.Is(err, drainer.ErrPermanent),
			"MAIL-33: отказ по настройке — БЕЗ бесконечных повторов")
		assert.Equal(t, 1, obs.count(clients.InviteMailOutcomeMisconfigured))
	})

	t.Run("неизвестный вид события — постоянный отказ, корзины «прочее» нет", func(t *testing.T) {
		t.Parallel()
		obs := newRecordingObserver()
		apply := clients.NewInviteMailApplier(sendFunc(func(context.Context, clients.InviteMailEvent) error {
			t.Fatal("применитель не вправе звать отправку по неизвестному виду события")
			return nil
		}), obs, nil)

		err := apply(context.Background(), "mail.invite.something_else",
			clients.InviteMailEvent{To: "a@example.invalid"})
		require.Error(t, err)
		assert.True(t, errors.Is(err, drainer.ErrPermanent))
	})
}

// Test_DecodeInviteMail_RowWithoutASubjectIsPermanentlyRefused — строка, не
// назвавшая адресата, нерастолковываема и повтором не станет таковой.
func Test_DecodeInviteMail_RowWithoutASubjectIsPermanentlyRefused(t *testing.T) {
	t.Parallel()

	_, err := clients.DecodeInviteMail([]byte(`{"account_id":"acc-1"}`))
	require.Error(t, err)
	assert.True(t, errors.Is(err, drainer.ErrPermanent),
		"без адресата письмо отправить некому — это ПОСТОЯННЫЙ отказ")

	ev, err := clients.DecodeInviteMail([]byte(`{"to":"a@example.invalid","account_id":"acc-1"}`))
	require.NoError(t, err, "положительный контроль: назвавшая адресата строка растолковывается")
	assert.Equal(t, "a@example.invalid", ev.To)
}

// Test_InviteMailOutcomes_IsAClosedSet — набор клеток ЗАКРЫТ и приходит из
// констант, а не из ответа узла: иначе кардинальность растёт с трафиком (Р25).
func Test_InviteMailOutcomes_IsAClosedSet(t *testing.T) {
	t.Parallel()
	assert.Equal(t,
		[]string{
			clients.InviteMailOutcomeSent,
			clients.InviteMailOutcomeTransient,
			clients.InviteMailOutcomeMisconfigured,
		},
		clients.InviteMailOutcomes,
		"клетки перечислены константами; расширение набора — правка кода, а не следствие трафика")
}

// Test_InviteMailBody_SaysSentNeverDelivered — Р15/MAIL-44 со стороны
// ПРОИЗВОДИТЕЛЯ: письмо и его состояние говорят об ОТПРАВКЕ, и слова
// «доставлено» продукт не произносит нигде — он этого не знает.
//
// Здесь утверждается наша половина: тело письма и словарь состояний, которые iam
// отдаёт наружу. Половина консоли — предмет своей полосы.
func Test_InviteMailBody_SaysSentNeverDelivered(t *testing.T) {
	t.Parallel()
	body := clients.RenderInviteMail(clients.MailRelay{From: "kacho@example.invalid"},
		clients.InviteMailEvent{
			To:       "invitee@example.invalid",
			LoginURL: "https://console.example.invalid/login",
		})
	lowered := strings.ToLower(string(body))
	for _, forbidden := range []string{"доставлен", "delivered"} {
		assert.NotContains(t, lowered, forbidden,
			"продукт видит СДАЧУ ретранслятору, а не получение адресатом — "+
				"утверждать доставку значит обещать то, чего он не знает")
	}
	assert.Contains(t, string(body), "https://console.example.invalid/login",
		"положительный контроль: письмо несёт адрес страницы входа — "+
			"иначе отрицание зеленело бы на пустом теле")
}

// sendFunc — подставной транспорт. Он НЕ снисходительнее настоящего: возвращает
// ровно то, что ему велено, и ни одной ветки не глотает.
type sendFunc func(context.Context, clients.InviteMailEvent) error

func (f sendFunc) Send(ctx context.Context, ev clients.InviteMailEvent) error { return f(ctx, ev) }

// acceptingRelay — минимальный узел, доводящий разговор до принятого письма.
// Возвращает адрес и читателя числа принятых писем.
func acceptingRelay(t *testing.T) (string, func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	accepted := 0

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if serveSMTP(c) {
					mu.Lock()
					accepted++
					mu.Unlock()
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() int {
		mu.Lock()
		defer mu.Unlock()
		return accepted
	}
}

// serveSMTP отыгрывает минимальный разговор SMTP и говорит, дошло ли письмо до
// точки, в которой узел его принял.
func serveSMTP(c net.Conn) bool {
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	write := func(s string) { _, _ = c.Write([]byte(s)) }
	write("220 relay.example.invalid ESMTP\r\n")
	inData := false
	for {
		n, err := c.Read(buf)
		if err != nil {
			return false
		}
		chunk := string(buf[:n])
		if inData {
			if strings.Contains(chunk, "\r\n.\r\n") {
				write("250 2.0.0 Ok: queued\r\n")
				return true
			}
			continue
		}
		switch {
		case strings.HasPrefix(chunk, "EHLO"), strings.HasPrefix(chunk, "HELO"):
			write("250-relay.example.invalid\r\n250 SIZE 10240000\r\n")
		case strings.HasPrefix(chunk, "MAIL FROM"), strings.HasPrefix(chunk, "RCPT TO"):
			write("250 2.1.0 Ok\r\n")
		case strings.HasPrefix(chunk, "DATA"):
			inData = true
			write("354 End data with <CR><LF>.<CR><LF>\r\n")
		case strings.HasPrefix(chunk, "QUIT"):
			write("221 2.0.0 Bye\r\n")
			return false
		default:
			write("250 2.0.0 Ok\r\n")
		}
	}
}
