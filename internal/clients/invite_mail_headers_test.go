// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

// invite_mail_headers_test.go — штамп отправки письма: `Date` и `Message-ID`
// (kaname#630).
//
// RFC 5322 требует `Date` у каждого письма, а `Message-ID` — то, по чему
// получатель и промежуточные узлы отличают одно письмо от другого. Письмо без
// них строгий получатель вправе отвергнуть или отправить в спам — а письмо
// подтверждения адреса, восстановления и приглашения не дошедшим быть не
// вправе.
//
// Пробы читают СОБРАННОЕ письмо: то, что ушло узлу в DATA, и то, что отдаёт
// RenderMail, — разбором `net/mail`, а не поиском подстроки. Каждое отрицание
// стоит в паре с законным близнецом.

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// letterKinds — все три вида письма. Перечень сверяется с ветвями применителя
// гейтом `TestEveryMailKindHasExactlyOneSender`; здесь он нужен, чтобы штамп
// проверялся у КАЖДОГО вида, а не у того, что попался первым.
var letterKinds = []string{
	clients.EventInviteMailSend, clients.EventRecoveryMailSend, clients.EventVerificationMailSend,
}

// parseLetter разбирает письмо как RFC 5322 сообщение. Письмо, которое не
// разбирается, — отказ пробы, а не «заголовка нет».
func parseLetter(t *testing.T, raw []byte) *mail.Message {
	t.Helper()
	require.NotEmpty(t, raw, "письмо собрано — иначе проверять нечего")
	msg, err := mail.ReadMessage(strings.NewReader(string(raw)))
	require.NoError(t, err, "собранное письмо разбирается как сообщение RFC 5322")
	return msg
}

// messageIDParts разбирает `Message-ID` по форме msg-id (RFC 5322 §3.6.4):
// `<левая@правая>`, ровно один `@`, обе части непусты.
func messageIDParts(t *testing.T, raw string) (left, right string) {
	t.Helper()
	require.NotEmpty(t, raw, "Message-ID стоит в письме")
	require.True(t, strings.HasPrefix(raw, "<") && strings.HasSuffix(raw, ">"),
		"Message-ID в угловых скобках: %q", raw)
	inner := raw[1 : len(raw)-1]
	require.Equal(t, 1, strings.Count(inner, "@"), "в Message-ID ровно один @: %q", raw)
	at := strings.Index(inner, "@")
	left, right = inner[:at], inner[at+1:]
	require.NotEmpty(t, left, "левая часть Message-ID непуста: %q", raw)
	require.NotEmpty(t, right, "правая часть Message-ID непуста: %q", raw)
	require.False(t, strings.ContainsAny(inner, " \t\r\n<>"), "Message-ID без пробелов и скобок внутри: %q", raw)
	return left, right
}

// sampleEvent — событие вида kind со всеми полями, которые не вправе попасть в
// заголовки штампа: адрес получателя, строка человека, аккаунт, код.
func sampleEvent(kind string) clients.MailEvent {
	return clients.MailEvent{
		Kind: kind, To: "person.private@recipient.example.invalid",
		UserID: "usr-0f3c9a7e", AccountID: "acc-71d2b4e8",
		Code: "ABCDE-FGH12", CodeValidMinutes: 30,
		LoginURL: "https://console.example.invalid/login",
	}
}

// TestEveryLetterKindCarriesADateParsedByRFC5322 — у каждого вида письма стоит
// `Date`, и он разбирается по RFC 5322 (`net/mail.ParseDate`). Момент — от
// часов отправителя: при часах по умолчанию он лежит между моментами до и
// после сборки.
func TestEveryLetterKindCarriesADateParsedByRFC5322(t *testing.T) {
	t.Parallel()
	relay := clients.MailRelay{From: "noreply@sender.example.invalid", FromName: "Облако"}
	for _, kind := range letterKinds {
		before := time.Now().Truncate(time.Second)
		msg := parseLetter(t, clients.RenderMail(relay, sampleEvent(kind)))
		after := time.Now()

		raw := msg.Header.Get("Date")
		require.NotEmptyf(t, raw, "%s: письмо несёт Date (RFC 5322 §3.6.1)", kind)
		at, err := mail.ParseDate(raw)
		require.NoErrorf(t, err, "%s: Date разбирается по RFC 5322: %q", kind, raw)
		require.Falsef(t, at.Before(before) || at.After(after),
			"%s: Date — момент сборки (%s), а не постороннее значение: %s", kind, before, at)
	}
	t.Logf("осмотрено видов письма %d", len(letterKinds))
}

// TestTwoLettersInARowCarryDistinctMessageIDsInTheSenderDomain — два письма
// подряд, одного вида и одному адресату, несут РАЗНЫЕ `Message-ID`, и правая
// часть каждого — домен адреса отправителя. Близнец по форме: одинаковое
// событие, иначе различие объяснялось бы разницей входа.
func TestTwoLettersInARowCarryDistinctMessageIDsInTheSenderDomain(t *testing.T) {
	t.Parallel()
	relay := clients.MailRelay{From: "Облако <noreply@sender.example.invalid>"}
	for _, kind := range letterKinds {
		ev := sampleEvent(kind)
		first := parseLetter(t, clients.RenderMail(relay, ev)).Header.Get("Message-ID")
		second := parseLetter(t, clients.RenderMail(relay, ev)).Header.Get("Message-ID")

		_, firstDomain := messageIDParts(t, first)
		_, secondDomain := messageIDParts(t, second)
		require.Equalf(t, "sender.example.invalid", firstDomain, "%s: Message-ID в домене отправителя", kind)
		require.Equalf(t, "sender.example.invalid", secondDomain, "%s: Message-ID в домене отправителя", kind)
		require.NotEqualf(t, first, second, "%s: два письма подряд — два разных Message-ID", kind)
	}
}

// TestLetterStampCarriesNoRecipientUserAccountOrCode — заголовки штампа видят
// адресат и каждый промежуточный узел, поэтому в `Message-ID` и `Date` нет ни
// адреса получателя, ни строки человека, ни аккаунта, ни кода. Положительный
// контроль: те же значения в событии ЕСТЬ, и код письмо несёт — в теле.
func TestLetterStampCarriesNoRecipientUserAccountOrCode(t *testing.T) {
	t.Parallel()
	relay := clients.MailRelay{From: "noreply@sender.example.invalid"}
	for _, kind := range letterKinds {
		ev := sampleEvent(kind)
		raw := clients.RenderMail(relay, ev)
		msg := parseLetter(t, raw)
		stamp := msg.Header.Get("Message-ID") + " " + msg.Header.Get("Date")
		require.NotEmptyf(t, msg.Header.Get("Message-ID"), "%s: положительный контроль — Message-ID стоит", kind)
		for _, private := range []string{ev.To, "person.private", "recipient.example.invalid", ev.UserID, ev.AccountID, ev.Code, "ABCDEFGH12"} {
			require.NotContainsf(t, stamp, private, "%s: штамп письма не несёт %q", kind, private)
		}
	}
	body := string(clients.RenderMail(relay, sampleEvent(clients.EventRecoveryMailSend)))
	require.Contains(t, body, "ABCDE-FGH12", "близнец: код письмо несёт — в теле, а не в штампе")
}

// capturedLetters — узел, принимающий письма и отдающий их содержимое.
type capturedLetters struct {
	mu      sync.Mutex
	letters [][]byte
	data    int
}

func (c *capturedLetters) snapshot() (letters [][]byte, dataCommands int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.letters...), c.data
}

// capturingRelay — минимальный узел SMTP: доводит разговор до принятого письма
// и запоминает, ЧТО ему сдали в DATA, и сколько раз до DATA дошло.
func capturingRelay(t *testing.T) (string, *capturedLetters) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	got := &capturedLetters{}
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go serveCapturing(conn, got)
		}
	}()
	return ln.Addr().String(), got
}

func serveCapturing(c net.Conn, got *capturedLetters) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	write := func(s string) { _, _ = io.WriteString(c, s) }
	write("220 relay.example.invalid ESMTP\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			write("250-relay.example.invalid\r\n250 SIZE 10240000\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
			write("250 2.1.0 Ok\r\n")
		case cmd == "DATA":
			got.mu.Lock()
			got.data++
			got.mu.Unlock()
			write("354 End data with <CR><LF>.<CR><LF>\r\n")
			var letter strings.Builder
			for {
				dl, derr := r.ReadString('\n')
				if derr != nil {
					return
				}
				if dl == ".\r\n" {
					break
				}
				letter.WriteString(strings.TrimPrefix(dl, "."))
			}
			got.mu.Lock()
			got.letters = append(got.letters, []byte(letter.String()))
			got.mu.Unlock()
			write("250 2.0.0 Ok: queued\r\n")
		case cmd == "QUIT":
			write("221 2.0.0 Bye\r\n")
			return
		default:
			write("250 Ok\r\n")
		}
	}
}

func sendThrough(t *testing.T, sender *clients.InviteMailSender, ev clients.MailEvent) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return sender.Send(ctx, ev)
}

// TestSenderWithoutDomainIsRefusedBeforeDATA — адрес отправителя без домена
// не даёт домена `Message-ID`, и письмо без штампа не уходит: отказ ПО
// НАСТРОЙКЕ до DATA, клетка `misconfigured`. Молчаливого `@localhost` нет.
// Текст отказа называет шаг и не печатает адресата.
//
// Законный близнец меняет РОВНО ОДИН факт — домен у адреса отправителя: письмо
// сдано, и узел получил его со штампом.
func TestSenderWithoutDomainIsRefusedBeforeDATA(t *testing.T) {
	t.Parallel()
	for _, from := range []string{"noreply", "noreply@", "Облако <noreply>"} {
		addr, got := capturingRelay(t)
		ev := sampleEvent(clients.EventInviteMailSend)
		err := sendThrough(t, clients.NewInviteMailSender(clients.MailRelay{
			Addr: addr, From: from, AttemptTimeout: 5 * time.Second, TLSMode: clients.MailTLSDisabledForTest,
		}), ev)
		require.Errorf(t, err, "from=%q: письмо без домена отправителя не уходит", from)
		require.Truef(t, errors.Is(err, clients.ErrMailMisconfigured), "from=%q: отказ по настройке, а не сбой: %v", from, err)
		require.Equal(t, clients.InviteMailOutcomeMisconfigured, clients.ClassifyInviteMailOutcome(err))
		require.Contains(t, err.Error(), "sender address has no domain", "текст отказа называет шаг")
		require.NotContains(t, err.Error(), ev.To, "текст отказа не печатает адресата")
		_, dataCommands := got.snapshot()
		require.Zerof(t, dataCommands, "from=%q: до DATA разговор не дошёл", from)
	}

	addr, got := capturingRelay(t)
	err := sendThrough(t, clients.NewInviteMailSender(clients.MailRelay{
		Addr: addr, From: "noreply@sender.example.invalid", AttemptTimeout: 5 * time.Second,
		TLSMode: clients.MailTLSDisabledForTest,
	}), sampleEvent(clients.EventInviteMailSend))
	require.NoError(t, err, "близнец: адрес отправителя с доменом — письмо сдано")
	letters, _ := got.snapshot()
	require.Len(t, letters, 1, "близнец: узел принял ровно одно письмо")
	msg := parseLetter(t, letters[0])
	_, domain := messageIDParts(t, msg.Header.Get("Message-ID"))
	require.Equal(t, "sender.example.invalid", domain, "сданное письмо несёт Message-ID в домене отправителя")
	_, derr := mail.ParseDate(msg.Header.Get("Date"))
	require.NoError(t, derr, "сданное письмо несёт разбираемый Date")
}

// TestSentLetterDateComesFromTheSendersClock — `Date` сданного письма ставят
// ЧАСЫ ОТПРАВИТЕЛЯ, а не стена процесса в обход них: при управляемых часах
// узел получает ровно их момент. Два письма подряд через тот же отправитель —
// два разных Message-ID на проводе.
func TestSentLetterDateComesFromTheSendersClock(t *testing.T) {
	t.Parallel()
	fixed := time.Date(2031, time.March, 4, 5, 6, 7, 0, time.UTC)
	addr, got := capturingRelay(t)
	sender := clients.NewInviteMailSender(clients.MailRelay{
		Addr: addr, From: "noreply@sender.example.invalid", AttemptTimeout: 5 * time.Second,
		TLSMode: clients.MailTLSDisabledForTest,
	}).WithClock(func() time.Time { return fixed })

	for i, kind := range letterKinds {
		require.NoErrorf(t, sendThrough(t, sender, sampleEvent(kind)), "письмо %d (%s) сдано", i, kind)
	}
	letters, _ := got.snapshot()
	require.Len(t, letters, len(letterKinds), "узел принял по письму каждого вида")
	seen := map[string]bool{}
	for i, raw := range letters {
		msg := parseLetter(t, raw)
		at, err := mail.ParseDate(msg.Header.Get("Date"))
		require.NoError(t, err)
		require.Truef(t, at.Equal(fixed), "письмо %d: Date от часов отправителя (%s), получено %s", i, fixed, at)
		id := msg.Header.Get("Message-ID")
		messageIDParts(t, id)
		require.Falsef(t, seen[id], "письмо %d: Message-ID не повторяет предыдущего: %s", i, id)
		seen[id] = true
	}
	t.Logf("сдано писем %d, различных Message-ID %d", len(letters), len(seen))
}
