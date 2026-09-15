// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_sending_paths_injection_test.go — доказательство падучести MAIL-47 в
// обе стороны, на синтетических мирах.
//
// Каждый мир отличается от КОНТРОЛЯ (законного мира той же формы, что дерево
// службы) РОВНО ОДНИМ фактом: добавлен один файл, снят один файл либо в одном
// файле заменена одна форма. Тогда красное обязано прийти от этого факта, а не
// от соседа (`change-graph.md` §6).
//
// Настоящее дерево и синтетика проходят ОДНИ функции — ScanMailSending и
// JudgeMailSending, — поэтому доказанное здесь верно для гейта на дереве.
package check_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// mailWorldModule — путь модуля синтетического мира.
const mailWorldModule = "example.com/kaname"

// mailWorldSender — отправитель приглашения той же формы, что в дереве:
// транспорт открывает разговор `NewClient`, объявление называет вид своими
// именами (получатель, тип события). Рядом — функция, которая строит
// удостоверение (`PlainAuth`) и разговора НЕ открывает: путём отправки она не
// является, и это законный близнец внутри контроля.
const mailWorldSender = `package clients

import (
	"context"
	"net"
	"net/smtp"
)

// EventInviteMailSend — вид события очереди.
const EventInviteMailSend = "mail.invite.send"

type InviteMailEvent struct{ To string }

type InviteMailSender struct{ addr string }

// Send — разговор с почтовым узлом; в комментарии упомянут smtp.SendMail, и
// упоминание путём не является.
func (s *InviteMailSender) Send(ctx context.Context, ev InviteMailEvent) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, "relay")
	if err != nil {
		return err
	}
	if err := c.Auth(authFor("u", "p")); err != nil {
		return err
	}
	return c.Quit()
}

func authFor(user, pass string) smtp.Auth { return smtp.PlainAuth("", user, pass, "relay") }
`

// mailWorldQueueWriter — писатель очереди: объявляет тот же вид вторым
// литералом. Второе объявление ОДНОГО вида видом не прибавляет.
const mailWorldQueueWriter = `package invite_mail_outbox

// EventSend — единственный вид события очереди.
const EventSend = "mail.invite.send"
`

// mailWorldNeighbours — законные соседи, каждый своей формы: разбор адреса
// `net/mail` (транспортом не является), пакет СВОЕГО модуля с «mail» в пути
// импорта, строка, называющая транспорт словами, ТИП пакета транспорта
// (разговора не открывает) и локальная переменная, ЗАТЕНЯЮЩАЯ имя пакета
// транспорта, чей метод называется как открывающий.
const mailWorldNeighbours = `package user

import (
	"net/mail"
	"net/smtp"

	outbox "example.com/kaname/internal/repo/kaname/pg/invite_mail_outbox"
)

const doc = "smtp.SendMail(addr, nil, from, to, body) здесь не зовётся"

// Тип пакета транспорта разговора не открывает.
var _ smtp.Auth

type fakeTransport struct{}

func (fakeTransport) NewClient() {}

func validAddress(s string) bool {
	_, err := mail.ParseAddress(s)
	_ = outbox.EventSend
	smtp := fakeTransport{}
	smtp.NewClient()
	return err == nil
}
`

// mailControl — законный мир той же формы, что дерево службы.
func mailControl() map[string]string {
	return map[string]string{
		"internal/clients/invite_mail.go":                      mailWorldSender,
		"internal/repo/kaname/pg/invite_mail_outbox/outbox.go": mailWorldQueueWriter,
		"internal/apps/kaname/api/user/validate.go":            mailWorldNeighbours,
	}
}

func mailWorldWith(extra map[string]string, drop ...string) map[string]string {
	w := mailControl()
	for _, d := range drop {
		delete(w, d)
	}
	for k, v := range extra {
		w[k] = v
	}
	return w
}

// judgeMailWorld разбирает мир теми же функциями, что гейт на дереве.
func judgeMailWorld(t *testing.T, world map[string]string) check.MailSendingVerdict {
	t.Helper()
	names := make([]string, 0, len(world))
	for n := range world {
		names = append(names, n)
	}
	sort.Strings(names)
	var facts []check.MailSendingFacts
	for _, n := range names {
		f, err := check.ScanMailSending(n, []byte(world[n]), mailWorldModule)
		if err != nil {
			t.Fatalf("синтетика %s не разобралась: %v — мир сломан, вердикта нет", n, err)
		}
		facts = append(facts, f)
	}
	return check.JudgeMailSending(facts)
}

func requireFinding(t *testing.T, v check.MailSendingVerdict, want ...string) {
	t.Helper()
	for _, f := range v.Findings {
		ok := true
		for _, w := range want {
			if !strings.Contains(f, w) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
	}
	t.Fatalf("ИНЪЕКЦИЯ: находки, называющей %q, нет; находки: %q", want, v.Findings)
}

// TestMAIL47Injection_ControlIsSilentAndCountsOnePath — положительный контроль:
// законный мир молчит, и перепись называет РОВНО то, что утверждает MAIL-47 —
// «1 · приглашение». Без контроля красное инъекций не отличить от гейта,
// краснеющего на всём.
func TestMAIL47Injection_ControlIsSilentAndCountsOnePath(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailControl())
	if len(v.Findings) != 0 {
		t.Fatalf("законный мир дал находки — гейт краснеет на исправном: %q", v.Findings)
	}
	if v.Paths != 1 {
		t.Fatalf("путей отправки в законном мире %d, ожидался 1 — разбор не видит "+
			"путь либо видит лишний", v.Paths)
	}
	if len(v.Kinds) != 1 || v.Kinds[0] != check.MailKindInvite {
		t.Fatalf("видов письма в законном мире %v, ожидалось [%s]", v.Kinds, check.MailKindInvite)
	}
}

// TestMAIL47Injection_SecondInvitePathIsNamedWithCoordinates — второй путь
// отправки приглашения: находка с координатами ОБОИХ путей.
func TestMAIL47Injection_SecondInvitePathIsNamedWithCoordinates(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(map[string]string{
		"internal/handler/invite_notify.go": `package handler

import "net/smtp"

type InviteNotifier struct{}

func (n *InviteNotifier) notifyInvited(to string) error {
	return smtp.SendMail("relay:587", nil, "noreply@example.org", []string{to}, nil)
}
`,
	}))
	requireFinding(t, v, string(check.MailKindInvite),
		"internal/handler/invite_notify.go:", "internal/clients/invite_mail.go:")
}

// TestMAIL47Injection_OurPathSendingConfirmationIsNamedByKind — наш путь,
// отправляющий подтверждение адреса: находка с ИМЕНЕМ вида.
func TestMAIL47Injection_OurPathSendingConfirmationIsNamedByKind(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(map[string]string{
		"internal/clients/verification_mail.go": `package clients

import "net/smtp"

type VerificationMailer struct{ addr string }

func (m *VerificationMailer) Send(to string) error {
	c, err := smtp.Dial(m.addr)
	if err != nil {
		return err
	}
	return c.Quit()
}
`,
	}))
	requireFinding(t, v, string(check.MailKindVerification), "internal/clients/verification_mail.go:")
}

// TestMAIL47Injection_QueueDeclaringRecoveryIsNamedByKind — словарь очереди
// отправки объявляет вид восстановления: наш код кладёт в отправку письмо
// чужого вида, даже если транспорт у него общий.
func TestMAIL47Injection_QueueDeclaringRecoveryIsNamedByKind(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(map[string]string{
		"internal/repo/kaname/pg/invite_mail_outbox/recovery.go": `package invite_mail_outbox

// EventRecoverySend — второй вид события той же очереди.
const EventRecoverySend = "mail.recovery.send"
`,
	}))
	requireFinding(t, v, string(check.MailKindRecovery), "mail.recovery.send")
}

// TestMAIL47Injection_RemovedOnlyPathIsAKindWithoutProducer — снятие
// единственного пути: «вид письма без производителя» (§12 п. 3а). Очередь
// по-прежнему кладёт письмо в отправку — разговора с узлом у дерева нет.
func TestMAIL47Injection_RemovedOnlyPathIsAKindWithoutProducer(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(nil, "internal/clients/invite_mail.go"))
	requireFinding(t, v, string(check.MailKindInvite), "без производителя")
	if v.Paths != 0 {
		t.Fatalf("после снятия единственного пути перепись называет %d путей", v.Paths)
	}
}

// TestMAIL47Injection_PathOfUnrecognisedKindIsRefused — путь, чьё объявление
// не называет ни одного вида: разбор не угадывает, он отказывает.
func TestMAIL47Injection_PathOfUnrecognisedKindIsRefused(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(map[string]string{
		"internal/notify/deliver.go": `package notify

import "net/smtp"

func deliver(to string, body []byte) error {
	return smtp.SendMail("relay:587", nil, "noreply@example.org", []string{to}, body)
}
`,
	}))
	requireFinding(t, v, "internal/notify/deliver.go:", "не распознан")
}

// TestMAIL47Injection_UnknownTransportFormIsRefused — транспорт формы, которой
// разбор не знает (сторонняя библиотека почты): отказ с путём импорта, а не
// тишина. Иначе путь отправки уезжал бы из-под наблюдения, не давая ни
// красного, ни зелёного.
func TestMAIL47Injection_UnknownTransportFormIsRefused(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(map[string]string{
		"internal/notify/gomail.go": `package notify

import gomail "github.com/wneessen/go-mail"

var _ = gomail.NewMsg
`,
	}))
	requireFinding(t, v, "github.com/wneessen/go-mail", "internal/notify/gomail.go:")
}

// TestMAIL47Injection_DotImportOfTransportIsRefused — точечный импорт
// транспорта делает открывающий вызов неотличимым от своей функции того же
// имени: форма объявлена неразбираемой и отвергается явно.
func TestMAIL47Injection_DotImportOfTransportIsRefused(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(map[string]string{
		"internal/notify/dot.go": `package notify

import . "net/smtp"

var _ = SendMail
`,
	}))
	requireFinding(t, v, "net/smtp", "internal/notify/dot.go:")
}

// TestMAIL47Injection_AliasFormIsKnownBothWays — форма псевдонима импорта:
// законный отправитель под псевдонимом молчит, второй путь под тем же
// псевдонимом — находка. Одной стороны мало: молчание на псевдониме было бы
// неотличимо от слепоты к нему.
func TestMAIL47Injection_AliasFormIsKnownBothWays(t *testing.T) {
	t.Parallel()
	aliased := strings.Replace(mailWorldSender, `"net/smtp"`, `mailer "net/smtp"`, 1)
	aliased = strings.ReplaceAll(aliased, "smtp.NewClient", "mailer.NewClient")
	aliased = strings.ReplaceAll(aliased, "smtp.Auth", "mailer.Auth")
	aliased = strings.ReplaceAll(aliased, "smtp.PlainAuth", "mailer.PlainAuth")
	twin := mailWorldWith(map[string]string{"internal/clients/invite_mail.go": aliased})
	if v := judgeMailWorld(t, twin); len(v.Findings) != 0 || v.Paths != 1 {
		t.Fatalf("законный отправитель под псевдонимом: путей %d, находки %q — "+
			"форма псевдонима не узнана", v.Paths, v.Findings)
	}

	defect := mailWorldWith(map[string]string{
		"internal/clients/invite_mail.go": aliased,
		"internal/handler/invite_again.go": `package handler

import post "net/smtp"

type InviteResender struct{}

func (r *InviteResender) resend(to string) error {
	return post.SendMail("relay:587", nil, "noreply@example.org", []string{to}, nil)
}
`,
	})
	requireFinding(t, judgeMailWorld(t, defect), string(check.MailKindInvite), "internal/handler/invite_again.go:")
}

// TestMAIL47Injection_MethodValueIsAPath — открывающая функция, взятая
// значением, а не вызванная на месте, всё равно открывает разговор там, где её
// позовут. Форма узнаётся: второй путь приглашения этой формы — находка.
func TestMAIL47Injection_MethodValueIsAPath(t *testing.T) {
	t.Parallel()
	v := judgeMailWorld(t, mailWorldWith(map[string]string{
		"internal/handler/invite_value.go": `package handler

import "net/smtp"

type InviteDispatcher struct {
	send func(string, smtp.Auth, string, []string, []byte) error
}

func NewInviteDispatcher() *InviteDispatcher {
	return &InviteDispatcher{send: smtp.SendMail}
}
`,
	}))
	requireFinding(t, v, string(check.MailKindInvite), "internal/handler/invite_value.go:")
}
