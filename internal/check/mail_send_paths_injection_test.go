// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_send_paths_injection_test.go — доказательство падучести MAIL-47 в обе
// стороны, на синтетике.
//
// Инъекция меняет РОВНО ОДИН факт против своего законного близнеца, и близнец
// прогоняется рядом в каждом случае: без него красное доказывало бы лишь то,
// что разбор вообще что-то находит.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// mailLawfulSender — ЗАКОННЫЙ БЛИЗНЕЦ оси транспорта: единственный путь,
// отправляющий оба наших вида — приглашение и восстановление (с Ф5). Дословная
// форма сегодняшнего дерева.
const mailLawfulSender = `package clients

import (
	"net/smtp"
)

const EventInviteMailSend = "mail.invite.send"
const EventRecoveryMailSend = "mail.recovery.send"

func send(c *smtp.Client) error { return nil }
`

// mailLawfulInviteOnlySender — путь, отправляющий ТОЛЬКО приглашение: до Ф5 это
// было всё дерево; с Ф5 такой путь оставляет вид восстановления без
// производителя, и это судится отдельной пробой ниже.
const mailLawfulInviteOnlySender = `package clients

import (
	"net/smtp"
)

const EventInviteMailSend = "mail.invite.send"

func send(c *smtp.Client) error { return nil }
`

// mailLawfulQueueStore — ВТОРОЙ законный близнец: файл называет вид письма и
// транспорта НЕ импортирует. Хранилище очереди — не путь отправки, и ось 1
// обязана на нём молчать, иначе она считала бы своё же хранилище отправителем.
const mailLawfulQueueStore = `package invite_mail_outbox

const EventSend = "mail.invite.send"
`

// mailInjectedSecondSender — ось 1, дефект A: ВТОРОЙ путь отправки того же вида.
const mailInjectedSecondSender = `package notify

import "net/smtp"

const eventKind = "mail.invite.send"

func resend(c *smtp.Client) error { return nil }
`

// mailInjectedForeignKind — ось 1, дефект Б: наш путь отправки ЧУЖОГО вида.
// Против близнеца выше меняется ровно один факт — слово вида в литерале.
const mailInjectedForeignKind = `package clients

import (
	"net/smtp"
)

const EventVerificationMailSend = "mail.verification.send"

func send(c *smtp.Client) error { return nil }
`

// mailInjectedKindlessSender — ось 1, дефект В: путь отправки, не назвавший вида.
const mailInjectedKindlessSender = `package clients

import "net/smtp"

func send(c *smtp.Client) error { return nil }
`

// mailWorldModule — путь модуля синтетического мира: пакеты СВОЕГО модуля с
// «почтой» в пути импорта (хранилище очереди) — наш код, а не чужая форма.
const mailWorldModule = "example.com/kaname"

// scanOne — разбор одного синтетического файла.
func scanOneMailFile(t *testing.T, rel, src string) ([]check.MailSendPath, []check.MailKindSite, check.MailSendCensus) {
	t.Helper()
	p, k, c, err := check.ScanMailSendFile(rel, []byte(src), mailWorldModule)
	if err != nil {
		t.Fatalf("разбор синтетики %s: %v", rel, err)
	}
	if c.Imports == 0 && c.Literals == 0 {
		t.Fatalf("%s: осмотрено ноль импортов и ноль литералов — разбирается не то", rel)
	}
	return p, k, c
}

// findingsFor — вердикт по набору синтетических файлов.
func findingsFor(t *testing.T, files map[string]string) []check.MailSendFinding {
	t.Helper()
	var paths []check.MailSendPath
	var kinds []check.MailKindSite
	// Порядок обхода карты не важен: вердикт сортирован.
	for rel, src := range files {
		p, k, _ := scanOneMailFile(t, rel, src)
		paths = append(paths, p...)
		kinds = append(kinds, k...)
	}
	return check.AdjudicateMailSendPaths(paths, kinds)
}

// TestMAIL47Injection_LawfulTreeIsSilent — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него всё остальное доказывало бы лишь то, что разбор что-то находит:
// проверка, краснеющая на исправном дереве, отличима от исправной только здесь.
func TestMAIL47Injection_LawfulTreeIsSilent(t *testing.T) {
	t.Parallel()
	got := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go":                     mailLawfulSender,
		"internal/repo/kaname/pg/invite_mail_outbox/store.go": mailLawfulQueueStore,
	})
	if len(got) != 0 {
		t.Fatalf("законное дерево дало %d находок, ожидалось ноль: %+v", len(got), got)
	}
}

// TestMAIL47Injection_SecondSenderOfTheSameKind — дефект A: второй путь того же
// вида. Находка обязана называть ОБЕ координаты: у дефекта нет «главного» места.
func TestMAIL47Injection_SecondSenderOfTheSameKind(t *testing.T) {
	t.Parallel()
	got := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go": mailLawfulSender,
		"internal/notify/resend.go":       mailInjectedSecondSender,
	})
	var hit *check.MailSendFinding
	for i := range got {
		if strings.Contains(got[i].What, "путей отправки вида `invite` — 2") {
			hit = &got[i]
		}
	}
	if hit == nil {
		t.Fatalf("второй путь отправки приглашения НЕ найден: %+v", got)
	}
	for _, want := range []string{"internal/clients/invite_mail.go", "internal/notify/resend.go"} {
		if !strings.Contains(hit.Where, want) {
			t.Errorf("находка не называет координату %s: %q", want, hit.Where)
		}
	}
}

// TestMAIL47Injection_ForeignKindIsNamed — дефект Б: наш путь отправки чужого
// вида. Находка обязана называть ВИД: по координате одной не отличить, чем
// именно нарушено решение Р23.
func TestMAIL47Injection_ForeignKindIsNamed(t *testing.T) {
	t.Parallel()
	got := findingsFor(t, map[string]string{
		"internal/clients/verification_mail.go": mailInjectedForeignKind,
	})
	var transport, vocabulary bool
	for _, f := range got {
		if !strings.Contains(f.What, "verification") {
			continue
		}
		switch f.Axis {
		case "transport":
			transport = true
			if !strings.Contains(f.Where, "internal/clients/verification_mail.go") {
				t.Errorf("находка оси транспорта без координаты: %q", f.Where)
			}
		case "vocabulary":
			vocabulary = true
		}
	}
	if !transport {
		t.Errorf("ось транспорта не назвала чужой вид письма: %+v", got)
	}
	if !vocabulary {
		t.Errorf("ось словаря не назвала чужой вид письма: %+v", got)
	}
}

// TestMAIL47Injection_VocabularyAxisSeesASenderWithoutTransport — ось 2
// отдельно: чужой вид в словаре очереди — находка ДАЖЕ без транспорта рядом.
// Чужой здесь — подтверждение адреса (за поставщиком до Ф6); законный близнец —
// то же хранилище с видом `invite` (проверен выше) и с видом `recovery`, который
// наш с Ф5 (ниже).
func TestMAIL47Injection_VocabularyAxisSeesASenderWithoutTransport(t *testing.T) {
	t.Parallel()
	got := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go": mailLawfulSender,
		"internal/repo/kaname/pg/verification_mail_outbox/store.go": `package verification_mail_outbox

const EventSend = "mail.verification.send"
`,
	})
	var found bool
	for _, f := range got {
		if f.Axis == "vocabulary" && strings.Contains(f.What, "verification") {
			found = true
			if !strings.Contains(f.Where, "verification_mail_outbox/store.go") {
				t.Errorf("находка словаря без координаты: %q", f.Where)
			}
		}
	}
	if !found {
		t.Fatalf("вид `verification` в словаре очереди НЕ найден: %+v", got)
	}

	// Законный близнец Ф5: вид восстановления в словаре очереди рядом с
	// единственным путём, отправляющим оба наших вида, — молчание.
	twin := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go": mailLawfulSender,
		"internal/repo/kaname/pg/invite_mail_outbox/store.go": `package invite_mail_outbox

const EventSend = "mail.invite.send"
const EventRecoverySend = "mail.recovery.send"
`,
	})
	if len(twin) != 0 {
		t.Fatalf("законный близнец (оба наших вида, один путь) дал находки: %+v", twin)
	}
	// И обратная сторона перечня: путь, отправляющий ТОЛЬКО приглашение, при
	// живом виде восстановления в словаре — «путей отправки вида recovery — ноль».
	half := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go": mailLawfulInviteOnlySender,
	})
	var missing bool
	for _, f := range half {
		if strings.Contains(f.What, "путей отправки вида `recovery` — ноль") {
			missing = true
		}
	}
	if !missing {
		t.Fatalf("вид восстановления без пути НЕ назван находкой: %+v", half)
	}
}

// TestMAIL47Injection_KindlessSenderIsAFinding — дефект В: путь, не назвавший
// вида. Перепись печатает две величины, и вторая из воздуха не берётся.
func TestMAIL47Injection_KindlessSenderIsAFinding(t *testing.T) {
	t.Parallel()
	got := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go": mailInjectedKindlessSender,
	})
	var found bool
	for _, f := range got {
		if strings.Contains(f.What, "не называет вида письма") {
			found = true
		}
	}
	if !found {
		t.Fatalf("путь отправки без вида НЕ найден: %+v", got)
	}
}

// TestMAIL47Injection_RemovingTheOnlySenderIsAFinding — обратная сторона:
// снятие единственного пути даёт находку «вид письма без производителя», а не
// молчание. Без этого гейт зеленел бы ровно там, где продукт обещает письмо и
// не отправляет его ничем (§12 п. 3а приёмки).
func TestMAIL47Injection_RemovingTheOnlySenderIsAFinding(t *testing.T) {
	t.Parallel()
	got := findingsFor(t, map[string]string{
		"internal/repo/kaname/pg/invite_mail_outbox/store.go": mailLawfulQueueStore,
	})
	var found bool
	for _, f := range got {
		if strings.Contains(f.What, "путей отправки вида `invite` — ноль") {
			found = true
			if f.Where != "" {
				t.Errorf("находка об ОТСУТСТВИИ пути назвала координату %q — координаты у неё нет", f.Where)
			}
		}
	}
	if !found {
		t.Fatalf("снятие единственного пути НЕ дало находки: %+v", got)
	}
}

// mailLawfulMailishNeighbour — ТРЕТИЙ законный близнец: файл, чьи импорты
// говорят о почте, но транспортом не являются — разбор адреса `net/mail` и
// хранилище очереди СВОЕГО модуля. Ось формы обязана на нём молчать: иначе она
// звала бы неизвестной формой то, что разбор знает by construction.
const mailLawfulMailishNeighbour = `package user

import (
	"net/mail"

	outbox "example.com/kaname/internal/repo/kaname/pg/invite_mail_outbox"
)

func validAddress(s string) bool {
	_, err := mail.ParseAddress(s)
	_ = outbox.EventSend
	return err == nil
}
`

// mailInjectedUnknownTransportForm — ось 1, дефект Г: транспорт ФОРМЫ, которой
// закрытый список не знает. Против близнеца выше меняется ровно один факт —
// путь импорта: он говорит о почте, а ни транспортом, ни не-транспортом, ни
// своим модулем не объявлен.
const mailInjectedUnknownTransportForm = `package notify

import mail "github.com/xhit/go-simple-mail/v2"

var _ = mail.NewSMTPClient
`

// TestMAIL47Injection_UnknownTransportFormIsRefused — дефект Г: импорт,
// говорящий о почте, которого закрытый список не знает, — ОТКАЗ с координатой
// и путём импорта, а не тишина. Иначе второй отправитель на библиотеке, не
// названной в списке, уезжал бы из-под наблюдения, не давая ни красного, ни
// зелёного: якорная предпосылка (`net/smtp` в дереве есть) на нём молчит, а
// ось словаря молчит, если вид взят константой хранилища, а не литералом.
//
// Рядом — законный близнец: те же «почтовые» слова в путях импорта
// (`net/mail`, хранилище очереди своего модуля), и ось обязана молчать.
func TestMAIL47Injection_UnknownTransportFormIsRefused(t *testing.T) {
	t.Parallel()

	lawful := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go":           mailLawfulSender,
		"internal/apps/kaname/api/user/validate.go": mailLawfulMailishNeighbour,
	})
	if len(lawful) != 0 {
		t.Fatalf("законный сосед с «почтой» в путях импорта дал %d находок, ожидалось ноль: %+v",
			len(lawful), lawful)
	}

	got := findingsFor(t, map[string]string{
		"internal/clients/invite_mail.go":           mailLawfulSender,
		"internal/apps/kaname/api/user/validate.go": mailLawfulMailishNeighbour,
		"internal/notify/simple.go":                 mailInjectedUnknownTransportForm,
	})
	var hit *check.MailSendFinding
	for i := range got {
		if strings.Contains(got[i].What, "github.com/xhit/go-simple-mail/v2") {
			hit = &got[i]
		}
	}
	if hit == nil {
		t.Fatalf("транспорт неизвестной формы НЕ отвергнут — форма вне наблюдения: %+v", got)
	}
	if !strings.Contains(hit.Where, "internal/notify/simple.go:") {
		t.Errorf("отказ формы без координаты: %q", hit.Where)
	}
	if hit.Axis != "transport" {
		t.Errorf("отказ формы пришёл по оси %q, ожидалась transport", hit.Axis)
	}
	if len(got) != 1 {
		t.Errorf("ожидалась РОВНО одна находка (отказ формы), получено %d: %+v", len(got), got)
	}
}

// TestMAIL47Injection_UnknownFormPredicateKnowsItsThreeExemptions — предикат
// отказа знает три исключения: известный транспорт, известный не-транспорт и
// пакет своего модуля. Одной стороны мало: предикат, отвергающий всё с «mail»
// в пути, назвал бы неизвестной формой собственное хранилище очереди.
func TestMAIL47Injection_UnknownFormPredicateKnowsItsThreeExemptions(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"github.com/xhit/go-simple-mail/v2", true},
		{"github.com/mailjet/mailjet-apiv3-go", true},
		{"github.com/jordan-wright/email", true},
		{"net/smtp", false},                                                      // известный транспорт
		{"github.com/wneessen/go-mail", false},                                   // известный транспорт
		{"net/mail", false},                                                      // известный НЕ-транспорт: разбор адреса
		{"example.com/kaname/internal/repo/kaname/pg/invite_mail_outbox", false}, // свой модуль
		{"example.com/kaname", false},                                            // свой модуль, корень
		{"example.com/kanamemail/x", true},                                       // ЧУЖОЙ модуль с похожим префиксом
		{"context", false},                                                       // о почте не говорит
	} {
		if got := check.MailImportFormIsUnknown(tc.path, mailWorldModule); got != tc.want {
			t.Errorf("MailImportFormIsUnknown(%q) = %v, ожидалось %v", tc.path, got, tc.want)
		}
	}
}

// TestMAIL47Injection_TransportPredicateKnowsSegmentsNotSubstrings — предикат
// оси 1 судит СЕГМЕНТЫ пути импорта. Подстрочный предикат объявил бы
// транспортом собственное хранилище очереди (`…/invite_mail_outbox`) и
// всякий внутренний каталог со словом `mail` в имени.
func TestMAIL47Injection_TransportPredicateKnowsSegmentsNotSubstrings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"net/smtp", true},
		{"github.com/emersion/go-smtp", true},
		{"gopkg.in/gomail.v2", true},
		{"github.com/wneessen/go-mail", true},
		{"github.com/aws/aws-sdk-go-v2/service/sesv2", true},
		{"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/invite_mail_outbox", false},
		{"github.com/PRO-Robotech/kaname/internal/clients", false},
		{"net/mail", false}, // разбор адреса — не транспорт
	} {
		if got := check.MailImportIsTransport(tc.path); got != tc.want {
			t.Errorf("MailImportIsTransport(%q) = %v, ожидалось %v", tc.path, got, tc.want)
		}
	}
}

// TestMAIL47Injection_KindLiteralIsAnchoredAtBothEnds — образец вида привязан к
// обоим концам: проза об этом же предмете несёт те же слова посреди
// предложения, и образец без привязки краснел бы на собственном объяснении.
func TestMAIL47Injection_KindLiteralIsAnchoredAtBothEnds(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		lit  string
		kind string
		ok   bool
	}{
		{"mail.invite.send", "invite", true},
		{"mail.verification.send", "verification", true},
		{"вид события очереди — mail.invite.send, и словарь закрыт", "", false},
		{"mail.invite.send.retry", "", false},
		{"kaname.invite_mail_outbox", "", false},
	} {
		kind, ok := check.MailKindOfLiteral(tc.lit)
		if ok != tc.ok || kind != tc.kind {
			t.Errorf("MailKindOfLiteral(%q) = (%q,%v), ожидалось (%q,%v)",
				tc.lit, kind, ok, tc.kind, tc.ok)
		}
	}
}
