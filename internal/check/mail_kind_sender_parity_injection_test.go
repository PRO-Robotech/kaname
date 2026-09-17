// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_kind_sender_parity_injection_test.go — доказательство падучести
// TestEveryMailKindHasExactlyOneSender в ОБЕ стороны, по КАЖДОЙ форме записи,
// которую распознаватель объявляет законной (Ф5-10, Ф5-11; `testing.md`
// §«Гейт на класс», пп. 2, 3, 7).
//
// Синтетика подаётся корпусом, а не деревом: гейт получает обход параметром
// (задача #17), поэтому пустой корпус и корпус без применителя доказываются
// исполнением, а не чтением.
package check_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// ── Схема: формы записи словаря ──────────────────────────────────────────────

const mailInjSchemaCreate = `-- +goose Up
CREATE TABLE kaname.invite_mail_outbox (
    id bigint NOT NULL,
    event_type text NOT NULL,
    CONSTRAINT invite_mail_outbox_event_type_check CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text]))),
    CONSTRAINT invite_mail_outbox_partition_key_ck CHECK ((length(resource_id) > 0))
);
CREATE TABLE kaname.audit_outbox (
    id bigint NOT NULL,
    event_type text NOT NULL,
    CONSTRAINT audit_outbox_event_type_check CHECK ((event_type = ANY (ARRAY['iam.user.created'::text, 'iam.user.updated'::text])))
);
-- +goose Down
DROP TABLE kaname.invite_mail_outbox;
`

// mailInjSchemaAlter — вторая миграция: словарь ПЕРЕОБЪЯВЛЕН формой
// ALTER TABLE, и в секции ОТКАТА стоит объявление с прежним перечнем — его
// читать нельзя.
const mailInjSchemaAlter = `-- +goose Up
ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox ADD CONSTRAINT invite_mail_outbox_event_type_check
  CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text, 'mail.recovery.send'::text])));
-- +goose Down
ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
ALTER TABLE kaname.invite_mail_outbox ADD CONSTRAINT invite_mail_outbox_event_type_check
  CHECK ((event_type = ANY (ARRAY['mail.invite.send'::text])));
`

// mailInjSchemaDropOnly — третья миграция: словарь снят и НЕ объявлен заново.
const mailInjSchemaDropOnly = `-- +goose Up
ALTER TABLE kaname.invite_mail_outbox DROP CONSTRAINT invite_mail_outbox_event_type_check;
-- +goose Down
`

// mailInjSchemaProse — законный близнец: те же слова В КОММЕНТАРИИ и в секции
// отката, объявления в накате нет.
const mailInjSchemaProse = `-- +goose Up
-- Перечень видов держит CONSTRAINT x CHECK ((event_type = ANY (ARRAY['mail.ghost.send'::text])))
-- и расширяется только новой миграцией.
SELECT 1;
-- +goose Down
ALTER TABLE kaname.invite_mail_outbox ADD CONSTRAINT ghost_check
  CHECK ((event_type = ANY (ARRAY['mail.ghost.send'::text])));
`

func TestMailKindsOfSchema_CreateTableForm(t *testing.T) {
	t.Parallel()
	kinds, site, read, decls, err := check.MailKindsOfSchema(check.TreeCorpus{
		"internal/migrations/0001_initial.sql": mailInjSchemaCreate,
	})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if read != 1 || decls != 2 {
		t.Fatalf("перепись: миграций %d (ждали 1), объявлений словаря %d (ждали 2 — почтовый и аудитный)", read, decls)
	}
	if strings.Join(kinds, ",") != "mail.invite.send" {
		t.Fatalf("ИНЪЕКЦИЯ: форма CREATE TABLE не прочитана либо прочитан чужой словарь: %v", kinds)
	}
	if site != "internal/migrations/0001_initial.sql" {
		t.Fatalf("координата живого объявления неверна: %q", site)
	}
}

func TestMailKindsOfSchema_AlterTableFormWinsAndDownIsIgnored(t *testing.T) {
	t.Parallel()
	kinds, site, _, _, err := check.MailKindsOfSchema(check.TreeCorpus{
		"internal/migrations/0001_initial.sql":                    mailInjSchemaCreate,
		"internal/migrations/20260917000000_second_mail_kind.sql": mailInjSchemaAlter,
	})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if strings.Join(kinds, ",") != "mail.invite.send,mail.recovery.send" {
		t.Fatalf("ИНЪЕКЦИЯ: переобъявление формой ALTER TABLE не победило либо прочитана секция "+
			"отката (там прежний одноэлементный перечень): %v", kinds)
	}
	if !strings.HasSuffix(site, "second_mail_kind.sql") {
		t.Fatalf("живое объявление обязано быть ПОСЛЕДНИМ (ALTER), названо %q", site)
	}
}

func TestMailKindsOfSchema_DroppedWithoutRedeclareIsARefusal(t *testing.T) {
	t.Parallel()
	_, _, _, _, err := check.MailKindsOfSchema(check.TreeCorpus{
		"internal/migrations/0001_initial.sql":              mailInjSchemaCreate,
		"internal/migrations/20260917000000_drop_vocab.sql": mailInjSchemaDropOnly,
	})
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("словарь снят и не объявлен заново — ждали отказ ErrEmptyTraversal, получили %v", err)
	}
}

func TestMailKindsOfSchema_ProseAndDownSectionStaySilent(t *testing.T) {
	t.Parallel()
	kinds, _, _, decls, err := check.MailKindsOfSchema(check.TreeCorpus{
		"internal/migrations/0001_initial.sql":         mailInjSchemaCreate,
		"internal/migrations/20260917000000_prose.sql": mailInjSchemaProse,
	})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	for _, k := range kinds {
		if k == "mail.ghost.send" {
			t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: вид из комментария либо из секции отката попал в словарь: %v", kinds)
		}
	}
	if decls != 2 {
		t.Fatalf("объявлений словаря осмотрено %d — комментарий либо откат посчитаны объявлением", decls)
	}
}

func TestMailKindsOfSchema_EmptyCorpusIsARefusal(t *testing.T) {
	t.Parallel()
	_, _, _, _, err := check.MailKindsOfSchema(check.TreeCorpus{})
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("пустой корпус миграций — ждали ErrEmptyTraversal, получили %v", err)
	}
	_, _, _, _, err = check.MailKindsOfSchema(check.TreeCorpus{
		"internal/migrations/0001_initial.sql": "-- +goose Up\nCREATE TABLE kaname.users (id text NOT NULL);\n",
	})
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("корпус без словаря видов письма — ждали ErrEmptyTraversal, получили %v", err)
	}
}

// ── Применитель: формы ветвления ─────────────────────────────────────────────

// mailInjApplierIf — сегодняшняя форма дерева: `if eventType != Const`.
const mailInjApplierIf = `package clients

import "context"

const EventInviteMailSend = "mail.invite.send"

type MailEvent struct{ To string }

func NewInviteMailApplier() func(ctx context.Context, eventType string, ev MailEvent) error {
	return func(ctx context.Context, eventType string, ev MailEvent) error {
		if eventType != EventInviteMailSend {
			return nil
		}
		return nil
	}
}
`

// mailInjApplierSwitch — форма `switch` с перечислением и селектором
// `pkg.Const`, а также сравнение в обратном порядке и литералом.
const mailInjApplierSwitch = `package clients

import (
	"context"

	mailq "example.com/kaname/internal/repo/kaname/pg/invite_mail_outbox"
)

const EventRecoveryMailSend = "mail.recovery.send"

func applyMail(ctx context.Context, eventType string, ev []byte) error {
	switch eventType {
	case mailq.EventSend, EventRecoveryMailSend:
		return nil
	case "mail.literal.send":
		return nil
	}
	if "mail.reversed.send" == eventType {
		return nil
	}
	return nil
}
`

// mailInjApplierTwin — законные близнецы: функция НЕ формы применителя,
// сравнивающая строку с почтовым видом (сканер сдачи, не отправитель);
// применитель ДРУГОЙ очереди с не-почтовым видом; и проза о видах письма.
const mailInjApplierTwin = `package clients

import "context"

const EventInviteMailSend = "mail.invite.send"

// Отправитель ветвится так: if eventType == "mail.invite.send" — и это проза.
func isMailKind(kind string) bool {
	return kind == EventInviteMailSend
}

func applyAudit(ctx context.Context, eventType string, ev []byte) error {
	if eventType != "iam.user.created" {
		return nil
	}
	return nil
}

func notAnApplier(ctx context.Context, eventType string) error {
	if eventType == EventInviteMailSend {
		return nil
	}
	return nil
}
`

const mailInjConsts = `package invite_mail_outbox

const EventSend = "mail.invite.send"
`

func TestMailSendersOf_IfForm(t *testing.T) {
	t.Parallel()
	senders, census, err := check.MailSendersOf(check.TreeCorpus{
		"internal/clients/invite_mail.go": mailInjApplierIf,
	})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.Appliers != 1 || census.ComparisonSites != 1 {
		t.Fatalf("перепись: применителей %d (ждали 1), сравнений %d (ждали 1)", census.Appliers, census.ComparisonSites)
	}
	sites := senders["mail.invite.send"]
	if len(sites) != 1 || sites[0].Func != "NewInviteMailApplier/func" {
		t.Fatalf("ИНЪЕКЦИЯ: форма `if eventType != Const` не опознана: %+v", senders)
	}
}

func TestMailSendersOf_SwitchSelectorLiteralAndReversedForms(t *testing.T) {
	t.Parallel()
	senders, census, err := check.MailSendersOf(check.TreeCorpus{
		"internal/clients/recovery_mail.go":                    mailInjApplierSwitch,
		"internal/repo/kaname/pg/invite_mail_outbox/outbox.go": mailInjConsts,
	})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.Appliers != 1 {
		t.Fatalf("применителей %d, ждали 1", census.Appliers)
	}
	for _, want := range []string{"mail.invite.send", "mail.recovery.send", "mail.literal.send", "mail.reversed.send"} {
		if got := senders[want]; len(got) != 1 || got[0].Func != "applyMail" {
			t.Errorf("ИНЪЕКЦИЯ: вид %q формы switch/селектор/литерал/обратный порядок не опознан: %+v", want, senders)
		}
	}
	if census.Unresolved != 0 {
		t.Errorf("неразрешённых сравнений %d — селектор `mailq.EventSend` не разрешён словарём констант", census.Unresolved)
	}
}

func TestMailSendersOf_LawfulTwinsStaySilent(t *testing.T) {
	t.Parallel()
	senders, census, err := check.MailSendersOf(check.TreeCorpus{
		"internal/clients/twins.go": mailInjApplierTwin,
	})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	// applyAudit — единственная функция формы применителя; сканер сдачи и
	// двухпараметрическая функция применителями не являются.
	if census.Appliers != 1 {
		t.Fatalf("применителей %d, ждали 1 (только applyAudit)", census.Appliers)
	}
	if len(senders) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: сканер сдачи, не-применитель либо проза засчитаны отправителем: %+v", senders)
	}
}

func TestMailSendersOf_EmptyAndApplierlessCorporaAreRefusals(t *testing.T) {
	t.Parallel()
	if _, _, err := check.MailSendersOf(check.TreeCorpus{}); !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("пустой прод-корпус — ждали ErrEmptyTraversal, получили %v", err)
	}
	_, _, err := check.MailSendersOf(check.TreeCorpus{
		"internal/clients/x.go": "package clients\n\nconst EventInviteMailSend = \"mail.invite.send\"\n",
	})
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("корпус без единого применителя — ждали ErrEmptyTraversal, получили %v", err)
	}
}

// ── Паритет: три оси находок и молчание близнеца ─────────────────────────────

func TestMailKindInventory_KindWithoutSenderIsAFinding(t *testing.T) {
	t.Parallel()
	inv, err := check.MailKindInventoryOf(
		check.TreeCorpus{
			"internal/migrations/0001_initial.sql":                    mailInjSchemaCreate,
			"internal/migrations/20260917000000_second_mail_kind.sql": mailInjSchemaAlter,
		},
		check.TreeCorpus{"internal/clients/invite_mail.go": mailInjApplierIf},
	)
	if err != nil {
		t.Fatalf("перепись синтетики: %v", err)
	}
	if len(inv.Kinds) != 2 || inv.KindsWithSender() != 1 {
		t.Fatalf("перепись: видов %d (ждали 2), с отправителем %d (ждали 1)", len(inv.Kinds), inv.KindsWithSender())
	}
	fs := inv.Findings()
	if len(fs) != 1 || !strings.Contains(fs[0], `"mail.recovery.send"`) || !strings.Contains(fs[0], "second_mail_kind.sql") {
		t.Fatalf("ИНЪЕКЦИЯ: вид без отправителя не назван по имени и координате объявления: %v", fs)
	}
}

func TestMailKindInventory_SenderWithoutKindIsAFinding(t *testing.T) {
	t.Parallel()
	inv, err := check.MailKindInventoryOf(
		check.TreeCorpus{"internal/migrations/0001_initial.sql": mailInjSchemaCreate},
		check.TreeCorpus{
			"internal/clients/recovery_mail.go":                    mailInjApplierSwitch,
			"internal/repo/kaname/pg/invite_mail_outbox/outbox.go": mailInjConsts,
		},
	)
	if err != nil {
		t.Fatalf("перепись синтетики: %v", err)
	}
	fs := inv.Findings()
	// Три вида приняты применителем и не допущены схемой: recovery, literal,
	// reversed. Каждый назван файлом, строкой и функцией.
	if len(fs) != 3 {
		t.Fatalf("ИНЪЕКЦИЯ: ждали три находки «отправитель без вида», получили %d: %v", len(fs), fs)
	}
	for _, f := range fs {
		if !strings.Contains(f, "internal/clients/recovery_mail.go:") || !strings.Contains(f, "applyMail") {
			t.Errorf("находка не несёт координаты и имени функции: %s", f)
		}
	}
}

func TestMailKindInventory_TwoSendersOfOneKindIsAFinding(t *testing.T) {
	t.Parallel()
	second := strings.Replace(mailInjApplierIf, "NewInviteMailApplier", "NewSecondApplier", 1)
	second = strings.Replace(second, "const EventInviteMailSend = \"mail.invite.send\"\n", "", 1)
	second = strings.Replace(second, "type MailEvent struct{ To string }\n", "", 1)
	inv, err := check.MailKindInventoryOf(
		check.TreeCorpus{"internal/migrations/0001_initial.sql": mailInjSchemaCreate},
		check.TreeCorpus{
			"internal/clients/invite_mail.go": mailInjApplierIf,
			"internal/clients/second.go":      second,
		},
	)
	if err != nil {
		t.Fatalf("перепись синтетики: %v", err)
	}
	fs := inv.Findings()
	if len(fs) != 1 || !strings.Contains(fs[0], "ДВА отправителя") ||
		!strings.Contains(fs[0], "NewInviteMailApplier/func") || !strings.Contains(fs[0], "NewSecondApplier/func") {
		t.Fatalf("ИНЪЕКЦИЯ: два применителя одного вида не названы оба: %v", fs)
	}
}

func TestMailKindInventory_LawfulTwinStaysSilent(t *testing.T) {
	t.Parallel()
	inv, err := check.MailKindInventoryOf(
		check.TreeCorpus{
			"internal/migrations/0001_initial.sql":                    mailInjSchemaCreate,
			"internal/migrations/20260917000000_second_mail_kind.sql": mailInjSchemaAlter,
		},
		check.TreeCorpus{
			"internal/clients/invite_mail.go":                      mailInjApplierIf,
			"internal/clients/recovery_mail.go":                    strings.Replace(strings.Replace(mailInjApplierSwitch, "\tcase \"mail.literal.send\":\n\t\treturn nil\n", "", 1), "\tif \"mail.reversed.send\" == eventType {\n\t\treturn nil\n\t}\n", "", 1),
			"internal/repo/kaname/pg/invite_mail_outbox/outbox.go": mailInjConsts,
		},
	)
	if err != nil {
		t.Fatalf("перепись синтетики: %v", err)
	}
	// Два вида в схеме; invite принят ДВУМЯ применителями — это и есть находка,
	// поэтому близнец строится так, чтобы у каждого вида был ровно один.
	fs := inv.Findings()
	if len(fs) != 1 || !strings.Contains(fs[0], "ДВА отправителя") {
		t.Fatalf("контроль формы близнеца: ждали ровно одну находку о двух отправителях invite, получили %v", fs)
	}
	// Теперь настоящий близнец: второй применитель принимает только recovery.
	onlyRecovery := strings.Replace(mailInjApplierSwitch, "\tcase mailq.EventSend, EventRecoveryMailSend:\n", "\tcase EventRecoveryMailSend:\n", 1)
	onlyRecovery = strings.Replace(onlyRecovery, "\tcase \"mail.literal.send\":\n\t\treturn nil\n", "", 1)
	onlyRecovery = strings.Replace(onlyRecovery, "\tif \"mail.reversed.send\" == eventType {\n\t\treturn nil\n\t}\n", "", 1)
	onlyRecovery = strings.Replace(onlyRecovery, "\n\tmailq \"example.com/kaname/internal/repo/kaname/pg/invite_mail_outbox\"\n", "\n", 1)
	inv, err = check.MailKindInventoryOf(
		check.TreeCorpus{
			"internal/migrations/0001_initial.sql":                    mailInjSchemaCreate,
			"internal/migrations/20260917000000_second_mail_kind.sql": mailInjSchemaAlter,
		},
		check.TreeCorpus{
			"internal/clients/invite_mail.go":   mailInjApplierIf,
			"internal/clients/recovery_mail.go": onlyRecovery,
		},
	)
	if err != nil {
		t.Fatalf("перепись близнеца: %v", err)
	}
	if fs := inv.Findings(); len(fs) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ: два вида, у каждого ровно один отправитель — гейт покраснел: %v", fs)
	}
	if len(inv.Kinds) != 2 || inv.KindsWithSender() != 2 {
		t.Fatalf("перепись близнеца: видов %d, с отправителем %d — ждали 2 · 2", len(inv.Kinds), inv.KindsWithSender())
	}
}
