// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// email_change_no_address_in_log_test.go — журнал и аудит глаголов смены
// адреса НЕ НЕСУТ адресов: ни прежнего, ни нового (приёмка
// `email-change-is-confirmed-from-the-new-address.md`, Р7; норма
// security-hardening hard-no-pii-in-logs; задача PRO-Robotech/kaname#789).
//
// Оба глагола — запрос и предъявление кода — прогоняются по успешному исходу,
// по отказам и по КАЖДОЙ точке отказа хранилища, на которой глагол пишет в
// журнал. Журнал — настоящий обработчик `slog` над буфером, аудит — полезная
// нагрузка событий, которые глагол отдал транзакции. Положительный контроль:
// у сценария, объявленного пишущим, запись в журнале ЕСТЬ — иначе «адреса нет»
// было бы неотличимо от «журнала не читали».

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// errECStoreDown — отказ хранилища без адреса в тексте: предмет пробы — то,
// что глагол пишет в журнал САМ.
var errECStoreDown = errors.New("store down")

// ecLogWriter — транзакция смены, отказывающая в названной точке и
// запоминающая полезную нагрузку событий аудита.
type ecLogWriter struct {
	*ecWriter
	failAt string
	audits []outboxtypes.AuditEvent
}

func (w *ecLogWriter) failed(step string) error {
	if w.failAt == step {
		return errECStoreDown
	}
	return nil
}

func (w *ecLogWriter) AddressTaken(ctx context.Context, e domain.Email) (bool, error) {
	if err := w.failed("AddressTaken"); err != nil {
		return false, err
	}
	return w.ecWriter.AddressTaken(ctx, e)
}

func (w *ecLogWriter) SupersedeEmailChangeCodes(ctx context.Context, u domain.UserID, at time.Time) (int, error) {
	if err := w.failed("Supersede"); err != nil {
		return 0, err
	}
	return w.ecWriter.SupersedeEmailChangeCodes(ctx, u, at)
}

func (w *ecLogWriter) InsertEmailChangeCodePaced(ctx context.Context, c domain.EmailChangeCode, p humansession.VerificationPace) (humansession.LetterRefusal, error) {
	if err := w.failed("InsertPaced"); err != nil {
		return humansession.LetterRefusal{}, err
	}
	return w.ecWriter.InsertEmailChangeCodePaced(ctx, c, p)
}

func (w *ecLogWriter) ChargeEmailChangeWindow(ctx context.Context, e domain.Email, l outboxtypes.InviteMailRateLimit) (humansession.LetterRefusal, error) {
	if err := w.failed("ChargeWindow"); err != nil {
		return humansession.LetterRefusal{}, err
	}
	return w.ecWriter.ChargeEmailChangeWindow(ctx, e, l)
}

func (w *ecLogWriter) EmitEmailChangeMail(ctx context.Context, in humansession.EmailChangeMailIntent) error {
	if err := w.failed("EmitChangeMail"); err != nil {
		return err
	}
	return w.ecWriter.EmitEmailChangeMail(ctx, in)
}

func (w *ecLogWriter) PresentEmailChangeCode(ctx context.Context, u domain.UserID, d domain.CodeDigest, at time.Time, n int) (humansession.PresentedCode, domain.Email, error) {
	if err := w.failed("Present"); err != nil {
		return 0, "", err
	}
	return w.ecWriter.PresentEmailChangeCode(ctx, u, d, at, n)
}

func (w *ecLogWriter) ChangeEmail(ctx context.Context, u domain.UserID, e domain.Email) (domain.Email, error) {
	if err := w.failed("ChangeEmail"); err != nil {
		return "", err
	}
	return w.ecWriter.ChangeEmail(ctx, u, e)
}

func (w *ecLogWriter) MarkEmailVerified(ctx context.Context, u domain.UserID, e domain.Email, at time.Time) (bool, error) {
	if err := w.failed("Mark"); err != nil {
		return false, err
	}
	return w.ecWriter.MarkEmailVerified(ctx, u, e, at)
}

func (w *ecLogWriter) RotateBearer(ctx context.Context, id domain.HumanSessionID, d domain.BearerDigest, at time.Time) error {
	if err := w.failed("Rotate"); err != nil {
		return err
	}
	return w.ecWriter.RotateBearer(ctx, id, d, at)
}

func (w *ecLogWriter) EndOtherSessions(ctx context.Context, u domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error) {
	if err := w.failed("EndOthers"); err != nil {
		return 0, err
	}
	return w.ecWriter.EndOtherSessions(ctx, u, keep, at, reason)
}

func (w *ecLogWriter) SupersedeRecoveryCodes(ctx context.Context, u domain.UserID) (int, error) {
	if err := w.failed("WithdrawRecovery"); err != nil {
		return 0, err
	}
	return w.ecWriter.SupersedeRecoveryCodes(ctx, u)
}

func (w *ecLogWriter) EmitEmailChangedMail(ctx context.Context, in humansession.EmailChangedMailIntent) error {
	if err := w.failed("EmitNotice"); err != nil {
		return err
	}
	return w.ecWriter.EmitEmailChangedMail(ctx, in)
}

func (w *ecLogWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	if err := w.failed("Audit"); err != nil {
		return err
	}
	w.audits = append(w.audits, ev)
	return w.ecWriter.EmitAudit(ctx, ev)
}

func (w *ecLogWriter) EmitSubjectChangeEvent(ctx context.Context, c humansession.SubjectChange) error {
	if err := w.failed("SubjectChange"); err != nil {
		return err
	}
	return w.ecWriter.EmitSubjectChangeEvent(ctx, c)
}

func (w *ecLogWriter) Commit(ctx context.Context) error {
	if err := w.failed("Commit"); err != nil {
		return err
	}
	return w.ecWriter.Commit(ctx)
}

// ecLogStore — хранилище смены, отдающее транзакцию ecLogWriter.
type ecLogStore struct {
	*ecStore
	lw *ecLogWriter
}

func (s *ecLogStore) EmailChangeWriter(context.Context, domain.UserID) (humansession.EmailChangeWriter, error) {
	s.opened++
	return s.lw, nil
}

// ecAddresses — адреса сценария в той форме, в какой их подаёт клиент, и в
// приведённой: проба ищет каждую без учёта регистра.
const (
	ecOldAddress    = "old@example.test"
	ecNewAddressRaw = "New.Person@Example.Test"
	ecNewAddress    = "new.person@example.test"
)

type ecLogScenario struct {
	name string
	// confirm — глагол предъявления кода; иначе — запрос смены.
	confirm bool
	// arrange — состояние дублёров до вызова.
	arrange func(s *ecLogStore)
	// writesLog — глагол на этом исходе ОБЯЗАН писать в журнал: положительный
	// контроль того, что журнал прочитан.
	writesLog bool
}

// runECLogScenario — прогон сценария; возвращает журнал и полезную нагрузку
// аудита одним текстом.
func runECLogScenario(t *testing.T, sc ecLogScenario) (logText, auditText string) {
	t.Helper()
	base, bearer := newECStore(t)
	base.resolved.User.Email = ecOldAddress
	lw := &ecLogWriter{ecWriter: base.w}
	lw.presented, lw.newEmail = humansession.CodeMatched, ecNewAddress
	s := &ecLogStore{ecStore: base, lw: lw}
	if sc.arrange != nil {
		sc.arrange(s)
	}
	var buf bytes.Buffer
	deps := ecDeps(base)
	deps.Store = s
	deps.Logger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := context.Background()
	if sc.confirm {
		uc, err := humansession.NewConfirmEmailChangeUseCase(deps)
		require.NoError(t, err)
		_, _ = uc.Execute(ctx, humansession.ConfirmEmailChangeInput{Bearer: bearer, Code: "ABCDE-FGHJK"})
	} else {
		uc, err := humansession.NewRequestEmailChangeUseCase(deps)
		require.NoError(t, err)
		_, _ = uc.Execute(ctx, humansession.RequestEmailChangeInput{Bearer: bearer, NewEmail: ecNewAddressRaw})
	}
	var audit strings.Builder
	for _, ev := range lw.audits {
		fmt.Fprintf(&audit, "%s %s %v\n", ev.EventType, ev.TenantAccountID, ev.Payload)
	}
	return buf.String(), audit.String()
}

func ecLogScenarios() []ecLogScenario {
	fail := func(step string) func(*ecLogStore) { return func(s *ecLogStore) { s.lw.failAt = step } }
	out := []ecLogScenario{
		{name: "запрос: письмо поставлено"},
		{name: "запрос: адрес занят", arrange: func(s *ecLogStore) { s.lw.taken = true }},
		{name: "запрос: темп человека", arrange: func(s *ecLogStore) {
			s.lw.paced = humansession.LetterRefusal{Refused: true, RetryAfter: time.Minute}
		}},
		{name: "запрос: окно адресата", arrange: func(s *ecLogStore) {
			s.lw.window = humansession.LetterRefusal{Refused: true, RetryAfter: time.Minute}
		}},
		{name: "запрос: заведённое не прочитано", writesLog: true,
			arrange: func(s *ecLogStore) { s.methods.fail = true }},
		{name: "предъявление: исход смены", confirm: true},
		{name: "предъявление: неверный код", confirm: true,
			arrange: func(s *ecLogStore) { s.lw.presented = humansession.CodeMismatched }},
		{name: "предъявление: адрес занят на исходе", confirm: true,
			arrange: func(s *ecLogStore) { s.lw.changeErr = humansession.ErrEmailInUse }},
		{name: "предъявление: отметка не легла", confirm: true, writesLog: true,
			arrange: func(s *ecLogStore) { s.lw.marked = false }},
		{name: "предъявление: заведённое не прочитано", confirm: true, writesLog: true,
			arrange: func(s *ecLogStore) { s.methods.fail = true }},
	}
	for _, step := range []string{"AddressTaken", "Supersede", "InsertPaced", "ChargeWindow", "EmitChangeMail", "Commit"} {
		out = append(out, ecLogScenario{name: "запрос: отказ хранилища на " + step, arrange: fail(step), writesLog: true})
	}
	for _, step := range []string{"Present", "ChangeEmail", "Mark", "Rotate", "EndOthers", "WithdrawRecovery",
		"EmitNotice", "Audit", "SubjectChange", "Commit"} {
		out = append(out, ecLogScenario{name: "предъявление: отказ хранилища на " + step, confirm: true, arrange: fail(step), writesLog: true})
	}
	return out
}

// TestEmailChangeVerbsLogNoAddress — Р7: ни в журнале, ни в аудите глаголов
// смены адреса нет ни прежнего, ни нового адреса — на успехе, на отказах и на
// каждой точке отказа хранилища.
func TestEmailChangeVerbsLogNoAddress(t *testing.T) {
	scenarios := ecLogScenarios()
	if len(scenarios) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: сценариев 0")
	}
	logged, audited := 0, 0
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			logText, auditText := runECLogScenario(t, sc)
			if sc.writesLog {
				require.NotEmpty(t, logText, "положительный контроль: этот исход пишет в журнал, а записи нет — журнал не прочитан")
				logged++
			}
			if auditText != "" {
				audited++
			}
			journal := strings.ToLower(logText + auditText)
			for _, addr := range []string{ecOldAddress, ecNewAddressRaw, ecNewAddress} {
				require.NotContains(t, journal, strings.ToLower(addr),
					"Р7: адрес %q в журнале или аудите глагола смены\nжурнал: %s\nаудит: %s", addr, logText, auditText)
			}
		})
	}
	if logged == 0 || audited == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: сценариев с записью журнала %d, с событием аудита %d", logged, audited)
	}
	t.Logf("перепись: сценариев %d, с записью журнала %d, с событием аудита %d — адресов 0",
		len(scenarios), logged, audited)
}
