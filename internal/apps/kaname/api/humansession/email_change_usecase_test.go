// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// email_change_usecase_test.go — порядок суждения глаголов смены адреса
// (kaname#635, приёмка `email-change-is-confirmed-from-the-new-address.md`, Р2–Р8)
// на портах-дублёрах, без базы: какая ступень отвечает и чего она НЕ делает.
// Свойства хранилища (темп одним оператором, ключ адреса, однократность) держит
// уровень I (`internal/handler/loginlanehttp/email_change_integration_test.go`).

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// ecWriter — дублёр транзакции смены: записывает вызовы по порядку и отвечает
// объявленными исходами. Методы порта, которых глаголы смены звать не вправе,
// не переопределены: вызов такого метода — паника пробы, а не тихий успех.
type ecWriter struct {
	humansession.Writer
	calls     []string
	taken     bool
	paced     humansession.LetterRefusal
	window    humansession.LetterRefusal
	inserted  domain.EmailChangeCode
	presented humansession.PresentedCode
	newEmail  domain.Email
	changeErr error
	marked    bool
	committed bool
}

func (w *ecWriter) rec(c string) { w.calls = append(w.calls, c) }

func (w *ecWriter) AddressTaken(context.Context, domain.Email) (bool, error) {
	w.rec("AddressTaken")
	return w.taken, nil
}

func (w *ecWriter) SupersedeEmailChangeCodes(context.Context, domain.UserID, time.Time) (int, error) {
	w.rec("Supersede")
	return 0, nil
}

func (w *ecWriter) InsertEmailChangeCodePaced(_ context.Context, c domain.EmailChangeCode, _ humansession.VerificationPace) (humansession.LetterRefusal, error) {
	w.rec("InsertPaced")
	w.inserted = c
	return w.paced, nil
}

func (w *ecWriter) ChargeEmailChangeWindow(context.Context, domain.Email, outboxtypes.InviteMailRateLimit) (humansession.LetterRefusal, error) {
	w.rec("ChargeWindow")
	return w.window, nil
}

func (w *ecWriter) EmitEmailChangeMail(context.Context, humansession.EmailChangeMailIntent) error {
	w.rec("EmitChangeMail")
	return nil
}

func (w *ecWriter) PresentEmailChangeCode(context.Context, domain.UserID, domain.CodeDigest, time.Time, int) (humansession.PresentedCode, domain.Email, error) {
	w.rec("Present")
	return w.presented, w.newEmail, nil
}

func (w *ecWriter) ChangeEmail(context.Context, domain.UserID, domain.Email) (domain.Email, error) {
	w.rec("ChangeEmail")
	return "old@example.test", w.changeErr
}

func (w *ecWriter) MarkEmailVerified(context.Context, domain.UserID, domain.Email, time.Time) (bool, error) {
	w.rec("Mark")
	return w.marked, nil
}

func (w *ecWriter) RotateBearer(context.Context, domain.HumanSessionID, domain.BearerDigest, time.Time) error {
	w.rec("Rotate")
	return nil
}

func (w *ecWriter) EndOtherSessions(_ context.Context, _ domain.UserID, _ domain.HumanSessionID, _ time.Time, reason string) (int, error) {
	w.rec("EndOthers:" + reason)
	return 1, nil
}

func (w *ecWriter) SupersedeRecoveryCodes(context.Context, domain.UserID) (int, error) {
	w.rec("WithdrawRecovery")
	return 0, nil
}

func (w *ecWriter) EmitEmailChangedMail(_ context.Context, in humansession.EmailChangedMailIntent) error {
	w.rec("EmitNotice:" + string(in.To))
	return nil
}

func (w *ecWriter) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	w.rec("Audit:" + ev.EventType)
	return nil
}

func (w *ecWriter) EmitSubjectChangeEvent(_ context.Context, c humansession.SubjectChange) error {
	w.rec("SubjectChange:" + c.SubjectType + ":" + c.Op)
	return nil
}

func (w *ecWriter) Commit(context.Context) error {
	w.rec("Commit")
	w.committed = true
	return nil
}

func (w *ecWriter) Rollback(context.Context) error { return nil }

// ecStore — дублёр хранилища: сессия свежая и подтверждённая, если не сказано
// иначе; открытия транзакции считаются.
type ecStore struct {
	resolved humansession.Resolved
	reason   humansession.NoSessionReason
	w        *ecWriter
	opened   int
}

func (s *ecStore) Resolve(context.Context, domain.BearerDigest, time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	return s.resolved, s.reason, nil
}

func (s *ecStore) EmailChangeWriter(context.Context, domain.UserID) (humansession.EmailChangeWriter, error) {
	s.opened++
	return s.w, nil
}

var ecNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

func newECStore(t *testing.T) (*ecStore, domain.SessionBearer) {
	t.Helper()
	bearer, err := domain.NewSessionBearer()
	require.NoError(t, err)
	return &ecStore{
		resolved: humansession.Resolved{
			Session:       domain.HumanSession{ID: "hs-1", LastPresentedAt: ecNow.Add(-time.Minute)},
			User:          domain.User{ID: "usr-1", AccountID: "acc-1", Email: "old@example.test"},
			EmailVerified: true,
		},
		w: &ecWriter{marked: true},
	}, bearer
}

func ecDeps(s *ecStore) humansession.EmailChangeDeps {
	return humansession.EmailChangeDeps{
		Store:     s,
		Pace:      humansession.VerificationPace{CodeTTL: 30 * time.Minute, Attempts: 5, Interval: time.Minute, Limit: 5, Window: 24 * time.Hour},
		Freshness: 15 * time.Minute,
		MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 3, Window: time.Hour},
		Now:       func() time.Time { return ecNow },
	}
}

func TestEmailChangeRequest_FieldAndFreshnessRefusalsOpenNoTransaction(t *testing.T) {
	for _, tc := range []struct {
		name, email string
		stale       bool
		want        string
	}{
		{"пусто", "", false, "Illegal argument newEmail: required"},
		{"форма", "not-an-address", false, "Illegal argument newEmail: invalid format"},
		{"совпал с текущим после приведения", " OLD@Example.Test ", false, "Illegal argument newEmail: must differ from the current address"},
		{"несвежая сессия", "new@example.test", true, humansession.TextSessionNotFresh},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b := newECStore(t)
			if tc.stale {
				s.resolved.Session.LastPresentedAt = ecNow.Add(-15*time.Minute - time.Second)
			}
			uc, err := humansession.NewRequestEmailChangeUseCase(ecDeps(s))
			require.NoError(t, err)
			_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: tc.email})
			require.EqualError(t, err, tc.want)
			require.Zero(t, s.opened, "отказ формы и свежести транзакции не открывает — темп не расходован")
		})
	}
}

func TestEmailChangeRequest_FreshnessBoundaryIsIncluded(t *testing.T) {
	s, b := newECStore(t)
	s.resolved.Session.LastPresentedAt = ecNow.Add(-15 * time.Minute)
	uc, err := humansession.NewRequestEmailChangeUseCase(ecDeps(s))
	require.NoError(t, err)
	out, err := uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "New@Example.Test"})
	require.NoError(t, err, "ровно окно — ещё свежая")
	require.Equal(t, time.Minute, out.NextAllowedIn)
	require.Equal(t, domain.Email("new@example.test"), s.w.inserted.NewEmail, "адрес хранится приведённым")
}

func TestEmailChangeRequest_NoSessionAndVerificationPosition(t *testing.T) {
	s, b := newECStore(t)
	s.reason = humansession.NoSessionEnded
	uc, err := humansession.NewRequestEmailChangeUseCase(ecDeps(s))
	require.NoError(t, err)
	_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
	require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)

	s2, b2 := newECStore(t)
	s2.resolved.EmailVerified = false
	uc2, err := humansession.NewRequestEmailChangeUseCase(ecDeps(s2))
	require.NoError(t, err)
	_, err = uc2.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b2, NewEmail: "new@example.test"})
	require.ErrorIs(t, err, humansession.ErrEmailNotVerified)
	require.Zero(t, s.opened+s2.opened)
}

func TestEmailChangeRequest_TakenAndFreeDifferOnlyInTheLetter(t *testing.T) {
	run := func(taken bool) (*ecWriter, humansession.RequestEmailChangeOutput) {
		s, b := newECStore(t)
		s.w.taken = taken
		uc, err := humansession.NewRequestEmailChangeUseCase(ecDeps(s))
		require.NoError(t, err)
		out, err := uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
		require.NoError(t, err)
		return s.w, out
	}
	free, outFree := run(false)
	taken, outTaken := run(true)
	require.Equal(t, outFree, outTaken, "исход наружу один (Р4)")
	require.Equal(t, []string{"AddressTaken", "Supersede", "InsertPaced", "ChargeWindow", "EmitChangeMail", "Commit"}, free.calls)
	require.Equal(t, []string{"AddressTaken", "Supersede", "InsertPaced", "ChargeWindow", "Commit"}, taken.calls,
		"занятый: та же запись, тот же темп и то же окно, письма нет")
	require.NotEmpty(t, free.inserted.Digest, "свободный: строка несёт свёртку кода")
	require.Empty(t, taken.inserted.Digest, "занятый: строка кода не несёт")
}

func TestEmailChangeRequest_PaceRefusalsLeaveNothing(t *testing.T) {
	s, b := newECStore(t)
	s.w.paced = humansession.LetterRefusal{Refused: true, RetryAfter: 42 * time.Second}
	uc, err := humansession.NewRequestEmailChangeUseCase(ecDeps(s))
	require.NoError(t, err)
	_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
	var tma *humansession.TooManyAttemptsError
	require.ErrorAs(t, err, &tma)
	require.Equal(t, 42*time.Second, tma.RetryAfter)
	require.False(t, s.w.committed, "темп человека: запрос не записан")
	require.NotContains(t, s.w.calls, "ChargeWindow", "окно адресата не списано")

	s2, b2 := newECStore(t)
	s2.w.window = humansession.LetterRefusal{Refused: true, RetryAfter: 7 * time.Second}
	uc2, err := humansession.NewRequestEmailChangeUseCase(ecDeps(s2))
	require.NoError(t, err)
	_, err = uc2.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b2, NewEmail: "new@example.test"})
	require.ErrorAs(t, err, &tma)
	require.Equal(t, 7*time.Second, tma.RetryAfter)
	require.False(t, s2.w.committed, "окно адресата: запрос не записан, прежний код не вытеснен")
	require.NotContains(t, s2.w.calls, "EmitChangeMail")
}

func TestEmailChangeConfirm_OutcomeIsOneTransactionInOrder(t *testing.T) {
	s, b := newECStore(t)
	s.w.presented, s.w.newEmail = humansession.CodeMatched, "new@example.test"
	uc, err := humansession.NewConfirmEmailChangeUseCase(ecDeps(s))
	require.NoError(t, err)
	out, err := uc.Execute(context.Background(), humansession.ConfirmEmailChangeInput{Bearer: b, Code: "ABCDE-FGHJK"})
	require.NoError(t, err)
	require.Equal(t, []string{
		"Present", "ChangeEmail", "Mark", "Rotate", "EndOthers:" + domain.RevokeReasonEmailChanged, "WithdrawRecovery",
		"EmitNotice:old@example.test", "Audit:" + humansession.AuditEmailChanged,
		"SubjectChange:user:" + humansession.SubjectChangeUserEmail, "Commit",
	}, s.w.calls)
	require.Equal(t, domain.Email("new@example.test"), out.View.User.Email)
	require.True(t, out.View.EmailVerified)
	require.False(t, out.Bearer.IsZero(), "новый носитель")
}

func TestEmailChangeConfirm_RefusalsStopTheOutcome(t *testing.T) {
	for _, tc := range []struct {
		name      string
		presented humansession.PresentedCode
		changeErr error
		marked    bool
		want      error
		commits   bool
		last      string
	}{
		{"неверный код — попытка засчитана", humansession.CodeMismatched, nil, true, humansession.ErrAuthenticationFailed, true, "Commit"},
		{"кода нет", humansession.CodeNotFound, nil, true, humansession.ErrAuthenticationFailed, false, "Present"},
		{"адрес занят на исходе", humansession.CodeMatched, humansession.ErrEmailInUse, true, humansession.ErrEmailInUse, false, "ChangeEmail"},
		{"хранилище не ответило на смену", humansession.CodeMatched, errors.New("boom"), true, humansession.ErrStoreUnavailable, false, "ChangeEmail"},
		{"отметка не легла", humansession.CodeMatched, nil, false, humansession.ErrStoreUnavailable, false, "Mark"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, b := newECStore(t)
			s.w.presented, s.w.newEmail, s.w.changeErr, s.w.marked = tc.presented, "new@example.test", tc.changeErr, tc.marked
			uc, err := humansession.NewConfirmEmailChangeUseCase(ecDeps(s))
			require.NoError(t, err)
			_, err = uc.Execute(context.Background(), humansession.ConfirmEmailChangeInput{Bearer: b, Code: "ABCDE-FGHJK"})
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, tc.commits, s.w.committed)
			require.Equal(t, tc.last, s.w.calls[len(s.w.calls)-1], "исход остановлен на ступени: %v", s.w.calls)
			for _, c := range s.w.calls {
				require.False(t, strings.HasPrefix(c, "EmitNotice") || strings.HasPrefix(c, "SubjectChange"),
					"отказ не ставит уведомления и строки очереди: %v", s.w.calls)
			}
		})
	}
}

func TestEmailChangeConfirm_EmptyCodeIsAFieldRefusalWithoutATransaction(t *testing.T) {
	s, b := newECStore(t)
	uc, err := humansession.NewConfirmEmailChangeUseCase(ecDeps(s))
	require.NoError(t, err)
	_, err = uc.Execute(context.Background(), humansession.ConfirmEmailChangeInput{Bearer: b, Code: "  "})
	require.EqualError(t, err, "Illegal argument code: required")
	require.Zero(t, s.opened)
}

func TestEmailChangeDeps_RefuseToBuildWithoutTheirValues(t *testing.T) {
	s, _ := newECStore(t)
	for _, mut := range []func(*humansession.EmailChangeDeps){
		func(d *humansession.EmailChangeDeps) { d.Store = nil },
		func(d *humansession.EmailChangeDeps) { d.Freshness = 0 },
		func(d *humansession.EmailChangeDeps) { d.MailLimit = outboxtypes.InviteMailRateLimit{} },
		func(d *humansession.EmailChangeDeps) { d.Pace.Interval = 0 },
	} {
		d := ecDeps(s)
		mut(&d)
		_, err := humansession.NewRequestEmailChangeUseCase(d)
		require.Error(t, err)
		_, err = humansession.NewConfirmEmailChangeUseCase(d)
		require.Error(t, err)
	}
}
