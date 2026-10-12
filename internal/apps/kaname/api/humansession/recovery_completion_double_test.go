// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recovery_completion_double_test.go — ДУБЛЁР И ЖУРНАЛ транзакции исхода
// завершения восстановления (порт `humansession.RecoveryCompletionStore`,
// kaname#458). Дублёр повторяет РАБОТУ адаптера
// (`internal/repo/kaname/pg/recovery_completion_store.go`): открытие и
// оператор замка строки личности — та же дверь и та же цена, что
// `SessionSetWriter`; у операторов исхода — по одному оператору базы на
// обращение, у снятия начатых заведений — два (начатое заведение генератора ·
// испытания регистрации ключа). Журнал пишет каждое обращение
// явно, как и обёртки портов `recording_store_test.go`.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// RecoveryCompletionWriter — транзакция исхода дублёра: та же работа, что у
// `SessionSetWriter`.
func (f *fakeStore) RecoveryCompletionWriter(_ context.Context, userID domain.UserID) (humansession.RecoveryCompletionWriter, error) {
	w, err := f.open(userID)
	if err != nil {
		return nil, err
	}
	if err := w.holdPerson(userID); err != nil {
		return nil, err
	}
	return fakeCompletionWriter{fakeWriter: w}, nil
}

// fakeCompletionWriter — операторы перехода над транзакцией дублёра.
type fakeCompletionWriter struct{ *fakeWriter }

var _ humansession.RecoveryCompletionWriter = fakeCompletionWriter{}

// AddressVerified — отметка, прочитанная транзакцией; отказ по имени
// "address-verified".
func (w fakeCompletionWriter) AddressVerified(_ context.Context, userID domain.UserID) (bool, error) {
	if userID == "" {
		return false, errFakeArg("Illegal argument user_id: required")
	}
	w.store.trip()
	if err := w.fail("address-verified"); err != nil {
		return false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	return w.store.verified[userID], nil
}

// UserTokenHeld — одно чтение наличия строки личного токена. Отказ по имени
// "user-token-held".
func (w fakeCompletionWriter) UserTokenHeld(_ context.Context, userID domain.UserID) (bool, error) {
	if userID == "" {
		return false, errFakeArg("Illegal argument user_id: required")
	}
	w.store.trip()
	if err := w.fail("user-token-held"); err != nil {
		return false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	return w.store.userTokens[userID], nil
}

// RetireStartedEnrolmentsOf — два оператора снятия (начатое заведение
// генератора · испытания регистрации ключа); записи — на фиксации. Заведённую
// строку оператор не касается, как и адаптер. Отказ по имени "retire-started".
func (w fakeCompletionWriter) RetireStartedEnrolmentsOf(_ context.Context, userID domain.UserID) (humansession.RetiredEnrolments, error) {
	if userID == "" {
		return humansession.RetiredEnrolments{}, errFakeArg("Illegal argument user_id: required")
	}
	for range 2 {
		w.store.trip()
	}
	if err := w.fail("retire-started"); err != nil {
		return humansession.RetiredEnrolments{}, err
	}
	w.store.mu.Lock()
	var out humansession.RetiredEnrolments
	if row, ok := w.store.factors[userID][domain.LoginMethodTOTP]; ok && row.State == domain.LoginMethodStatePending {
		out.SecondFactorRows = 1
	}
	w.store.mu.Unlock()
	w.ops = append(w.ops, func() {
		if row, ok := w.store.factors[userID][domain.LoginMethodTOTP]; ok && row.State == domain.LoginMethodStatePending {
			delete(w.store.factors[userID], domain.LoginMethodTOTP)
		}
	})
	return out, nil
}

// ActivateInviteOnVerification — строка `PENDING` становится `ACTIVE` на
// фиксации; иная строка либо приглашение, снятое пробой (`inviteGone`), —
// ErrInviteNotValid, как у адаптера. Отказ по имени "activate-invite".
func (w fakeCompletionWriter) ActivateInviteOnVerification(_ context.Context, pending domain.User) (humansession.InviteActivation, error) {
	w.store.trip()
	if err := w.fail("activate-invite"); err != nil {
		return humansession.InviteActivation{}, err
	}
	w.store.mu.Lock()
	u, ok := w.store.users[pending.ID]
	w.store.mu.Unlock()
	if !ok || u.InviteStatus != domain.InviteStatusPending || w.store.inviteGone[pending.ID] {
		return humansession.InviteActivation{}, humansession.ErrInviteNotValid
	}
	u.InviteStatus = domain.InviteStatusActive
	w.ops = append(w.ops, func() { w.store.users[u.ID] = u })
	return humansession.InviteActivation{User: u}, nil
}

// recordingCompletionStore — humansession.RecoveryCompletionStore с журналом.
type recordingCompletionStore struct {
	inner humansession.RecoveryCompletionStore
	j     *storeJournal
	meter func() int64
}

var _ humansession.RecoveryCompletionStore = recordingCompletionStore{}

func (s recordingCompletionStore) RecoveryCompletionWriter(ctx context.Context, userID domain.UserID) (humansession.RecoveryCompletionWriter, error) {
	defer record(s.j, s.meter, storeOp{Port: "store", Name: "RecoveryCompletionWriter"})()
	w, err := s.inner.RecoveryCompletionWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	return recordingCompletionWriter{recordingWriter: recordingWriter{inner: w, j: s.j, meter: s.meter}, completion: w}, nil
}

// recordingCompletionWriter — humansession.RecoveryCompletionWriter с журналом:
// операторы `Writer` пишет встроенный журнал писателя, операторы перехода —
// свои записи.
type recordingCompletionWriter struct {
	recordingWriter
	completion humansession.RecoveryCompletionWriter
}

var _ humansession.RecoveryCompletionWriter = recordingCompletionWriter{}

func (w recordingCompletionWriter) AddressVerified(ctx context.Context, userID domain.UserID) (bool, error) {
	defer w.rec("AddressVerified")()
	return w.completion.AddressVerified(ctx, userID)
}

func (w recordingCompletionWriter) UserTokenHeld(ctx context.Context, userID domain.UserID) (bool, error) {
	defer w.rec("UserTokenHeld")()
	return w.completion.UserTokenHeld(ctx, userID)
}

func (w recordingCompletionWriter) RetireStartedEnrolmentsOf(ctx context.Context, userID domain.UserID) (humansession.RetiredEnrolments, error) {
	defer w.rec("RetireStartedEnrolmentsOf")()
	return w.completion.RetireStartedEnrolmentsOf(ctx, userID)
}

func (w recordingCompletionWriter) ActivateInviteOnVerification(ctx context.Context, pending domain.User) (humansession.InviteActivation, error) {
	defer w.rec("ActivateInviteOnVerification")()
	return w.completion.ActivateInviteOnVerification(ctx, pending)
}
