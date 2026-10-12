// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recovery_completion_double_test.go — ДУБЛЁР И ЖУРНАЛ транзакции исхода
// завершения восстановления (порт `humansession.RecoveryCompletionStore`,
// kaname#458). Дублёр повторяет РАБОТУ адаптера
// (`internal/repo/kaname/pg/recovery_completion_store.go`): открытие и
// оператор замка строки личности — та же дверь и та же цена, что
// `SessionSetWriter`; у операторов перехода — по одному оператору базы на
// обращение, у снятия удостоверений — четыре (второй фактор · испытания
// регистрации ключа · ключи · личные токены). Журнал пишет каждое обращение
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

// RetireCredentialsOf — четыре оператора снятия; записи — на фиксации. Отказ по
// имени "retire-credentials".
func (w fakeCompletionWriter) RetireCredentialsOf(_ context.Context, userID domain.UserID) (humansession.RetiredCredentials, error) {
	if userID == "" {
		return humansession.RetiredCredentials{}, errFakeArg("Illegal argument user_id: required")
	}
	for range 4 {
		w.store.trip()
	}
	if err := w.fail("retire-credentials"); err != nil {
		return humansession.RetiredCredentials{}, err
	}
	w.store.mu.Lock()
	out := humansession.RetiredCredentials{SecondFactorRows: int64(len(w.store.factors[userID]))}
	for _, owner := range w.store.accessKeyRows {
		if owner == userID {
			out.AccessKeyRows++
		}
	}
	w.store.mu.Unlock()
	w.ops = append(w.ops, func() {
		delete(w.store.factors, userID)
		delete(w.store.keys, userID)
		for id, owner := range w.store.accessKeyRows {
			if owner == userID {
				delete(w.store.accessKeyRows, id)
			}
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

func (w recordingCompletionWriter) RetireCredentialsOf(ctx context.Context, userID domain.UserID) (humansession.RetiredCredentials, error) {
	defer w.rec("RetireCredentialsOf")()
	return w.completion.RetireCredentialsOf(ctx, userID)
}

func (w recordingCompletionWriter) ActivateInviteOnVerification(ctx context.Context, pending domain.User) (humansession.InviteActivation, error) {
	defer w.rec("ActivateInviteOnVerification")()
	return w.completion.ActivateInviteOnVerification(ctx, pending)
}
