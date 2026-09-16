// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// recovery_fakes_test.go — дублёр хранилища для восстановления доступа (Ф5):
// коды, письма, журнал завершений. НЕ снисходительнее настоящего: применение —
// один оператор по (личность, свёртка, ещё не применён, срок не вышел); журнал
// по ключу потока — вставка только нового ключа; намерение письма без адресата
// либо без кода отвергается, как отвергает ограничение очереди.

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func (f *fakeStore) codesOf(user domain.UserID) []domain.RecoveryCode {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.RecoveryCode
	for _, c := range f.codes {
		if c.UserID == user {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt.Before(out[j].IssuedAt) })
	return out
}

func (f *fakeStore) RecoveryTarget(_ context.Context, email domain.Email) (humansession.RecoveryTarget, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == "target" {
		return humansession.RecoveryTarget{}, false, errFakePort
	}
	for _, u := range f.users {
		if humansession.AddressKey(string(u.Email)) == humansession.AddressKey(string(email)) {
			return humansession.RecoveryTarget{User: u, EmailVerified: f.verified[u.ID]}, true, nil
		}
	}
	return humansession.RecoveryTarget{}, false, nil
}

func (w *fakeWriter) InsertRecoveryCode(_ context.Context, c domain.RecoveryCode) error {
	if err := c.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if err := w.fail("insert-code"); err != nil {
		return err
	}
	if _, ok := w.store.users[c.UserID]; !ok {
		return iamerr.Wrapf(iamerr.ErrFailedPrecondition, "User %s not found", c.UserID)
	}
	w.ops = append(w.ops, func() { row := c; w.store.codes[c.ID] = &row })
	return nil
}

func (w *fakeWriter) SupersedeRecoveryCodes(_ context.Context, userID domain.UserID) (int, error) {
	if err := w.fail("supersede"); err != nil {
		return 0, err
	}
	n := 0
	for id, c := range w.store.codes {
		if c.UserID == userID && c.ConsumedAt == nil {
			n++
			id := id
			w.ops = append(w.ops, func() { delete(w.store.codes, id) })
		}
	}
	return n, nil
}

func (w *fakeWriter) ConsumeRecoveryCode(_ context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time) (domain.RecoveryCode, bool, error) {
	if err := w.fail("consume"); err != nil {
		return domain.RecoveryCode{}, false, err
	}
	for _, c := range w.store.codes {
		if c.UserID == userID && c.Digest == digest && c.ConsumedAt == nil && now.Before(c.ExpiresAt) {
			row := c
			at := now
			w.ops = append(w.ops, func() { row.ConsumedAt = &at })
			out := *c
			out.ConsumedAt = &at
			return out, true, nil
		}
	}
	return domain.RecoveryCode{}, false, nil
}

func (w *fakeWriter) EmitRecoveryMail(_ context.Context, in humansession.RecoveryMailIntent) error {
	if err := w.fail("emit-mail"); err != nil {
		return err
	}
	if strings.TrimSpace(in.To) == "" || in.Code.IsZero() || in.UserID == "" {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "recovery mail intent: recipient, code and user required")
	}
	w.ops = append(w.ops, func() { w.store.mail = append(w.store.mail, in) })
	return nil
}

func (w *fakeWriter) InsertRecoveryCompletion(_ context.Context, rc domain.RecoveryCompletion) (bool, error) {
	if err := rc.Validate(); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if err := w.fail("ledger"); err != nil {
		return false, err
	}
	if _, exists := w.store.completions[rc.RecoveryJTI]; exists {
		return false, nil
	}
	w.ops = append(w.ops, func() { w.store.completions[rc.RecoveryJTI] = rc })
	return true, nil
}

func (o *countingObserver) RecoveryRequestObserved(x humansession.RecoveryRequestOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.recoveryRequest[x]++
}

func (o *countingObserver) RecoveryCompletionObserved(x humansession.RecoveryCompletionOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.recoveryCompletion[x]++
}
