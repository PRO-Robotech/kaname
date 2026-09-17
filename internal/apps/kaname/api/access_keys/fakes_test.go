// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// fakes_test.go — подставные порты глаголов ключа. Дублёр НЕ снисходительнее
// продукта: уникальность идентификатора удостоверения, потолок, однократность
// испытания и условный сдвиг счётчика он исполняет теми же исходами, что
// база, — иначе отрицания зеленели бы на дублёре и краснели на настоящей базе.
// Гонки дублёр не судит: они — предмет интеграционных проб адаптера.

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

type fakeStore struct {
	mu         sync.Mutex
	users      map[domain.UserID]domain.User
	keys       map[domain.AccessKeyID]domain.AccessKey
	challenges map[string]domain.AccessKeyChallenge
	// ceiling — потолок ключей у человека; nil — не объявлен (KQ002).
	ceiling *int64
	audit   []outboxtypes.AuditEvent
	// failWriter — Writer не открывается (недоступность).
	failWriter bool
	// beforeAdvance — крючок конкуренции (Ф7-20, ветвь б): исполняется перед
	// сдвигом счётчика, чтобы соседнее утверждение успело перехватить слот.
	beforeAdvance func()
}

func newFakeStore() *fakeStore {
	ten := int64(10)
	return &fakeStore{users: map[domain.UserID]domain.User{}, keys: map[domain.AccessKeyID]domain.AccessKey{},
		challenges: map[string]domain.AccessKeyChallenge{}, ceiling: &ten}
}

func (s *fakeStore) addUser(id domain.UserID, status domain.InviteStatus) domain.User {
	u := domain.User{ID: id, AccountID: "acc00000000000000001", Email: domain.Email(string(id) + "@example.invalid"),
		DisplayName: "Person", InviteStatus: status}
	s.users[id] = u
	return u
}

func (s *fakeStore) UserOf(_ context.Context, id domain.UserID) (domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	return u, nil
}

func (s *fakeStore) KeyByCredentialID(_ context.Context, cred []byte) (domain.AccessKey, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.keys {
		if bytes.Equal(k.CredentialID, cred) {
			return k, true, nil
		}
	}
	return domain.AccessKey{}, false, nil
}

func (s *fakeStore) KeysOf(_ context.Context, userID domain.UserID, _ string, _ int32) ([]domain.AccessKey, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []domain.AccessKey
	for _, k := range s.keys {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	return out, "", nil
}

func (s *fakeStore) CredentialIDsOf(_ context.Context, userID domain.UserID) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for _, k := range s.keys {
		if k.UserID == userID {
			out = append(out, k.CredentialID)
		}
	}
	return out, nil
}

func (s *fakeStore) Challenge(_ context.Context, ch []byte, userID domain.UserID, p domain.AccessKeyChallengePurpose) (domain.AccessKeyChallenge, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.challenges[string(ch)]
	if !ok || c.UserID != userID || c.Purpose != p {
		return domain.AccessKeyChallenge{}, false, nil
	}
	return c, true, nil
}

func (s *fakeStore) Writer(_ context.Context) (access_keys.Writer, error) {
	if s.failWriter {
		return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable")
	}
	return &fakeWriter{s: s, pendingKeys: map[domain.AccessKeyID]domain.AccessKey{}}, nil
}

// fakeWriter — транзакция дублёра: изменения копятся и ложатся Commit-ом.
type fakeWriter struct {
	s           *fakeStore
	pendingKeys map[domain.AccessKeyID]domain.AccessKey
	ops         []func()
	done        bool
}

func (w *fakeWriter) InsertChallenge(_ context.Context, c domain.AccessKeyChallenge) error {
	w.ops = append(w.ops, func() { w.s.challenges[string(c.Challenge)] = c })
	return nil
}

func (w *fakeWriter) ConsumeChallenge(_ context.Context, ch []byte, userID domain.UserID, p domain.AccessKeyChallengePurpose, now time.Time) (bool, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	c, ok := w.s.challenges[string(ch)]
	if !ok || c.UserID != userID || c.Purpose != p || c.ConsumedAt != nil || !now.Before(c.ExpiresAt) {
		return false, nil
	}
	at := now
	w.ops = append(w.ops, func() { c.ConsumedAt = &at; w.s.challenges[string(ch)] = c })
	return true, nil
}

func (w *fakeWriter) InsertKey(_ context.Context, k domain.AccessKey) (domain.AccessKey, error) {
	if err := k.Validate(); err != nil {
		return domain.AccessKey{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%v", err)
	}
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	for _, e := range w.s.keys {
		if bytes.Equal(e.CredentialID, k.CredentialID) {
			return domain.AccessKey{}, iamerr.Wrapf(iamerr.ErrAlreadyExists, "access key credential is already registered")
		}
	}
	if w.s.ceiling == nil {
		return domain.AccessKey{}, iamerr.Wrapf(iamerr.ErrQuotaNotProvisioned, "iam.user %s has no ceiling stated for iam.user.accessKey", k.UserID)
	}
	n := int64(0)
	for _, e := range w.s.keys {
		if e.UserID == k.UserID {
			n++
		}
	}
	if n >= *w.s.ceiling {
		return domain.AccessKey{}, iamerr.Wrapf(iamerr.ErrQuotaExceeded, "iam.user %s has reached its limit of %d iam.user.accessKey", k.UserID, *w.s.ceiling)
	}
	w.pendingKeys[k.ID] = k
	w.ops = append(w.ops, func() { w.s.keys[k.ID] = k })
	return k, nil
}

func (w *fakeWriter) LockKeysOf(_ context.Context, userID domain.UserID) ([]domain.AccessKey, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	var out []domain.AccessKey
	for _, k := range w.s.keys {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	return out, nil
}

func (w *fakeWriter) DeleteOwnedByID(_ context.Context, userID domain.UserID, id domain.AccessKeyID) (domain.AccessKey, bool, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	k, ok := w.s.keys[id]
	if !ok || k.UserID != userID {
		return domain.AccessKey{}, false, nil
	}
	w.ops = append(w.ops, func() { delete(w.s.keys, id) })
	return k, true, nil
}

func (w *fakeWriter) AdvanceSignCount(_ context.Context, id domain.AccessKeyID, expected, reported uint32, at time.Time) (bool, error) {
	if w.s.beforeAdvance != nil {
		w.s.beforeAdvance()
	}
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	k, ok := w.s.keys[id]
	if !ok || k.SignCount != expected {
		return false, nil
	}
	if !(expected == 0 && reported == 0) && reported <= expected {
		return false, nil
	}
	w.ops = append(w.ops, func() {
		k.SignCount = reported
		used := at
		k.LastUsedAt = &used
		w.s.keys[id] = k
	})
	return true, nil
}

func (w *fakeWriter) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	w.ops = append(w.ops, func() { w.s.audit = append(w.s.audit, ev) })
	return nil
}

func (w *fakeWriter) Commit(_ context.Context) error {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	if w.done {
		return nil
	}
	w.done = true
	for _, op := range w.ops {
		op()
	}
	return nil
}

func (w *fakeWriter) Rollback(_ context.Context) error {
	w.done = true
	return nil
}

func (s *fakeStore) auditOf(kind string) []outboxtypes.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []outboxtypes.AuditEvent
	for _, e := range s.audit {
		if e.EventType == kind {
			out = append(out, e)
		}
	}
	return out
}

func (s *fakeStore) keyCount(userID domain.UserID) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, k := range s.keys {
		if k.UserID == userID {
			n++
		}
	}
	return n
}

// fakeFreshness — момент последнего предъявления по человеку.
type fakeFreshness struct {
	mu sync.Mutex
	at map[domain.UserID]time.Time
}

func (f *fakeFreshness) LastPresentedAt(_ context.Context, id domain.UserID) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.at[id]
	return t, ok, nil
}

func (f *fakeFreshness) set(id domain.UserID, t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.at == nil {
		f.at = map[domain.UserID]time.Time{}
	}
	f.at[id] = t
}

// fakeMethods — есть ли пароль.
type fakeMethods struct{ password map[domain.UserID]bool }

func (m *fakeMethods) HasPassword(_ context.Context, id domain.UserID) (bool, error) {
	return m.password[id], nil
}

// recordingObserver — клетки как счётчики.
type recordingObserver struct {
	mu       sync.Mutex
	refusals map[string]int
	events   map[access_keys.Event]int
	signals  int
}

func newObserver() *recordingObserver {
	return &recordingObserver{refusals: map[string]int{}, events: map[access_keys.Event]int{}}
}

func (o *recordingObserver) AccessKeyRefusalObserved(l access_keys.Lane, r access_keys.Refusal) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refusals[string(l)+"/"+string(r)]++
}

func (o *recordingObserver) AccessKeyEventObserved(e access_keys.Event) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.events[e]++
}

func (o *recordingObserver) SignCountRegressionObserved() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.signals++
}

func (o *recordingObserver) refusal(l access_keys.Lane, r access_keys.Refusal) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.refusals[string(l)+"/"+string(r)]
}

func (o *recordingObserver) signalCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.signals
}
