// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// fake_store_test.go — дублёр хранилища для проб вариантов использования.
// НЕ снисходительнее настоящего: семантика операций та же, что у адаптера
// (снятие — отметка; замещение — только существующей строки; счёт — по оси и
// окну); подставные отказы — по имени операции, чтобы проба «одним исходом»
// могла уронить любую из записей.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

type fakeRow struct {
	s      domain.HumanSession
	digest domain.BearerDigest
	ended  *time.Time
	reason string
}

type fakeFailure struct {
	scope humansession.FailureScope
	key   string
	at    time.Time
}

type fakeCutoff struct {
	at     time.Time
	reason string
	actor  domain.UserID
}

type fakeStore struct {
	mu        sync.Mutex
	rows      map[domain.HumanSessionID]*fakeRow
	users     map[domain.UserID]domain.User
	verified  map[domain.UserID]bool
	first     map[domain.UserID]time.Time
	failures  []fakeFailure
	cutoffs   map[domain.UserID]fakeCutoff
	verifiers map[domain.UserID]domain.LoginVerifier
	// factors — строки второго фактора (Ф12): вид → строка; пароль живёт в
	// verifiers, как прежде. Семантика операторов — та же, что у адаптера.
	factors map[domain.UserID]map[domain.LoginMethodKind]*domain.LoginMethod
	audit   []outboxtypes.AuditEvent
	// Восстановление доступа (Ф5): коды, письма, журнал завершений.
	codes       map[domain.RecoveryCodeID]*domain.RecoveryCode
	mail        []humansession.RecoveryMailIntent
	completions map[string]domain.RecoveryCompletion
	// failOn — имя операции, на которой Writer отказывает (подставной отказ
	// порта); "" — не отказывает. "writer" — отказ открыть транзакцию;
	// "resolve" — отказ чтения.
	failOn string
}

var errFakePort = errors.New("fake store: port failure")

func newFakeStore() *fakeStore {
	return &fakeStore{
		rows: map[domain.HumanSessionID]*fakeRow{}, users: map[domain.UserID]domain.User{},
		verified: map[domain.UserID]bool{}, first: map[domain.UserID]time.Time{},
		cutoffs: map[domain.UserID]fakeCutoff{}, verifiers: map[domain.UserID]domain.LoginVerifier{},
		factors: map[domain.UserID]map[domain.LoginMethodKind]*domain.LoginMethod{},
		codes:   map[domain.RecoveryCodeID]*domain.RecoveryCode{}, completions: map[string]domain.RecoveryCompletion{},
	}
}

func (f *fakeStore) Resolve(_ context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failOn == "resolve" {
		return humansession.Resolved{}, "", errFakePort
	}
	for _, r := range f.rows {
		if r.digest != digest {
			continue
		}
		switch {
		case r.ended != nil:
			return humansession.Resolved{}, humansession.NoSessionEnded, nil
		case r.s.Expired(now):
			return humansession.Resolved{}, humansession.NoSessionExpired, nil
		case f.users[r.s.UserID].InviteStatus != domain.InviteStatusActive:
			return humansession.Resolved{}, humansession.NoSessionBlocked, nil
		}
		return humansession.Resolved{Session: r.s, User: f.users[r.s.UserID], EmailVerified: f.verified[r.s.UserID]}, humansession.SessionFound, nil
	}
	return humansession.Resolved{}, humansession.NoSessionUnknown, nil
}

func (f *fakeStore) CountFailures(_ context.Context, scope humansession.FailureScope, key string, since time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, x := range f.failures {
		if x.scope == scope && x.key == key && x.at.After(since) {
			n++
		}
	}
	return n, nil
}

func (f *fakeStore) OldestFailureSince(_ context.Context, scope humansession.FailureScope, key string, since time.Time) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var oldest time.Time
	found := false
	for _, x := range f.failures {
		if x.scope == scope && x.key == key && x.at.After(since) && (!found || x.at.Before(oldest)) {
			oldest, found = x.at, true
		}
	}
	return oldest, found, nil
}

func (f *fakeStore) FirstAuthentication(_ context.Context, userID domain.UserID) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.first[userID]
	return at, ok, nil
}

func (f *fakeStore) Writer(context.Context) (humansession.Writer, error) {
	if f.failOn == "writer" {
		return nil, errFakePort
	}
	return &fakeWriter{store: f}, nil
}

// fakeWriter — транзакция дублёра: записи копятся и применяются на Commit;
// Rollback их сбрасывает. Отказ по имени операции — на самой операции.
type fakeWriter struct {
	store *fakeStore
	ops   []func()
	done  bool
}

func (w *fakeWriter) fail(op string) error {
	if w.store.failOn == op {
		return errFakePort
	}
	return nil
}

func (w *fakeWriter) InsertSession(_ context.Context, s domain.HumanSession, digest domain.BearerDigest) error {
	if err := s.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if err := w.fail("insert"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() { w.store.rows[s.ID] = &fakeRow{s: s, digest: digest} })
	return nil
}

func (w *fakeWriter) RememberFirstAuthentication(_ context.Context, userID domain.UserID, at time.Time) error {
	if err := w.fail("remember"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() {
		if cur, ok := w.store.first[userID]; !ok || at.Before(cur) {
			w.store.first[userID] = at
		}
	})
	return nil
}

func (w *fakeWriter) FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	return w.store.FirstAuthentication(ctx, userID)
}

func (w *fakeWriter) EndSession(_ context.Context, id domain.HumanSessionID, at time.Time, reason string) (bool, error) {
	if err := w.fail("end"); err != nil {
		return false, err
	}
	r, ok := w.store.rows[id]
	if !ok || r.ended != nil {
		return false, nil
	}
	w.ops = append(w.ops, func() { r.ended = &at; r.reason = reason })
	return true, nil
}

func (w *fakeWriter) EndOtherSessions(_ context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error) {
	if err := w.fail("end-others"); err != nil {
		return 0, err
	}
	n := 0
	for id, r := range w.store.rows {
		if r.s.UserID == userID && id != keep && r.ended == nil {
			n++
			row := r
			w.ops = append(w.ops, func() { row.ended = &at; row.reason = reason })
		}
	}
	return n, nil
}

func (w *fakeWriter) RotateBearer(_ context.Context, id domain.HumanSessionID, digest domain.BearerDigest, presentedAt time.Time) error {
	if err := w.fail("rotate"); err != nil {
		return err
	}
	r, ok := w.store.rows[id]
	if !ok || r.ended != nil {
		return iamerr.Wrapf(iamerr.ErrNotFound, "HumanSession %s not found", id)
	}
	w.ops = append(w.ops, func() { r.digest = digest; r.s.LastPresentedAt = presentedAt })
	return nil
}

func (w *fakeWriter) ClearPasswordChangeRequired(_ context.Context, id domain.HumanSessionID) error {
	if err := w.fail("clear-requirement"); err != nil {
		return err
	}
	if r, ok := w.store.rows[id]; ok {
		w.ops = append(w.ops, func() { r.s.PasswordChangeRequired = false })
	}
	return nil
}

func (w *fakeWriter) UpsertCutoff(_ context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	if err := w.fail("cutoff"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() {
		cur, ok := w.store.cutoffs[u.UserID]
		if !ok || !u.RevokeBefore.Before(cur.at) {
			w.store.cutoffs[u.UserID] = fakeCutoff{at: u.RevokeBefore, reason: u.Reason, actor: revokedBy}
		}
	})
	return nil
}

func (w *fakeWriter) ReplaceLoginVerifier(_ context.Context, m domain.LoginMethod) (bool, error) {
	if err := w.fail("replace"); err != nil {
		return false, err
	}
	if _, ok := w.store.verifiers[m.UserID]; !ok {
		return false, nil
	}
	w.ops = append(w.ops, func() { w.store.verifiers[m.UserID] = m.Verifier })
	return true, nil
}

func (w *fakeWriter) RecordFailure(_ context.Context, scope humansession.FailureScope, key string, at time.Time) error {
	if err := w.fail("record-failure"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() { w.store.failures = append(w.store.failures, fakeFailure{scope: scope, key: key, at: at}) })
	return nil
}

func (w *fakeWriter) ResetFailures(_ context.Context, scope humansession.FailureScope, key string) error {
	if err := w.fail("reset-failures"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() {
		kept := w.store.failures[:0]
		for _, x := range w.store.failures {
			if !(x.scope == scope && x.key == key) {
				kept = append(kept, x)
			}
		}
		w.store.failures = kept
	})
	return nil
}

func (w *fakeWriter) EmitAudit(_ context.Context, ev outboxtypes.AuditEvent) error {
	if err := w.fail("audit"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() { w.store.audit = append(w.store.audit, ev) })
	return nil
}

func (w *fakeWriter) Commit(context.Context) error {
	if err := w.fail("commit"); err != nil {
		return err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	for _, op := range w.ops {
		op()
	}
	w.done = true
	return nil
}

func (w *fakeWriter) Rollback(context.Context) error { w.ops = nil; return nil }

// --- второй фактор (Ф12): семантика операторов адаптера, не снисходительнее ---

func (w *fakeWriter) factorRow(userID domain.UserID, kind domain.LoginMethodKind) (*domain.LoginMethod, bool) {
	row, ok := w.store.factors[userID][kind]
	return row, ok
}

func (w *fakeWriter) putFactor(m domain.LoginMethod) {
	if w.store.factors[m.UserID] == nil {
		w.store.factors[m.UserID] = map[domain.LoginMethodKind]*domain.LoginMethod{}
	}
	row := m
	w.store.factors[m.UserID][m.Kind] = &row
}

func (w *fakeWriter) UpsertPendingTOTP(_ context.Context, m domain.LoginMethod) (bool, error) {
	if err := m.Validate(); err != nil {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if err := w.fail("enroll"); err != nil {
		return false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	if row, ok := w.factorRow(m.UserID, domain.LoginMethodTOTP); ok && row.State == domain.LoginMethodStateActive {
		return false, nil
	}
	w.ops = append(w.ops, func() { w.putFactor(m) })
	return true, nil
}

func (w *fakeWriter) ActivateTOTP(_ context.Context, userID domain.UserID, pendingSince time.Time, step int64, at time.Time) (bool, error) {
	if err := w.fail("activate"); err != nil {
		return false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	row, ok := w.factorRow(userID, domain.LoginMethodTOTP)
	if !ok || row.State != domain.LoginMethodStatePending || !row.CreatedAt.Equal(pendingSince) {
		return false, nil
	}
	w.ops = append(w.ops, func() {
		if cur, ok := w.factorRow(userID, domain.LoginMethodTOTP); ok && cur.State == domain.LoginMethodStatePending && cur.CreatedAt.Equal(pendingSince) {
			cur.State, cur.AcceptedStep, cur.StepAccepted, cur.CreatedAt = domain.LoginMethodStateActive, step, true, at
		}
	})
	return true, nil
}

func (w *fakeWriter) ReplaceLookupSet(_ context.Context, m domain.LoginMethod) error {
	if err := m.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", err.Error())
	}
	if err := w.fail("replace-set"); err != nil {
		return err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	w.ops = append(w.ops, func() { w.putFactor(m) })
	return nil
}

func (w *fakeWriter) LockLookupSet(_ context.Context, userID domain.UserID) (domain.LoginMethod, bool, error) {
	if err := w.fail("lock-set"); err != nil {
		return domain.LoginMethod{}, false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	row, ok := w.factorRow(userID, domain.LoginMethodLookupSecret)
	if !ok {
		return domain.LoginMethod{}, false, nil
	}
	return *row, true, nil
}

func (w *fakeWriter) ConsumeLookupElement(_ context.Context, userID domain.UserID, element string) (bool, error) {
	if err := w.fail("consume"); err != nil {
		return false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	row, ok := w.factorRow(userID, domain.LoginMethodLookupSecret)
	if !ok || !strings.Contains(row.Verifier.Reveal(), ","+element+",") {
		return false, nil
	}
	w.ops = append(w.ops, func() {
		cur, ok := w.factorRow(userID, domain.LoginMethodLookupSecret)
		if !ok {
			return
		}
		v, err := domain.NewLoginVerifier(strings.Replace(cur.Verifier.Reveal(), ","+element+",", ",", 1))
		if err == nil {
			cur.Verifier = v
		}
	})
	return true, nil
}

func (w *fakeWriter) RecordAcceptedStep(_ context.Context, userID domain.UserID, step int64) (bool, error) {
	if err := w.fail("record-step"); err != nil {
		return false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	row, ok := w.factorRow(userID, domain.LoginMethodTOTP)
	if !ok || row.State != domain.LoginMethodStateActive || (row.StepAccepted && row.AcceptedStep >= step) {
		return false, nil
	}
	w.ops = append(w.ops, func() {
		if cur, ok := w.factorRow(userID, domain.LoginMethodTOTP); ok && cur.State == domain.LoginMethodStateActive && (!cur.StepAccepted || cur.AcceptedStep < step) {
			cur.AcceptedStep, cur.StepAccepted = step, true
		}
	})
	return true, nil
}

func (w *fakeWriter) RemoveSecondFactor(_ context.Context, userID domain.UserID) (bool, error) {
	if err := w.fail("remove-factor"); err != nil {
		return false, err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	row, ok := w.factorRow(userID, domain.LoginMethodTOTP)
	if !ok || row.State != domain.LoginMethodStateActive {
		return false, nil
	}
	w.ops = append(w.ops, func() {
		delete(w.store.factors[userID], domain.LoginMethodTOTP)
		delete(w.store.factors[userID], domain.LoginMethodLookupSecret)
	})
	return true, nil
}

// Дублёры соседних портов.

type fakeUsers struct{ store *fakeStore }

func (d fakeUsers) UserByEmail(_ context.Context, email domain.Email) (domain.User, error) {
	for _, u := range d.store.users {
		if humansession.AddressKey(string(u.Email)) == humansession.AddressKey(string(email)) {
			return u, nil
		}
	}
	return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User with email %s not found", email)
}

type fakeMethods struct{ store *fakeStore }

func (m fakeMethods) Create(_ context.Context, lm domain.LoginMethod) (domain.LoginMethod, error) {
	m.store.verifiers[lm.UserID] = lm.Verifier
	return lm, nil
}

func (m fakeMethods) Get(_ context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	m.store.mu.Lock()
	defer m.store.mu.Unlock()
	if kind != domain.LoginMethodPassword {
		if row, ok := m.store.factors[userID][kind]; ok {
			return *row, nil
		}
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrNotFound, "Login method %s of user %s not found", kind, userID)
	}
	v, ok := m.store.verifiers[userID]
	if !ok {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrNotFound, "Login method %s of user %s not found", kind, userID)
	}
	return domain.LoginMethod{UserID: userID, Kind: kind, Verifier: v, State: domain.LoginMethodStateActive}, nil
}

func (m fakeMethods) MarkEmailVerified(_ context.Context, userID domain.UserID, _ domain.Email, _ time.Time) error {
	m.store.verified[userID] = true
	return nil
}

func (m fakeMethods) EmailVerification(_ context.Context, userID domain.UserID) (time.Time, bool, error) {
	if m.store.verified[userID] {
		return time.Unix(1, 0), true, nil
	}
	return time.Time{}, false, nil
}

// countingObserver — приёмник, считающий клетки.
type countingObserver struct {
	mu     sync.Mutex
	login  map[humansession.LoginOutcome]int
	noSess map[humansession.NoSessionReason]int
	rate   map[humansession.FailureScope]int
	breach map[humansession.BreachCheckOutcome]int
	rewrit map[humansession.RewriteOutcome]int
	form   map[humansession.FormRefusal]int
	logout int
	// Восстановление доступа (Ф5).
	recoveryRequest    map[humansession.RecoveryRequestOutcome]int
	recoveryCompletion map[humansession.RecoveryCompletionOutcome]int
	// sourceUnknown — вопросов о частоте без адреса источника.
	sourceUnknown int
}

func newCountingObserver() *countingObserver {
	return &countingObserver{
		login: map[humansession.LoginOutcome]int{}, noSess: map[humansession.NoSessionReason]int{},
		rate: map[humansession.FailureScope]int{}, breach: map[humansession.BreachCheckOutcome]int{},
		rewrit: map[humansession.RewriteOutcome]int{}, form: map[humansession.FormRefusal]int{},
		recoveryRequest:    map[humansession.RecoveryRequestOutcome]int{},
		recoveryCompletion: map[humansession.RecoveryCompletionOutcome]int{},
	}
}

func (o *countingObserver) LoginObserved(x humansession.LoginOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.login[x]++
}
func (o *countingObserver) NoSessionObserved(x humansession.NoSessionReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.noSess[x]++
}
func (o *countingObserver) FormRefusalObserved(x humansession.FormRefusal) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.form[x]++
}
func (o *countingObserver) SourceUnknownObserved() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sourceUnknown++
}
func (o *countingObserver) RateLimitObserved(x humansession.FailureScope) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rate[x]++
}
func (o *countingObserver) BreachCheckObserved(x humansession.BreachCheckOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.breach[x]++
}
func (o *countingObserver) LogoutStoreFailureObserved() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.logout++
}
func (o *countingObserver) RewriteObserved(x humansession.RewriteOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rewrit[x]++
}
