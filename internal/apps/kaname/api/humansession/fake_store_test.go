// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// fake_store_test.go — дублёр хранилища для проб вариантов использования.
// НЕ снисходительнее настоящего: семантика операций та же, что у адаптера
// (снятие — отметка; замещение — только существующей строки; счёт — по оси и
// окну); подставные отказы — по имени операции, чтобы проба «одним исходом»
// могла уронить любую из записей.
//
// # Работа базы — тоже семантика
//
// Каждый метод повторяет у адаптера не только исход, но и РАБОТУ: вход,
// который адаптер отвергает аргументом, не доходя до базы, дублёр отвергает тем
// же классом отказа и без обхода; дошедший до базы — считает один оператор
// (`trips`). Порядок в каждом методе поэтому один: отказы аргументом адаптера →
// оператор (`trip`) → подставной отказ → семантика. Число читают журнал работы
// хранилища (`recording_store_test.go`) и замок равенства работы полос отказа;
// что дублёр на осях полос отвечает и работает как адаптер, держит сверка с
// настоящим адаптером над Postgres (`store_double_parity_integration_test.go`).

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
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
	// opened — каждая открытая транзакция, в порядке открытия: чем она открыта
	// и чьи записи сессии в ней сняты — часть утверждений о порядке замков.
	opened []*fakeWriter
	// trips — операторы базы, которые исполнил бы адаптер (шапка файла).
	trips atomic.Int64
}

// trip — один оператор базы: обращение, дошедшее до неё.
func (f *fakeStore) trip() { f.trips.Add(1) }

// tripCount — операторов базы с начала жизни дублёра.
func (f *fakeStore) tripCount() int64 { return f.trips.Load() }

// errFakeArg — отказ аргументом в форме адаптера: класс INVALID_ARGUMENT, базы
// обращение не касается.
func errFakeArg(text string) error { return iamerr.Wrapf(iamerr.ErrInvalidArg, "%s", text) }

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
	if digest == "" {
		// Адаптер: пустой свёртке строки не бывает — ответ без обхода базы.
		return humansession.Resolved{}, humansession.NoSessionUnknown, nil
	}
	f.trip()
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
	f.trip()
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
	f.trip()
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
	f.trip()
	return f.firstAuthentication(userID)
}

// firstAuthentication — чтение памяти первой аутентификации; оператор считает
// вызывающий (пул либо транзакция — оператор один).
func (f *fakeStore) firstAuthentication(userID domain.UserID) (time.Time, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at, ok := f.first[userID]
	return at, ok, nil
}

func (f *fakeStore) Writer(context.Context) (humansession.Writer, error) {
	w, err := f.open("")
	if err != nil {
		return nil, err
	}
	return w, nil
}

// SessionSetWriter — транзакция, открытая ДЕРЖАЩЕЙ строку личности. Замков
// дублёр не моделирует — ни ожиданий, ни взаимных блокировок: он запоминает,
// чьей строкой транзакция открыта, до первого её оператора, и повторяет РАБОТУ
// адаптера — открытие и оператор замка строки личности; у пустой личности
// оператор исполняется так же, но держать нечего (`holdPersonForSessionSet`).
func (f *fakeStore) SessionSetWriter(_ context.Context, userID domain.UserID) (humansession.Writer, error) {
	w, err := f.open(userID)
	if err != nil {
		return nil, err
	}
	if err := w.holdPerson(userID); err != nil {
		return nil, err
	}
	return w, nil
}

func (f *fakeStore) open(lockedFor domain.UserID) (*fakeWriter, error) {
	f.trip()
	if f.failOn == "writer" {
		return nil, errFakePort
	}
	w := &fakeWriter{store: f, lockedFor: lockedFor}
	f.mu.Lock()
	f.opened = append(f.opened, w)
	f.mu.Unlock()
	return w, nil
}

// fakeWriter — транзакция дублёра: записи копятся и применяются на Commit;
// Rollback их сбрасывает. Отказ по имени операции — на самой операции.
// Закрытая транзакция (зафиксирована либо откачена) откат базе не шлёт, как у
// адаптера.
type fakeWriter struct {
	store  *fakeStore
	ops    []func()
	closed bool
	// lockedFor — личность, чьей строкой транзакция открыта (`SessionSetWriter`);
	// пусто — открыта `Writer`.
	lockedFor domain.UserID
	// endedOthersOf — чьи записи сессии сняты `EndOtherSessions`, по вызову.
	endedOthersOf []domain.UserID
	// holds — личность, чью строку транзакция уже держит замком писателя
	// нескольких сессий (у адаптера — `humanSessionWriter.person`): повторного
	// оператора замка на ней нет, строку другой личности транзакция не берёт.
	holds domain.UserID
}

// errFakeSecondPerson — вторая личность в транзакции, уже держащей строку
// первой: у адаптера отказ класса INTERNAL без обращения к базе.
func errFakeSecondPerson() error {
	return iamerr.Wrapf(iamerr.ErrInternal,
		"human session writer: the transaction already holds another person and cannot serialize on a second one")
}

// holdPerson — оператор замка строки личности, если транзакция её ещё не
// держит (`holdPersonForSessionSet`): пустая личность — оператор есть, отметки
// нет.
func (w *fakeWriter) holdPerson(userID domain.UserID) error {
	if w.holds != "" && w.holds != userID {
		return errFakeSecondPerson()
	}
	if w.holds != "" {
		return nil
	}
	w.store.trip()
	w.holds = userID
	return nil
}

func (w *fakeWriter) fail(op string) error {
	if w.store.failOn == op {
		return errFakePort
	}
	return nil
}

func (w *fakeWriter) InsertSession(_ context.Context, s domain.HumanSession, digest domain.BearerDigest) error {
	if err := s.Validate(); err != nil {
		return errFakeArg(err.Error())
	}
	if digest == "" {
		return errFakeArg("Illegal argument human_session.bearer_digest: required")
	}
	w.store.trip()
	if err := w.fail("insert"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() { w.store.rows[s.ID] = &fakeRow{s: s, digest: digest} })
	return nil
}

func (w *fakeWriter) RememberFirstAuthentication(_ context.Context, userID domain.UserID, at time.Time) error {
	if userID == "" || at.IsZero() {
		return errFakeArg("Illegal argument first_authentication: user_id and moment required")
	}
	w.store.trip()
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

func (w *fakeWriter) FirstAuthentication(_ context.Context, userID domain.UserID) (time.Time, bool, error) {
	w.store.trip()
	return w.store.firstAuthentication(userID)
}

// EndSession — снятие одной записи и, если снята, отзыв выданного в ней
// (`revokeFamiliesOfSessionsTx`, kaname#313): у адаптера это второй оператор.
func (w *fakeWriter) EndSession(_ context.Context, id domain.HumanSessionID, at time.Time, reason string) (bool, error) {
	w.store.trip()
	if err := w.fail("end"); err != nil {
		return false, err
	}
	r, ok := w.store.rows[id]
	if !ok || r.ended != nil {
		return false, nil
	}
	w.store.trip()
	w.ops = append(w.ops, func() { r.ended = &at; r.reason = reason })
	return true, nil
}

func (w *fakeWriter) EndOtherSessions(_ context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error) {
	// Работа — как у адаптера: строка личности, если транзакция её ещё не
	// держит (kaname#340), оператор снятия и, если снято хоть что-то, отзыв
	// выданного в снятых записях (kaname#313).
	if err := w.holdPerson(userID); err != nil {
		return 0, err
	}
	w.store.trip()
	w.endedOthersOf = append(w.endedOthersOf, userID)
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
	if n > 0 {
		w.store.trip()
	}
	return n, nil
}

func (w *fakeWriter) RotateBearer(_ context.Context, id domain.HumanSessionID, digest domain.BearerDigest, presentedAt time.Time) error {
	if digest == "" {
		return errFakeArg("Illegal argument human_session.bearer_digest: required")
	}
	w.store.trip()
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

// PresentInSession — предъявление способа внутри сессии (Ф12): множество,
// уровень, носитель и момент — одной записью на живой строке.
func (w *fakeWriter) PresentInSession(_ context.Context, id domain.HumanSessionID, methods []string, level string, digest domain.BearerDigest, presentedAt time.Time) error {
	if digest == "" {
		return errFakeArg("Illegal argument human_session.bearer_digest: required")
	}
	if len(methods) == 0 {
		return errFakeArg("Illegal argument human_session.presented_methods: required")
	}
	w.store.trip()
	if err := w.fail("present"); err != nil {
		return err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	r, ok := w.store.rows[id]
	if !ok || r.ended != nil {
		return iamerr.Wrapf(iamerr.ErrNotFound, "HumanSession %s not found", id)
	}
	w.ops = append(w.ops, func() {
		if cur, ok := w.store.rows[id]; ok && cur.ended == nil {
			cur.s.PresentedMethods = append([]string(nil), methods...)
			cur.s.AssuranceLevel = level
			cur.s.LastPresentedAt = presentedAt
			cur.digest = digest
		}
	})
	return nil
}

func (w *fakeWriter) UpsertCutoff(_ context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	if err := u.Validate(); err != nil {
		return errFakeArg(err.Error())
	}
	// Две записи одной двери (`upsertSubjectCutoff`, kaname#313): строка
	// отсечки субъекта и отсечка выпущенного — два оператора.
	w.store.trip()
	if err := w.fail("cutoff"); err != nil {
		return err
	}
	w.store.trip()
	w.ops = append(w.ops, func() {
		cur, ok := w.store.cutoffs[u.UserID]
		if !ok || !u.RevokeBefore.Before(cur.at) {
			w.store.cutoffs[u.UserID] = fakeCutoff{at: u.RevokeBefore, reason: u.Reason, actor: revokedBy}
		}
	})
	return nil
}

func (w *fakeWriter) ReplaceLoginVerifier(_ context.Context, m domain.LoginMethod) (bool, error) {
	if err := m.Validate(); err != nil {
		return false, errFakeArg(err.Error())
	}
	w.store.trip()
	if err := w.fail("replace"); err != nil {
		return false, err
	}
	if _, ok := w.store.verifiers[m.UserID]; !ok {
		return false, nil
	}
	w.ops = append(w.ops, func() { w.store.verifiers[m.UserID] = m.Verifier })
	return true, nil
}

// LoginMethod — то же чтение, что `fakeMethods.Get`, транзакцией дублёра;
// отказ по имени "login-method". Пустую личность и вид вне словаря адаптер
// отвергает аргументом, до базы (`getLoginMethod`).
func (w *fakeWriter) LoginMethod(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	if userID == "" {
		return domain.LoginMethod{}, errFakeArg("Illegal argument login_method.user_id: required")
	}
	if err := kind.Validate(); err != nil {
		return domain.LoginMethod{}, errFakeArg(err.Error())
	}
	w.store.trip()
	if err := w.fail("login-method"); err != nil {
		return domain.LoginMethod{}, err
	}
	return fakeMethods{w.store}.Get(ctx, userID, kind)
}

func (w *fakeWriter) RecordFailure(_ context.Context, scope humansession.FailureScope, key string, at time.Time) error {
	if key == "" {
		return errFakeArg("Illegal argument login_failure.key: required")
	}
	w.store.trip()
	if err := w.fail("record-failure"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() { w.store.failures = append(w.store.failures, fakeFailure{scope: scope, key: key, at: at}) })
	return nil
}

func (w *fakeWriter) ResetFailures(_ context.Context, scope humansession.FailureScope, key string) error {
	w.store.trip()
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
	if ev.EventType == "" {
		// Адаптер: отказ записи события — без класса словаря, до базы.
		return errors.New("emit audit_outbox: event_type required")
	}
	w.store.trip()
	if err := w.fail("audit"); err != nil {
		return err
	}
	w.ops = append(w.ops, func() { w.store.audit = append(w.store.audit, ev) })
	return nil
}

// errFakeTxClosed — фиксация закрытой транзакции: у адаптера отказ без класса
// словаря и без обращения к базе.
var errFakeTxClosed = errors.New("fake store: tx is closed")

// Commit — фиксация закрывает транзакцию и при отказе: так закрывает её и
// соединение адаптера.
func (w *fakeWriter) Commit(context.Context) error {
	if w.closed {
		return errFakeTxClosed
	}
	w.store.trip()
	w.closed = true
	if err := w.fail("commit"); err != nil {
		return err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	for _, op := range w.ops {
		op()
	}
	return nil
}

// Rollback — у закрытой транзакции ничего не делает и базе ничего не шлёт.
func (w *fakeWriter) Rollback(context.Context) error {
	if w.closed {
		return nil
	}
	w.store.trip()
	w.closed = true
	w.ops = nil
	return nil
}

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
		return false, errFakeArg(err.Error())
	}
	if m.Kind != domain.LoginMethodTOTP || m.State != domain.LoginMethodStatePending || m.CreatedAt.IsZero() {
		return false, errFakeArg("Illegal argument login_method: enrollment row must be a pending totp row with its moment")
	}
	w.store.trip()
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
	if userID == "" || pendingSince.IsZero() || at.IsZero() {
		return false, errFakeArg("Illegal argument login_method: user, enrollment moment and confirmation moment required")
	}
	w.store.trip()
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
		return errFakeArg(err.Error())
	}
	if m.Kind != domain.LoginMethodLookupSecret || m.CreatedAt.IsZero() {
		return errFakeArg("Illegal argument login_method: lookup set row must be a lookup_secret row with its moment")
	}
	w.store.trip()
	if err := w.fail("replace-set"); err != nil {
		return err
	}
	w.store.mu.Lock()
	defer w.store.mu.Unlock()
	w.ops = append(w.ops, func() { w.putFactor(m) })
	return nil
}

func (w *fakeWriter) LockLookupSet(_ context.Context, userID domain.UserID) (domain.LoginMethod, bool, error) {
	if userID == "" {
		return domain.LoginMethod{}, false, errFakeArg("Illegal argument login_method.user_id: required")
	}
	w.store.trip()
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
	if userID == "" || element == "" || strings.ContainsRune(element, ',') {
		return false, errFakeArg("Illegal argument lookup element: required and without a separator")
	}
	w.store.trip()
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
	if userID == "" {
		return false, errFakeArg("Illegal argument login_method.user_id: required")
	}
	w.store.trip()
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
	if userID == "" {
		return false, errFakeArg("Illegal argument login_method.user_id: required")
	}
	w.store.trip()
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
	// Второй фактор (Ф12): предъявления по способу × исходу, отказы по причине,
	// события.
	sfPresent  map[string]int
	sfRefusals map[humansession.SecondFactorRefusal]int
	sfEvents   map[humansession.SecondFactorEvent]int
}

func newCountingObserver() *countingObserver {
	return &countingObserver{
		login: map[humansession.LoginOutcome]int{}, noSess: map[humansession.NoSessionReason]int{},
		rate: map[humansession.FailureScope]int{}, breach: map[humansession.BreachCheckOutcome]int{},
		rewrit: map[humansession.RewriteOutcome]int{}, form: map[humansession.FormRefusal]int{},
		recoveryRequest:    map[humansession.RecoveryRequestOutcome]int{},
		recoveryCompletion: map[humansession.RecoveryCompletionOutcome]int{},
		sfPresent:          map[string]int{},
		sfRefusals:         map[humansession.SecondFactorRefusal]int{},
		sfEvents:           map[humansession.SecondFactorEvent]int{},
	}
}

func (o *countingObserver) SecondFactorPresentationObserved(m assurance.Method, x humansession.PresentationOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sfPresent[m.String()+"/"+string(x)]++
}
func (o *countingObserver) SecondFactorRefusalObserved(x humansession.SecondFactorRefusal) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sfRefusals[x]++
}
func (o *countingObserver) SecondFactorEventObserved(x humansession.SecondFactorEvent) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sfEvents[x]++
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
