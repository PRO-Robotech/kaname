// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_overlap_harness_integration_test.go — СТЕНД проб границы входа с
// принудительным выходом (задача kaname#385, приёмка «вход, встретивший
// принудительный выход, не выдаёт сессии, которую отсечка уже накрыла», §4
// «Общее для всех сценариев»). Сами пробы — `login_overlap_integration_test.go`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИЗ ЧЕГО СОБРАН
//
// Вход — `POST /iam/v1/auth/login` слушателем полосы поверх настоящего
// `LoginUseCase` и настоящего `HumanSessionRepo` (`newSessionLaneWith`, те же
// конструкторы, что у корня). Принудительный выход — настоящий обработчик
// `InternalIAMService/ForceLogout`, собранный, как его собирает корень на посадке
// `own`: снятие наших записей провязано. Пара края — ответ службы краю о сессии
// (`Resolve` на соединении стенда) и `SessionCutoffOf` настоящим читателем
// отсечки. Всё — над одной базой в контейнере.
//
// Между вариантом использования входа и хранилищем стоит ОБЁРТКА ХРАНИЛИЩА
// ВХОДА (`overlapStore`), между обработчиком выхода и его хранилищем — ОБЁРТКА
// ВЫХОДА (`overlapForceSide`). Обе передают каждый вызов настоящей реализации и
// ничего не решают; они задерживают вызов каналом в названной точке. Точки
// транзакции выдачи в их порядке — З1 → З3 → З4 → З2, у выхода — З5. Задержка
// взводится пробой на ОДИН вызов (`overlapGates.arm`): первый вызов, дошедший
// до точки, её забирает, прочие проходят. Сна нет нигде: порядок задают каналы,
// а ожидание замка опознаётся по состоянию движка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАХВАТ СТРОКИ ЛИЧНОСТИ — ОПЕРАЦИЯ, КОТОРУЮ ОБЪЯВЛЯЕТ ЭТА ПРОБА
//
// Р4 заводит операцию писателя сессии: захват строки личности транзакцией
// выдачи входа, отвечающий стоящей отсечкой. Точка З3 — вход в неё, и обёртка
// перехватывает её ПО ИМЕНИ И ФОРМЕ, объявленным здесь (`personLoginLocker`):
//
//	LockPersonForLogin(ctx, userID) (revokeBefore time.Time, hasCutoff bool, err error)
//
// Четыре исхода Р4: (T, true, nil) — строка взята, отсечка T; (_, false, nil)
// — строка взята, отсечки нет; `NOT_FOUND` семейства `internal/errors` —
// строки нет; прочая ошибка — операция не ответила. Порт `humansession.Writer`
// этой операции ещё не объявляет, и транзакция выдачи её не зовёт — поэтому на
// дереве до правки перехватывать обёртке нечего: счёт её вызовов — ноль, точка
// З3 не наступает. Операция, объявленная портом под ИНЫМ именем, обёртку
// обошла бы, и счёт остался бы нулём; под тем же именем, но иной формой, стенд
// не соберётся — оба расхождения видны, а не молчат.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ КАТЕГОРИИ ИСХОДА
//
// Отказ фикстуры либо несостоявшаяся сцена (точка не наступила, событие не
// пришло за предел, выход не завершился, задержку снял предел, а не проба)
// печатается приставкой «НЕ ВЫПОЛНИЛОСЬ:» — это не красный правила. Красный —
// только утверждение «Тогда», которому противоречит исход на построенной сцене.
package loginlanehttp_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	sessionrev "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	// overlapSceneBudget — предел ожидания шага сцены. Не пауза: ожидание
	// кончается, как только условие наступило; по пределу проба называет
	// несостоявшийся шаг, а не висит.
	overlapSceneBudget = 20 * time.Second
	// overlapHoldBudget — предел задержки в точке. Задержка, снятая пределом, а
	// не пробой, — сцена не та, о которой сценарий.
	overlapHoldBudget = 30 * time.Second
	// overlapPollEvery — шаг опроса состояния движка. Выход ждёт замка не
	// дольше `forceLogoutLockWait` (2 с), и опрос обязан увидеть ожидание
	// раньше, чем оно кончится отказом.
	overlapPollEvery = 5 * time.Millisecond
	// overlapHTTPBudget — срок запроса клиента стенда: дольше задержки в точке.
	overlapHTTPBudget = 60 * time.Second
	// overlapBarrierBudget — предел ожидания второй стороны на своде старта
	// KN-OVL-05.
	overlapBarrierBudget = 5 * time.Second
	// overlapForcedExitReason — причина снятия записи принудительным выходом,
	// выписанная дословно, а не взятая из домена.
	overlapForcedExitReason = "admin-force-logout"
	// overlapAdminID — вызывающий принудительного выхода. Страж не предмет
	// сценариев: проверяющий привязок разрешает (§4, «Принудительный выход»).
	overlapAdminID = "usr0000000000000admin"
	// overlapSource — адрес источника, который прислал бы край.
	overlapSource = "203.0.113.7"
)

// overlapPoint — точка задержки (§4 «Общее»).
type overlapPoint string

const (
	pointOpen       overlapPoint = "З1 (открытие транзакции записи входа)"
	pointCapture    overlapPoint = "З3 (вход в захват строки личности)"
	pointInsert     overlapPoint = "З4 (вход в запись сессии)"
	pointCommit     overlapPoint = "З2 (фиксация транзакции выдачи)"
	pointExitCommit overlapPoint = "З5 (фиксация транзакции выхода)"
)

// errOverlapCaptureRefused — ответ обёртки на захват в KN-OVL-10: ошибка
// хранилища, вызов хранилищу не передан.
var errOverlapCaptureRefused = errors.New("login overlap probe: the store did not answer the person capture")

// errOverlapNoCapture — адаптер под обёрткой операции захвата не несёт. На
// дереве до правки недостижимо: транзакция выдачи захват не зовёт.
var errOverlapNoCapture = errors.New("login overlap probe: the session writer under the wrapper declares no person capture")

// ─────────────────────────────────────────────────────────────────────────────
// Задержки.

// overlapGate — одна задержка: точка достигнута → ждать снятия пробой.
type overlapGate struct {
	point     overlapPoint
	reached   chan struct{}
	release   chan struct{}
	reachOnce sync.Once
	liftOnce  sync.Once
	timedOut  atomic.Bool
}

func (g *overlapGate) hold() {
	g.reachOnce.Do(func() { close(g.reached) })
	select {
	case <-g.release:
	case <-time.After(overlapHoldBudget):
		g.timedOut.Store(true)
	}
}

func (g *overlapGate) lift() { g.liftOnce.Do(func() { close(g.release) }) }

// awaitReached — точка наступила; иначе сцена не построена.
func (g *overlapGate) awaitReached(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(overlapSceneBudget):
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: %s не дошёл до точки %s за %s — сцена не построена", what, g.point, overlapSceneBudget)
	}
}

// requireLiftedByProbe — задержку сняла проба, а не предел.
func (g *overlapGate) requireLiftedByProbe(t *testing.T) {
	t.Helper()
	if g.timedOut.Load() {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: задержку в точке %s снял предел %s, а не проба — сцена не та", g.point, overlapHoldBudget)
	}
}

// overlapGates — взведённые задержки, по одной на точку; взведённая
// забирается первым вызовом, дошедшим до точки (атомарно, один раз).
type overlapGates struct {
	mu    sync.Mutex
	armed map[overlapPoint]*overlapGate
	all   []*overlapGate
}

func newOverlapGates(t *testing.T) *overlapGates {
	gs := &overlapGates{armed: map[overlapPoint]*overlapGate{}}
	// Ни одна задержка не переживает пробу: упавшая посреди сцены проба иначе
	// оставила бы глагол висеть до предела.
	t.Cleanup(func() {
		gs.mu.Lock()
		defer gs.mu.Unlock()
		for _, g := range gs.all {
			g.lift()
		}
	})
	return gs
}

func (gs *overlapGates) arm(t *testing.T, p overlapPoint) *overlapGate {
	t.Helper()
	gs.mu.Lock()
	defer gs.mu.Unlock()
	if _, busy := gs.armed[p]; busy {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: точка %s уже взведена — сцена собрана неверно", p)
	}
	g := &overlapGate{point: p, reached: make(chan struct{}), release: make(chan struct{})}
	gs.armed[p] = g
	gs.all = append(gs.all, g)
	return g
}

func (gs *overlapGates) take(p overlapPoint) *overlapGate {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	g := gs.armed[p]
	delete(gs.armed, p)
	return g
}

// ─────────────────────────────────────────────────────────────────────────────
// Обёртка хранилища входа.

// personLoginLocker — операция захвата строки личности транзакцией выдачи
// входа в том имени и той форме, в которых её объявляет эта проба (шапка
// файла, Р4).
type personLoginLocker interface {
	LockPersonForLogin(ctx context.Context, userID domain.UserID) (time.Time, bool, error)
}

var _ personLoginLocker = (*overlapWriter)(nil)

// overlapStore — обёртка порта `humansession.Store` глагола входа.
type overlapStore struct {
	humansession.Store
	gates *overlapGates
	clock *overlapClock
	seq   *atomic.Int64

	// failCapture — KN-OVL-10: захват отвечает ошибкой, вызов хранилищу не
	// передаётся.
	failCapture atomic.Bool
	// captureCalls — вызовов захвата строки личности.
	captureCalls atomic.Int32
	// committing — порядковый номер входа в фиксацию транзакции выдачи, взятый
	// ДО оператора фиксации: выход, ждавший замка выдачи, отвечает только после
	// её фиксации, поэтому его номер позже при любом расписании горутин.
	committing atomic.Int64

	mu sync.Mutex
	// barrier — свод старта KN-OVL-05 на открытии транзакции выдачи; берётся
	// один раз.
	barrier func()
	// openReadings — показание часов входа, последнее к открытию каждой
	// транзакции записи входа.
	openReadings []time.Time
}

func (s *overlapStore) setBarrier(b func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.barrier = b
}

func (s *overlapStore) noteOpen() func() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.openReadings = append(s.openReadings, s.clock.latest())
	b := s.barrier
	s.barrier = nil
	return b
}

// readingsAtOpen — показания часов к открытию транзакций записи с номера from.
func (s *overlapStore) readingsAtOpen(from int) []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if from >= len(s.openReadings) {
		return nil
	}
	return append([]time.Time(nil), s.openReadings[from:]...)
}

func (s *overlapStore) opens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.openReadings)
}

func (s *overlapStore) Writer(ctx context.Context) (humansession.Writer, error) {
	if b := s.noteOpen(); b != nil {
		b()
	}
	if g := s.gates.take(pointOpen); g != nil {
		g.hold()
	}
	w, err := s.Store.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return &overlapWriter{Writer: w, store: s}, nil
}

// overlapWriter — обёртка транзакции записи входа.
type overlapWriter struct {
	humansession.Writer
	store    *overlapStore
	inserted atomic.Bool
}

// LockPersonForLogin — точка З3: счёт вызова, задержка, в KN-OVL-10 — ошибка
// без передачи вызова; иначе вызов уходит настоящему адаптеру.
func (w *overlapWriter) LockPersonForLogin(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	w.store.captureCalls.Add(1)
	if g := w.store.gates.take(pointCapture); g != nil {
		g.hold()
	}
	if w.store.failCapture.Load() {
		return time.Time{}, false, errOverlapCaptureRefused
	}
	inner, ok := w.Writer.(personLoginLocker)
	if !ok {
		return time.Time{}, false, errOverlapNoCapture
	}
	return inner.LockPersonForLogin(ctx, userID)
}

// InsertSession — точка З4.
func (w *overlapWriter) InsertSession(ctx context.Context, s domain.HumanSession, digest domain.BearerDigest) error {
	if g := w.store.gates.take(pointInsert); g != nil {
		g.hold()
	}
	err := w.Writer.InsertSession(ctx, s, digest)
	if err == nil {
		w.inserted.Store(true)
	}
	return err
}

// Commit — точка З2: только у транзакции, положившей запись сессии.
func (w *overlapWriter) Commit(ctx context.Context) error {
	if w.inserted.Load() {
		if g := w.store.gates.take(pointCommit); g != nil {
			g.hold()
		}
		w.store.committing.Store(w.store.seq.Add(1))
	}
	return w.Writer.Commit(ctx)
}

// ─────────────────────────────────────────────────────────────────────────────
// Приёмник исходов входа и часы входа.

// overlapObserver — клетки счётчика исходов входа (`LoginOutcomes()`).
type overlapObserver struct {
	humansession.NopObserver
	mu    sync.Mutex
	cells map[humansession.LoginOutcome]int
}

func (o *overlapObserver) LoginObserved(outcome humansession.LoginOutcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cells[outcome]++
}

// overlapCells — снимок клеток; «выросла на один» — разность двух снимков.
type overlapCells map[humansession.LoginOutcome]int

func (o *overlapObserver) snapshot() overlapCells {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := overlapCells{}
	for k, v := range o.cells {
		out[k] = v
	}
	return out
}

// Клетки, которые называют сценарии. `before-cutoff` заводит изменение
// (Р3), и в перечне дерева до правки её нет — проба называет её словом.
const (
	cellIssued       humansession.LoginOutcome = "issued"
	cellBeforeCutoff humansession.LoginOutcome = "before-cutoff"
	cellMismatched   humansession.LoginOutcome = "mismatched"
	cellNoRow        humansession.LoginOutcome = "no-row"
	cellStoreFailed  humansession.LoginOutcome = "store-failed"
)

// grew — на сколько клетка выросла между снимками.
func grew(before, after overlapCells, cell humansession.LoginOutcome) int {
	return after[cell] - before[cell]
}

// overlapClock — часы входа: часы процесса либо значение пробы; каждое
// показание запоминается.
type overlapClock struct {
	mu      sync.Mutex
	fixed   time.Time
	isFixed bool
	last    time.Time
}

func (c *overlapClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	v := time.Now()
	if c.isFixed {
		v = c.fixed
	}
	c.last = v
	return v
}

func (c *overlapClock) fix(v time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fixed, c.isFixed = v, true
}

// unfix — часы входа снова часы процесса.
func (c *overlapClock) unfix() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isFixed = false
}

func (c *overlapClock) latest() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// storeResolution — разрешение хранилища (§0.12): микросекунда.
func storeResolution(v time.Time) time.Time { return v.UTC().Truncate(time.Microsecond) }

// ─────────────────────────────────────────────────────────────────────────────
// Обёртка выхода.

// overlapExit — задержки, свод старта и журнал шагов транзакции выхода.
type overlapExit struct {
	gates *overlapGates
	mu    sync.Mutex
	// barrier — свод старта KN-OVL-05 на открытии транзакции выхода.
	barrier func()
	steps   []string
}

func (e *overlapExit) setBarrier(b func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.barrier = b
}

func (e *overlapExit) takeBarrier() func() {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := e.barrier
	e.barrier = nil
	return b
}

func (e *overlapExit) note(step string, err error) {
	if err == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.steps = append(e.steps, step+": "+err.Error())
}

func (e *overlapExit) refusedSteps() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.steps...)
}

// overlapForceSide — обёртка порта `internaliam.OwnSessions`.
type overlapForceSide struct {
	inner internaliam.OwnSessions
	exit  *overlapExit
}

func (o overlapForceSide) ForceLogoutWriter(ctx context.Context, subject domain.UserID,
	lockWait time.Duration,
) (internaliam.OwnSessionsWriter, error) {
	if b := o.exit.takeBarrier(); b != nil {
		b()
	}
	w, err := o.inner.ForceLogoutWriter(ctx, subject, lockWait)
	if err != nil {
		o.exit.note("открытие", err)
		return nil, err
	}
	return overlapForceWriter{inner: w, exit: o.exit}, nil
}

type overlapForceWriter struct {
	inner internaliam.OwnSessionsWriter
	exit  *overlapExit
}

func (w overlapForceWriter) EndOtherSessions(ctx context.Context, userID domain.UserID,
	keep domain.HumanSessionID, at time.Time, reason string,
) (int, error) {
	n, err := w.inner.EndOtherSessions(ctx, userID, keep, at, reason)
	w.exit.note("снятие", err)
	return n, err
}

func (w overlapForceWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	err := w.inner.UpsertCutoff(ctx, u, revokedBy)
	w.exit.note("отсечка", err)
	return err
}

func (w overlapForceWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	err := w.inner.EmitAudit(ctx, ev)
	w.exit.note("событие", err)
	return err
}

// Commit — точка З5: снятие, отсечка и событие положены, замок строки
// личности держится.
func (w overlapForceWriter) Commit(ctx context.Context) error {
	if g := w.exit.gates.take(pointExitCommit); g != nil {
		g.hold()
	}
	err := w.inner.Commit(ctx)
	w.exit.note("фиксация", err)
	return err
}

func (w overlapForceWriter) Rollback(ctx context.Context) error { return w.inner.Rollback(ctx) }

// overlapAllowAdmin — разрешающий проверяющий привязок.
type overlapAllowAdmin struct{}

func (overlapAllowAdmin) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Стенд.

// overlapLane — стенд проб границы.
type overlapLane struct {
	*sessionLane
	store   *overlapStore
	obs     *overlapObserver
	clock   *overlapClock
	exit    *overlapExit
	gates   *overlapGates
	force   *internaliam.Handler
	cutoffs *sessionrev.Handler
	slow    *http.Client
	status  *humansession.SecondFactorStatusUseCase
	seq     atomic.Int64
}

func newOverlapLane(t *testing.T) *overlapLane {
	t.Helper()
	gates := newOverlapGates(t)
	clock := &overlapClock{}
	obs := &overlapObserver{cells: map[humansession.LoginOutcome]int{}}
	h := &overlapLane{obs: obs, clock: clock, gates: gates, exit: &overlapExit{gates: gates}}
	h.sessionLane = newSessionLaneWith(t, sessionLaneOptions{
		loginStore: func(r *kanamepg.HumanSessionRepo) humansession.Store {
			h.store = &overlapStore{Store: r, gates: gates, clock: clock, seq: &h.seq}
			return h.store
		},
		loginObserver: obs,
		loginNow:      clock.Now,
	})
	require.NotNil(t, h.store, "НЕ ВЫПОЛНИЛОСЬ: стенд не отдал глаголу входа обёртку хранилища")
	h.force = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(h.pool)).
		WithAdminChecker(overlapAllowAdmin{}).
		WithOperations(operations.NewRepo(h.pool, "kaname")).
		WithOwnSessions(overlapForceSide{inner: kanamepg.NewHumanSessionRepo(h.pool), exit: h.exit})
	h.cutoffs = sessionrev.NewHandler(nil, nil).WithCutoffReader(kanamepg.NewUserTokenRevocationRepo(h.pool))
	status, err := humansession.NewSecondFactorStatusUseCase(h.secondFactor)
	require.NoError(t, err)
	h.status = status
	h.slow = h.slowClient(t)
	return h
}

// slowClient — клиент стенда со сроком дольше задержки в точке.
func (h *overlapLane) slowClient(t *testing.T) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(h.lane.ca.cert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{h.lane.ca.leaf(t, gatewaySAN, x509.ExtKeyUsageClientAuth)}}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: overlapHTTPBudget}
}

// overlapPerson — личность сцены.
type overlapPerson struct {
	id    domain.UserID
	email string
}

// personP — личность стенда: заведена регистрацией полосой, у неё S0.
func (h *overlapLane) personP() overlapPerson { return overlapPerson{id: h.user.ID, email: h.email} }

// registerPerson — свежая личность той же регистрацией полосой (S0 у неё есть).
func (h *overlapLane) registerPerson(t *testing.T) overlapPerson {
	t.Helper()
	email := "ovl-" + ids.NewID("tst")[3:11] + "@example.invalid"
	reg, err := h.register.Execute(h.ctx, registration.Input{Email: email, Password: integrationPassword, Source: overlapSource})
	require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: регистрация свежей личности")
	require.NotEmpty(t, reg.View.User.ID, "НЕ ВЫПОЛНИЛОСЬ: регистрация не назвала личность")
	return overlapPerson{id: reg.View.User.ID, email: email}
}

// seedMember — личность Q (§0.10): не-владелец без привязок и членств в
// аккаунте личности стенда, формой `seedAccountMember` соседа; строка пароля —
// писателем продукта `LoginMethodRepo.Create`. Записи сессии у Q нет.
func (h *overlapLane) seedMember(t *testing.T) overlapPerson {
	t.Helper()
	q := overlapPerson{id: domain.UserID(ids.NewID(domain.PrefixUser)), email: "ovq-" + ids.NewID("tst")[3:11] + "@example.invalid"}
	_, err := h.pool.Exec(h.ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		SELECT $1, account_id, $2, $3, 'Login Overlap Member', 'ACTIVE'
		  FROM kaname.users WHERE id = $4`,
		string(q.id), "ext-"+string(q.id), q.email, string(h.user.ID))
	require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: строка личности Q")
	v, err := h.hasher.Hash(integrationPassword)
	require.NoError(t, err)
	_, err = kanamepg.NewLoginMethodRepo(h.pool).Create(h.ctx, domain.LoginMethod{
		UserID: q.id, Kind: domain.LoginMethodPassword, Verifier: v, State: domain.LoginMethodStateActive,
		CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: строка пароля Q")
	var owned, bindings, memberships int
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT (SELECT count(*) FROM kaname.accounts WHERE owner_user_id = $1),
		       (SELECT count(*) FROM kaname.access_bindings WHERE subject_id = $1)
		     + (SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_id = $1),
		       (SELECT count(*) FROM kaname.group_members WHERE member_type = 'user' AND member_id = $1)`, string(q.id)).
		Scan(&owned, &bindings, &memberships), "НЕ ВЫПОЛНИЛОСЬ: перепись Q")
	require.Zero(t, owned+bindings+memberships,
		"НЕ ВЫПОЛНИЛОСЬ: Q обязана быть не-владельцем без привязок и членств (§0.10): владений %d, привязок %d, членств %d",
		owned, bindings, memberships)
	return q
}

// loginNow — вход без задержки, обязанный выдать сессию (фикстура).
func (h *overlapLane) loginNow(t *testing.T, p overlapPerson) laneSession {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	r := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathLogin,
		map[string]any{"email": p.email, "password": integrationPassword, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, r.status, "НЕ ВЫПОЛНИЛОСЬ: вход фикстуры: %s", r.body)
	s := laneSession{bearer: cookieNamed(r.cookies, loginlanehttp.CookieSession), form: cookieNamed(r.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer, "НЕ ВЫПОЛНИЛОСЬ: вход фикстуры не написал носитель")
	return s
}

// enrolledFactor — второй фактор личности глаголами Ф12 в сессии входа полосой
// (форма `sessionLane.enrolledSecondFactor`); отдаёт полный набор запасных
// кодов и проверяет, что он полон.
func (h *overlapLane) enrolledFactor(t *testing.T, p overlapPerson) []string {
	t.Helper()
	enroll, err := humansession.NewEnrollSecondFactorUseCase(h.secondFactor)
	require.NoError(t, err)
	confirm, err := humansession.NewConfirmSecondFactorUseCase(h.secondFactor)
	require.NoError(t, err)
	s := h.loginNow(t, p)
	bearer := domain.PresentedSessionBearer(s.bearer.Value)
	en, err := enroll.Execute(h.ctx, humansession.EnrollInput{Bearer: bearer})
	require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: заведение фактора")
	out, err := confirm.Execute(h.ctx, humansession.ConfirmInput{
		Bearer: bearer, Code: laneTOTP(t, en.Secret, totpverify.StepAt(time.Now())), Source: overlapSource,
	})
	require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: подтверждение фактора")
	require.Len(t, out.BackupCodes, passwordverify.BackupCodeCount, "НЕ ВЫПОЛНИЛОСЬ: подтверждение не выдало полного набора")
	// Подтверждение перевыпускает носитель сессии (Ф11 Р5): состояние читается
	// новым.
	require.Equal(t, passwordverify.BackupCodeCount, h.backupCodesRemaining(t, out.Bearer.CookieValue()),
		"НЕ ВЫПОЛНИЛОСЬ: набор после заведения не полон")
	return out.BackupCodes
}

// backupCodesRemaining — остаток набора глаголом состояния фактора из сессии
// носителя (форма `TestLaneIntegration_F12_28_…`).
func (h *overlapLane) backupCodesRemaining(t *testing.T, bearer string) int {
	t.Helper()
	st, err := h.status.Execute(h.ctx, humansession.StatusInput{Bearer: domain.PresentedSessionBearer(bearer)})
	require.NoError(t, err, "чтение состояния фактора")
	require.NotNil(t, st.BackupCodes, "у заведённого фактора есть набор")
	return st.BackupCodes.Remaining
}

// ─────────────────────────────────────────────────────────────────────────────
// Глаголы сцены, идущие параллельно пробе.

// overlapLoginReply — ответ входа на транспорте.
type overlapLoginReply struct {
	status int
	body   string
	bearer string
	err    error
	seq    int64
}

type overlapLoginCall struct {
	done chan struct{}
	res  overlapLoginReply
}

// startLogin — вход паролем (и запасным кодом, если code непуст) через
// слушатель; признак формы берётся до старта.
func (h *overlapLane) startLogin(t *testing.T, p overlapPerson, password, code string) *overlapLoginCall {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormLogin), nil)
	body := map[string]any{"email": p.email, "password": password, "csrfToken": tok}
	if code != "" {
		body["secondFactor"] = map[string]string{"method": assurance.MethodLookupSecret.String(), "code": code}
	}
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	call := &overlapLoginCall{done: make(chan struct{})}
	go func() {
		defer close(call.done)
		req, rerr := http.NewRequest(http.MethodPost, h.lane.srv.URL+loginlanehttp.PathLogin, bytes.NewReader(raw))
		if rerr != nil {
			call.res.err = rerr
			return
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range fwd() {
			req.Header.Set(k, v)
		}
		if ctxCk != nil {
			req.AddCookie(ctxCk)
		}
		resp, derr := h.slow.Do(req)
		if derr != nil {
			call.res.err = derr
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, berr := io.ReadAll(resp.Body)
		call.res.seq = h.seq.Add(1)
		call.res.status, call.res.body, call.res.err = resp.StatusCode, string(b), berr
		if ck := cookieNamed(resp.Cookies(), loginlanehttp.CookieSession); ck != nil {
			call.res.bearer = ck.Value
		}
	}()
	return call
}

func (c *overlapLoginCall) await(t *testing.T, what string) overlapLoginReply {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(overlapSceneBudget):
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: %s не ответил за %s", what, overlapSceneBudget)
	}
	require.NoError(t, c.res.err, "НЕ ВЫПОЛНИЛОСЬ: %s — ответа на транспорте нет", what)
	return c.res
}

// overlapExitReply — исход принудительного выхода.
type overlapExitReply struct {
	err   error
	done  bool
	opErr string
	seq   int64
}

// completed — «выход завершён»: операция `done = true`, `error` пуст.
func (r overlapExitReply) completed() bool { return r.err == nil && r.done && r.opErr == "" }

type overlapExitCall struct {
	done chan struct{}
	res  overlapExitReply
}

func (h *overlapLane) startForceLogout(p overlapPerson) *overlapExitCall {
	call := &overlapExitCall{done: make(chan struct{})}
	go func() {
		defer close(call.done)
		ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: overlapAdminID})
		op, err := h.force.ForceLogout(ctx, &iamv1.ForceLogoutRequest{UserId: string(p.id)})
		call.res.seq = h.seq.Add(1)
		call.res.err = err
		if err == nil {
			call.res.done = op.GetDone()
			if op.GetError() != nil {
				call.res.opErr = op.GetError().GetMessage()
			}
		}
	}()
	return call
}

func (c *overlapExitCall) await(t *testing.T) overlapExitReply {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(overlapSceneBudget):
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: принудительный выход не ответил за %s", overlapSceneBudget)
	}
	return c.res
}

// requireCompleted — «выход завершён»; иначе сцена не построена, и печатаются
// шаги транзакции выхода, на которых она отказала.
func (h *overlapLane) requireCompleted(t *testing.T, r overlapExitReply) {
	t.Helper()
	if !r.completed() {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: принудительный выход не завершён: err=%v done=%t error=%q; шаги отказа транзакции: %s",
			r.err, r.done, r.opErr, strings.Join(h.exit.refusedSteps(), "; "))
	}
}

// forceLogoutDone — принудительный выход, завершённый до следующего шага.
func (h *overlapLane) forceLogoutDone(t *testing.T, p overlapPerson) overlapExitReply {
	t.Helper()
	r := h.startForceLogout(p).await(t)
	h.requireCompleted(t, r)
	return r
}

type overlapDeleteCall struct {
	done chan struct{}
	err  error
}

// startDelete — удаление личности настоящим писателем полосы удаления в своей
// транзакции (форма соседа `TestIntegration_ForceLogoutAndIdentityDeletionDoNotDeadlock`).
func (h *overlapLane) startDelete(p overlapPerson) *overlapDeleteCall {
	call := &overlapDeleteCall{done: make(chan struct{})}
	go func() {
		defer close(call.done)
		w, err := h.users.Writer(h.ctx)
		if err != nil {
			call.err = err
			return
		}
		defer func() { _ = w.Rollback(h.ctx) }()
		if err := w.UsersW().Delete(h.ctx, p.id); err != nil {
			call.err = err
			return
		}
		call.err = w.Commit(h.ctx)
	}()
	return call
}

func (c *overlapDeleteCall) await(t *testing.T) error {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(overlapSceneBudget):
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: удаление не ответило за %s", overlapSceneBudget)
	}
	return c.err
}

// ─────────────────────────────────────────────────────────────────────────────
// Состояние движка.

// overlapEvent — первое из двух событий, которого ждёт сценарий.
type overlapEvent string

const (
	eventWaitsOnLock overlapEvent = "стоит на замке"
	eventFinished    overlapEvent = "ответил"
)

// lockWaiters — операторы базы стенда, стоящие на замке. Опознание — по
// состоянию движка (`wait_event_type = 'Lock'`), а не по тексту оператора:
// текст идёт только в печать.
func (h *overlapLane) lockWaiters(t *testing.T) []string {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT left(regexp_replace(query, '\s+', ' ', 'g'), 90) FROM pg_stat_activity
		 WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> pg_backend_pid()`)
	require.NoError(t, err, "наблюдатель замков")
	defer rows.Close()
	var out []string
	for rows.Next() {
		var q string
		require.NoError(t, rows.Scan(&q))
		out = append(out, q)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// firstOf — первое из двух событий: «транзакция стоит на замке» либо «глагол
// ответил». За предел — сцена не построена.
func (h *overlapLane) firstOf(t *testing.T, who string, done <-chan struct{}) (overlapEvent, []string) {
	t.Helper()
	ticker := time.NewTicker(overlapPollEvery)
	defer ticker.Stop()
	deadline := time.After(overlapSceneBudget)
	for {
		select {
		case <-done:
			return eventFinished, nil
		default:
		}
		if w := h.lockWaiters(t); len(w) > 0 {
			return eventWaitsOnLock, w
		}
		select {
		case <-done:
			return eventFinished, nil
		case <-ticker.C:
		case <-deadline:
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: %s за %s не встал на замке и не ответил", who, overlapSceneBudget)
		}
	}
}

// deadlocksNow — счётчик взаимных блокировок базы стенда до сцены.
func (h *overlapLane) deadlocksNow(t *testing.T) int64 {
	t.Helper()
	var n int64
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&n))
	return n
}

// overlapDeadlocksAfterPoolClose — счётчик взаимных блокировок, прочитанный
// ПОСЛЕ закрытия пула стенда своим соединением (форма соседа
// `deadlocksAfterPoolClose`): обслуживающий процесс сбрасывает статистику на
// выходе, а живой — лишь спустя интервал простоя. Пул после этого закрыт.
func (h *overlapLane) overlapDeadlocksAfterPoolClose(t *testing.T) int64 {
	t.Helper()
	h.pool.Close()
	conn, err := pgx.Connect(h.ctx, h.dsn)
	require.NoError(t, err, "соединение для чтения статистики")
	defer func() { _ = conn.Close(h.ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var others int
		require.NoError(t, conn.QueryRow(h.ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&others))
		if others == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: процессов пула в базе %d через 10 с после закрытия — статистика не сброшена", others)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var n int64
	require.NoError(t, conn.QueryRow(h.ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&n))
	return n
}

// ─────────────────────────────────────────────────────────────────────────────
// Наблюдения.

// overlapFootprint — три наблюдения «входом ничего не записано» (§4).
type overlapFootprint struct {
	sessions     int
	issuedEvents int
	failures     int
}

func (h *overlapLane) footprint(t *testing.T, p overlapPerson) overlapFootprint {
	t.Helper()
	var f overlapFootprint
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT (SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1),
		       (SELECT count(*) FROM kaname.audit_outbox WHERE event_type = $2 AND event_payload->>'user_id' = $1),
		       (SELECT count(*) FROM kaname.login_failures WHERE scope = $3 AND key = $4)`,
		string(p.id), humansession.AuditSessionIssued, string(humansession.FailureByAddress),
		humansession.AddressKey(p.email)).Scan(&f.sessions, &f.issuedEvents, &f.failures))
	return f
}

// overlapRow — запись сессии в хранилище службы.
type overlapRow struct {
	id      string
	authAt  time.Time
	endedAt *time.Time
	reason  *string
}

func (r overlapRow) live() bool { return r.endedAt == nil }

func (r overlapRow) endedReason() string {
	if r.reason == nil {
		return "<NULL>"
	}
	return *r.reason
}

func (r overlapRow) String() string {
	ended := "жива"
	if r.endedAt != nil {
		ended = "снята " + r.endedAt.UTC().Format(time.RFC3339Nano) + " (" + r.endedReason() + ")"
	}
	return fmt.Sprintf("%s authenticated_at=%s %s", r.id, r.authAt.UTC().Format(time.RFC3339Nano), ended)
}

func (h *overlapLane) rowsOf(t *testing.T, p overlapPerson) []overlapRow {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT id, authenticated_at, ended_at, ended_reason FROM kaname.human_sessions
		 WHERE user_id = $1 ORDER BY authenticated_at, id`, string(p.id))
	require.NoError(t, err, "чтение записей сессии")
	defer rows.Close()
	var out []overlapRow
	for rows.Next() {
		var r overlapRow
		require.NoError(t, rows.Scan(&r.id, &r.authAt, &r.endedAt, &r.reason))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

// rowOfBearer — запись по носителю; ok=false — записи нет.
func (h *overlapLane) rowOfBearer(t *testing.T, bearer string) (overlapRow, bool) {
	t.Helper()
	var r overlapRow
	err := h.pool.QueryRow(h.ctx, `
		SELECT id, authenticated_at, ended_at, ended_reason FROM kaname.human_sessions WHERE bearer_digest = $1`,
		string(domain.PresentedSessionBearer(bearer).Digest())).Scan(&r.id, &r.authAt, &r.endedAt, &r.reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return overlapRow{}, false
	}
	require.NoError(t, err, "чтение записи по носителю")
	return r, true
}

// storeReason — ответ резолва хранилища о носителе (`HumanSessionRepo.Resolve`).
func (h *overlapLane) storeReason(t *testing.T, bearer string) humansession.NoSessionReason {
	t.Helper()
	_, reason, err := h.sessions.Resolve(h.ctx, domain.PresentedSessionBearer(bearer).Digest(), time.Now().UTC())
	require.NoError(t, err, "резолв хранилища")
	return reason
}

// cutoffOf — отсечка личности, как её читает край (`SessionCutoffOf`).
func (h *overlapLane) cutoffOf(t *testing.T, p overlapPerson) (time.Time, bool) {
	t.Helper()
	resp, err := h.cutoffs.SessionCutoffOf(h.ctx, &iamv1.SessionCutoffOfRequest{UserId: string(p.id)})
	require.NoError(t, err, "SessionCutoffOf")
	if !resp.GetFound() {
		return time.Time{}, false
	}
	return resp.GetRevokeBefore().AsTime().UTC(), true
}

// requireCutoff — T: отсечка обязана стоять.
func (h *overlapLane) requireCutoff(t *testing.T, p overlapPerson) time.Time {
	t.Helper()
	cut, ok := h.cutoffOf(t, p)
	require.True(t, ok, "НЕ ВЫПОЛНИЛОСЬ: после выхода отсечки у личности нет")
	return cut
}

// overlapPair — пара края (§0.4): ответ `Resolve` о носителе и ответ
// `SessionCutoffOf` о личности.
type overlapPair struct {
	resolved    bool
	authAt      time.Time
	cutoffFound bool
	cutoff      time.Time
}

// fit — край судит пару включающе: годна ⟺ сессия найдена и её момент строго
// позже отсечки (правило края цитируется, здесь не исполняется иначе).
func (p overlapPair) fit() bool { return p.resolved && (!p.cutoffFound || p.authAt.After(p.cutoff)) }

func (p overlapPair) String() string {
	cut := "отсечки нет"
	if p.cutoffFound {
		cut = "отсечка " + p.cutoff.Format(time.RFC3339Nano)
	}
	return fmt.Sprintf("Resolve found=%t authenticatedAt=%s · %s", p.resolved, p.authAt.Format(time.RFC3339Nano), cut)
}

func (h *overlapLane) edgePair(t *testing.T, bearer string, p overlapPerson) overlapPair {
	t.Helper()
	out := overlapPair{}
	r := h.resolve(t, bearer)
	out.resolved = r.GetFound()
	if r.GetSession().GetAuthenticatedAt() != nil {
		out.authAt = r.GetSession().GetAuthenticatedAt().AsTime().UTC()
	}
	out.cutoff, out.cutoffFound = h.cutoffOf(t, p)
	return out
}

// exitEvents — записи события `iam.session.force_logout` о личности.
func (h *overlapLane) exitEvents(t *testing.T, p overlapPerson) []map[string]any {
	t.Helper()
	rows, err := h.pool.Query(h.ctx, `
		SELECT event_payload FROM kaname.audit_outbox
		 WHERE event_type = 'iam.session.force_logout' AND event_payload->>'subject_id' = $1
		 ORDER BY created_at, id`, string(p.id))
	require.NoError(t, err, "чтение событий выхода")
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		m := map[string]any{}
		require.NoError(t, json.Unmarshal(raw, &m))
		out = append(out, m)
	}
	require.NoError(t, rows.Err())
	return out
}

// sessionsEnded — `sessions_ended` единственного события выхода; -1 — поля нет.
func (h *overlapLane) sessionsEnded(t *testing.T, p overlapPerson) int {
	t.Helper()
	evs := h.exitEvents(t, p)
	require.Len(t, evs, 1, "НЕ ВЫПОЛНИЛОСЬ: один выход обязан оставить одно событие: %v", evs)
	v, ok := evs[0]["sessions_ended"].(float64)
	if !ok {
		return -1
	}
	return int(v)
}

// personGone — личности нет, её записей сессии и строк способов входа нет.
func (h *overlapLane) personGone(t *testing.T, p overlapPerson) (users, sessions, methods int) {
	t.Helper()
	require.NoError(t, h.pool.QueryRow(h.ctx, `
		SELECT (SELECT count(*) FROM kaname.users WHERE id = $1),
		       (SELECT count(*) FROM kaname.human_sessions WHERE user_id = $1),
		       (SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1)`, string(p.id)).
		Scan(&users, &sessions, &methods))
	return users, sessions, methods
}

// overlapRefusal — тело отказа слушателя.
type overlapRefusal struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func refusalOf(body string) (overlapRefusal, bool) {
	var r overlapRefusal
	if err := json.Unmarshal([]byte(body), &r); err != nil || r.Code == 0 {
		return overlapRefusal{}, false
	}
	return r, true
}

// oneRefusal — «тот же один отказ» (§4): 401, `UNAUTHENTICATED` (16), текст
// `authentication failed` — статус, код и текст вместе. "" — он.
func oneRefusal(r overlapLoginReply) string {
	ref, ok := refusalOf(r.body)
	if r.status == http.StatusUnauthorized && ok && ref.Code == 16 && ref.Message == humansession.TextAuthenticationFailed {
		return ""
	}
	return fmt.Sprintf("вход ответил %d %s, а не 401 UNAUTHENTICATED `authentication failed`", r.status, r.body)
}

// notPerformed — ответ «не выполнено» (Р4 исход 4): 503, `UNAVAILABLE` (14),
// текст `request not performed; try again later`. "" — он.
func notPerformed(r overlapLoginReply) string {
	ref, ok := refusalOf(r.body)
	if r.status == http.StatusServiceUnavailable && ok && ref.Code == 14 && ref.Message == humansession.TextRequestNotPerformed {
		return ""
	}
	return fmt.Sprintf("вход ответил %d %s, а не 503 UNAVAILABLE `request not performed; try again later`", r.status, r.body)
}

// firstDiff — первое различие двух тел.
func firstDiff(a, b string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return fmt.Sprintf("байт %d: %q против %q", i, a[i:min(len(a), i+24)], b[i:min(len(b), i+24)])
		}
	}
	if len(a) != len(b) {
		return fmt.Sprintf("длина %d против %d", len(a), len(b))
	}
	return ""
}

// momentLabel — момент для текста отказа.
func momentLabel(v time.Time) string { return v.UTC().Format(time.RFC3339Nano) }
