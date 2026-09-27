// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_versus_own_logout_integration_test.go — ПРИЧИНУ ПИШЕТ ТОТ, КТО
// СНЯЛ ЗАПИСЬ ПЕРВЫМ, И ВЫХОД НАЗЫВАЕТ СВОЙ ИСХОД ТАК ЖЕ, КАК ЗАПИСЬ (задача
// kaname#334; приёмка
// `docs/engineering/acceptance/forced-exit-has-its-own-session-end-reason.md`,
// KN-SER-05, половины 05/1…05/4; таблица «снят производитель → какая половина
// краснеет» — под §5).
//
// ─────────────────────────────────────────────────────────────────────────────
// СТРОКА ПРОТИВ СЕБЯ САМОЙ НЕ СВИДЕТЕЛЬ
//
// Второе снятие поверх первого переписало бы ту же пару (`ended_at`,
// `ended_reason`), поэтому исход читается из мест ВНЕ строки (§0.6):
//
//   - `LogoutUseCase.Execute` — снята ли запись ЭТИМ вызовом;
//   - событие `iam.session.logged_out` с `session_id` записи в очереди аудита;
//   - вызов записи отсечки на писателе, выданном выходу, — по счёту обёртки;
//   - момент отсечки принудительного выхода (`revoke_before` у личности): глагол
//     пишет одно значение и в отсечку, и в снятие.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЁРТКА ХРАНИЛИЩА ВЫХОДА (§0.6 п.6)
//
// Выход берёт хранилище портом `humansession.Store`, принудительный выход —
// своей транзакцией `ForceLogoutWriter` своего экземпляра `HumanSessionRepo`.
// Поэтому обёртка на хранилище выхода задерживает ТОЛЬКО выход. Она ВСТРАИВАЕТ
// порт (семь методов) и переопределяет два: `Resolve` — задержка после
// «сессия есть», снимаемая каналом, и `Writer` — счёт вызовов записи отсечки.
// Сна нет нигде: порядок задают каналы, а не время.
//
// Три упорядоченные половины различает одно — где стоит принудительный выход
// относительно шагов выхода: после выхода (05/1), до его резолва (05/2), между
// резолвом и записью (05/4). 05/3 — спорный путь без порядка: старт сведён на
// входе двух операторов снятия, исход решает база.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

const (
	// serOrderBudget — предел ожидания шага сцены. Это не пауза: ожидание
	// кончается раньше, как только условие наступило, а по пределу проба
	// называет несостоявшийся шаг, а не висит.
	serOrderBudget = 30 * time.Second
	// serBarrierBudget — предел ожидания второй стороны на своде старта 05/3.
	serBarrierBudget = 5 * time.Second
	// serContestedRounds — раундов 05/3: «не меньше двадцати» (приёмка).
	serContestedRounds = 20
)

// serLogoutGate — задержка выхода между резолвом и открытием писателя.
type serLogoutGate struct {
	reached  chan struct{}
	release  chan struct{}
	reach    sync.Once
	open     sync.Once
	timedOut atomic.Bool
}

func newSERLogoutGate() *serLogoutGate {
	return &serLogoutGate{reached: make(chan struct{}), release: make(chan struct{})}
}

func (g *serLogoutGate) hold() {
	g.reach.Do(func() { close(g.reached) })
	select {
	case <-g.release:
	case <-time.After(serOrderBudget):
		g.timedOut.Store(true)
	}
}

func (g *serLogoutGate) lift() { g.open.Do(func() { close(g.release) }) }

// serLogoutStore — обёртка хранилища выхода.
type serLogoutStore struct {
	humansession.Store
	// gate — задержка после «сессия есть»; nil — задержки нет (05/3).
	gate *serLogoutGate
	// cutoffs — вызовы записи отсечки на писателе выхода.
	cutoffs *atomic.Int32
	// atEnd — свод старта 05/3 на входе снятия выхода; nil — свода нет.
	atEnd func()
}

func (s serLogoutStore) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	res, reason, err := s.Store.Resolve(ctx, digest, now)
	if err == nil && reason == humansession.SessionFound && s.gate != nil {
		s.gate.hold()
	}
	return res, reason, err
}

func (s serLogoutStore) Writer(ctx context.Context) (humansession.Writer, error) {
	w, err := s.Store.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return serLogoutWriter{Writer: w, cutoffs: s.cutoffs, atEnd: s.atEnd}, nil
}

// PersonWriter — транзакция выхода открывается ключевым замком строки личности
// (kaname#382); обёртка та же, что у `Writer`.
func (s serLogoutStore) PersonWriter(ctx context.Context, userID domain.UserID) (humansession.Writer, error) {
	w, err := s.Store.PersonWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	return serLogoutWriter{Writer: w, cutoffs: s.cutoffs, atEnd: s.atEnd}, nil
}

type serLogoutWriter struct {
	humansession.Writer
	cutoffs *atomic.Int32
	atEnd   func()
}

func (w serLogoutWriter) EndSession(ctx context.Context, id domain.HumanSessionID, at time.Time, reason string) (bool, error) {
	if w.atEnd != nil {
		w.atEnd()
	}
	return w.Writer.EndSession(ctx, id, at, reason)
}

func (w serLogoutWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	w.cutoffs.Add(1)
	return w.Writer.UpsertCutoff(ctx, u, revokedBy)
}

// serLogoutOutcome — ответ глагола выхода.
type serLogoutOutcome struct {
	ended bool
	err   error
}

// serStartLogout — выход носителем на часах пробы; ответ — в канал.
func (sc *serScene) serStartLogout(t *testing.T, store humansession.Store, clock time.Time,
	bearer domain.SessionBearer,
) <-chan serLogoutOutcome {
	t.Helper()
	uc, err := humansession.NewLogoutUseCase(store, nil, func() time.Time { return clock }, nil)
	require.NoError(t, err, "глагол выхода полосы входа")
	out := make(chan serLogoutOutcome, 1)
	go func() {
		ended, err := uc.Execute(sc.ctx, bearer)
		out <- serLogoutOutcome{ended: ended, err: err}
	}()
	return out
}

func serAwaitLogout(t *testing.T, ch <-chan serLogoutOutcome) serLogoutOutcome {
	t.Helper()
	select {
	case o := <-ch:
		return o
	case <-time.After(serOrderBudget):
		t.Fatalf("выход не ответил за %s — сцена не построена", serOrderBudget)
		return serLogoutOutcome{}
	}
}

func serAwaitReached(t *testing.T, g *serLogoutGate) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(serOrderBudget):
		t.Fatalf("Дано: резолв выхода не нашёл запись ЖИВОЙ за %s — задержка не взвелась, "+
			"и порядок актов не тот, о котором половина", serOrderBudget)
	}
}

// serLoggedOutEvents — событий выхода по идентификатору записи.
func (sc *serScene) serLoggedOutEvents(t *testing.T, id domain.HumanSessionID) int {
	t.Helper()
	var n int
	require.NoError(t, sc.pool.QueryRow(sc.ctx, `
		SELECT count(*) FROM kaname.audit_outbox
		 WHERE event_type = $1 AND event_payload->>'session_id' = $2`,
		humansession.AuditSessionLoggedOut, string(id)).Scan(&n), "счёт событий выхода")
	return n
}

// serForceLogoutDone — принудительный выход без причины; «Когда» требует,
// чтобы операция была завершена успехом.
func (sc *serScene) serForceLogoutDone(t *testing.T, h *internaliam.Handler, uid domain.UserID) {
	t.Helper()
	op, err := h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{UserId: string(uid)})
	require.NoError(t, err, "принудительный выход обязан завершиться успехом")
	require.True(t, op.GetDone(), "принудительный выход: done = true")
	require.Nil(t, op.GetError(), "принудительный выход: error пуст, получено %v", op.GetError())
}

// serMomentLabel — момент для текста отказа.
func serMomentLabel(p *time.Time) string {
	if p == nil {
		return "<NULL>"
	}
	return p.UTC().Format(time.RFC3339Nano)
}

// serProbeClock — часы выхода, которые задаёт проба: разрешение хранилища —
// микросекунда, и момент усечён до неё, чтобы строка и часы сравнивались
// равенством.
func serProbeClock() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// TestLogoutVersusForceLogout_KN_SER_05_1_LogoutFirstKeepsItsReasonAndMoment —
// выход, затем принудительный выход: первые причина и момент не переписаны.
func TestLogoutVersusForceLogout_KN_SER_05_1_LogoutFirstKeepsItsReasonAndMoment(t *testing.T) {
	sc := newSERScene(t)
	p := sc.serPerson(t)
	s := sc.serLiveSession(t, p)

	cutoffs := &atomic.Int32{}
	gate := newSERLogoutGate()
	clock := serProbeClock()
	done := sc.serStartLogout(t, serLogoutStore{Store: sc.sessions, gate: gate, cutoffs: cutoffs}, clock, s.bearer)
	serAwaitReached(t, gate)
	gate.lift()
	lo := serAwaitLogout(t, done)
	require.False(t, gate.timedOut.Load(), "Дано: задержку сняла проба, а не предел")
	require.NoError(t, lo.err, "выход без ошибки")

	sc.serForceLogoutDone(t, sc.handler, p.ID)

	assert.True(t, lo.ended, "Execute обязан вернуть ended = true: запись снял выход")
	assert.Equal(t, 1, sc.serLoggedOutEvents(t, s.id), "событие выхода для S — одно")
	assert.Equal(t, int32(1), cutoffs.Load(), "вызов записи отсечки на писателе выхода — один")
	row := sc.serRow(t, s.id)
	assert.Equal(t, serOwnLogoutReason, row.reason(),
		"у S причина собственного выхода: второй акт причину не переписывает")
	if assert.NotNil(t, row.endedAt, "у S стоит ended_at") {
		assert.True(t, row.endedAt.Equal(clock),
			"ended_at у S — момент часов выхода %s, а в строке %s: второй акт переписал момент",
			clock.Format(time.RFC3339Nano), serMomentLabel(row.endedAt))
	}
}

// TestLogoutVersusForceLogout_KN_SER_05_2_ForceLogoutFirstLeavesLogoutNothingToWrite
// — принудительный выход завершён, затем выход: выход отвечает «сессии нет» и
// ничего не пишет; строка несёт принудительный выход.
func TestLogoutVersusForceLogout_KN_SER_05_2_ForceLogoutFirstLeavesLogoutNothingToWrite(t *testing.T) {
	sc := newSERScene(t)
	p := sc.serPerson(t)
	s := sc.serLiveSession(t, p)

	sc.serForceLogoutDone(t, sc.handler, p.ID)

	cutoffs := &atomic.Int32{}
	gate := newSERLogoutGate()
	done := sc.serStartLogout(t, serLogoutStore{Store: sc.sessions, gate: gate, cutoffs: cutoffs}, serProbeClock(), s.bearer)
	resolvedLive := false
	var lo serLogoutOutcome
	select {
	case lo = <-done:
	case <-gate.reached:
		// Задержке не на чем срабатывать: резолв, нашедший запись живой ПОСЛЕ
		// завершённого принудительного выхода, — находка, а не фикстура.
		resolvedLive = true
		gate.lift()
		lo = serAwaitLogout(t, done)
	case <-time.After(serOrderBudget):
		t.Fatalf("выход не ответил за %s", serOrderBudget)
	}

	assert.False(t, resolvedLive, "резолв выхода нашёл S ЖИВОЙ после завершённого принудительного выхода")
	assert.NoError(t, lo.err, "выход без ошибки (Ф3-18)")
	assert.False(t, lo.ended, "Execute обязан вернуть ended = false: запись снял не выход")
	assert.Zero(t, sc.serLoggedOutEvents(t, s.id), "событий выхода для S — ноль")
	assert.Zero(t, cutoffs.Load(), "вызовов записи отсечки на писателе выхода — ноль")
	row := sc.serRow(t, s.id)
	cut := sc.serCutoffOf(t, p.ID)
	assert.Equal(t, serForcedExitReason, row.reason(), "у S причина принудительного выхода")
	if assert.NotNil(t, row.endedAt, "у S стоит ended_at") {
		assert.True(t, row.endedAt.Equal(cut.revokeBefore),
			"ended_at у S (%s) обязан равняться моменту отсечки принудительного выхода (%s)",
			serMomentLabel(row.endedAt), cut.revokeBefore.UTC().Format(time.RFC3339Nano))
	}
}

// TestLogoutVersusForceLogout_KN_SER_05_4_ForceLogoutBetweenResolveAndWriteWins
// — выход нашёл запись живой и задержан; принудительный выход завершается;
// выход доходит до своей записи и ничего не пишет.
func TestLogoutVersusForceLogout_KN_SER_05_4_ForceLogoutBetweenResolveAndWriteWins(t *testing.T) {
	sc := newSERScene(t)
	p := sc.serPerson(t)
	s := sc.serLiveSession(t, p)

	cutoffs := &atomic.Int32{}
	gate := newSERLogoutGate()
	clock := serProbeClock()
	done := sc.serStartLogout(t, serLogoutStore{Store: sc.sessions, gate: gate, cutoffs: cutoffs}, clock, s.bearer)
	serAwaitReached(t, gate)
	sc.serForceLogoutDone(t, sc.handler, p.ID)
	gate.lift()
	lo := serAwaitLogout(t, done)
	require.False(t, gate.timedOut.Load(), "Дано: задержку сняла проба, а не предел")

	assert.NoError(t, lo.err, "выход без ошибки (Ф3-18)")
	assert.False(t, lo.ended, "Execute обязан вернуть ended = false: запись снял принудительный выход")
	assert.Zero(t, sc.serLoggedOutEvents(t, s.id), "событий выхода для S — ноль")
	assert.Zero(t, cutoffs.Load(), "вызовов записи отсечки на писателе выхода — ноль")
	row := sc.serRow(t, s.id)
	cut := sc.serCutoffOf(t, p.ID)
	assert.Equal(t, serForcedExitReason, row.reason(), "у S причина принудительного выхода")
	if assert.NotNil(t, row.endedAt, "у S стоит ended_at") {
		assert.True(t, row.endedAt.Equal(cut.revokeBefore),
			"ended_at у S (%s) обязан равняться моменту отсечки принудительного выхода (%s); "+
				"момент часов выхода — %s",
			serMomentLabel(row.endedAt), cut.revokeBefore.UTC().Format(time.RFC3339Nano),
			clock.Format(time.RFC3339Nano))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 05/3 — СПОРНЫЙ ПУТЬ

// serStartBarrier — свод старта: принудительный выход ждёт на входе своего
// снятия, выход — на входе своего; обе стороны отпускаются вместе.
type serStartBarrier struct {
	force, logout         chan struct{}
	forceOnce, logoutOnce sync.Once
	met                   atomic.Int32
}

func newSERStartBarrier() *serStartBarrier {
	return &serStartBarrier{force: make(chan struct{}), logout: make(chan struct{})}
}

func (b *serStartBarrier) arrive(mine chan struct{}, once *sync.Once, other chan struct{}) {
	once.Do(func() { close(mine) })
	select {
	case <-other:
		b.met.Add(1)
	case <-time.After(serBarrierBudget):
	}
}

func (b *serStartBarrier) forceArrives()  { b.arrive(b.force, &b.forceOnce, b.logout) }
func (b *serStartBarrier) logoutArrives() { b.arrive(b.logout, &b.logoutOnce, b.force) }

// serStepLog — шаги, на которых отказала транзакция принудительного выхода.
type serStepLog struct {
	mu    sync.Mutex
	steps []string
}

func (l *serStepLog) note(step string, err error) {
	if err == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.steps = append(l.steps, step+": "+err.Error())
}

func (l *serStepLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.steps...)
}

// serForceSide — исполнитель снятия принудительного выхода с сводом старта и
// записью шага отказа. Реализация — настоящая; обёртка ничего не решает.
type serForceSide struct {
	inner   internaliam.OwnSessions
	barrier *serStartBarrier
	steps   *serStepLog
}

func (o serForceSide) ForceLogoutWriter(ctx context.Context, subject domain.UserID,
	lockWait time.Duration,
) (internaliam.OwnSessionsWriter, error) {
	w, err := o.inner.ForceLogoutWriter(ctx, subject, lockWait)
	if err != nil {
		o.steps.note("открытие", err)
		return nil, err
	}
	return serForceWriter{inner: w, barrier: o.barrier, steps: o.steps}, nil
}

type serForceWriter struct {
	inner   internaliam.OwnSessionsWriter
	barrier *serStartBarrier
	steps   *serStepLog
}

func (w serForceWriter) EndOtherSessions(ctx context.Context, userID domain.UserID,
	keep domain.HumanSessionID, at time.Time, reason string,
) (int, error) {
	w.barrier.forceArrives()
	n, err := w.inner.EndOtherSessions(ctx, userID, keep, at, reason)
	w.steps.note("снятие", err)
	return n, err
}

func (w serForceWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	err := w.inner.UpsertCutoff(ctx, u, revokedBy)
	w.steps.note("отсечка", err)
	return err
}

func (w serForceWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	err := w.inner.EmitAudit(ctx, ev)
	w.steps.note("событие", err)
	return err
}

func (w serForceWriter) Commit(ctx context.Context) error {
	err := w.inner.Commit(ctx)
	w.steps.note("фиксация", err)
	return err
}

func (w serForceWriter) Rollback(ctx context.Context) error { return w.inner.Rollback(ctx) }

// serRound — исход одного раунда 05/3.
type serRound struct {
	n           int
	logout      serLogoutOutcome
	forceErr    error
	forceDone   bool
	forceOpErr  string
	reason      string
	events      int
	cutoffCalls int32
	barrierMet  int32
	forceSteps  []string
}

// mismatch — расхождение исхода, названного выходом, с записью; "" — согласны.
func (r serRound) mismatch() string {
	var out []string
	if r.logout.err != nil {
		out = append(out, "выход отказал: "+r.logout.err.Error())
	}
	if r.forceErr != nil {
		out = append(out, fmt.Sprintf("принудительный выход отказал: %v (шаги: %s)", r.forceErr, strings.Join(r.forceSteps, "; ")))
	} else if !r.forceDone || r.forceOpErr != "" {
		out = append(out, fmt.Sprintf("операция принудительного выхода: done=%t error=%q", r.forceDone, r.forceOpErr))
	}
	switch r.reason {
	case serOwnLogoutReason:
		if !r.logout.ended || r.events != 1 || r.cutoffCalls != 1 {
			out = append(out, fmt.Sprintf("ended_reason=%q, а Execute вернул ended=%t, событий выхода %d, вызовов записи отсечки %d "+
				"(при `logout` обязаны быть true, 1, 1)", r.reason, r.logout.ended, r.events, r.cutoffCalls))
		}
	case serForcedExitReason:
		if r.logout.ended || r.events != 0 || r.cutoffCalls != 0 {
			out = append(out, fmt.Sprintf("ended_reason=%q, а Execute вернул ended=%t, событий выхода %d, вызовов записи отсечки %d "+
				"(при `admin-force-logout` обязаны быть false, 0, 0)", r.reason, r.logout.ended, r.events, r.cutoffCalls))
		}
	default:
		out = append(out, fmt.Sprintf("ended_reason=%q — ни один из двух актов записи не назван "+
			"(Execute ended=%t, событий %d, вызовов записи отсечки %d)", r.reason, r.logout.ended, r.events, r.cutoffCalls))
	}
	if len(out) == 0 {
		return ""
	}
	return fmt.Sprintf("раунд %d: %s", r.n, strings.Join(out, "; "))
}

// TestLogoutVersusForceLogout_KN_SER_05_3_ContestedRoundsAgreeWithTheRecord —
// выход и принудительный выход одновременно, на свежей записи в каждом
// раунде: ни один глагол не отказывает, и исход, названный выходом,
// совпадает с записью. Кто выиграл, проба печатает, а не требует.
func TestLogoutVersusForceLogout_KN_SER_05_3_ContestedRoundsAgreeWithTheRecord(t *testing.T) {
	sc := newSERScene(t)
	ops := operations.NewRepo(sc.pool, "kaname")

	rounds := make([]serRound, 0, serContestedRounds)
	for n := 1; n <= serContestedRounds; n++ {
		p := sc.serPerson(t)
		s := sc.serLiveSession(t, p)

		barrier := newSERStartBarrier()
		steps := &serStepLog{}
		h := internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).
			WithSessionRevoker(kanamepg.NewSessionRevocationsAdapter(sc.pool)).
			WithAdminChecker(allowAdmin{}).
			WithOperations(ops).
			WithOwnSessions(serForceSide{inner: kanamepg.NewHumanSessionRepo(sc.pool), barrier: barrier, steps: steps})
		cutoffs := &atomic.Int32{}
		store := serLogoutStore{Store: sc.sessions, cutoffs: cutoffs, atEnd: barrier.logoutArrives}

		var wg sync.WaitGroup
		r := serRound{n: n}
		logoutDone := sc.serStartLogout(t, store, serProbeClock(), s.bearer)
		wg.Add(1)
		go func() {
			defer wg.Done()
			op, err := h.ForceLogout(forceLogoutAdminCtx(), &iamv1.ForceLogoutRequest{UserId: string(p.ID)})
			r.forceErr = err
			if err == nil {
				r.forceDone = op.GetDone()
				if op.GetError() != nil {
					r.forceOpErr = op.GetError().GetMessage()
				}
			}
		}()
		r.logout = serAwaitLogout(t, logoutDone)
		wg.Wait()

		r.reason = sc.serRow(t, s.id).reason()
		r.events = sc.serLoggedOutEvents(t, s.id)
		r.cutoffCalls = cutoffs.Load()
		r.barrierMet = barrier.met.Load()
		r.forceSteps = steps.all()
		rounds = append(rounds, r)
	}

	var (
		logoutWins, forceWins, forceRefusals, logoutRefusals, barriersMet int
		refusalSteps                                                      = map[string]int{}
		mismatches                                                        []string
	)
	for _, r := range rounds {
		if r.logout.ended {
			logoutWins++
		} else {
			forceWins++
		}
		if r.logout.err != nil {
			logoutRefusals++
		}
		if r.forceErr != nil {
			forceRefusals++
		}
		for _, st := range r.forceSteps {
			refusalSteps[strings.SplitN(st, ":", 2)[0]]++
		}
		if r.barrierMet == 2 {
			barriersMet++
		}
		if m := r.mismatch(); m != "" {
			mismatches = append(mismatches, m)
		}
	}
	stepNames := make([]string, 0, len(refusalSteps))
	for st, c := range refusalSteps {
		stepNames = append(stepNames, fmt.Sprintf("%s ×%d", st, c))
	}
	sort.Strings(stepNames)
	t.Logf("раундов %d: выход выиграл %d, принудительный выход выиграл %d (по счёту Execute); "+
		"отказов принудительного выхода %d (шаги отказа транзакции: %s); отказов выхода %d; "+
		"свод старта состоялся в %d раундах из %d",
		len(rounds), logoutWins, forceWins, forceRefusals, strings.Join(stepNames, ", "),
		logoutRefusals, barriersMet, len(rounds))

	if len(mismatches) != 0 {
		t.Fatalf("исход, названный выходом, разошёлся с записью в %d раундах из %d:\n  %s",
			len(mismatches), len(rounds), strings.Join(mismatches, "\n  "))
	}
}
