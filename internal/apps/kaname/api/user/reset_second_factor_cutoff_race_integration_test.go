// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reset_second_factor_cutoff_race_integration_test.go — сброс второго фактора
// против одновременного входа на НАСТОЯЩЕЙ базе (задача PRO-Robotech/kaname#680).
//
// # Предмет
//
// Записи сессии сброс не снимает — отсекает, поэтому «ВСЕ сессии человека
// покрыты отсечкой» держится только моментом отсечки. Сессия, выпущенная до
// фиксации сброса, обязана быть отсечена: момент аутентификации НЕ позже
// отсечки (правило края, сравнение включающее — `RevokedBefore`).
//
// # Две сцены, детерминированным чередованием, без сна
//
//   - (а) вход раньше захвата: исполнитель сброса остановлен швом писателя ДО
//     открытия его транзакции; в этом окне проба открывает транзакцию выдачи
//     входа так, как её открывает вход (`Writer` → `LockPersonForLogin` → сверка
//     отсечки → `InsertSession`), отпускает сброс и фиксирует выдачу. Момент,
//     прочитанный сбросом ДО своей транзакции, опережала бы эта выдача, и её
//     сессия переживала бы сброс.
//   - (б) сброс раньше входа: исполнитель сброса остановлен швом ВНУТРИ своей
//     транзакции (на снятии строк фактора); проба начинает выдачу входа. Выдача
//     обязана ждать фиксации сброса на строке личности — и потому видеть его
//     отсечку, — а не фиксироваться, пока сброс открыт.
//
// Положительный близнец обеих — вход, начатый после фиксации сброса: его
// сессия жива (момент строго позже отсечки).
//
// Run: `go test ./internal/apps/kaname/api/user/ -run ResetSecondFactorCutoffRace -count=3` (Docker).
// Skipped under -short.

package user

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// rsfRaceWindow — точка, в которой исполнитель сброса сообщает о приходе и ждёт,
// пока проба не исполнит встречное действие (со сроком: зависание — отказ
// пробы, а не вечный прогон).
type rsfRaceWindow struct {
	once    sync.Once
	arrived chan struct{}
	release chan struct{}
}

func newRSFRaceWindow() *rsfRaceWindow {
	return &rsfRaceWindow{arrived: make(chan struct{}), release: make(chan struct{})}
}

func (w *rsfRaceWindow) hold() {
	w.once.Do(func() { close(w.arrived) })
	select {
	case <-w.release:
	case <-time.After(20 * time.Second):
	}
}

func (w *rsfRaceWindow) awaitArrival(t *testing.T, what string) {
	t.Helper()
	select {
	case <-w.arrived:
	case <-time.After(20 * time.Second):
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: исполнитель сброса не дошёл до шва (%s)", what)
	}
}

// rsfRaceStore — порт писателя сброса над адаптером базы, как в корне
// композиции; beforeOpen — окно ДО открытия транзакции писателя, inside — окно
// внутри неё, на снятии строк фактора.
type rsfRaceStore struct {
	sessions   *kanamepg.HumanSessionRepo
	beforeOpen *rsfRaceWindow
	inside     *rsfRaceWindow
}

func (s rsfRaceStore) ResetWriter(ctx context.Context, userID domain.UserID) (SecondFactorResetWriter, error) {
	if s.beforeOpen != nil {
		s.beforeOpen.hold()
	}
	w, err := s.sessions.SecondFactorResetWriter(ctx, userID)
	if err != nil {
		return nil, err
	}
	if s.inside == nil {
		return w, nil
	}
	return rsfHeldWriter{SecondFactorResetWriter: w, window: s.inside}, nil
}

// rsfHeldWriter — писатель, останавливающийся перед снятием строк фактора.
type rsfHeldWriter struct {
	SecondFactorResetWriter
	window *rsfRaceWindow
}

func (w rsfHeldWriter) RemoveSecondFactor(ctx context.Context, userID domain.UserID) (bool, error) {
	w.window.hold()
	return w.SecondFactorResetWriter.RemoveSecondFactor(ctx, userID)
}

// rsfRace — сцена: база, адаптеры и человек с заведённым вторым фактором.
type rsfRace struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	sessions *kanamepg.HumanSessionRepo
	clock    *kanamepg.SharedClock
	admin    domain.UserID
	subject  domain.UserID
}

func newRSFRace(t *testing.T) *rsfRace {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	r := &rsfRace{ctx: ctx, pool: pool, sessions: kanamepg.NewHumanSessionRepo(pool), clock: kanamepg.NewSharedClock(pool)}
	r.admin, _ = seedUserWithAccount(t, ctx, pool, "rsfadm")
	r.subject, _ = seedUserWithAccount(t, ctx, pool, "rsfsub")
	r.enrollSecondFactor(t)
	return r
}

// enrollSecondFactor — строка `totp` в состоянии `active` и набор запасных
// кодов писателем продукта (те же операторы, что у заведения и подтверждения).
func (r *rsfRace) enrollSecondFactor(t *testing.T) {
	t.Helper()
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	verifier := func(material string) domain.LoginVerifier {
		v, err := domain.NewLoginVerifier(material)
		require.NoError(t, err)
		return v
	}
	w, err := r.sessions.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(r.ctx) }()
	accepted, err := w.UpsertPendingTOTP(r.ctx, domain.LoginMethod{UserID: r.subject, Kind: domain.LoginMethodTOTP,
		Verifier: verifier("material-totp-rsf-race"), State: domain.LoginMethodStatePending, CreatedAt: at})
	require.NoError(t, err)
	require.True(t, accepted, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): заведение фактора")
	require.NoError(t, w.Commit(r.ctx))

	w, err = r.sessions.Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(r.ctx) }()
	activated, err := w.ActivateTOTP(r.ctx, r.subject, at, 100, at.Add(time.Second))
	require.NoError(t, err)
	require.True(t, activated, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): подтверждение фактора")
	require.NoError(t, w.ReplaceLookupSet(r.ctx, domain.LoginMethod{UserID: r.subject, Kind: domain.LoginMethodLookupSecret,
		Verifier: verifier(",e1,e2,"), State: domain.LoginMethodStateActive, CreatedAt: at}))
	require.NoError(t, w.Commit(r.ctx))
}

// resetUC — глагол сброса над адаптерами базы и названным швом писателя.
func (r *rsfRace) resetUC(s rsfRaceStore) *ResetSecondFactorUseCase {
	s.sessions = r.sessions
	return NewResetSecondFactorUseCase(kanamepg.New(r.pool, nil), operations.NewRepo(r.pool, "kaname"),
		kanamepg.NewLoginMethodRepo(r.pool), s)
}

// startReset — сброс администратором прошёл синхронную сверку; исполнение идёт.
func (r *rsfRace) startReset(t *testing.T, s rsfRaceStore) string {
	t.Helper()
	op, err := r.resetUC(s).Execute(operations.WithPrincipal(r.ctx,
		operations.Principal{Type: "user", ID: string(r.admin)}), r.subject)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): сброс прошёл синхронную сверку (фактор заведён)")
	return op.ID
}

// awaitResetDone — операция сброса терминальна и исполнена без ошибки.
func (r *rsfRace) awaitResetDone(t *testing.T, id string) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(waitCtx), "НЕ ВЫПОЛНИЛОСЬ: исполнитель операций не завершил очередь")
	got, err := operations.NewRepo(r.pool, "kaname").Get(r.ctx, id)
	require.NoError(t, err)
	require.True(t, got.Done, "операция сброса не терминальна")
	require.Nilf(t, got.Error, "сброс завершён ошибкой: %v", got.Error)
}

// loginTx — открытая транзакция выдачи входа в том порядке, что у
// `humansession.LoginUseCase.issue`: момент из общего источника до транзакции,
// захват строки личности первым оператором, сверка с отсечкой под ним, вставка
// записи сессии. refused — выдача отказала отсечкой (`issueBeforeCutoff`).
type loginTx struct {
	w       humansession.Writer
	at      time.Time
	refused bool
}

func (r *rsfRace) openLogin(t *testing.T, onLocked func()) *loginTx {
	t.Helper()
	l, err := r.openLoginE(onLocked)
	require.NoError(t, err)
	return l
}

// openLoginE — то же без утверждений: исполняется и вне горутины пробы.
func (r *rsfRace) openLoginE(onLocked func()) (*loginTx, error) {
	m, err := r.clock.Now(r.ctx)
	if err != nil {
		return nil, fmt.Errorf("момент выдачи: %w", err)
	}
	w, err := r.sessions.Writer(r.ctx)
	if err != nil {
		return nil, fmt.Errorf("транзакция выдачи: %w", err)
	}
	cutoff, has, err := w.LockPersonForLogin(r.ctx, r.subject)
	if err != nil {
		_ = w.Rollback(r.ctx)
		return nil, fmt.Errorf("захват строки личности выдачей: %w", err)
	}
	if onLocked != nil {
		onLocked()
	}
	if has && !m.After(cutoff) {
		return &loginTx{w: w, at: m, refused: true}, nil
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		_ = w.Rollback(r.ctx)
		return nil, err
	}
	if err := w.InsertSession(r.ctx, domain.HumanSession{
		ID: domain.HumanSessionID("hss-" + string(r.subject[3:]) + m.Format("150405.000000")), UserID: r.subject,
		AuthenticatedAt: m, LastPresentedAt: m, ExpiresAt: m.Add(24 * time.Hour),
		AssuranceLevel: "1", PresentedMethods: []string{"password"},
	}, bearer.Digest()); err != nil {
		_ = w.Rollback(r.ctx)
		return nil, fmt.Errorf("вставка записи сессии выдачей: %w", err)
	}
	return &loginTx{w: w, at: m}, nil
}

func (l *loginTx) finish(t *testing.T, ctx context.Context) {
	t.Helper()
	if l.refused {
		require.NoError(t, l.w.Rollback(ctx))
		return
	}
	require.NoError(t, l.w.Commit(ctx), "фиксация выдачи")
}

// cut — момент at покрыт отсечкой человека правилом края (включающее).
func (r *rsfRace) cut(t *testing.T, at time.Time) (bool, time.Time) {
	t.Helper()
	cutoff, found, err := kanamepg.NewUserTokenRevocationRepo(r.pool).RevokedBefore(r.ctx, string(r.subject))
	require.NoError(t, err)
	require.True(t, found, "сброс записал отсечку")
	return !at.After(cutoff), cutoff
}

// twinAfterReset — положительный близнец: вход, начатый после фиксации сброса,
// не отказывает и даёт сессию позже отсечки.
func (r *rsfRace) twinAfterReset(t *testing.T) {
	t.Helper()
	l := r.openLogin(t, nil)
	require.False(t, l.refused, "близнец: вход после фиксации сброса не отказывает")
	l.finish(t, r.ctx)
	isCut, cutoff := r.cut(t, l.at)
	require.Falsef(t, isCut, "близнец: сессия после сброса жива (момент %s, отсечка %s)", l.at, cutoff)
}

// TestResetSecondFactorCutoffRace_LoginCommittedBeforeTheResetTakesThePersonIsCut — (а).
func TestResetSecondFactorCutoffRace_LoginCommittedBeforeTheResetTakesThePersonIsCut(t *testing.T) {
	r := newRSFRace(t)
	window := newRSFRaceWindow()
	opID := r.startReset(t, rsfRaceStore{beforeOpen: window})
	window.awaitArrival(t, "до открытия транзакции")

	login := r.openLogin(t, nil)
	require.False(t, login.refused, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): выдача в окне до захвата не видит отсечки")
	close(window.release)
	login.finish(t, r.ctx)
	r.awaitResetDone(t, opID)

	isCut, cutoff := r.cut(t, login.at)
	require.Truef(t, isCut,
		"kaname#680: сессия, выданная до фиксации сброса второго фактора, пережила сброс — момент сессии %s позже отсечки %s",
		login.at, cutoff)
	r.twinAfterReset(t)
}

// TestResetSecondFactorCutoffRace_LoginWaitsForAResetThatHoldsThePerson — (б).
func TestResetSecondFactorCutoffRace_LoginWaitsForAResetThatHoldsThePerson(t *testing.T) {
	r := newRSFRace(t)
	window := newRSFRaceWindow()
	opID := r.startReset(t, rsfRaceStore{inside: window})
	window.awaitArrival(t, "внутри транзакции, на снятии строк фактора")

	locked := make(chan struct{})
	var once sync.Once
	type result struct {
		login *loginTx
		err   error
	}
	done := make(chan result, 1)
	go func() {
		l, err := r.openLoginE(func() { once.Do(func() { close(locked) }) })
		done <- result{login: l, err: err}
	}()

	// Выдача обязана встать в ожидание замка строки личности, пока сброс открыт.
	// Наблюдается базой (ожидание замка у соединения выдачи), а не сроком.
	waited := r.awaitLoginBlockedOrLocked(t, locked)
	close(window.release)
	got := <-done
	require.NoError(t, got.err)
	got.login.finish(t, r.ctx)
	r.awaitResetDone(t, opID)

	require.Truef(t, waited,
		"kaname#680: выдача входа захватила строку личности, пока сброс второго фактора был открыт — сброс не держит личность")
	if !got.login.refused {
		isCut, cutoff := r.cut(t, got.login.at)
		require.Falsef(t, isCut, "выдача, дождавшаяся фиксации сброса и прошедшая сверку, позже отсечки (момент %s, отсечка %s)",
			got.login.at, cutoff)
	}
	r.twinAfterReset(t)
}

// awaitLoginBlockedOrLocked — true, если соединение выдачи встало в ожидание
// замка (сброс держит личность); false, если выдача захватила личность раньше.
// Опрос базы ограничен сроком; исход — первое из двух наблюдений.
func (r *rsfRace) awaitLoginBlockedOrLocked(t *testing.T, locked <-chan struct{}) bool {
	t.Helper()
	deadline := time.After(20 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-locked:
			return false
		case <-deadline:
			t.Fatal("НЕ ВЫПОЛНИЛОСЬ: выдача не встала в ожидание и не захватила личность")
			return false
		case <-tick.C:
			var n int
			require.NoError(t, r.pool.QueryRow(r.ctx, `
				SELECT count(*) FROM pg_stat_activity
				 WHERE datname = current_database() AND wait_event_type = 'Lock'
				   AND query LIKE '%FOR SHARE%'`).Scan(&n))
			if n > 0 {
				return true
			}
		}
	}
}
