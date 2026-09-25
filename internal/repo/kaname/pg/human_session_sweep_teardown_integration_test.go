// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// human_session_sweep_teardown_integration_test.go — УБОРКА ЗАПИСЕЙ СЕССИИ НЕ
// ЖДЁТ СТРОК, КОТОРЫЕ ДЕРЖИТ СНЯТИЕ (задача kaname#340).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Уборка (`SweepUnservableSessions`) и снятие (`EndOtherSessions`) пишут
// НЕСКОЛЬКО строк сессии одним оператором, и кандидаты у них пересекаются:
// снятие помечает и истёкшие не снятые строки человека, уборка удаляет
// истёкшие старше порога. Снятие проходит строки человека в одном порядке,
// уборка — в своём, и порядки эти никто не согласовывал. Уборка строки
// личности не берёт (она многоличностная), поэтому сериализация на строке
// личности, общая для писателей нескольких сессий одного человека, её не
// касается. Если уборка ждёт строку, которую держит снятие, а снятие — строку,
// которую уже держит уборка, движок снимает одного из них взаимной
// блокировкой.
//
// Утверждается: уборка на занятой строке сессии НЕ ВСТАЁТ В ОЖИДАНИЕ, снятие
// и уборка обе фиксируются, каждая строка пары взята ровно одним из них, а
// строку, пропущенную уборкой, берёт следующий её проход. Второй прибор —
// счётчик базы `pg_stat_database.deadlocks`, прочитанный после закрытия пула.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ПОСТРОЕНА СЦЕНА — ЗАМКОМ И ПОРЯДКОМ, А НЕ ВРЕМЕНЕМ
//
// У человека две строки сессии, которые берут ОБА писателя: истёкшие старше
// порога уборки и не снятые. Порядок, в котором каждый оператор проходит
// строки пары, узнаётся сухим прогоном его НАСТОЯЩЕГО текста (мост пакета) в
// откатываемой транзакции. Пара подбирается так, чтобы порядки были
// ВСТРЕЧНЫМИ, — это и есть враждебное расположение: при согласованных
// порядках ждущая уборка цикла не даёт. Не подобралась за отведённое число
// попыток — сцена не построена, и это отказ фикстуры, а не вердикт.
//
// Порядок уборки задаёт план, а план — статистика таблицы. На пустой
// неразобранной таблице это хеш-полусоединение с последовательным просмотром,
// то есть порядок физического размещения — тот же, что у снятия, и встречных
// порядков не бывает вовсе (16 попыток из 16). На таблице, где кандидаты —
// малая доля живых записей многих людей, план — хеш-агрегат по `ctid` и
// выборка по `ctid`, порядок — порядок хеша. Сцена строит вторую форму — форму
// таблицы службы: живые записи другого человека и `ANALYZE`.
//
// Окно расширяет держатель: чужая транзакция держит строку, которую снятие
// берёт ПЕРВОЙ (а уборка — второй). Снятие встаёт за держателем, не тронув
// второй строки; затем приходит уборка. Ждущая уборка взяла бы вторую строку и
// встала бы за снятием на первой: после ухода держателя снятие пошло бы ко
// второй строке, занятой уборкой, — цикл. Уборка, не ждущая занятых строк,
// берёт вторую, первую оставляет и завершается раньше, чем уходит держатель.

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

const (
	// sweepSceneGrace — порог уборки; строки пары истекли задолго до него.
	sweepSceneGrace = time.Hour
	// sweepSceneBatch — партия уборки больше числа кандидатов в базе сцены:
	// уборка обязана дойти до обеих строк пары.
	sweepSceneBatch = 100
	// sweepSceneLockWait — предел ожидания замка транзакции снятия. Дольше окна
	// держателя и дольше срока обнаружения взаимной блокировки, чтобы отказ
	// снятия, если он случится, был отказом цикла, а не своего предела.
	sweepSceneLockWait = 10 * time.Second
	// sweepScenePairAttempts — сколько пар пробовать, пока порядки не встречны.
	sweepScenePairAttempts = 16
	// sweepSceneLiveRows — живых записей другого человека: кандидаты уборки —
	// малая их доля, как в таблице службы, и план уборки — её план.
	sweepSceneLiveRows = 2000
)

// sweepSceneServiceShapedTable — живые записи сессии другого человека и
// разобранная статистика: план уборки тот, что на таблице службы.
func sweepSceneServiceShapedTable(t *testing.T, ctx context.Context, pool *pgxpool.Pool, other domain.UserID) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO human_sessions
		    (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		     assurance_level, presented_methods)
		SELECT 'hss-swplive-' || i, $1, md5(i::text) || md5((i + $2)::text),
		       now(), now(), now() + interval '12 hours', '1', ARRAY['password']
		  FROM generate_series(1, $2) AS i`, string(other), sweepSceneLiveRows)
	require.NoError(t, err, "фикстура: живые записи другого человека")
	_, err = pool.Exec(ctx, `ANALYZE human_sessions`)
	require.NoError(t, err, "фикстура: статистика таблицы")
}

// sweepSceneDryRunOrder — порядок, в котором оператор проходит строки,
// узнанный его исполнением в откатываемой транзакции.
func sweepSceneDryRunOrder(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) []string {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "сухой прогон: транзакция")
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, sql, args...)
	require.NoError(t, err, "сухой прогон: оператор")
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err, "сухой прогон: строки")
	return ids
}

// sweepSceneOpposedPair — две строки сессии человека, общие для уборки и
// снятия, чьи порядки у этих операторов встречны. Отвечает порядком снятия и
// числом попыток подбора.
func sweepSceneOpposedPair(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	repo *kanamepg.HumanSessionRepo, uid domain.UserID, round int,
) (teardownOrder []string, attempts int) {
	t.Helper()
	for attempt := 0; attempt < sweepScenePairAttempts; attempt++ {
		expiredAt := time.Now().UTC().Add(-3 * hsTTL)
		pair := map[string]bool{}
		for _, suffix := range []string{"a", "b"} {
			s := hsSession(uid, fmt.Sprintf("swp%d-%d%s", round, attempt, suffix), expiredAt)
			hsIssue(t, repo, s)
			pair[string(s.ID)] = true
		}
		teardownOrder = sweepSceneDryRunOrder(t, ctx, pool, kanamepg.EndSessionsOfSQL,
			string(uid), "", time.Now().UTC(), domain.RevokeReasonLogout)
		var sweepOrder []string
		for _, id := range sweepSceneDryRunOrder(t, ctx, pool,
			kanamepg.SweepUnservableSessionsSQL+" RETURNING id", sweepSceneGrace, sweepSceneBatch) {
			if pair[id] {
				sweepOrder = append(sweepOrder, id)
			}
		}
		require.Len(t, teardownOrder, 2, "фикстура: снятие обязано брать обе строки пары")
		require.Len(t, sweepOrder, 2, "фикстура: уборка обязана брать обе строки пары")
		if sweepOrder[0] == teardownOrder[1] {
			return teardownOrder, attempt + 1
		}
		_, err := pool.Exec(ctx, `DELETE FROM human_sessions WHERE id = ANY($1)`, teardownOrder)
		require.NoError(t, err, "фикстура: снять пару с согласованными порядками")
	}
	t.Fatalf("за %d попыток не подобрано пары со встречными порядками снятия и уборки — "+
		"сцена не построена", sweepScenePairAttempts)
	return nil, 0
}

func sweepSceneLockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var waiting int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_stat_activity
		 WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
	return waiting
}

// sweepSceneDeadlocksAfterClose — счётчик взаимных блокировок базы, прочитанный
// после закрытия пула: обслуживающий процесс сбрасывает статистику на выходе.
func sweepSceneDeadlocksAfterClose(t *testing.T, ctx context.Context, dsn string, pool *pgxpool.Pool) int64 {
	t.Helper()
	pool.Close()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err, "соединение для чтения статистики")
	defer func() { _ = conn.Close(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var others int
		require.NoError(t, conn.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND pid <> pg_backend_pid()`).Scan(&others))
		if others == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("процессов пула в базе %d через 10 с после закрытия — статистика не сброшена", others)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var deadlocks int64
	require.NoError(t, conn.QueryRow(ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&deadlocks))
	return deadlocks
}

type sweepSceneTeardown struct {
	ended int
	err   error
}

type sweepScenePass struct {
	removed int64
	err     error
}

// sweepSceneTeardownTx — снятие всех живых записей человека транзакцией
// писателя принудительного выхода: открытие с замком личности, снятие,
// фиксация.
func sweepSceneTeardownTx(ctx context.Context, repo *kanamepg.HumanSessionRepo, uid domain.UserID) sweepSceneTeardown {
	w, err := repo.ForceLogoutWriter(ctx, uid, sweepSceneLockWait)
	if err != nil {
		return sweepSceneTeardown{err: err}
	}
	n, err := w.EndOtherSessions(ctx, uid, "", time.Now().UTC(), domain.RevokeReasonLogout)
	if err == nil {
		err = w.Commit(ctx)
	}
	if err != nil {
		_ = w.Rollback(ctx)
		return sweepSceneTeardown{err: err}
	}
	return sweepSceneTeardown{ended: n}
}

func TestIntegration_SessionSweepDoesNotWaitOnRowsATeardownHolds(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	dsn := iampgtest.NewTestPostgres(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kanamepg.NewHumanSessionRepo(pool)
	var deadlocksBefore int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&deadlocksBefore))

	const rounds = 3
	people := lmPeople(t, pool, "swp", rounds+1)
	sweepSceneServiceShapedTable(t, ctx, pool, people[rounds])
	var denominator, sumTaken, attempts, sweepWaited, aborted, failures int
	var nextPassRemoved int64
	for round := 0; round < rounds; round++ {
		uid := people[round]
		order, tries := sweepSceneOpposedPair(t, ctx, pool, repo, uid, round)
		attempts += tries
		denominator += len(order)

		holder, err := pool.Begin(ctx)
		require.NoError(t, err, "прогон %d: транзакция держателя", round)
		_, err = holder.Exec(ctx, `SELECT 1 FROM human_sessions WHERE id = $1 FOR UPDATE`, order[0])
		require.NoError(t, err, "прогон %d: держатель берёт первую строку снятия", round)

		teardownDone := make(chan sweepSceneTeardown, 1)
		go func() { teardownDone <- sweepSceneTeardownTx(ctx, repo, uid) }()
		waitDeadline := time.Now().Add(10 * time.Second)
		for sweepSceneLockWaiters(t, ctx, pool) < 1 {
			if time.Now().After(waitDeadline) {
				_ = holder.Rollback(ctx)
				t.Fatalf("прогон %d: снятие не встало за держателем за 10 с — сцена не построена", round)
			}
			time.Sleep(5 * time.Millisecond)
		}

		sweepDone := make(chan sweepScenePass, 1)
		go func() {
			n, _, err := repo.SweepUnservableSessions(ctx, sweepSceneGrace, sweepSceneBatch)
			sweepDone <- sweepScenePass{removed: n, err: err}
		}()
		var sweep sweepScenePass
		returned, waited := false, false
		for !returned && !waited {
			select {
			case sweep = <-sweepDone:
				returned = true
			default:
				waited = sweepSceneLockWaiters(t, ctx, pool) >= 2
				if !waited {
					if time.Now().After(waitDeadline) {
						_ = holder.Rollback(ctx)
						t.Fatalf("прогон %d: уборка не вернулась и не встала ждать за 10 с — сцена не построена", round)
					}
					time.Sleep(5 * time.Millisecond)
				}
			}
		}
		if waited {
			sweepWaited++
		}
		require.NoError(t, holder.Commit(ctx), "прогон %d: держатель уходит", round)
		teardown := <-teardownDone
		if !returned {
			sweep = <-sweepDone
		}

		for _, err := range []error{teardown.err, sweep.err} {
			if err == nil {
				continue
			}
			failures++
			if stderrors.Is(err, iamerr.ErrAborted) {
				aborted++
			}
		}
		taken := teardown.ended + int(sweep.removed)
		sumTaken += taken

		next, _, err := repo.SweepUnservableSessions(ctx, sweepSceneGrace, sweepSceneBatch)
		require.NoError(t, err, "прогон %d: следующий проход уборки", round)
		nextPassRemoved += next
		var left int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM human_sessions WHERE user_id = $1`, string(uid)).Scan(&left))
		t.Logf("прогон %d: попыток подбора %d · уборка ждала=%v · снятие: снято=%d ошибка=%v · "+
			"уборка: убрано=%d ошибка=%v · следующий проход убрал %d · строк человека после %d",
			round, tries, waited, teardown.ended, teardown.err, sweep.removed, sweep.err, next, left)

		assert.False(t, waited, "прогон %d: уборка встала ждать строку сессии, которую держит снятие", round)
		assert.NoError(t, teardown.err, "прогон %d: снятие", round)
		assert.NoError(t, sweep.err, "прогон %d: уборка", round)
		assert.Equal(t, len(order), taken,
			"прогон %d: каждая строка пары обязана быть взята ровно одним из двух писателей", round)
		assert.EqualValues(t, teardown.ended, next,
			"прогон %d: следующий проход уборки обязан убрать строки, снятые снятием", round)
		assert.Zero(t, left, "прогон %d: строки человека после следующего прохода", round)
	}

	deadlocksAfter := sweepSceneDeadlocksAfterClose(t, ctx, dsn, pool)
	t.Logf("прогонов %d · знаменатель (строк пар) %d · Σ взятых в окне %d · убрано следующими проходами %d · "+
		"попыток подбора пар %d · уборка ждала в %d · отказов %d · ABORTED %d · pg_stat_database.deadlocks +%d",
		rounds, denominator, sumTaken, nextPassRemoved, attempts, sweepWaited, failures, aborted,
		deadlocksAfter-deadlocksBefore)

	require.Positive(t, denominator, "знаменатель пуст — сумма ниже равнялась бы нулю на пустом месте")
	assert.Equal(t, denominator, sumTaken, "Σ строк, взятых снятием и уборкой в окне держателя")
	assert.Zero(t, sweepWaited, "прогонов, где уборка ждала занятую строку")
	assert.Zero(t, aborted, "ABORTED (40P01) у снятия и уборки")
	assert.Zero(t, deadlocksAfter-deadlocksBefore, "pg_stat_database.deadlocks")
}
