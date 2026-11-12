// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Это значения wire-протокола, а не подмена функции хеширования. Все ключи
// аккаунтов ниже вычисляет тот же PostgreSQL, на котором проверяются locks.
const authorityAccountNS = 0x4b414741

func authorityAccounts(ids ...string) kaname.AuthorityFencePlan {
	p := kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceAccounts}
	for _, id := range ids {
		p.Accounts = append(p.Accounts, domain.AccountID(id))
	}
	return p
}

func authorityTestDB(t *testing.T) (context.Context, *pgxpool.Pool, *kanamepg.Repository) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return ctx, pool, kanamepg.New(pool, nil)
}

func authorityOpen(t *testing.T, ctx context.Context, repo *kanamepg.Repository, plan kaname.AuthorityFencePlan) kaname.AuthorityWriter {
	t.Helper()
	w, err := repo.AuthorityWriter(ctx, plan)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	})
	return w
}

type authorityOpenResult struct {
	w   kaname.AuthorityWriter
	err error
}
type authorityPending struct {
	result chan authorityOpenResult
	cancel context.CancelFunc
	taken  bool
}

func authorityStart(t *testing.T, ctx context.Context, repo *kanamepg.Repository, plan kaname.AuthorityFencePlan) *authorityPending {
	t.Helper()
	waitCtx, cancel := context.WithCancel(ctx)
	p := &authorityPending{result: make(chan authorityOpenResult, 1), cancel: cancel}
	go func() {
		w, err := repo.AuthorityWriter(waitCtx, plan)
		p.result <- authorityOpenResult{w, err}
	}()
	t.Cleanup(func() {
		cancel()
		if p.taken {
			return
		}
		select {
		case result := <-p.result:
			if result.w != nil {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = result.w.Rollback(cleanup)
			}
		case <-time.After(6 * time.Second):
			t.Error("authority writer не завершился после отмены")
		}
	})
	return p
}

func (p *authorityPending) take(t *testing.T) authorityOpenResult {
	t.Helper()
	select {
	case result := <-p.result:
		p.taken = true
		if result.w != nil {
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = result.w.Rollback(cleanup)
			})
		}
		return result
	case <-time.After(6 * time.Second):
		t.Fatal("authority writer не вернул результат")
		return authorityOpenResult{}
	}
}

// Барьер наблюдается в БД; отсутствие ответа за sleep не считается блокировкой.
func authorityWaitLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int32 {
	t.Helper()
	var pid int32
	require.Eventually(t, func() bool {
		err := pool.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND objsubid=2 AND NOT granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) LIMIT 1`).Scan(&pid)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "второй writer должен ждать настоящий advisory lock")
	return pid
}

func authorityWaitReleased(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// После отмены pgx передаёт повреждённое соединение асинхронному destructor
	// puddle: Release уже вызван, но slot ещё учитывается до CleanupDone.
	// Наблюдаем завершение очистки; устойчивая утечка остаётся отказом.
	require.Eventually(t, func() bool { return pool.Stat().AcquiredConns() == 0 },
		2*time.Second, 10*time.Millisecond, "очистка должна вернуть все pool slots")
}

func TestAuthorityWriterRejectsPlanBeforeOpeningTransaction(t *testing.T) {
	// nil pool намерен: неверный план обязан завершиться до первого вызова BeginTx.
	repo := kanamepg.New(nil, nil)
	tooMany := make([]domain.AccountID, kaname.MaxAuthorityFenceAccounts+1)
	for i := range tooMany {
		tooMany[i] = domain.AccountID(fmt.Sprintf("acc-%d", i))
	}
	plans := []kaname.AuthorityFencePlan{
		{}, {Mode: 99}, {Mode: kaname.AuthorityFenceAccounts},
		authorityAccounts(""), authorityAccounts(" acc-a"), authorityAccounts("acc-a\x00"),
		{Mode: kaname.AuthorityFenceGlobal, Accounts: []domain.AccountID{"acc-a"}},
		{Mode: kaname.AuthorityFenceAccounts, Accounts: tooMany},
	}
	for i, plan := range plans {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w, err := repo.AuthorityWriter(context.Background(), plan)
			require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
			require.Nil(t, w)
		})
	}
}

func TestAuthorityWriterSameAccountAndGlobalBarriers(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	global := kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
	cases := []struct {
		name          string
		first, second kaname.AuthorityFencePlan
	}{
		{"same-account", authorityAccounts("acc-a"), authorityAccounts("acc-a")},
		{"account-before-global", authorityAccounts("acc-a"), global},
		{"global-before-account", global, authorityAccounts("acc-a")},
		{"global-before-global", global, global},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool, repo := authorityTestDB(t)
			first := authorityOpen(t, ctx, repo, tc.first)
			second := authorityStart(t, ctx, repo, tc.second)
			authorityWaitLock(t, ctx, pool)
			var afterWait time.Time
			require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&afterWait))
			require.NoError(t, first.Commit(ctx))
			result := second.take(t)
			require.NoError(t, result.err)
			require.NotNil(t, result.w)
			require.False(t, result.w.AuthorityFence().DecisionAt().Before(afterWait), "decision_at должен быть после ожидания, не временем BEGIN")
			require.Equal(t, tc.second.Mode, result.w.AuthorityFence().Mode())
			require.NoError(t, result.w.Rollback(ctx))
			authorityWaitReleased(t, pool)
		})
	}
}

func TestAuthorityWriterDifferentAccountsAndSnapshotCopies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	// Фикстура подтверждает различие физических ключей, а не предполагает его.
	var distinct bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT hashtext('acc-a') <> hashtext('acc-b')`).Scan(&distinct))
	require.True(t, distinct)
	plan := authorityAccounts("acc-a", "acc-a")
	first := authorityOpen(t, ctx, repo, plan)
	plan.Accounts[0] = "acc-mutated"
	got := first.AuthorityFence().Accounts()
	require.Equal(t, []domain.AccountID{"acc-a"}, got)
	got[0] = "acc-mutated-again"
	require.Equal(t, []domain.AccountID{"acc-a"}, first.AuthorityFence().Accounts())
	secondCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	second := authorityOpen(t, secondCtx, repo, authorityAccounts("acc-b"))
	require.NoError(t, second.Commit(ctx))
	require.NoError(t, first.Rollback(ctx))
	// Rollback освобождает и cluster, и account barrier.
	global := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	require.Empty(t, global.AuthorityFence().Accounts())
	require.NoError(t, global.Rollback(ctx))
	authorityWaitReleased(t, pool)
}

func TestAuthorityWriterReadsCommittedSourceAfterFenceWait(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	uid := mustSeedUser(t, ctx, pool, "authority-snapshot")
	account := seedAccount(t, ctx, repo, "authority-snapshot-account", uid)
	g := seedGroup(t, ctx, repo, account.ID, "authority-snapshot-group")
	plan := authorityAccounts(string(account.ID))
	first := authorityOpen(t, ctx, repo, plan)
	g.Description = "изменено первым writer до передачи барьера"
	_, err := first.GroupsW().Update(ctx, g, []string{"description"})
	require.NoError(t, err)
	second := authorityStart(t, ctx, repo, plan)
	authorityWaitLock(t, ctx, pool)
	require.NoError(t, first.Commit(ctx))
	result := second.take(t)
	require.NoError(t, result.err)
	require.NotNil(t, result.w)
	// При REPEATABLE READ снимок мог бы устареть ещё в ожидании lock.
	// Проверяется фактический source read, а не только время DecisionAt.
	current, err := result.w.Groups().Get(ctx, g.ID)
	require.NoError(t, err)
	require.Equal(t, g.Description, current.Description)
	require.NoError(t, result.w.Rollback(ctx))
}

func TestAuthorityWriterPhysicalOrderAndCancellationCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	var lowID, highID string
	var lowKey, highKey int32
	// Лексический порядок намеренно противоположен физическому. Нужны два
	// разных знаковых int32; PostgreSQL сам выбирает реальную пару для пробы.
	require.NoError(t, pool.QueryRow(ctx, `WITH keys AS (SELECT 'acc-order-' || n AS id, hashtext('acc-order-' || n) AS key FROM generate_series(1,64) n)
 SELECT a.id,a.key,b.id,b.key FROM keys a CROSS JOIN keys b
 WHERE a.id > b.id AND a.key < 0 AND b.key > 0 ORDER BY a.id,b.id LIMIT 1`).Scan(&lowID, &lowKey, &highID, &highKey))
	require.Less(t, lowKey, highKey)
	// Если adapter сортирует логические IDs либо unsigned keys, он успеет
	// захватить high, прежде чем остановится на low. Правильный — не успеет.
	holder := authorityOpen(t, ctx, repo, authorityAccounts(lowID))
	pending := authorityStart(t, ctx, repo, authorityAccounts(highID, lowID, lowID))
	pid := authorityWaitLock(t, ctx, pool)
	var held int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND objsubid=2 AND classid::bigint=$2 AND granted`, pid, int64(authorityAccountNS)).Scan(&held))
	require.Zero(t, held, "первым должен ожидаться минимальный physical key")
	pending.cancel()
	result := pending.take(t)
	require.Error(t, result.err)
	require.Nil(t, result.w)
	require.NoError(t, holder.Rollback(ctx))
	authorityWaitReleased(t, pool)

	// Теперь low должен быть уже взят, когда writer ждёт high. Его отмена
	// обязана освободить частично полученный план, не затрагивая holder high.
	holder = authorityOpen(t, ctx, repo, authorityAccounts(highID))
	pending = authorityStart(t, ctx, repo, authorityAccounts(highID, lowID))
	pid = authorityWaitLock(t, ctx, pool)
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND objsubid=2 AND classid::bigint=$2 AND granted`, pid, int64(authorityAccountNS)).Scan(&held))
	require.Equal(t, 1, held)
	pending.cancel()
	result = pending.take(t)
	require.Error(t, result.err)
	require.Nil(t, result.w)
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	probe := authorityOpen(t, checkCtx, repo, authorityAccounts(lowID))
	require.NoError(t, probe.Rollback(ctx))
	require.NoError(t, holder.Rollback(ctx))
	global := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	require.NoError(t, global.Rollback(ctx))
	authorityWaitReleased(t, pool)
}

func TestAuthorityWriterRealHashCollisionRetainsLogicalAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	// Пара найдена первым native прогоном на PostgreSQL 16. Повторный census
	// миллиона строк не нужен: сама БД заново подтверждает реальную коллизию.
	pair := []string{"acc-collision-716556", "acc-collision-916815"}
	var same bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT hashtext($1)=hashtext($2)`, pair[0], pair[1]).Scan(&same))
	require.True(t, same)
	var collisionKey int32
	require.NoError(t, pool.QueryRow(ctx, `SELECT hashtext($1)`, pair[0]).Scan(&collisionKey))
	require.Equal(t, int32(-2116289360), collisionKey)
	writer := authorityOpen(t, ctx, repo, authorityAccounts(pair[1], pair[0], pair[1]))
	require.Equal(t, []domain.AccountID{domain.AccountID(pair[0]), domain.AccountID(pair[1])}, writer.AuthorityFence().Accounts())
	var physicalLocks int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objsubid=2 AND classid::bigint=$1 AND granted AND database=(SELECT oid FROM pg_database WHERE datname=current_database())`, int64(authorityAccountNS)).Scan(&physicalLocks))
	require.Equal(t, 1, physicalLocks)
	// Коллизия сужает параллелизм, но не позволяет второму логическому аккаунту
	// пройти барьер; snapshot по-прежнему не расширен до всех colliding IDs.
	other := authorityStart(t, ctx, repo, authorityAccounts(pair[1]))
	authorityWaitLock(t, ctx, pool)
	require.NoError(t, writer.Rollback(ctx))
	result := other.take(t)
	require.NoError(t, result.err)
	require.Equal(t, []domain.AccountID{domain.AccountID(pair[1])}, result.w.AuthorityFence().Accounts())
	require.NoError(t, result.w.Rollback(ctx))
}
