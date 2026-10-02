// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// signing_key_sweeper_handover_race_integration_test.go — сметатели застрявших
// ключей против передачи подписи на тот же ключ (#314).
//
// Сцена строится наблюдением движка, а не выдержкой. Передача идёт настоящим
// путём ключницы (RotateIfDue → ReplaceActive), а триггер пробы задерживает её
// транзакцию ПОСЛЕ повышения ключа — на замке-советнике, который держит проба.
// Сметатели соседних реплик, чьи часы ушли вперёд дальше StrandedAfter, прочли
// этот ключ опубликованным и встают на замок его строки. Сцена считается
// построенной, когда движок показывает ждущими замка все реплики сметателей, и
// только тогда проба решает исход передачи: фиксация либо обрыв. Сметатели
// перечитывают условие вывода на той версии строки, которую оставила передача.
//
// Каждая реплика — свой пул, как у служб: число одновременных соединений сцены
// не упирается в предел одного пула, зависящий от числа ядер машины прогона.
//
// Пара меняет ровно один факт — легла ли передача. Легла: подписывает её ключ,
// и ни один сметатель его не вывел. Оборвана: тот же ключ выведен ровно один
// раз — сметателем либо откатом ключницы, — подписывает прежний. На обоих
// исходах застрявших нет, подписывающий ровно один, отказов у сметателей нет.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// promoteHoldKey — ключ замка-советника, на котором триггер пробы задерживает
// повышение ключа. Замки-советники делятся по базе, а база у пробы своя.
const promoteHoldKey = 314

// sceneWaitLimit — сколько проба ждёт, пока движок покажет построенную сцену.
// Кончился — сцена не построена, и это не вердикт о предмете.
const sceneWaitLimit = 10 * time.Second

func TestSigningKey_SweepersRacingAHandOverToTheSameKeyRetireOnlyWhatStaysPublished(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	const (
		lifetime, lead = 48 * time.Hour, time.Hour
		replicas       = 4
		stranded       = 2
	)
	for _, tc := range []struct {
		name  string
		lands bool
	}{
		{"передача ложится, пока сметатели ждут строку её ключа", true},
		{"передача обрывается, пока сметатели ждут строку её ключа", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dsn := setupTestDB(t)
			pool := replicaPool(t, ctx, dsn)
			repo := kanamepg.NewSigningKeyRepo(pool)
			wrapper, err := keywrap.New(make([]byte, keywrap.KeySize))
			require.NoError(t, err)
			newKS := func(at time.Time, r *kanamepg.SigningKeyRepo) *signingkeys.Keystore {
				ks, err := signingkeys.New(signingkeys.Config{
					Algorithm: domain.SigningAlgES256, KeyLifetime: lifetime,
					RemovalGrace: tokenpolicy.KeyRemovalGrace, RotationLead: lead,
					HandoverLimit: time.Minute, StrandedAfter: 2 * time.Minute,
					Clock: func() time.Time { return at },
				}, r, r, wrapper)
				require.NoError(t, err)
				return ks
			}

			start := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
			gen := newKS(start, repo)
			require.NoError(t, gen.EnsureSigningKey(ctx))
			first, err := repo.Active(ctx)
			require.NoError(t, err)
			strandedKIDs := map[domain.KeyID]bool{}
			for i := 0; i < stranded; i++ {
				pub, err := gen.Generate(ctx)
				require.NoError(t, err)
				strandedKIDs[pub.KID] = true
			}
			due := first.NotAfter.Add(-lead)
			// Часы сметателей ушли вперёд дальше StrandedAfter: ключ передачи,
			// порождённый в `due`, для них уже застрял.
			ahead := due.Add(10 * time.Minute)

			// Пулы реплик — до уборки сцены: уборка идёт в обратном порядке
			// регистрации, и пул, закрытый раньше, чем участники отпустят
			// соединения, ждал бы их вечно.
			handOverRepo := kanamepg.NewSigningKeyRepo(replicaPool(t, ctx, dsn))
			sweeperRepos := make([]*kanamepg.SigningKeyRepo, replicas)
			for i := range sweeperRepos {
				sweeperRepos[i] = kanamepg.NewSigningKeyRepo(replicaPool(t, ctx, dsn))
			}

			installPromoteHold(t, ctx, pool)
			holder, err := pool.Acquire(ctx)
			require.NoError(t, err)
			_, err = holder.Exec(ctx, `SELECT pg_advisory_lock($1)`, promoteHoldKey)
			require.NoError(t, err)
			var unlockOnce sync.Once
			unlock := func() (err error) {
				unlockOnce.Do(func() {
					_, err = holder.Exec(ctx, `SELECT pg_advisory_unlock($1)`, promoteHoldKey)
				})
				return err
			}

			var wg sync.WaitGroup
			// Отказ пробы посреди сцены не оставляет участников на замках:
			// замок снимается, участники дожидаются, соединение возвращается
			// в пул до закрытия пулов.
			t.Cleanup(func() {
				_ = unlock()
				wg.Wait()
				holder.Release()
			})

			handOver := newKS(due, handOverRepo)
			handOverCtx, endHandOver := context.WithCancel(ctx)
			defer endHandOver()
			var (
				rotated     bool
				handOverErr error
			)
			wg.Add(1)
			go func() {
				defer wg.Done()
				rotated, handOverErr = handOver.RotateIfDue(handOverCtx)
			}()
			handOverPID := awaitPromoteHeld(t, ctx, pool)

			contested := contestedKey(t, ctx, pool, strandedKIDs)

			sweepers := make([]*signingkeys.Keystore, replicas)
			sweepErrs := make([]error, replicas)
			for i := range sweepers {
				sweepers[i] = newKS(ahead, sweeperRepos[i])
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					_, sweepErrs[i] = sweepers[i].SweepRemovable(ctx)
				}(i)
			}
			awaitSweepersBlocked(t, ctx, pool, handOverPID, replicas)

			if tc.lands {
				require.NoError(t, unlock(), "передача получает замок и фиксируется")
			} else {
				endHandOver()
			}
			awaitScene(t, &wg)
			require.NoError(t, unlock())

			for i, err := range sweepErrs {
				require.NoError(t, err, "сметатель %d не получает отказа: невыполненное предусловие вывода — не отказ", i)
			}
			var sweptRetired uint64
			for _, s := range sweepers {
				sweptRetired += s.Stats().Retired
			}
			states := signingKeyStates(t, pool)
			t.Logf("передача: rotated=%v err=%v; сметатели вывели %d; состояния: %v", rotated, handOverErr, sweptRetired, states)

			require.Zero(t, states[domain.SigningKeyPublished], "застрявших не остаётся: %v", states)
			if tc.lands {
				require.Equal(t, 1, states[domain.SigningKeyActive],
					"ключ легшей передачи подписывает: сметатель, ждавший его строку, не выводит подписывающего: %v", states)
				require.NoError(t, handOverErr)
				require.True(t, rotated)
				active, err := repo.Active(ctx)
				require.NoError(t, err)
				require.Equal(t, contested, active.KID, "подписывает ключ легшей передачи")
				require.Equal(t, uint64(stranded), sweptRetired,
					"каждый застрявший выведен ровно одним сметателем, ключ передачи — ни одним")
			} else {
				require.Equal(t, 1, states[domain.SigningKeyActive], "подписывающий ровно один: %v", states)
				require.Error(t, handOverErr)
				require.False(t, rotated)
				active, err := repo.Active(ctx)
				require.NoError(t, err)
				require.Equal(t, first.KID, active.KID, "оборванная передача не трогает подписывающего")
				require.Equal(t, uint64(stranded+1), sweptRetired+handOver.Stats().Retired,
					"застрявшие и ключ оборванной передачи выведены ровно по разу — сметателем либо откатом ключницы")
			}
			require.Equal(t, stranded+1, states[domain.SigningKeyRetired],
				"выведены застрявшие и один ключ исхода передачи: %v", states)
		})
	}
}

// replicaPool — пул одной реплики к базе пробы; закрывается в конце пробы.
func replicaPool(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool
}

// installPromoteHold ставит триггер пробы: повышение ОПУБЛИКОВАННОГО ключа в
// подписывающие ждёт замка-советника promoteHoldKey внутри своей транзакции —
// после того, как новая версия строки записана, и до фиксации.
func installPromoteHold(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE FUNCTION kaname.probe_hold_signing_key_promote() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(%d);
			RETURN NULL;
		END $$`, promoteHoldKey))
	require.NoError(t, err, "функция задержки повышения")
	_, err = pool.Exec(ctx, `
		CREATE TRIGGER probe_hold_signing_key_promote
		AFTER UPDATE ON kaname.token_signing_keys
		FOR EACH ROW WHEN (OLD.state = 'PUBLISHED' AND NEW.state = 'ACTIVE')
		EXECUTE FUNCTION kaname.probe_hold_signing_key_promote()`)
	require.NoError(t, err, "триггер задержки повышения")
}

// awaitPromoteHeld ждёт, пока передача встанет на замке-советнике, то есть
// повышение записано и не зафиксировано, и возвращает её процесс базы.
func awaitPromoteHeld(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	deadline := time.Now().Add(sceneWaitLimit)
	for {
		var pids []int
		rows, err := pool.Query(ctx, `
			SELECT pid FROM pg_stat_activity
			 WHERE datname = current_database()
			   AND wait_event_type = 'Lock' AND wait_event = 'advisory'`)
		require.NoError(t, err)
		for rows.Next() {
			var pid int
			require.NoError(t, rows.Scan(&pid))
			pids = append(pids, pid)
		}
		require.NoError(t, rows.Err())
		if len(pids) == 1 {
			return pids[0]
		}
		require.Empty(t, pids, "сцена: замка повышения ждёт одна передача, а ждут %v", pids)
		if time.Now().After(deadline) {
			t.Fatalf("за %s передача не встала на повышении — сцена не построена", sceneWaitLimit)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// contestedKey — ключ, порождённый передачей: опубликован для всех, кроме
// самой передачи, и не из числа заранее застрявших.
func contestedKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool, stranded map[domain.KeyID]bool) domain.KeyID {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT kid FROM kaname.token_signing_keys WHERE state = 'PUBLISHED'`)
	require.NoError(t, err)
	defer rows.Close()
	var contested []domain.KeyID
	for rows.Next() {
		var kid string
		require.NoError(t, rows.Scan(&kid))
		if !stranded[domain.KeyID(kid)] {
			contested = append(contested, domain.KeyID(kid))
		}
	}
	require.NoError(t, rows.Err())
	require.Len(t, contested, 1, "сцена: передача порождает ровно один ключ, опубликованный на время передачи")
	return contested[0]
}

// awaitSweepersBlocked ждёт, пока все реплики сметателей встанут на замке.
// Ждать им, кроме передачи, некого: друг друга они держат лишь на время одного
// оператора, а у передачи из строк, которые трогает сметатель, только строка
// её ключа. Все сметатели ждут — значит все ждут строку ключа передачи.
func awaitSweepersBlocked(t *testing.T, ctx context.Context, pool *pgxpool.Pool, handOverPID, replicas int) {
	t.Helper()
	deadline := time.Now().Add(sceneWaitLimit)
	for {
		var waiting int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database()
			   AND wait_event_type = 'Lock' AND pid <> $1`, handOverPID).Scan(&waiting))
		if waiting == replicas {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("за %s строку ключа передачи ждут %d сметателей из %d — сцена не построена",
				sceneWaitLimit, waiting, replicas)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// awaitScene дожидается участников сцены под своим пределом: зависший
// участник — отказ пробы, а не зависший прогон.
func awaitScene(t *testing.T, wg *sync.WaitGroup) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(sceneWaitLimit):
		t.Fatalf("за %s после исхода передачи участники сцены не завершились", sceneWaitLimit)
	}
}
