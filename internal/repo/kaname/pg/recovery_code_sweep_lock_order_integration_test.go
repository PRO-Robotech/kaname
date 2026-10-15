// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_code_sweep_lock_order_integration_test.go — уборка кодов
// восстановления не ждёт строки, которую держит живая транзакция запроса
// (kaname#774).
//
// Взаимоблокировке нужен цикл ожиданий. Запрос восстановления и подтверждение
// смены адреса снимают живые коды личности одним оператором
// (`SupersedeRecoveryCodes`) в порядке индекса личности, а уборка удаляла
// просроченные строки в порядке своего плана и, наткнувшись на строку,
// занятую транзакцией запроса, ЖДАЛА её, держа уже снятые: два порядка одних
// строк — и цикл замыкается (40P01). Уборка, которая не ждёт ни одной строки,
// в цикл ожиданий не входит вовсе — это свойство и утверждается, потому что
// сам цикл зависит от порядка физического расположения строк и
// детерминированно не воспроизводится.
//
// Утверждается:
//
//	У1  транзакция запроса сняла (не зафиксировав) код личности U — уборка,
//	    запущенная в это время, возвращается в пределах срока, снимает
//	    просроченный код личности V и пропускает занятую строку U;
//	У2  после фиксации запроса строки U нет, повторная уборка снимает ноль;
//	У3  под конкуренцией — уборка против запросов восстановления по многим
//	    личностям с просроченными кодами — ни одна транзакция не получает 40P01.
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestRecoveryCodes_774_SweepDoesNotWaitOnARowHeldByARequest(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	people := lmPeople(t, pool, "rcsl", 2)
	u, v := people[0], people[1]
	var dbNow time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT now()`).Scan(&dbNow))
	held, _ := rcCode(t, "rcv-sl-held", u, dbNow.Add(-time.Hour))
	free, _ := rcCode(t, "rcv-sl-free", v, dbNow.Add(-time.Hour))
	rcInsert(t, repo, held)
	rcInsert(t, repo, free)

	// Транзакция запроса: живые коды U сняты, фиксации нет — строка занята.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	n, err := w.SupersedeRecoveryCodes(ctx, u)
	require.NoError(t, err)
	require.Equal(t, 1, n, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код U не снят транзакцией запроса")

	sweepCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	started := time.Now()
	removed, _, err := repo.SweepUnservableRecoveryCodes(sweepCtx, 0, 100)
	took := time.Since(started)
	t.Logf("уборка при занятой строке: снято %d · ошибка %v · %s", removed, err, took)
	require.NoErrorf(t, err, "У1: уборка ждала строку, занятую транзакцией запроса (%s) — участник цикла ожиданий", took)
	require.EqualValues(t, 1, removed, "У1: снимается просроченный код V, занятая строка U пропускается")

	require.NoError(t, w.Commit(ctx))
	removed, _, err = repo.SweepUnservableRecoveryCodes(ctx, 0, 100)
	require.NoError(t, err)
	require.Zero(t, removed, "У2: строку U сняла транзакция запроса — уборке снимать нечего")
}

func TestRecoveryCodes_774_SweepAgainstRequestsNeverDeadlocks(t *testing.T) {
	pool := hsPool(t)
	repo := pg.NewHumanSessionRepo(pool)
	ctx := context.Background()
	const persons, rounds = 8, 25
	people := lmPeople(t, pool, "rcdl", persons)
	var dbNow time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT now()`).Scan(&dbNow))
	seed := func(round int) {
		for i, p := range people {
			for k := 0; k < 3; k++ {
				c, _ := rcCode(t, fmt.Sprintf("rcv-dl-%d-%d-%d", round, i, k), p, dbNow.Add(-time.Hour-time.Duration(k)*time.Minute))
				rcInsert(t, repo, c)
			}
		}
	}
	deadlocks := 0
	var mu sync.Mutex
	note := func(err error) {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
			mu.Lock()
			deadlocks++
			mu.Unlock()
		}
	}
	for round := 0; round < rounds; round++ {
		seed(round)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, p := range people {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				w, err := repo.Writer(ctx)
				if err != nil {
					note(err)
					return
				}
				defer func() { _ = w.Rollback(ctx) }()
				if _, err := w.SupersedeRecoveryCodes(ctx, p); err != nil {
					note(err)
					return
				}
				note(w.Commit(ctx))
			}()
		}
		for s := 0; s < 2; s++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _, err := repo.SweepUnservableRecoveryCodes(ctx, 0, 1000)
				note(err)
			}()
		}
		close(start)
		wg.Wait()
	}
	t.Logf("ПЕРЕПИСЬ: раундов %d · личностей %d · запросов %d · уборок %d · 40P01 %d", rounds, persons, rounds*persons, rounds*2, deadlocks)
	require.Zero(t, deadlocks, "У3: уборка и запрос взаимно заблокировались")
}
