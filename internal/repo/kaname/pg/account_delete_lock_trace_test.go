// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Диагностика сохраняет ограниченный ряд фактических блокировок до ошибки.
// Только SELECT: тексты запросов и параметры не читаются и не выводятся.
func accountDeleteLockTrace(t *testing.T, parent context.Context, pool *pgxpool.Pool) func(bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	finished := make(chan []string, 1)
	go func() {
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		samples := make([]string, 0, 24)
		defer func() { finished <- samples }()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			sampleCtx, stop := context.WithTimeout(ctx, 500*time.Millisecond)
			var sample string
			err := pool.QueryRow(sampleCtx, `WITH p AS (
 SELECT pid,state,wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers,md5(query) AS query_hash
 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state<>'idle'
 ORDER BY pid LIMIT 8
), l AS (
 SELECT pid,locktype,mode,granted,relation::regclass::text AS relation,
        classid,objid,objsubid,transactionid::text AS transaction_id
 FROM pg_locks WHERE pid IN (SELECT pid FROM p)
 ORDER BY granted,pid,locktype,relation,classid,objid LIMIT 64
)
SELECT jsonb_build_object('activity',coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY pid) FROM p),'[]'::jsonb),
 'locks',coalesce((SELECT jsonb_agg(to_jsonb(l)) FROM l),'[]'::jsonb))::text`).Scan(&sample)
			stop()
			if err != nil {
				continue
			}
			if len(samples) > 0 && samples[len(samples)-1] == sample {
				continue
			}
			if len(samples) == 24 {
				copy(samples, samples[1:])
				samples = samples[:23]
			}
			samples = append(samples, sample)
		}
	}()
	var once sync.Once
	stop := func(report bool) {
		once.Do(func() {
			cancel()
			select {
			case samples := <-finished:
				if report {
					for i, sample := range samples {
						t.Logf("account delete lock diagnostic sample=%d state=%s", i, sample)
					}
				}
			case <-time.After(2 * time.Second):
				if report {
					t.Error("диагностический SELECT не завершился при отмене")
				}
			}
		})
	}
	t.Cleanup(func() { stop(false) })
	return stop
}
