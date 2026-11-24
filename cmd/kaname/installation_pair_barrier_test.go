// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Настоящая транзакция PostgreSQL владеет ТОЧНОЙ производственной блокировкой пары. Этот барьер не пишет строки GD,
// удостоверений, полномочий, временных меток или допуска.
// AwaitTwo связывает двух точных участников с удерживаемым ключом через настоящий
// граф ожиданий: authority guards могут сериализовать их раньше legacy pair lock.
// Полная история пары должна оставаться пустой до освобождения.
type nativePairBarrier struct {
	pool              *pgxpool.Pool
	tx                pgx.Tx
	pid               int32
	account, delegate string
}

func holdNativeAbsentPair(ctx context.Context, pool *pgxpool.Pool, account, delegate string) (*nativePairBarrier, error) {
	b := &nativePairBarrier{pool: pool, account: account, delegate: delegate}
	var err error
	b.tx, err = pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	good := false
	defer func() {
		if !good {
			_ = b.tx.Rollback(context.Background())
		}
	}()
	if err = b.tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&b.pid); err != nil {
		return nil, err
	}
	if _, err = b.tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1038))`, account+"/"+delegate); err != nil {
		return nil, err
	}
	var count int
	if err = b.tx.QueryRow(ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, account, delegate).Scan(&count); err != nil {
		return nil, err
	}
	if count != 0 {
		return nil, fmt.Errorf("concurrency fixture requires no pair history, found %d", count)
	}
	good = true
	return b, nil
}
func (b *nativePairBarrier) AwaitTwo(ctx context.Context, applications []string) ([]int32, error) {
	if len(applications) != 2 || applications[0] == "" || applications[1] == "" || applications[0] == applications[1] {
		return nil, fmt.Errorf("two distinct exact participant applications required")
	}
	var lastPIDs []int32
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		rows, err := b.pool.Query(ctx, `WITH RECURSIVE participants AS MATERIALIZED (
 SELECT pid,application_name,pg_blocking_pids(pid) AS blockers
 FROM pg_stat_activity
 WHERE datname=current_database() AND application_name=ANY($2::text[])
 AND state='active' AND wait_event_type='Lock'
), contenders(pid) AS (
 SELECT DISTINCT waiting.pid FROM pg_locks waiting
 JOIN pg_locks held ON held.locktype='advisory' AND held.granted AND held.pid=$1
 AND waiting.database=held.database AND waiting.classid=held.classid
 AND waiting.objid=held.objid AND waiting.objsubid=held.objsubid
 JOIN participants a ON a.pid=waiting.pid
 WHERE waiting.locktype='advisory' AND NOT waiting.granted
 AND $1=ANY(a.blockers)
 UNION
 SELECT a.pid FROM participants a JOIN contenders c ON c.pid=ANY(a.blockers)
)
SELECT c.pid,a.application_name FROM contenders c JOIN participants a ON a.pid=c.pid ORDER BY c.pid`, b.pid, applications)
		if err != nil {
			return nil, err
		}
		var pids []int32
		seen := map[string]bool{}
		for rows.Next() {
			var pid int32
			var application string
			if err = rows.Scan(&pid, &application); err != nil {
				rows.Close()
				return nil, err
			}
			if seen[application] {
				rows.Close()
				return nil, fmt.Errorf("multiple blocked backends from the same participant %s", application)
			}
			seen[application] = true
			pids = append(pids, pid)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
		lastPIDs = pids
		if len(pids) > 2 {
			return nil, fmt.Errorf("unexpected extra pair contender: %d", len(pids))
		}
		if len(pids) == 2 {
			var count int
			if err = b.pool.QueryRow(ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, b.account, b.delegate).Scan(&count); err != nil {
				return nil, err
			}
			if count != 0 {
				return nil, fmt.Errorf("pair appeared before barrier release")
			}
			return pids, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("two exact participants did not reach the held pair through the lock graph (observed %d): %w", len(lastPIDs), ctx.Err())
		case <-ticker.C:
		}
	}
}
func (b *nativePairBarrier) Release(ctx context.Context) error { return b.tx.Rollback(ctx) }
