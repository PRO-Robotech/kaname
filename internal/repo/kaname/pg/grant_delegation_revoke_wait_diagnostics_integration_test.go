// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"
)

// Только диагностика красного исхода: прежние 20 секунд и global drain
// остаются обязательными. Снимок относится к изолированной БД этой фикстуры,
// поэтому поздний worker другой БД не выдаётся за причину текущего отказа.
func delegationRevokeWaitDiagnosticsOnFailure(t *testing.T, w delegationUCWorld) {
	t.Helper()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
		defer cancel()
		stat := w.r.runtime.Stat()
		t.Logf("staged revoke: pool acquired=%d idle=%d total=%d max=%d acquire_count=%d cancelled_acquire=%d empty_acquire=%d", stat.AcquiredConns(), stat.IdleConns(), stat.TotalConns(), stat.MaxConns(), stat.AcquireCount(), stat.CanceledAcquireCount(), stat.EmptyAcquireCount())
		var data []byte
		err := w.r.admin.QueryRow(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(a)),'[]'::jsonb) FROM (
 SELECT pid,application_name,state,wait_event_type,wait_event,
        pg_blocking_pids(pid) AS blocker_pids,
        extract(epoch FROM clock_timestamp()-xact_start) AS transaction_seconds,
        extract(epoch FROM clock_timestamp()-query_start) AS query_seconds,
        left(query,1200) AS query,
        (SELECT coalesce(jsonb_agg(jsonb_build_object(
          'type',l.locktype,'mode',l.mode,'granted',l.granted,
          'relation',l.relation::regclass::text,'transaction',l.transactionid::text,
          'classid',l.classid::text,'objid',l.objid::text,'objsubid',l.objsubid)), '[]'::jsonb)
         FROM pg_locks l WHERE l.pid=s.pid) AS locks
 FROM pg_stat_activity s
 WHERE datname=current_database() AND pid<>pg_backend_pid()
 ORDER BY pid LIMIT 64
) a`).Scan(&data)
		if err != nil {
			t.Logf("staged revoke: снимок SQL/locks не получен: %v", err)
			return
		}
		t.Logf("staged revoke: SQL/locks текущей fixture БД (не более 64 сеансов): %s", data)
	})
}
