// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	rid11AdmissionFixtureApplication = "rid11-admission-fixture"
	rid11AdmissionServeApplication   = "rid11-admission-serve"
)

type rid11ConsumerAdmissionSample struct {
	blocker, transactionAge string
	waits                   int
}

type rid11ConsumerAdmissionWatch struct {
	cancel context.CancelFunc
	done   chan struct{}
	sample rid11ConsumerAdmissionSample
}

func (f *installationNativeWorld) startInitialDelivery(t *testing.T, input installruntime.DeliveryInput) (*installruntime.Process, error) {
	watch := f.consumerAdmission
	if watch == nil {
		return f.session.StartDelivery(f.given.ctx, input)
	}
	// Атрибуция по application_name, как у участников RID02. PGAPPNAME меняет
	// только метку соединения исходного serve, сохраняя тот же DSN и политику пула.
	environment := f.session.Environment
	f.session.Environment = append(slices.Clone(environment), "PGAPPNAME="+rid11AdmissionServeApplication)
	process, err := f.session.StartDelivery(f.given.ctx, input)
	f.session.Environment = environment
	if err == nil {
		watch.start(t, f.given.pool)
	}
	return process, err
}

func (w *rid11ConsumerAdmissionWatch) start(t *testing.T, pool *pgxpool.Pool) {
	ctx, cancel := context.WithCancel(t.Context())
	w.cancel, w.done = cancel, make(chan struct{})
	w.sample = rid11ConsumerAdmissionSample{blocker: "unknown", transactionAge: "unknown"}
	t.Cleanup(func() { w.stop() })
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				attempt, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
				sample, ok := rid11ReadConsumerAdmissionSample(attempt, pool)
				cancel()
				if ok {
					w.sample = sample
					return
				}
			}
		}
	}()
}

func (w *rid11ConsumerAdmissionWatch) stop() rid11ConsumerAdmissionSample {
	w.cancel()
	<-w.done
	return w.sample
}

func rid11ReadConsumerAdmissionSample(ctx context.Context, pool *pgxpool.Pool) (rid11ConsumerAdmissionSample, bool) {
	// Снимаем первый длительный wait на точном двухкомпонентном advisory key.
	// $1 в a.query — параметр extended protocol: его значение в статистике не видно.
	// Как и в RID02, pg_blocking_pids связывает точного ожидающего с прямыми
	// блокирующими сессиями, включая тех, кто стоит впереди в очереди.
	// Возраст относится к самой старой видимой транзакции, если видны все.
	var s rid11ConsumerAdmissionSample
	err := pool.QueryRow(ctx, `WITH admission_locks AS MATERIALIZED (
 SELECT pid, mode, granted, waitstart FROM pg_locks
 WHERE locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2
 AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
), waiters AS MATERIALIZED (
 SELECT pg_blocking_pids(a.pid) AS blockers
 FROM admission_locks l JOIN pg_stat_activity a ON a.pid=l.pid
 WHERE a.datname=current_database() AND a.application_name=$1 AND a.backend_type='client backend'
 AND a.state='active' AND a.wait_event_type='Lock'
 AND a.query='SELECT kaname.authority_installation_enter_v2($1)'
 AND l.mode='ExclusiveLock' AND NOT l.granted
 AND l.waitstart <= statement_timestamp()-interval '20 seconds'
), blockers AS (
 SELECT CASE WHEN a.application_name=$1 THEN 'serve'
             WHEN a.application_name=$2 THEN 'fixture'
             WHEN a.pid IS NULL THEN 'unknown'
             ELSE 'other' END AS category,
        a.xact_start
 FROM waiters w LEFT JOIN LATERAL unnest(w.blockers) b(pid) ON true
 LEFT JOIN pg_stat_activity a ON a.pid=b.pid AND a.datname=current_database()
 AND EXISTS (SELECT FROM admission_locks l WHERE l.pid=b.pid)
)
SELECT (SELECT least(count(*),64)::int FROM waiters),
 CASE WHEN min(category)=max(category) THEN min(category) ELSE 'unknown' END,
 CASE WHEN bool_and(xact_start IS NOT NULL) IS NOT TRUE THEN 'unknown'
      WHEN statement_timestamp()-min(xact_start)<interval '30 seconds' THEN 'under-30s'
      WHEN statement_timestamp()-min(xact_start)<interval '60 seconds' THEN '30s-to-60s'
      ELSE '60s-or-more' END
FROM blockers`, rid11AdmissionServeApplication, rid11AdmissionFixtureApplication).
		Scan(&s.waits, &s.blocker, &s.transactionAge)
	return s, err == nil && s.waits > 0 && s.waits <= 64 &&
		slices.Contains([]string{"fixture", "serve", "other", "unknown"}, s.blocker) &&
		slices.Contains([]string{"under-30s", "30s-to-60s", "60s-or-more", "unknown"}, s.transactionAge)
}
