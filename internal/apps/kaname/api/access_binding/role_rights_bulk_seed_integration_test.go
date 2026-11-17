// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Трассировщик сохраняет только соединение; штатный наблюдатель получает свои вызовы.
type s1p8SeedConnectionTrace struct {
	conn *pgx.Conn
}

func (s *s1p8SeedConnectionTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	s.conn = conn
	return ctx
}

func (*s1p8SeedConnectionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Это исключительно тестовый доступ к транзакции настоящего писателя репозитория.
type s1p8BulkSeed struct {
	writer kaname.Writer
	conn   *pgx.Conn
	pid    uint32
}

func (s *s1p8BulkSeed) rollback() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.writer.Rollback(ctx)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

func newS1P8BulkSeed(t *testing.T, ctx context.Context, original *pgxpool.Pool) *s1p8BulkSeed {
	t.Helper()
	cfg := original.Config()
	cfg.MaxConns, cfg.MinConns = 1, 0
	trace := &s1p8SeedConnectionTrace{}
	tracers := []pgx.QueryTracer{trace}
	if cfg.ConnConfig.Tracer != nil {
		tracers = append(tracers, cfg.ConnConfig.Tracer)
	}
	cfg.ConnConfig.Tracer = multitracer.New(tracers...)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	writer, err := kanamepg.New(pool, nil).Writer(ctx)
	require.NoError(t, err)
	seed := &s1p8BulkSeed{writer: writer, conn: trace.conn}
	t.Cleanup(func() {
		if err := seed.rollback(); err != nil {
			t.Errorf("очистка посева: %v", err)
		}
	})
	require.NotNil(t, seed.conn, "соединение настоящего писателя захвачено трассировщиком")
	require.Equal(t, byte('T'), seed.conn.PgConn().TxStatus(), "соединение удерживает настоящую открытую транзакцию")
	seed.pid = seed.conn.PgConn().PID()
	// Физическое исключение писателей сохраняет guards и журнал, заменяя
	// накопление отдельного advisory key для каждой строки массового посева.
	_, err = seed.conn.Exec(ctx, "LOCK TABLE kaname.resource_journal IN SHARE ROW EXCLUSIVE MODE")
	require.NoError(t, err)
	return seed
}

func TestS1P8BulkSeedIsAtomicAndExcludesJournalWriter(t *testing.T) {
	w := newGDWorld(t)
	ctx, cancel := context.WithTimeout(w.ctx, 35*time.Second)
	defer cancel()
	bindings := make([]domain.AccessBinding, 32)
	bindingIDs := make([]string, len(bindings))
	for i := range bindings {
		project := seedProjectInAccount(t, ctx, w.pool, w.accA, fmt.Sprintf("bulk-seed-%d", i))
		bindingIDs[i] = ids.NewID(domain.PrefixAccessBinding)
		bindings[i] = domain.AccessBinding{
			ID: domain.AccessBindingID(bindingIDs[i]), SubjectType: domain.SubjectTypeUser,
			SubjectID: domain.SubjectID(w.usrA), RoleID: w.rolPusher,
			ResourceType: "project", ResourceID: string(project),
			Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive,
		}
	}
	seed := newS1P8BulkSeed(t, ctx, w.pool)
	for i, binding := range bindings {
		_, err := bindingset.Insert(ctx, seed.writer.AccessBindingsW(), binding)
		require.NoError(t, err, "посев выдачи %d", i)
	}
	var bindingCount, subjectCount int
	require.NoError(t, seed.conn.QueryRow(ctx, `SELECT
(SELECT count(*) FROM kaname.access_bindings WHERE id=ANY($1::text[])),
(SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=ANY($1::text[]))`, bindingIDs).Scan(&bindingCount, &subjectCount))
	require.Equal(t, 32, bindingCount)
	require.Equal(t, 32, subjectCount)
	rows, err := seed.conn.Query(ctx, `SELECT sequence_no, event_type FROM kaname.resource_journal WHERE resource_id=ANY($1::text[]) ORDER BY sequence_no`, bindingIDs)
	require.NoError(t, err)
	journalIDs := make([]int64, 0, 64)
	events := map[string]int{}
	for rows.Next() {
		var id int64
		var event string
		err = rows.Scan(&id, &event)
		if err != nil {
			rows.Close()
			require.NoError(t, err)
		}
		journalIDs = append(journalIDs, id)
		events[event]++
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.Len(t, journalIDs, 64)
	require.Equal(t, map[string]int{"CREATED": 32, "UPDATED": 32}, events)
	var journalKeys int
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT count(*) FROM pg_locks
WHERE pid=$1 AND locktype='advisory' AND classid=1262569304::oid AND objsubid=2 AND granted`, seed.pid).Scan(&journalKeys))
	t.Logf("посев в одной транзакции: выдачи=%d субъекты=%d журнал=%d ключи=%d", bindingCount, subjectCount, len(journalIDs), journalKeys)
	require.Equal(t, 0, journalKeys, "массовый посев должен исключать писателей журнала без накопления ключей каждой строки")

	var physicalExclusion bool
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks
WHERE pid=$1 AND locktype='relation' AND relation='kaname.resource_journal'::regclass
AND mode='ShareRowExclusiveLock' AND granted)`, seed.pid).Scan(&physicalExclusion))
	require.True(t, physicalExclusion, "основная транзакция физически исключает писателей журнала")

	// Продолжение достижимо после зелёного контроля границы числа ключей.
	peerCfg := w.pool.Config()
	peerCfg.MaxConns, peerCfg.MinConns = 1, 0
	peerPool, err := pgxpool.NewWithConfig(ctx, peerCfg)
	require.NoError(t, err)
	t.Cleanup(peerPool.Close)
	peerTx, err := peerPool.BeginTx(ctx, pgx.TxOptions{})
	require.NoError(t, err)
	peerPID := peerTx.Conn().PgConn().PID()
	peerCtx, peerCancel := context.WithCancel(ctx)
	var peerDone chan error
	peerJoined := false
	t.Cleanup(func() {
		peerCancel()
		if err := seed.rollback(); err != nil {
			t.Errorf("очистка основной транзакции перед соединением конкурента: %v", err)
		}
		if peerDone != nil && !peerJoined {
			if err := <-peerDone; err != nil {
				t.Logf("завершение отменённой вставки конкурента: %v", err)
			}
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := peerTx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Errorf("очистка транзакции конкурента: %v", err)
		}
	})
	peerID := ids.NewID(domain.PrefixAccessBinding)
	peerDone = make(chan error, 1)
	go func() {
		_, insertErr := peerTx.Exec(peerCtx, `INSERT INTO kaname.resource_journal
(resource_kind,resource_id,event_type,payload)
VALUES ('iam_access_binding',$1,'UPDATED',jsonb_build_object('id',$1::text))`, peerID)
		peerDone <- insertErr
	}()
	barrier, stopBarrier := context.WithTimeout(ctx, 5*time.Second)
	defer stopBarrier()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var physicallyBlocked bool
		err = w.pool.QueryRow(barrier, `SELECT EXISTS(SELECT 1 FROM pg_locks
WHERE pid=$1 AND locktype='relation' AND relation='kaname.resource_journal'::regclass
AND mode='RowExclusiveLock' AND NOT granted) AND $2::integer=ANY(pg_blocking_pids($1::integer))`, peerPID, seed.pid).Scan(&physicallyBlocked)
		require.NoError(t, err, "наблюдение физического ожидания вставки журнала")
		if physicallyBlocked {
			break
		}
		select {
		case insertErr := <-peerDone:
			peerJoined = true
			require.NoError(t, insertErr, "конкурент завершился до физического барьера")
			t.Fatal("вставка конкурента прошла без физического исключения писателей журнала")
		case <-barrier.Done():
			t.Fatalf("физический барьер вставки не наблюдался: %v", barrier.Err())
		case <-ticker.C:
		}
	}
	require.NoError(t, seed.rollback())
	select {
	case insertErr := <-peerDone:
		peerJoined = true
		require.NoError(t, insertErr, "вставка конкурента после отката посева")
	case <-ctx.Done():
		t.Fatalf("вставка конкурента не завершилась после отката: %v", ctx.Err())
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = peerTx.Rollback(cleanup)
	stop()
	require.NoError(t, err)
	var remainingBindings, remainingSubjects, remainingJournal int
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT
(SELECT count(*) FROM kaname.access_bindings WHERE id=ANY($1::text[])),
(SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=ANY($1::text[])),
(SELECT count(*) FROM kaname.resource_journal WHERE resource_id=ANY($1::text[]) OR resource_id=$2)`, bindingIDs, peerID).Scan(&remainingBindings, &remainingSubjects, &remainingJournal))
	require.Zero(t, remainingBindings, "выдачи посева откатились")
	require.Zero(t, remainingSubjects, "субъекты посева откатились")
	require.Zero(t, remainingJournal, "строки журнала посева и конкурента откатились")
}
