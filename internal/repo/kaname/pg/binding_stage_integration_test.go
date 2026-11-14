// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func bindingStageEngine(t *testing.T, r protocolRig, tracer pgx.QueryTracer) *reconcile.Reconciler {
	t.Helper()
	if tracer != nil {
		cfg := r.runtime.Config()
		cfg.ConnConfig.Tracer = tracer
		pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(pool.Close)
		if release, ok := tracer.(interface{ releaseStage() }); ok {
			t.Cleanup(release.releaseStage)
		}
		r.runtime = pool
		r.repo = kanamepg.New(pool, nil)
	}
	participant, err := kanamepg.NewGroupMembershipParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	staged, err := participant.NewBindingStageParticipant(r.ctx, slog.Default())
	require.NoError(t, err)
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.runtime, catalog.Fixed{F: facts}), slog.Default(), catalog.Fixed{F: facts})
	require.NoError(t, engine.WithStagedBindingReconciler(staged))
	return engine
}
func stageSeedGroups(t *testing.T, r protocolRig, account string, count int, label string) []string {
	t.Helper()
	w, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(context.WithoutCancel(r.ctx)) }()
	result := make([]string, 0, count)
	for i := 0; i < count; i++ {
		id := ids.NewID("grp")
		_, err = w.GroupsW().Insert(r.ctx, domain.Group{ID: domain.GroupID(id), AccountID: domain.AccountID(account), Name: domain.GroupName(fmt.Sprintf("stage-%s-%d", label, i)), Labels: domain.Labels{"tier": domain.LabelVal(label)}})
		require.NoError(t, err)
		result = append(result, id)
	}
	require.NoError(t, w.Commit(r.ctx))
	return result
}
func stageBinding(t *testing.T, r protocolRig, account string, labels bool) domain.AccessBindingID {
	t.Helper()
	uid := seedMemberUser(t, r.ctx, r.admin, account, "stage-recipient-"+ids.NewID("usr"))
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, uid)
	require.NoError(t, err)
	rule := domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get", "list"}}
	if labels {
		rule.MatchLabels = map[string]string{"tier": "blue"}
	}
	return groupLifecycleBinding(t, r, account, uid, "stage_"+ids.NewID("rol"), rule)
}
func stageCount(t *testing.T, r protocolRig, id domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(DISTINCT object_id) FROM kaname.access_binding_target_members WHERE binding_id=$1 AND object_type='iam.group' AND verification_status='ACTIVE'`, string(id)).Scan(&n))
	return n
}

func TestBindingStageActualEntryPointsCoverLastPageAndStrict(t *testing.T) {
	r := writerProtocolRig(t)
	groups := stageSeedGroups(t, r, r.a, 259, "blue")
	foreign := stageSeedGroups(t, r, r.b, 1, "foreign")
	id := stageBinding(t, r, r.a, false)
	engine := bindingStageEngine(t, r, nil)
	require.NoError(t, engine.ReconcileBindingForward(r.ctx, id))
	require.Equal(t, 259, stageCount(t, r, id))
	var uid string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT subject_id FROM kaname.access_bindings WHERE id=$1`, string(id)).Scan(&uid))
	for _, gid := range []string{groups[0], groups[len(groups)-1]} {
		require.True(t, ledgerHasTuple(t, r.ctx, r.runtime, id, "user:"+uid, "v_get", "iam_group:"+gid))
	}
	// Получатель — обычный member, без owner/admin источника. Доступ доказывает
	// настоящий native Ask, включая отрицательную границу чужого аккаунта.
	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	var at time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&at))
	asker := relverdict.NewSemanticTransactionAsker(tx, r.bundle, at)
	for _, gid := range []string{groups[0], groups[len(groups)-1], foreign[0]} {
		allowed, e := asker.Allowed(r.ctx, "user:"+uid, "iam_group", gid, "v_get", nil)
		require.NoError(t, e)
		require.Equal(t, gid != foreign[0], allowed)
	}
	require.NoError(t, tx.Rollback(r.ctx))
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	require.NoError(t, engine.ConvergeBinding(r.ctx, id))
	require.NoError(t, engine.ReconcileBinding(r.ctx, id))
	require.Equal(t, 259, stageCount(t, r, id))
	var raw, unconfirmed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE subject=$1 AND relation='viewer'),EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$2 AND grant_capability_version<>0)`, "user:"+uid, string(id)).Scan(&raw, &unconfirmed))
	require.True(t, raw, "настоящий emitter/fold должен дать viewer")
	require.False(t, unconfirmed, "background stage не активирует meta carrier")
	_, err = r.runtime.Exec(r.ctx, `UPDATE kaname.groups SET labels='{}' WHERE id=$1`, groups[0])
	require.Error(t, err, "strict raw writer не получает participation")
}

type stageQueryBarrier struct {
	contains string
	reached  chan struct{}
	release  chan struct{}
	once     sync.Once
	stages   atomic.Int32
	pid      atomic.Uint32
}

func (b *stageQueryBarrier) TraceQueryStart(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "CREATE TEMP TABLE kaname_binding_stage") {
		b.stages.Add(1)
	}
	if strings.Contains(d.SQL, b.contains) {
		b.pid.Store(conn.PgConn().PID())
		b.once.Do(func() {
			close(b.reached)
			select {
			case <-b.release:
			case <-ctx.Done():
			}
		})
	}
	return ctx
}
func (*stageQueryBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func stageBarrier(t *testing.T, contains string) *stageQueryBarrier {
	t.Helper()
	b := &stageQueryBarrier{contains: contains, reached: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-b.release:
		default:
			close(b.release)
		}
	})
	return b
}
func stageWait(t *testing.T, r protocolRig, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-r.ctx.Done():
		t.Fatal(r.ctx.Err())
	}
}

func TestBindingStageLegacyLatePageAndMovedSourceRestageAtomically(t *testing.T) {
	for _, change := range []string{"last-page-insert", "label-change", "old-new-account"} {
		t.Run(change, func(t *testing.T) {
			r := writerProtocolRig(t)
			groups := stageSeedGroups(t, r, r.a, 257, "blue")
			id := stageBinding(t, r, r.a, true)
			b := stageBarrier(t, "SELECT kaname.authority_binding_epoch_lock")
			engine := bindingStageEngine(t, r, b)
			done := make(chan error, 1)
			go func() { done <- engine.ReconcileBinding(r.ctx, id) }()
			stageWait(t, r, b.reached)
			require.Zero(t, stageCount(t, r, id), "до apply stage не пишет domain")
			want := 257
			switch change {
			case "last-page-insert":
				stageSeedGroups(t, r, r.a, 1, "late")
				_, err := r.admin.Exec(r.ctx, `UPDATE kaname.groups SET labels='{"tier":"blue"}' WHERE account_id=$1 AND name='stage-late-0'`, r.a)
				require.NoError(t, err)
				want++
			case "label-change":
				_, err := r.runtime.Exec(r.ctx, `UPDATE kaname.groups SET labels='{"tier":"red"}' WHERE id=$1`, groups[0])
				require.NoError(t, err)
				want--
			case "old-new-account":
				_, err := r.runtime.Exec(r.ctx, `UPDATE kaname.groups SET account_id=$2 WHERE id=$1`, groups[0], r.b)
				require.NoError(t, err)
				want--
			}
			close(b.release)
			require.NoError(t, <-done)
			require.GreaterOrEqual(t, b.stages.Load(), int32(2), "stale diff обязан полностью re-stage")
			require.Equal(t, want, stageCount(t, r, id))
		})
	}
}

func TestBindingStageIndependentAccountsDoNotUpgradeGlobalEpoch(t *testing.T) {
	r := writerProtocolRig(t)
	stageSeedGroups(t, r, r.a, 2, "a")
	stageSeedGroups(t, r, r.b, 2, "b")
	a, bid := stageBinding(t, r, r.a, false), stageBinding(t, r, r.b, false)
	barrier := stageBarrier(t, "SELECT seq,body FROM pg_temp.kaname_binding_stage")
	first := bindingStageEngine(t, r, barrier)
	second := bindingStageEngine(t, r, nil)
	done := make(chan error, 1)
	go func() { done <- first.ReconcileBinding(r.ctx, a) }()
	stageWait(t, r, barrier.reached)
	// Первый writer удерживает account A + epoch locks. B обязан закончить до release A.
	bounded, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, second.ReconcileBinding(bounded, bid))
	require.Equal(t, 2, stageCount(t, r, bid))
	close(barrier.release)
	require.NoError(t, <-done)
	require.Equal(t, 2, stageCount(t, r, a))
}

type stageCancelOnWrite struct {
	cancel context.CancelFunc
	once   sync.Once
	writes atomic.Int32
}

func (b *stageCancelOnWrite) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "INSERT INTO kaname.access_binding_target_members") {
		if b.writes.Add(1) == 2 {
			b.once.Do(b.cancel)
		}
	}
	return ctx
}
func (*stageCancelOnWrite) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func TestBindingStageCancellationRollsBackAlreadyAppliedBatch(t *testing.T) {
	r := writerProtocolRig(t)
	stageSeedGroups(t, r, r.a, 3, "blue")
	id := stageBinding(t, r, r.a, false)
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	tracer := &stageCancelOnWrite{cancel: cancel}
	engine := bindingStageEngine(t, r, tracer)
	require.Error(t, engine.ReconcileBinding(ctx, id))
	require.GreaterOrEqual(t, tracer.writes.Load(), int32(2))
	require.Zero(t, stageCount(t, r, id))
	var ledger int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(id)).Scan(&ledger))
	require.Zero(t, ledger)
	require.NoError(t, bindingStageEngine(t, r, nil).ReconcileBinding(r.ctx, id))
	require.Equal(t, 3, stageCount(t, r, id))
}

func TestBindingStageEpochPrivilegesAndNoEntryFailClosed(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.runtime.Exec(r.ctx, `UPDATE kaname.authority_binding_epoch SET revision=0`)
	require.Error(t, err)
	_, err = r.runtime.Exec(r.ctx, `TRUNCATE kaname.authority_binding_epoch`)
	require.Error(t, err)
	var snapshot []byte
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, []string{r.a}).Scan(&snapshot))
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, snapshot)
	require.Error(t, err)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	r.enter(t, tx, r.intent(r.a), "participant")
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, []string{r.b}, snapshot)
	require.Error(t, err)
	require.NoError(t, tx.Rollback(r.ctx))
}

// Трассировщик останавливает настоящий staging TX перед commit. Проверяем
// pg_locks именно его backend, а не отсутствие записей в предметных таблицах.
type stageSnapshotAudit struct {
	pid     atomic.Uint32
	reached chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	queries []string
}

func (b *stageSnapshotAudit) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "CREATE TEMP TABLE kaname_binding_stage") {
		b.pid.Store(c.PgConn().PID())
	}
	if c.PgConn().PID() == b.pid.Load() {
		b.mu.Lock()
		b.queries = append(b.queries, d.SQL)
		b.mu.Unlock()
		if strings.EqualFold(d.SQL, "commit") {
			b.once.Do(func() {
				close(b.reached)
				select {
				case <-b.release:
				case <-ctx.Done():
				}
			})
		}
	}
	return ctx
}
func (*stageSnapshotAudit) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func TestBindingStageSnapshotHasNoBusinessLocksBeforeCoordinator(t *testing.T) {
	r := writerProtocolRig(t)
	stageSeedGroups(t, r, r.a, 3, "blue")
	id := stageBinding(t, r, r.a, false)
	audit := &stageSnapshotAudit{reached: make(chan struct{}), release: make(chan struct{})}
	engine := bindingStageEngine(t, r, audit)
	t.Cleanup(func() {
		select {
		case <-audit.release:
		default:
			close(audit.release)
		}
	})
	done := make(chan error, 1)
	go func() { done <- engine.ReconcileBinding(r.ctx, id) }()
	stageWait(t, r, audit.reached)
	var bad int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM pg_catalog.pg_locks l LEFT JOIN pg_catalog.pg_class c ON c.oid=l.relation LEFT JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE l.pid=$1 AND (l.locktype='advisory' OR (n.nspname='kaname' AND l.mode<>'AccessShareLock'))`, audit.pid.Load()).Scan(&bad))
	require.Zero(t, bad, "snapshot discovery не удерживает business row/advisory locks")
	audit.mu.Lock()
	queries := append([]string(nil), audit.queries...)
	audit.mu.Unlock()
	for _, query := range queries {
		upper := strings.ToUpper(query)
		require.NotContains(t, upper, "FOR KEY SHARE")
		require.NotContains(t, upper, "FOR UPDATE")
		require.NotContains(t, upper, "FOR NO KEY UPDATE")
		require.NotContains(t, upper, "PG_ADVISORY")
	}
	require.Zero(t, stageCount(t, r, id))
	close(audit.release)
	require.NoError(t, <-done)
	require.Equal(t, 3, stageCount(t, r, id))
}

func TestBindingStageForeignSelectorAppendInvalidatesLocalScope(t *testing.T) {
	r := writerProtocolRig(t)
	stageSeedGroups(t, r, r.a, 2, "blue")
	id := stageBinding(t, r, r.a, false)
	foreignUser := seedMemberUser(t, r.ctx, r.admin, r.b, "foreign-stage")
	barrier := stageBarrier(t, "SELECT kaname.authority_binding_epoch_lock")
	engine := bindingStageEngine(t, r, barrier)
	done := make(chan error, 1)
	go func() { done <- engine.ReconcileBinding(r.ctx, id) }()
	stageWait(t, r, barrier.reached)
	// Новая foreign labels выдача расширяет реальный group classifier, хотя её
	// carrier принадлежит B и ещё не породил member/ledger на объекте A.
	groupLifecycleBinding(t, r, r.b, foreignUser, "foreign_stage", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"tier": "blue"}})
	close(barrier.release)
	require.NoError(t, <-done)
	require.GreaterOrEqual(t, barrier.stages.Load(), int32(2))
	require.Equal(t, 2, stageCount(t, r, id))
}

func TestBindingStageEpochWaitUsesPostWaitTimeAndCancellationReleases(t *testing.T) {
	r := writerProtocolRig(t)
	var snapshot []byte
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_binding_epoch_read($1::text[])`, []string{r.a}).Scan(&snapshot))
	for _, cancelWait := range []bool{false, true} {
		t.Run(map[bool]string{false: "clock", true: "cancel"}[cancelWait], func(t *testing.T) {
			blocker, e := r.admin.Begin(r.ctx)
			require.NoError(t, e)
			lifecycleRollback(t, blocker)
			_, e = blocker.Exec(r.ctx, `SELECT scope FROM kaname.authority_binding_epoch WHERE scope=$1 FOR UPDATE`, r.a)
			require.NoError(t, e)
			tx, e := r.runtime.Begin(r.ctx)
			require.NoError(t, e)
			lifecycleRollback(t, tx)
			r.enter(t, tx, r.intent(r.a), "participant")
			var pid int
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			ctx, cancel := context.WithCancel(r.ctx)
			defer cancel()
			type result struct {
				at  time.Time
				err error
			}
			done := make(chan result, 1)
			go func() {
				var at time.Time
				e := tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, []string{r.a}, snapshot).Scan(&at)
				done <- result{at, e}
			}()
			require.Eventually(t, func() bool {
				var waiting bool
				e := r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_catalog.pg_blocking_pids($1))>0`, pid).Scan(&waiting)
				return e == nil && waiting
			}, 5*time.Second, 10*time.Millisecond)
			var boundary time.Time
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&boundary))
			if cancelWait {
				cancel()
			} else {
				require.NoError(t, blocker.Commit(r.ctx))
			}
			got := <-done
			if cancelWait {
				require.Error(t, got.err)
				require.NoError(t, blocker.Rollback(r.ctx))
			} else {
				require.NoError(t, got.err)
				require.True(t, got.at.After(boundary))
				var witness time.Time
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT (kaname.authority_protocol_attestation()->>'decision_at')::timestamptz`).Scan(&witness))
				require.True(t, witness.Equal(got.at))
			}
			_ = tx.Rollback(context.WithoutCancel(r.ctx))
			fresh, e := r.runtime.Begin(r.ctx)
			require.NoError(t, e)
			lifecycleRollback(t, fresh)
			r.enter(t, fresh, r.intent(r.a), "participant")
			require.NoError(t, fresh.Rollback(r.ctx))
		})
	}
}

func TestBindingStageLegacyRowEpochInversionRetriesWholeTransaction(t *testing.T) {
	r := writerProtocolRig(t)
	stageSeedGroups(t, r, r.a, 3, "blue")
	id := stageBinding(t, r, r.a, false)
	barrier := stageBarrier(t, "SELECT kaname.authority_binding_epoch_lock")
	engine := bindingStageEngine(t, r, barrier)
	legacy, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, legacy)
	_, err = legacy.Exec(r.ctx, `SELECT id FROM kaname.access_bindings WHERE id=$1 FOR UPDATE`, string(id))
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- engine.ReconcileBinding(r.ctx, id) }()
	stageWait(t, r, barrier.reached)
	close(barrier.release)
	require.Eventually(t, func() bool {
		var waiting bool
		e := r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_catalog.pg_blocking_pids($1))>0`, barrier.pid.Load()).Scan(&waiting)
		return e == nil && waiting
	}, 5*time.Second, 10*time.Millisecond)
	// Legacy держит business row; apply уже взял epoch share и ждёт эту row.
	// AFTER STATEMENT epoch bump замыкает цикл. Любой victim допустим, но только
	// полный rollback/re-stage применителя; ни один первый batch не фиксируется.
	_, err = legacy.Exec(r.ctx, `UPDATE kaname.access_bindings SET status=status WHERE id=$1`, string(id))
	legacyCommitted := err == nil
	if err != nil {
		var pgerr *pgconn.PgError
		require.ErrorAs(t, err, &pgerr)
		require.Contains(t, []string{"40P01", "40001"}, pgerr.Code)
		require.NoError(t, legacy.Rollback(r.ctx))
	} else {
		require.NoError(t, legacy.Commit(r.ctx))
	}
	require.NoError(t, <-done)
	if legacyCommitted {
		require.GreaterOrEqual(t, barrier.stages.Load(), int32(2))
	}
	require.Equal(t, 3, stageCount(t, r, id))
}

func TestBindingStageEpochFirstBlocksLegacyMutationUntilAtomicCommit(t *testing.T) {
	r := writerProtocolRig(t)
	stageSeedGroups(t, r, r.a, 3, "blue")
	id := stageBinding(t, r, r.a, false)
	barrier := stageBarrier(t, "SELECT seq,body FROM pg_temp.kaname_binding_stage")
	engine := bindingStageEngine(t, r, barrier)
	done := make(chan error, 1)
	go func() { done <- engine.ReconcileBinding(r.ctx, id) }()
	stageWait(t, r, barrier.reached)
	legacy, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, legacy)
	var pid int
	require.NoError(t, legacy.QueryRow(r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	changed := make(chan error, 1)
	go func() {
		_, e := legacy.Exec(r.ctx, `UPDATE kaname.access_bindings SET status=status WHERE id=$1`, string(id))
		changed <- e
	}()
	require.Eventually(t, func() bool {
		var waiting bool
		e := r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_catalog.pg_blocking_pids($1))>0`, pid).Scan(&waiting)
		return e == nil && waiting
	}, 5*time.Second, 10*time.Millisecond)
	require.Zero(t, stageCount(t, r, id))
	close(barrier.release)
	require.NoError(t, <-done)
	require.NoError(t, <-changed)
	require.NoError(t, legacy.Commit(r.ctx))
	require.Equal(t, 3, stageCount(t, r, id))
}

func TestBindingStageConstructorRejectsWritableEpochMetadata(t *testing.T) {
	r := writerProtocolRig(t)
	participant, err := kanamepg.NewGroupMembershipParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, "GRANT UPDATE ON kaname.authority_binding_epoch TO "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	staged, err := participant.NewBindingStageParticipant(r.ctx, slog.Default())
	require.Error(t, err)
	require.Nil(t, staged)
	_, err = r.admin.Exec(r.ctx, "REVOKE UPDATE ON kaname.authority_binding_epoch FROM "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	staged, err = participant.NewBindingStageParticipant(r.ctx, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, staged)
}

func TestBindingStageExpiredCarrierIsNotRematerialized(t *testing.T) {
	r := writerProtocolRig(t)
	stageSeedGroups(t, r, r.a, 2, "blue")
	id := stageBinding(t, r, r.a, false)
	// kaname#1034: срок задаётся допустимым будущим значением; проверка
	// начинается только после его истечения по часам той же базы.
	_, err := r.runtime.Exec(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+interval '50 milliseconds' WHERE id=$1`, string(id))
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		var expired bool
		e := r.runtime.QueryRow(r.ctx, `SELECT expires_at<=clock_timestamp() FROM kaname.access_bindings WHERE id=$1`, string(id)).Scan(&expired)
		return e == nil && expired
	}, 5*time.Second, 10*time.Millisecond)
	engine := bindingStageEngine(t, r, nil)
	require.NoError(t, engine.ReconcileBinding(r.ctx, id))
	require.NoError(t, engine.ConvergeBinding(r.ctx, id))
	require.Zero(t, stageCount(t, r, id))
	var ledger int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(id)).Scan(&ledger))
	require.Zero(t, ledger)
}

func (b *stageQueryBarrier) releaseStage() {
	select {
	case <-b.release:
	default:
		close(b.release)
	}
}
func (b *stageSnapshotAudit) releaseStage() {
	select {
	case <-b.release:
	default:
		close(b.release)
	}
}

// kaname#1034: барьер стоит ПОСЛЕ RR commit и ДО entry SQL. Он требует,
// чтобы все занятые slots дошли до coordinator без приобретения второго slot.
type stagePoolBarrier struct {
	mu      sync.Mutex
	want    int
	staged  map[uint32]bool
	entered map[uint32]bool
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *stagePoolBarrier) TraceQueryStart(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	pid := conn.PgConn().PID()
	if strings.Contains(d.SQL, "CREATE TEMP TABLE kaname_binding_stage") {
		b.mu.Lock()
		b.staged[pid] = true
		b.mu.Unlock()
	}
	if strings.Contains(d.SQL, "SELECT kaname.authority_protocol_enter(") {
		b.mu.Lock()
		b.entered[pid] = true
		if len(b.entered) == b.want {
			b.once.Do(func() { close(b.reached) })
		}
		b.mu.Unlock()
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*stagePoolBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (b *stagePoolBarrier) releaseStage() {
	select {
	case <-b.release:
	default:
		close(b.release)
	}
}

func TestBindingStageOneSlotAndSaturatedPoolCompleteOrCancelWithoutLeaks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		slots  int32
		cancel bool
	}{
		{"one-slot", 1, false}, {"two-saturated-slots", 2, false}, {"cancel-saturated-slots", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := writerProtocolRig(t)
			stageSeedGroups(t, r, r.a, 2, "a")
			stageSeedGroups(t, r, r.b, 2, "b")
			bindingIDs := []domain.AccessBindingID{stageBinding(t, r, r.a, false)}
			if tc.slots == 2 {
				bindingIDs = append(bindingIDs, stageBinding(t, r, r.b, false))
			}
			barrier := &stagePoolBarrier{want: len(bindingIDs), staged: map[uint32]bool{}, entered: map[uint32]bool{}, reached: make(chan struct{}), release: make(chan struct{})}
			cfg := r.runtime.Config()
			cfg.MaxConns = tc.slots
			cfg.MinConns = 0
			cfg.ConnConfig.Tracer = barrier
			pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			t.Cleanup(barrier.releaseStage)
			limited := r
			limited.runtime = pool
			limited.repo = kanamepg.New(pool, nil)
			engine := bindingStageEngine(t, limited, nil)
			ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
			defer cancel()
			done := make(chan error, len(bindingIDs))
			for _, id := range bindingIDs {
				go func() { done <- engine.ReconcileBinding(ctx, id) }()
			}
			select {
			case <-barrier.reached:
			case <-ctx.Done():
				t.Fatal("coordinator не получил тот же stage slot:", ctx.Err())
			}
			barrier.mu.Lock()
			staged := len(barrier.staged)
			entered := len(barrier.entered)
			allSame := true
			for pid := range barrier.entered {
				allSame = allSame && barrier.staged[pid]
			}
			barrier.mu.Unlock()
			require.Equal(t, len(bindingIDs), staged)
			require.Equal(t, len(bindingIDs), entered)
			require.True(t, allSame, "RR stage и новый RC coordinator используют один backend")
			require.Equal(t, tc.slots, pool.Stat().AcquiredConns())
			for _, id := range bindingIDs {
				require.Zero(t, stageCount(t, r, id))
			}
			if tc.cancel {
				cancel()
			}
			barrier.releaseStage()
			for range bindingIDs {
				select {
				case err = <-done:
					if tc.cancel {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("stage не освободил slot после completion/cancellation")
				}
			}
			require.Zero(t, pool.Stat().AcquiredConns())
			for _, id := range bindingIDs {
				if tc.cancel {
					require.Zero(t, stageCount(t, r, id))
				} else {
					require.Equal(t, 2, stageCount(t, r, id))
				}
			}
			// Проверяем все slots, а не один случайно свободный. Stage connections
			// закрыты; следующий ordinary LOGIN не наследует spool или witness.
			var held []*pgxpool.Conn
			defer func() {
				for _, conn := range held {
					conn.Release()
				}
			}()
			for range bindingIDs {
				conn, e := pool.Acquire(r.ctx)
				require.NoError(t, e)
				held = append(held, conn)
				var clean bool
				var session string
				require.NoError(t, conn.QueryRow(r.ctx, `SELECT pg_catalog.to_regclass('pg_temp.kaname_binding_stage') IS NULL AND pg_catalog.to_regclass('pg_temp.kaname_authority_attestation') IS NULL,session_user`).Scan(&clean, &session))
				require.True(t, clean)
				require.Equal(t, r.role, session)
			}
			for _, conn := range held {
				conn.Release()
			}
			held = nil
			fresh, stop := context.WithTimeout(r.ctx, 10*time.Second)
			defer stop()
			require.NoError(t, engine.ReconcileBinding(fresh, bindingIDs[0]))
			require.Equal(t, 2, stageCount(t, r, bindingIDs[0]))
			require.Zero(t, pool.Stat().AcquiredConns())
		})
	}
}

type stageClockObservation struct {
	at  time.Time
	err error
}
type stageLegacyClockTrace struct {
	lockSQL    string
	pid        atomic.Uint32
	stages     atomic.Int32
	before     chan stageClockObservation
	after      chan stageClockObservation
	beforeOnce sync.Once
	afterOnce  sync.Once
}

func (b *stageLegacyClockTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "CREATE TEMP TABLE kaname_binding_stage") {
		b.stages.Add(1)
	}
	observe := func(ch chan stageClockObservation) {
		var at time.Time
		// QueryStart вызывается до отправки внешнего SQL; вложенное чтение
		// использует разрешённый validated API, а не private temp relation.
		err := conn.QueryRow(ctx, `SELECT (kaname.authority_protocol_attestation()->>'decision_at')::timestamptz`).Scan(&at)
		ch <- stageClockObservation{at, err}
	}
	if strings.Contains(d.SQL, b.lockSQL) {
		b.pid.Store(conn.PgConn().PID())
		b.beforeOnce.Do(func() { observe(b.before) })
	}
	if strings.Contains(d.SQL, "SELECT seq,body FROM pg_temp.kaname_binding_stage") {
		b.afterOnce.Do(func() { observe(b.after) })
	}
	return ctx
}
func (*stageLegacyClockTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestBindingStageExpiryAndWitnessAfterEveryLegacyLockWait(t *testing.T) {
	for _, kind := range []string{"advisory", "binding-row", "role-row"} {
		for _, expired := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/expired=%t", kind, expired), func(t *testing.T) {
				r := writerProtocolRig(t)
				stageSeedGroups(t, r, r.a, 3, "blue")
				id := stageBinding(t, r, r.a, false)
				lockSQL := "SELECT pg_advisory_xact_lock(hashtext($1))"
				if kind == "binding-row" {
					lockSQL = kanamepg.LockBindingsSQL
				}
				if kind == "role-row" {
					lockSQL = kanamepg.LockRolesOfBindingsSQL
				}
				trace := &stageLegacyClockTrace{lockSQL: lockSQL, before: make(chan stageClockObservation, 1), after: make(chan stageClockObservation, 1)}
				engine := bindingStageEngine(t, r, trace)
				var expires time.Time
				interval := "1 hour"
				if expired {
					interval = "3 seconds"
				}
				require.NoError(t, r.runtime.QueryRow(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, string(id), interval).Scan(&expires))
				var outboxBefore int
				require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&outboxBefore))
				blocker, err := r.runtime.Begin(r.ctx)
				require.NoError(t, err)
				lifecycleRollback(t, blocker)
				switch kind {
				case "advisory":
					_, err = blocker.Exec(r.ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, string(id))
				case "binding-row":
					_, err = blocker.Exec(r.ctx, `SELECT id FROM kaname.access_bindings WHERE id=$1 FOR UPDATE`, string(id))
				case "role-row":
					_, err = blocker.Exec(r.ctx, `SELECT id FROM kaname.roles WHERE id=(SELECT role_id FROM kaname.access_bindings WHERE id=$1) FOR UPDATE`, string(id))
				}
				require.NoError(t, err)
				ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- engine.ReconcileBinding(ctx, id) }()
				var before stageClockObservation
				select {
				case before = <-trace.before:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				require.NoError(t, before.err)
				require.True(t, before.at.Before(expires), "carrier обязан быть живым до старого lock wait")
				require.Eventually(t, func() bool {
					var waiting bool
					e := r.admin.QueryRow(r.ctx, `SELECT cardinality(pg_catalog.pg_blocking_pids($1))>0`, trace.pid.Load()).Scan(&waiting)
					return e == nil && waiting
				}, 5*time.Second, 10*time.Millisecond)
				if expired {
					require.Eventually(t, func() bool {
						var reached bool
						e := r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()>$1::timestamptz`, expires).Scan(&reached)
						return e == nil && reached
					}, 5*time.Second, 10*time.Millisecond)
				}
				require.Zero(t, stageCount(t, r, id))
				var releaseBoundary time.Time
				require.NoError(t, blocker.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&releaseBoundary))
				require.NoError(t, blocker.Commit(r.ctx)) // Ни одной source mutation/epoch bump.
				select {
				case err = <-done:
					require.NoError(t, err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				require.Equal(t, int32(1), trace.stages.Load(), "без mutation нет restage, clock обязан обновиться сам")
				var ledger, outbox int
				require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(id)).Scan(&ledger))
				require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&outbox))
				if expired {
					require.Zero(t, stageCount(t, r, id))
					require.Zero(t, ledger)
					require.Equal(t, outboxBefore, outbox)
					select {
					case <-trace.after:
						t.Fatal("expired carrier дошёл до replay")
					default:
					}
				} else {
					require.Equal(t, 3, stageCount(t, r, id))
					require.Positive(t, ledger)
					require.Greater(t, outbox, outboxBefore)
					select {
					case after := <-trace.after:
						require.NoError(t, after.err)
						require.True(t, after.at.After(releaseBoundary))
						require.True(t, after.at.After(before.at))
						require.True(t, after.at.Before(expires))
					default:
						t.Fatal("нет validated witness перед replay")
					}
				}
			})
		}
	}
}
