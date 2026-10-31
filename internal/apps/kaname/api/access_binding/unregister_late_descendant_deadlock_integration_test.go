// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// verifies https://github.com/PRO-Robotech/kaname/issues/1019
// Real PostgreSQL, lawful grants, and one-shot port barriers. The child is
// registered AFTER the first census, while the parent is still committed.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type lateCensus struct {
	pid         uint32
	isolation   string
	descendants []service.RegisteredDescendant
}
type lateCensusMirror struct {
	*kanamepg.ResourceMirrorEmitter
	first, beforeDelete pause
	mu                  sync.Mutex
	calls               int
	observed            chan lateCensus
}

func (h *lateCensusMirror) DescendantsTx(ctx context.Context, tx service.Tx, typ, id string) ([]service.RegisteredDescendant, error) {
	out, err := h.ResourceMirrorEmitter.DescendantsTx(ctx, tx, typ, id)
	if err != nil {
		return out, err
	}
	ptx := tx.(pgx.Tx)
	var isolation string
	if err = ptx.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil {
		return nil, err
	}
	h.mu.Lock()
	h.calls++
	call := h.calls
	h.mu.Unlock()
	h.observed <- lateCensus{pid: ptx.Conn().PgConn().PID(), isolation: isolation, descendants: out}
	if call == 1 {
		h.first.hit()
	}
	return out, nil
}
func (h *lateCensusMirror) DeleteTx(ctx context.Context, tx service.Tx, typ, id string, v time.Time) (bool, error) {
	h.beforeDelete.hit()
	return h.ResourceMirrorEmitter.DeleteTx(ctx, tx, typ, id, v)
}

func TestUnregisterLateDescendantVsObjectPass_NoDeadlock(t *testing.T) {
	w := newDescendantRingWorld(t)
	ctx, cancel := context.WithTimeout(w.ctx, 90*time.Second)
	defer cancel()
	// These are legitimate grants to a future child, not fabricated SQL rows.
	var fx descendantRing
	for i := 0; i < 20; i++ {
		parent := raceKey(24000, i)
		w.registerRegistry(parent)
		child := parent + "/app"
		b1 := w.grantTo(w.usrD, w.roleRepo, repoTarget(child), false, "1019 late: future-child B1")
		bx := w.grantTo(w.usrD, w.roleNested, urTarget(parent), false, "1019 late: parent BX")
		var ordered bool
		require.NoError(t, w.pool.QueryRow(ctx, `SELECT $1::text < $2::text`, b1, bx).Scan(&ordered))
		if ordered {
			fx = descendantRing{parent: parent, child: child, b1: b1, bx: bx}
			break
		}
	}
	require.NotEmpty(t, fx.parent, "fixture: lawful B1 < BX order")
	require.False(t, w.registered(pcrRepoType, fx.child), "fixture: C must not exist at first census")

	var rawMu sync.Mutex
	var rawErrors []pgconn.PgError
	newObservedPool := func(name string) *pgxpool.Pool {
		cfg := w.pool.Config()
		cfg.ConnConfig.RuntimeParams["application_name"] = name
		cfg.ConnConfig.RuntimeParams["deadlock_timeout"] = "200ms"
		cfg.ConnConfig.OnPgError = func(_ *pgconn.PgConn, e *pgconn.PgError) bool {
			rawMu.Lock()
			rawErrors = append(rawErrors, *e)
			rawMu.Unlock()
			return e.Severity != "FATAL"
		}
		p, err := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(p.Close)
		return p
	}
	upool := newObservedPool("kn1019-late-unregister")
	rpool := newObservedPool("kn1019-late-reconcile")
	var isolation string
	require.NoError(t, rpool.QueryRow(ctx, "SHOW transaction_isolation").Scan(&isolation))
	require.Equal(t, "read committed", isolation, "fixture: fresh late census isolation")
	h := &lateCensusMirror{ResourceMirrorEmitter: kanamepg.NewResourceMirrorEmitter(), observed: make(chan lateCensus, 16)}
	uc := internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), h, kanamepg.NewPoolTxBeginner(upool),
		kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld}),
		kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader())
	first, releaseFirstRaw := h.first.arm()
	beforeDelete, releaseDeleteRaw := h.beforeDelete.arm()
	var firstOnce, deleteOnce sync.Once
	releaseFirst := func() { firstOnce.Do(releaseFirstRaw) }
	releaseDelete := func() { deleteOnce.Do(releaseDeleteRaw) }
	defer releaseFirst()
	defer releaseDelete()
	uDone := make(chan error, 1)
	go func() { uDone <- w.withdrawWith(ctx, uc, fx.parent) }()
	select {
	case <-first:
	case e := <-uDone:
		t.Fatalf("fixture: U ended before first census: %v", e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	initial := <-h.observed
	require.Equal(t, "read committed", initial.isolation)
	for _, d := range initial.descendants {
		require.NotEqual(t, fx.child, d.ID, "fixture: child unexpectedly in first census")
	}
	w.registerRepository(fx.parent, "app")
	w.pollMember(fx.b1, fx.child, "fixture: B1 child member")
	w.pollMember(fx.bx, fx.child, "fixture: BX child member")
	require.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, fx.child), "fixture: lawful child access")
	releaseFirst()
	select {
	case <-beforeDelete:
	case e := <-uDone:
		t.Fatalf("fixture: U ended before delete: %v", e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r := reconcile.New(kanamepg.NewReconcileAdapter(rpool, catalog.Fixed{F: w.facts}), nil, catalog.Fixed{F: w.facts})
	rDone := make(chan error, 1)
	go func() { rDone <- r.ReconcileObject(ctx, dlRepoTgt, fx.child) }()
	var rpid int
	require.Eventually(t, func() bool {
		var p int
		err := w.pool.QueryRow(ctx, `SELECT pid FROM pg_stat_activity
		 WHERE datname=current_database() AND application_name='kn1019-late-reconcile'
		 AND $1::integer = ANY(pg_blocking_pids(pid)) AND query LIKE '%FOR NO KEY UPDATE%' LIMIT 1`, int(initial.pid)).Scan(&p)
		if err == nil {
			rpid = p
			return true
		}
		return false
	}, 15*time.Second, 10*time.Millisecond, "fixture: R must block on U's BX after sorted binding lock begins")
	// A third transaction proves B1 is already locked before U is released.
	probe, err := w.pool.Begin(ctx)
	require.NoError(t, err)
	_, err = probe.Exec(ctx, `SELECT id FROM kaname.access_bindings WHERE id=$1 FOR UPDATE NOWAIT`, fx.b1)
	var lockError *pgconn.PgError
	require.ErrorAs(t, err, &lockError, "fixture: B1 must already be locked")
	require.Equal(t, "55P03", lockError.Code)
	require.NoError(t, probe.Rollback(ctx))
	t.Logf("1019 schedule established: U pid=%d holds BX=%s; R pid=%d locks B1=%s and pg_blocking_pids(R) contains U", initial.pid, fx.bx, rpid, fx.b1)
	releaseDelete()
	var ue, re error
	select {
	case ue = <-uDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case re = <-rDone:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case late := <-h.observed:
		found := false
		for _, d := range late.descendants {
			found = found || d.ID == fx.child
		}
		require.True(t, found, "fixture: second census must discover C")
	default:
		t.Fatal("fixture: no late descendant census observed")
	}
	rawMu.Lock()
	captured := append([]pgconn.PgError(nil), rawErrors...)
	rawMu.Unlock()
	sawDeadlock := false
	for _, e := range captured {
		t.Logf("PostgreSQL SQLSTATE=%s message=%s detail=%s where=%s", e.Code, e.Message, e.Detail, e.Where)
		sawDeadlock = sawDeadlock || e.Code == "40P01"
	}
	t.Logf("1019 real outcomes: U=%v R=%v raw40P01=%t", ue, re, sawDeadlock)
	if ue != nil || re != nil {
		require.True(t, sawDeadlock, "not a valid baseline RED: failure without server SQLSTATE 40P01")
	}
	assert.NoError(t, ue, "1019 U must complete without deadlock")
	assert.NoError(t, re, "1019 R must complete without deadlock")
	if ue != nil {
		require.True(t, w.registered(pcrRegType, fx.parent), "deadlock victim U must roll back parent removal")
		require.NoError(t, w.withdrawErr(ctx, fx.parent), "cleanup/convergence after documented deadlock victim")
	}
	w.judgeDescendantRing(fx, fmt.Sprintf("1019 late, raw40P01=%t", sawDeadlock))
	// Откат первой попытки не оставляет аудит: один родительский event
	// принятого вызова называет ровно одного снятого потомка (#1020).
	// Отдельное снятие ребёнка не вызывалось и события о нём быть не должно.
	var parentEvents, childEvents, descendants int
	require.NoError(t, w.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE event_payload #>> '{object,id}'=$1),
		count(*) FILTER (WHERE event_payload #>> '{object,id}'=$2),
		coalesce(sum((event_payload->>'descendants')::integer)
			FILTER (WHERE event_payload #>> '{object,id}'=$1),0)
		FROM kaname.audit_outbox
		WHERE event_type='iam.resource_registration.unregistered'
		AND event_payload #>> '{object,id}' IN ($1,$2)`, fx.parent, fx.child).
		Scan(&parentEvents, &childEvents, &descendants))
	require.Equal(t, 1, parentEvents, "отброшенная попытка не оставляет второе событие")
	require.Equal(t, 1, descendants, "принятая попытка сняла ровно одного потомка")
	require.Zero(t, childEvents, "потомок отражён в событии родителя, отдельного вызова снятия не было")
}
