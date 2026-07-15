// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_rules_t31_iam_integration_test.go — cross-service ARM_LABELS revoke
// on label change, IAM-side confirmation test.
//
// An OBLIGATORY new integration test that fixes the eager-revoke
// guarantee END-TO-END through the reconciler-worker DRAIN path:
//
//   grant ACTIVE member by matchLabels:{network:treska}
//     → RegisterResource(object="vpc_network:X", labels={}) with a NEWER
//       source_version  (the consumer-side emit will add on label-Update)
//     → mirror.upsert FULL-REPLACE labels + enqueue resource_reconcile_outbox
//       event "mirror.upsert"  (RegisterResource use-case, ban #10 co-commit)
//     → worker.drain (NOT a direct ReconcileObject call) claims the event and
//       runs ReconcileObject(type,id)
//     → THEN: the matchLabels member is EAGER-REVOKED — a real DELETE from
//       access_binding_target_members + the FGA tuple-delete is emitted
//       (fell-out-loop reconcile.go:480-492).
//
// Expectation: GREEN against the CURRENT iam reconciler — the bug is purely
// the consumer-side emit; IAM already revokes correctly once the mirror gets the
// fresh (empty) labels. If this goes RED it is an IAM-side finding.
//
// TEST-ONLY (ban #13): no production code is touched.
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// newRegisterUCWired builds the RegisterResource use-case wired exactly like the
// composition-root (cmd/kacho-iam): fga_outbox emitter + resource_mirror emitter
// + tx beginner + reconcile-event emitter + account resolver.
// The reconcile-event wiring is what lets a label-change RegisterResource enqueue
// the resource_reconcile_outbox event the worker drains.
func newRegisterUCWired(pool *pgxpool.Pool) *internal_iam.RegisterResourceUseCase {
	return internal_iam.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
	).
		WithReconcile(kachopg.NewReconcileEventEmitter()).
		WithAccountResolver(kachopg.NewProjectAccountResolver())
}

// drainOnce drives the REAL reconciler-worker drain path to convergence (the
// test exercises the end-to-end RegisterResource→outbox→drain→ReconcileObject
// chain, NOT a direct ReconcileObject call). The worker's drain is unexported, so
// we run the worker loop with a tiny drain interval and a long sweep interval,
// then poll for the drained outbox event and cancel. Setting SweepInterval far in
// the future keeps the periodic sweep from racing the drain (the drain is the
// path under test); the one boot-sweep is harmless (idempotent reconcile).
func drainOnce(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	adapter := kachopg.NewReconcileAdapter(pool)
	engine := newReconcilerEngine(pool)
	worker := seed.NewReconcileWorker(engine, adapter, seed.ReconcileWorkerConfig{
		DrainInterval: 20 * time.Millisecond,
		SweepInterval: time.Hour, // keep the periodic sweep out of the way
		BatchSize:     64,
	})

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); _ = worker.Run(runCtx) }()

	// Wait until the worker has drained the reconcile event (sent_at set) — that
	// proves the DRAIN path (not the sweep) consumed the mirror.upsert event.
	require.Eventually(t, func() bool {
		var unsent int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM kacho_iam.resource_reconcile_outbox WHERE sent_at IS NULL`).
			Scan(&unsent); err != nil {
			return false
		}
		return unsent == 0
	}, 10*time.Second, 25*time.Millisecond, "worker must drain the resource_reconcile_outbox event")

	cancel()
	<-done
}

// newReconcilerEngine builds the reconcile use-case (ReconcileObject/Binding/
// ExpireBinding) backed by the pg adapter — the engine the worker drives.
func newReconcilerEngine(pool *pgxpool.Pool) seed.ReconcileEngine {
	rec, _ := newReconciler(pool)
	return rec
}

// ── label-change via RegisterResource → eager-revoke via drain ───────────────

func TestReconcile_T31Iam01_LabelChangeViaRegisterResource_EagerRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "t31iam01")
	rec, _ := newReconciler(pool)

	// Given: a rules-role granting v_get/v_list on vpc_network by matchLabels
	// {network:treska}, bound (thin) on the member's project scope.
	rule := domain.Rule{
		Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "list"},
		MatchLabels: map[string]string{"network": "treska"},
	}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "t31iam01role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	// Given: the network is in the mirror WITH the matching label, reconciled
	// ACTIVE (member row materialized + FGA write-tuple emitted). The mirror row
	// is created via the real RegisterResource use-case (same edge the consumer
	// uses on Create), with an early source_version.
	uc := newRegisterUCWired(pool)
	v0 := time.Now().Add(-time.Minute)
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + string(fx.prj),
		Relation:        "parent",
		Object:          "vpc_network:net-treska",
		Labels:          map[string]string{"network": "treska"},
		ParentProjectId: string(fx.prj),
		ParentAccountId: string(fx.accID),
		SourceVersion:   timestamppb.New(v0),
	}))
	require.NoError(t, rec.ReconcileBinding(ctx, bid)) // materialize the ACTIVE member

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "net-treska")
	require.True(t, ok, "matchLabels member materialized")
	require.Equal(t, domain.VerificationActive, st, "member ACTIVE before label removal")
	require.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "vpc_network:net-treska"), 1,
		"ACTIVE member emits the v_get/v_list write-tuple")

	// When: the label is REMOVED on the source resource → the consumer
	// re-emits RegisterResource with labels={} and a NEWER source_version. This is
	// the exact edge added on label-Update; here we drive it directly (IAM is
	// the callee — it must revoke regardless of which consumer emitted).
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId:       "project:" + string(fx.prj),
		Relation:        "parent",
		Object:          "vpc_network:net-treska",
		Labels:          map[string]string{}, // label removed (upsert {}, not Unregister)
		ParentProjectId: string(fx.prj),
		ParentAccountId: string(fx.accID),
		SourceVersion:   timestamppb.New(v0.Add(time.Minute)), // monotonic newer
	}))

	// Drive the REAL worker drain path (RegisterResource enqueued a mirror.upsert
	// reconcile event in the same writer-tx; the worker claims it and runs
	// ReconcileObject end-to-end — NOT a direct ReconcileObject call).
	drainOnce(t, ctx, pool)

	// Then (eager-revoke): the matchLabels member is GONE — a real DELETE from
	// access_binding_target_members (fell-out-loop reconcile.go:480-492).
	_, stillMember := memberStatusByRule(t, ctx, pool, bid, fp, "vpc.network", "net-treska")
	assert.False(t, stillMember,
		"label removed → member eager-revoked (real DELETE from access_binding_target_members)")

	// And: the FGA tuple-delete was emitted for the revoked member.
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "vpc_network:net-treska"), 1,
		"label removed → FGA tuple-delete emitted (visibility revoked)")

	// And: the mirror row STAYS with labels={} (upsert, not Unregister) — the
	// drain consumed a mirror.upsert event, and the row is present but label-empty.
	var mirrorRows int
	var labelsText string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) OVER (), labels::text FROM kacho_iam.resource_mirror
		  WHERE object_type='vpc.network' AND object_id='net-treska'`).Scan(&mirrorRows, &labelsText))
	assert.Equal(t, 1, mirrorRows, "mirror row survives the label removal (upsert, not Unregister)")
	assert.Equal(t, "{}", labelsText, "mirror labels fully replaced with {} (FULL-REPLACE upsert)")

	// And: the ledger no longer holds the revoked member's tuples (no orphan).
	var ledger int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id=$1 AND object='vpc_network:net-treska'`, string(bid)).Scan(&ledger))
	assert.Equal(t, 0, ledger, "revoked member leaves no ledger residual (no standing orphan tuple)")
}
